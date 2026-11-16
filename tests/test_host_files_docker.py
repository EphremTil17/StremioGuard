"""Opt-in Docker tests for AC-14 (file modes in rootless Docker) and AC-15 (request heads).

Run with:
    STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -q tests/test_host_files_docker.py
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from stremioguard.config import compose_command
from stremioguard.env import atomic_write_text
from stremioguard.guard import GluetunGuard
from stremioguard.publishing import StackPublisher, ensure_gluetun_auth_config
from tests.conftest import PUBLIC_IPV4_HOST, FakeRunner, completed, make_config

RESOURCE_PREFIX = "sgfix14-"
REPO_ROOT = Path(__file__).resolve().parent.parent

GLUETUN_IMAGE = (
    "qmcgaw/gluetun@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027"
)
BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
COMET_IMAGE = "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)


def _prefix() -> str:
    return os.environ.get("STREMIOGUARD_TEST_PREFIX", RESOURCE_PREFIX)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _network_gateway_ip(network_name: str) -> str:
    inspect = _docker(
        "network",
        "inspect",
        network_name,
        "-f",
        "{{(index .IPAM.Config 0).Subnet}}",
    )
    subnet = ipaddress.ip_network(inspect.stdout.strip(), strict=False)
    assert isinstance(subnet, ipaddress.IPv4Network)
    return str(subnet.network_address + 254)


def _gluetun_base_env() -> list[str]:
    dummy_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return [
        "-e",
        "VPN_SERVICE_PROVIDER=custom",
        "-e",
        "VPN_TYPE=wireguard",
        "-e",
        f"WIREGUARD_PRIVATE_KEY={dummy_key}",
        "-e",
        f"WIREGUARD_PUBLIC_KEY={dummy_key}",
        "-e",
        "WIREGUARD_ADDRESSES=10.64.222.21/32",
        "-e",
        "WIREGUARD_ENDPOINT_IP=192.0.2.1",
        "-e",
        "WIREGUARD_ENDPOINT_PORT=51820",
        "-e",
        "HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:18080",
        "-e",
        "UPDATER_PERIOD=0",
        "-e",
        "DNS_KEEP_NAMESERVER=off",
        "-e",
        "PUBLICIP_ENABLED=off",
    ]


def test_ac14_rootless_docker_reads_private_host_files(tmp_path: Path) -> None:
    """AC-14 (INV-9): gluetun 0600 auth (+ uid-1000 control), Comet bundle, Compose config."""
    prefix = _prefix()
    suffix = uuid.uuid4().hex[:8]
    net_name = f"{prefix}net-{suffix}"
    helper_name = f"{prefix}helper-{suffix}"
    gluetun_ok_name = f"{prefix}gluetun-ok-{suffix}"
    chown_name = f"{prefix}chown-{suffix}"
    gluetun_neg_name = f"{prefix}gluetun-neg-{suffix}"

    created_containers: list[str] = []
    network_created = False
    try:
        # --- (a) gluetun reads 0600 auth file under umask 0002 ---
        root_a = tmp_path / "root_a"
        root_a.mkdir()
        old_umask = os.umask(0o002)
        try:
            auth_file = ensure_gluetun_auth_config(root_a)
        finally:
            os.umask(old_umask)
        assert stat.S_IMODE(auth_file.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600

        _docker("network", "create", "--internal", net_name)
        network_created = True
        gw_ip = _network_gateway_ip(net_name)

        _docker(
            "run",
            "-d",
            "--name",
            helper_name,
            "--network",
            net_name,
            "--cap-add",
            "NET_ADMIN",
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            f"ip route add default via {gw_ip} dev eth0 onlink && sleep 180",
        )
        created_containers.append(helper_name)

        _docker(
            "run",
            "-d",
            "--name",
            gluetun_ok_name,
            "--network",
            f"container:{helper_name}",
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "--cap-drop",
            "DAC_OVERRIDE",
            "--cap-drop",
            "DAC_READ_SEARCH",
            "--cap-drop",
            "FOWNER",
            "-v",
            f"{auth_file}:/gluetun/auth/config.toml:ro",
            *_gluetun_base_env(),
            GLUETUN_IMAGE,
        )
        created_containers.append(gluetun_ok_name)

        deadline = time.monotonic() + 20.0
        body = ""
        logs_ok = ""
        while time.monotonic() < deadline:
            res = _docker(
                "exec",
                gluetun_ok_name,
                "wget",
                "-qO-",
                "http://127.0.0.1:18080/v1/publicip/ip",
                check=False,
            )
            logs_res = _docker("logs", gluetun_ok_name, check=False)
            logs_ok = (logs_res.stdout or "") + (logs_res.stderr or "")
            if res.returncode == 0 and res.stdout.strip() == '{"public_ip":""}':
                body = res.stdout.strip()
                break
            time.sleep(0.3)
        assert body == '{"public_ip":""}', f"Control server did not answer; logs:\n{logs_ok}"
        assert "read 1 roles from authentication file" in logs_ok

        # Negative control: same file at 0600, chowned to container uid 1000 by busybox
        neg_dir = tmp_path / "neg"
        neg_dir.mkdir()
        neg_auth = neg_dir / "config.toml"
        shutil.copyfile(auth_file, neg_auth)
        neg_auth.chmod(0o600)

        _docker(
            "run",
            "--name",
            chown_name,
            "--network",
            "none",
            "-v",
            f"{neg_auth}:/mnt/config.toml:rw",
            BUSYBOX_IMAGE,
            "chown",
            "1000:1000",
            "/mnt/config.toml",
        )
        created_containers.append(chown_name)

        _docker(
            "run",
            "-d",
            "--name",
            gluetun_neg_name,
            "--network",
            f"container:{helper_name}",
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "--cap-drop",
            "DAC_OVERRIDE",
            "--cap-drop",
            "DAC_READ_SEARCH",
            "--cap-drop",
            "FOWNER",
            "-v",
            f"{neg_auth}:/gluetun/auth/config.toml:ro",
            *_gluetun_base_env(),
            GLUETUN_IMAGE,
        )
        created_containers.append(gluetun_neg_name)

        neg_deadline = time.monotonic() + 20.0
        neg_exit: str | None = None
        while time.monotonic() < neg_deadline:
            st = _docker(
                "inspect",
                gluetun_neg_name,
                "-f",
                "{{.State.Status}}|{{.State.ExitCode}}",
                check=False,
            )
            status, _, code = st.stdout.strip().partition("|")
            if status == "exited":
                neg_exit = code
                break
            time.sleep(0.2)
        neg_logs_res = _docker("logs", gluetun_neg_name, check=False)
        neg_logs = (neg_logs_res.stdout or "") + (neg_logs_res.stderr or "")
        assert neg_exit is not None and neg_exit != "0", (
            f"Negative control did not exit non-zero:\n{neg_logs}"
        )
        assert "permission denied" in neg_logs.lower()

        # --- (b) Comet reads 0644 file nested under 0700 .stremio dirs ---
        root_b = tmp_path / "root_b"
        root_b.mkdir()
        bundle_file = root_b / ".stremio" / "comet" / "bundles" / "sha256-test" / "bundle.py"
        bundle_content = "# stremioguard comet bundle sentinel\n"
        atomic_write_text(bundle_file, bundle_content, mode=0o644)
        assert stat.S_IMODE((root_b / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE(bundle_file.stat().st_mode) == 0o644

        comet_cat_name = f"{prefix}comet-cat-{suffix}"
        created_containers.append(comet_cat_name)
        comet_res = _docker(
            "run",
            "--name",
            comet_cat_name,
            "--network",
            "none",
            "--entrypoint",
            "/bin/cat",
            "-v",
            f"{bundle_file}:/tmp/bundle.py:ro",
            COMET_IMAGE,
            "/tmp/bundle.py",
        )
        assert comet_res.stdout == bundle_content

        # --- (c) Compose validates rendered generation under umask 0002 ---
        root_c = tmp_path / "root_c"
        root_c.mkdir()
        shutil.copyfile(REPO_ROOT / "docker-compose.yml", root_c / "docker-compose.yml")
        (root_c / ".env").write_text(
            "VPN_SERVICE_PROVIDER=custom\n"
            "VPN_TYPE=wireguard\n"
            "WIREGUARD_PRIVATE_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            "STREMIO_BIND_ADDRS=127.0.0.1\n"
            "COMET_ENABLED=0\n",
            encoding="utf-8",
        )
        old_umask = os.umask(0o002)
        try:
            StackPublisher(root_c).publish()
        finally:
            os.umask(old_umask)
        assert stat.S_IMODE((root_c / ".stremio").stat().st_mode) == 0o700
        override_path = root_c / ".stremio" / "docker-compose.bindings.yml"
        assert stat.S_IMODE(override_path.stat().st_mode) == 0o600

        base_cmd = compose_command(root_c, "config", "--quiet")
        # Insert -p sgfix14-cfg right after `docker compose`
        cfg_cmd = [base_cmd[0], base_cmd[1], "-p", f"{prefix}cfg-{suffix}", *base_cmd[2:]]
        cfg_res = subprocess.run(cfg_cmd, capture_output=True, text=True, check=False)
        assert cfg_res.returncode == 0, cfg_res.stderr
    finally:
        for name in reversed(created_containers):
            _docker("rm", "-f", "-v", name, check=False)
        if network_created:
            _docker("network", "rm", net_name, check=False)


def test_ac15_optin_docker_wget_head_matches_urllib_head(tmp_path: Path) -> None:
    """AC-15 (INV-10, D16): wget in pinned gluetun sends identical head to host urllib."""
    prefix = _prefix()
    suffix = uuid.uuid4().hex[:8]
    net_name = f"{prefix}headnet-{suffix}"
    cap_name = f"{prefix}cap-{suffix}"
    wget_name = f"{prefix}wget-{suffix}"

    # Host HTTP capture server on 127.0.0.1 within allowed 19400-19449 range
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound_port: int | None = None
    for port in range(19400, 19450):
        try:
            srv.bind(("127.0.0.1", port))
            srv.listen(4)
            bound_port = port
            break
        except OSError:
            continue
    assert bound_port is not None
    srv.settimeout(0.2)
    host_heads: list[bytes] = []
    stop_srv = threading.Event()

    def _serve_host() -> None:
        while not stop_srv.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                host_heads.append(buf.partition(b"\r\n\r\n")[0])
                body = f"{PUBLIC_IPV4_HOST}\n".encode()
                head = (
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
                conn.sendall(head + body)
            finally:
                conn.close()

    srv_thread = threading.Thread(target=_serve_host, daemon=True)
    srv_thread.start()

    created_containers: list[str] = []
    network_created = False
    try:
        guard_host = GluetunGuard(
            make_config(tmp_path, ip_check_urls=(f"http://127.0.0.1:{bound_port}/",)),
            FakeRunner({}),
        )
        assert guard_host.public_ip() == PUBLIC_IPV4_HOST
        assert len(host_heads) == 1

        # Build the exact wget argv via public_ip_via_gluetun()
        target_url = f"http://{cap_name}:8080/"
        ps_call = (*compose_command(tmp_path, "ps", "-q", "gluetun"),)
        runner_rec = FakeRunner({ps_call: completed(list(ps_call), "gluetun-cid\n")})
        guard_gluetun = GluetunGuard(
            make_config(tmp_path, ip_check_urls=(target_url,), public_ip_timeout_seconds=3),
            runner_rec,
        )
        guard_gluetun.public_ip_via_gluetun()
        exec_calls = [c for c in runner_rec.calls if c[:2] == ["docker", "exec"]]
        assert len(exec_calls) == 1
        # Strip `docker exec <id>` -> ["timeout", "-s", "KILL", ...]
        inner_argv = exec_calls[0][3:]
        assert inner_argv[0] == "timeout"

        _docker("network", "create", "--internal", net_name)
        network_created = True

        cap_dir = tmp_path / "cap"
        cap_dir.mkdir()
        (cap_dir / "head.raw").write_bytes(b"")
        # BusyBox nc captures raw bytes until the blank line into /cap/head.raw, then answers 200.
        _docker(
            "run",
            "-d",
            "--name",
            cap_name,
            "--network",
            net_name,
            "-v",
            f"{cap_dir}:/cap:rw",
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            (
                "printf '#!/bin/sh\\n"
                ": > /cap/head.raw\\n"
                "while IFS= read -r line; do\\n"
                '  printf "%%s\\n" "$line" >> /cap/head.raw\\n'
                '  [ "$line" = "$(printf "\\r")" ] || [ -z "$line" ] && break\\n'
                "done\\n"
                'printf "HTTP/1.1 200 OK\\r\\nContent-Length: 8\\r\\n'
                'Connection: close\\r\\n\\r\\n1.1.1.1\\n"\\n'
                "' > /h.sh && chmod +x /h.sh && exec nc -lk -p 8080 -e /h.sh"
            ),
        )
        created_containers.append(cap_name)

        # Wait briefly for nc listener, then run the exact wget argv inside gluetun image
        time.sleep(0.5)
        created_containers.append(wget_name)
        wget_res = _docker(
            "run",
            "--name",
            wget_name,
            "--network",
            net_name,
            "--entrypoint",
            inner_argv[0],
            GLUETUN_IMAGE,
            *inner_argv[1:],
            check=False,
        )
        assert wget_res.returncode == 0, wget_res.stderr
        assert wget_res.stdout.strip() == "1.1.1.1"

        raw_wget = (cap_dir / "head.raw").read_bytes()
        # Strip the trailing blank line `\r\n` that terminated the header loop
        wget_head = raw_wget.split(b"\r\n\r\n", 1)[0].rstrip(b"\r\n")
        host_head = host_heads[0]

        # Compare line-by-line after replacing only the Host header value
        norm_host = re.sub(rb"(?i)Host: [^\r\n]+", b"Host: <HOST>", host_head)
        norm_wget = re.sub(rb"(?i)Host: [^\r\n]+", b"Host: <HOST>", wget_head)
        assert norm_wget == norm_host, f"wget={norm_wget!r} != host={norm_host!r}"
        assert b"stremio" not in host_head.lower()
        assert b"stremio" not in wget_head.lower()
    finally:
        stop_srv.set()
        srv.close()
        srv_thread.join(timeout=2)
        for name in reversed(created_containers):
            _docker("rm", "-f", "-v", name, check=False)
        if network_created:
            _docker("network", "rm", net_name, check=False)
