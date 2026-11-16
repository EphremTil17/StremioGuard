"""Opt-in real-Docker proofs for container hardening (AC-8, AC-10, AC-11, AC-12).

Run with:
  STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -q tests/test_container_hardening_docker.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from stremioguard.comet.manager import build_postgres_database_url, extract_image_source
from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager
from stremioguard.config import SubprocessRunner, compose_command
from stremioguard.overrides.bundle import write_override_bundle
from stremioguard.publishing import (
    GLUETUN_AUTH_CONTAINER_PATH,
    GLUETUN_AUTH_TEMPLATE,
    GLUETUN_PINNED_ENV,
)
from tests.test_network_boundary_docker import (
    BUSYBOX_IMAGE,
    COMET_IMAGE,
    STREMIO_IMAGE,
    _build_harness_compose,
    _compose,
    _docker,
    _vpn_server_sandbox,
    _wait_gluetun_ready,
)

PREFIX = os.environ.get("STREMIOGUARD_DOCKER_TEST_PREFIX", "sgfix12-")
REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)

_STREMTHRU_STUB_PY = """\
import http.server
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"192.0.2.1"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.HTTPServer(("127.0.0.1", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/leaf.pem", "/certs/leaf.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"""

_HTTP_STUB_PY = """\
import http.server
import json


RECORDS = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/__records":
            body = json.dumps(RECORDS).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        RECORDS.append(self.path)
        body = b'{"status":"ok"}\\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
"""


def _make_ipcheck_certs(certs_dir: Path) -> None:
    certs_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(certs_dir / "ca.key"),
            "-out",
            str(certs_dir / "ca.pem"),
            "-days",
            "2",
            "-subj",
            "/CN=stremioguard test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(certs_dir / "leaf.key"),
            "-out",
            str(certs_dir / "leaf.csr"),
            "-subj",
            "/CN=api.ipify.org",
        ],
        check=True,
        capture_output=True,
    )
    (certs_dir / "ext.cnf").write_text(
        "subjectAltName=DNS:api.ipify.org,DNS:whatismyip.akamai.com\n"
        "basicConstraints=CA:FALSE\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(certs_dir / "leaf.csr"),
            "-CA",
            str(certs_dir / "ca.pem"),
            "-CAkey",
            str(certs_dir / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(certs_dir / "leaf.pem"),
            "-days",
            "2",
            "-extfile",
            str(certs_dir / "ext.cnf"),
        ],
        check=True,
        capture_output=True,
    )
    for name in ("ca.pem", "leaf.pem", "leaf.key"):
        (certs_dir / name).chmod(0o644)


def _empty_subuid_dir(path: Path) -> None:
    if path.exists():
        _docker(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{path}:/target",
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            "rm -rf /target/* /target/.[!.]* /target/..?* 2>/dev/null || true",
            check=False,
        )


def _resolved_repo_compose() -> dict[str, object]:
    res = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-p",
            f"{PREFIX}config",
            "-f",
            str(REPO_ROOT / "docker-compose.yml"),
            "config",
            "--format",
            "json",
            "--no-env-resolution",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    data = json.loads(res.stdout)
    assert isinstance(data, dict)
    return data


def _http_probe_in_container(container: str, url: str) -> tuple[int, str]:
    script = (
        "import sys, urllib.error, urllib.request\n"
        "try:\n"
        "    r = urllib.request.urlopen(sys.argv[1], timeout=5)\n"
        "    print(r.status)\n"
        "    print(r.read().decode('utf-8', errors='replace'))\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "    print(e.read().decode('utf-8', errors='replace'))\n"
    )
    res = _docker(
        "exec",
        container,
        "/app/.venv/bin/python",
        "-c",
        script,
        url,
        check=False,
        timeout=15.0,
    )
    if res.returncode != 0:
        raise AssertionError(f"Probe failed for {url}: {res.stderr}")
    lines = res.stdout.splitlines()
    return int(lines[0]), "\n".join(lines[1:])


def _http_probe_ephemeral(owner_container: str, url: str) -> tuple[int, str]:
    script = (
        "import sys, urllib.error, urllib.request\n"
        "try:\n"
        "    r = urllib.request.urlopen(sys.argv[1], timeout=5)\n"
        "    print(r.status)\n"
        "    print(r.read().decode('utf-8', errors='replace'))\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "    print(e.read().decode('utf-8', errors='replace'))\n"
    )
    res = _docker(
        "run",
        "--rm",
        "--no-healthcheck",
        "--network",
        f"container:{owner_container}",
        "--entrypoint",
        "/app/.venv/bin/python",
        COMET_IMAGE,
        "-c",
        script,
        url,
        check=False,
        timeout=20.0,
    )
    if res.returncode != 0:
        raise AssertionError(f"Probe failed for {url}: {res.stderr}")
    lines = res.stdout.splitlines()
    return int(lines[0]), "\n".join(lines[1:])


def _wait_healthy(container_id: str, *, timeout: float = 90.0) -> float:
    start = time.monotonic()
    deadline = start + timeout
    while time.monotonic() < deadline:
        insp = _docker(
            "inspect",
            "--format",
            "{{.State.Running}}|{{.State.Health.Status}}",
            container_id,
            check=False,
        )
        if insp.returncode == 0:
            running, _, status = insp.stdout.strip().partition("|")
            if status == "healthy":
                return time.monotonic() - start
            if running == "false":
                logs = _docker("logs", container_id, check=False)
                raise AssertionError(
                    f"Container {container_id} exited:\n{logs.stdout}\n{logs.stderr}"
                )
        time.sleep(0.5)
    logs = _docker("logs", container_id, check=False)
    raise AssertionError(
        f"Container {container_id} did not become healthy within {timeout}s:\n"
        f"{logs.stdout}\n{logs.stderr}"
    )


def _proc_1_status(container_id: str) -> dict[str, str]:
    out = _docker("exec", container_id, "cat", "/proc/1/status").stdout
    result: dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def test_ac8_real_gluetun_pins_all_listeners_auth_and_firewall(tmp_path: Path) -> None:
    """AC-8 (opt-in, INV-1): D1 pins block proxies, open auth, and firewall holes in gluetun."""
    auth_file = tmp_path / "gluetun-auth.toml"
    auth_file.write_text(GLUETUN_AUTH_TEMPLATE, encoding="utf-8")
    auth_file.chmod(0o644)

    base_hostile = [
        "HTTPPROXY=on",
        "SHADOWSOCKS=on",
        "SHADOWSOCKS_PASSWORD=x",
        "PPROF_ENABLED=yes",
        "HEALTH_SERVER_ADDRESS=:9999",
        'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={"auth":"none"}',
        "FIREWALL_INPUT_PORTS=8000",
        "FIREWALL_VPN_INPUT_PORTS=8000",
        "FIREWALL_OUTBOUND_SUBNETS=192.0.2.0/24",
    ]
    full_hostile = [
        *base_hostile,
        "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=/tmp/none.toml",
        "VPN_PORT_FORWARDING=on",
        "VPN_INTERFACE=tun9",
    ]

    with _vpn_server_sandbox(tmp_path) as sb:
        cfg_dir = Path(sb["cfg_dir"])

        # 1. Pinned run
        pinned_dir = tmp_path / "pinned"
        pinned_dir.mkdir()
        pinned_proj = f"{PREFIX}ac8pin-{sb['suffix']}"
        pinned_compose = _build_harness_compose(
            work_dir=pinned_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
            extra_env_lines=full_hostile,
        )
        doc = json.loads(pinned_compose.read_text(encoding="utf-8"))
        doc["services"]["gluetun"]["volumes"].append(
            f"{auth_file}:{GLUETUN_AUTH_CONTAINER_PATH}:ro"
        )
        pinned_compose.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

        # 2. Control run (D1 additions removed from environment; 0008 pins kept)
        ctrl_dir = tmp_path / "ctrl"
        ctrl_dir.mkdir()
        ctrl_proj = f"{PREFIX}ac8ctrl-{sb['suffix']}"
        ctrl_compose = _build_harness_compose(
            work_dir=ctrl_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
            extra_env_lines=base_hostile,
        )
        ctrl_doc = json.loads(ctrl_compose.read_text(encoding="utf-8"))
        ctrl_env = ctrl_doc["services"]["gluetun"]["environment"]
        for key in list(ctrl_env):
            if key in GLUETUN_PINNED_ENV and key not in {
                "DNS_KEEP_NAMESERVER",
                "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT",
                "HTTP_CONTROL_SERVER_ADDRESS",
            }:
                del ctrl_env[key]
        ctrl_doc["services"]["gluetun"]["volumes"].append(
            f"{auth_file}:{GLUETUN_AUTH_CONTAINER_PATH}:ro"
        )
        ctrl_compose.write_text(json.dumps(ctrl_doc, indent=2) + "\n", encoding="utf-8")

        try:
            _compose(pinned_proj, pinned_compose, "up", "-d")
            gt_id = _compose(pinned_proj, pinned_compose, "ps", "-q", "gluetun").stdout.strip()
            assert gt_id
            _wait_gluetun_ready(gt_id)

            # Every pinned key matches in printenv
            env_lines = _docker("exec", gt_id, "printenv").stdout.splitlines()
            actual_env = dict(line.split("=", 1) for line in env_lines if "=" in line)
            for key, expected in GLUETUN_PINNED_ENV.items():
                assert actual_env.get(key) == expected, (key, actual_env.get(key))

            # Check listeners via netstat -tuln
            netstat = _docker("exec", gt_id, "netstat", "-tuln").stdout
            listen_addrs = []
            for line in netstat.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] in {"tcp", "tcp6", "udp", "udp6"}:
                    listen_addrs.append((parts[0], parts[3]))
            for forbidden_port in (":8888", ":8388", ":6060"):
                assert not any(addr.endswith(forbidden_port) for _, addr in listen_addrs), (
                    forbidden_port,
                    netstat,
                )
            assert ("tcp", "127.0.0.1:18080") in listen_addrs, netstat
            assert ("tcp", "127.0.0.1:9999") in listen_addrs, netstat
            assert any(
                proto.startswith("tcp") and addr.endswith(":53") for proto, addr in listen_addrs
            )
            assert any(
                proto.startswith("udp") and addr.endswith(":53") for proto, addr in listen_addrs
            )
            for proto, addr in listen_addrs:
                if addr.startswith("127.0.0.11:") or addr in {"127.0.0.1:18080", "127.0.0.1:9999"}:
                    continue
                if addr.endswith(":53"):
                    continue
                # Only OpenVPN's ephemeral UDP socket remains
                assert proto.startswith("udp"), (proto, addr, netstat)

            # Check iptables INPUT & OUTPUT
            bridge_subnet = _docker(
                "network",
                "inspect",
                sb["network"],
                "--format",
                "{{(index .IPAM.Config 0).Subnet}}",
            ).stdout.strip()
            ipt_in = _docker("exec", gt_id, "iptables", "-S", "INPUT").stdout
            assert "--dport" not in ipt_in, ipt_in

            ipt_out = _docker("exec", gt_id, "iptables", "-S", "OUTPUT").stdout
            assert "192.0.2.0/24" not in ipt_out, ipt_out
            allowed_dests = {"127.0.0.11/32", f"{sb['vpn_ip']}/32", bridge_subnet}
            for line in ipt_out.splitlines():
                match = re.search(r"\s-d\s+(\S+)", line)
                if match:
                    dest = match.group(1)
                    assert dest in allowed_dests, (dest, allowed_dests, line)

            # Control server auth
            code_status, _ = _http_probe_ephemeral(gt_id, "http://127.0.0.1:18080/v1/vpn/status")
            assert code_status == 401
            code_ip, _ = _http_probe_ephemeral(gt_id, "http://127.0.0.1:18080/v1/publicip/ip")
            assert code_ip == 200

            # Control run shows gaps are observable without the new pins
            _compose(ctrl_proj, ctrl_compose, "up", "-d")
            ctrl_id = _compose(ctrl_proj, ctrl_compose, "ps", "-q", "gluetun").stdout.strip()
            assert ctrl_id
            _wait_gluetun_ready(ctrl_id)

            ctrl_netstat = _docker("exec", ctrl_id, "netstat", "-tuln").stdout
            for expected_open in (":8888", ":8388", ":6060"):
                assert expected_open in ctrl_netstat, (expected_open, ctrl_netstat)

            ctrl_in = _docker("exec", ctrl_id, "iptables", "-S", "INPUT").stdout
            assert "--dport 8000" in ctrl_in, ctrl_in
            ctrl_out = _docker("exec", ctrl_id, "iptables", "-S", "OUTPUT").stdout
            assert "192.0.2.0/24" in ctrl_out, ctrl_out

            ctrl_status, _ = _http_probe_ephemeral(ctrl_id, "http://127.0.0.1:18080/v1/vpn/status")
            assert ctrl_status == 200
        finally:
            _compose(ctrl_proj, ctrl_compose, "down", "-v", check=False)
            _compose(pinned_proj, pinned_compose, "down", "-v", check=False)


def test_ac10_throwaway_hardened_stack_healthy_and_restarts_cleanly(tmp_path: Path) -> None:
    """AC-10 (opt-in, INV-4, INV-5): Full hardened stack works before and after compose restart."""
    suffix = uuid.uuid4().hex[:8]
    project = f"{PREFIX}stack-{suffix}"
    network_name = f"{PREFIX}stacknet-{suffix}"

    repo_cfg = _resolved_repo_compose()
    repo_services = repo_cfg["services"]
    repo_configs = repo_cfg.get("configs", {})
    assert isinstance(repo_services, dict)
    assert isinstance(repo_configs, dict)

    certs_dir = tmp_path / "certs"
    _make_ipcheck_certs(certs_dir)
    stub_file = tmp_path / "stub.py"
    stub_file.write_text(_STREMTHRU_STUB_PY, encoding="utf-8")
    stub_file.chmod(0o644)

    pg_data = tmp_path / "postgres-data"
    pg_data.mkdir()
    pg_env = tmp_path / "postgres.env"
    pg_pw = "Sg12_PgPass!"
    pg_env.write_text(
        f"POSTGRES_USER=comet\nPOSTGRES_PASSWORD={pg_pw}\nPOSTGRES_DB=comet\n",
        encoding="utf-8",
    )
    pg_env.chmod(0o600)

    stremthru_data = tmp_path / "stremthru-data"
    stremthru_data.mkdir()
    stremthru_env = tmp_path / "stremthru.env"
    stremthru_env.write_text("STREMTHRU_AUTH=stremioguard:test-stremthru-pw\n", encoding="utf-8")
    stremthru_env.chmod(0o600)

    stremio_data = tmp_path / "stremio-data"
    stremio_data.mkdir()

    gw_root = tmp_path / "gw-root"
    gw_root.mkdir()
    (gw_root / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    gw_cfg = CometGatewayConfig.from_env(gw_root)
    gw_mgr = CometGatewayManager(gw_cfg)
    _, gw_token = gw_mgr.add_token("ac10-test", make_default=True)
    gw_mgr.prepare_runtime()

    comet_data = tmp_path / "comet-data"
    comet_data.mkdir()
    api_token = "Ac10Api_Token-1"
    comet_env = tmp_path / "comet.env"
    comet_env.write_text(
        "\n".join(
            [
                "DATABASE_TYPE=postgresql",
                f"DATABASE_URL={build_postgres_database_url(pg_pw)}",
                "DISABLE_TORRENT_STREAMS=True",
                "ADMIN_DASHBOARD_PASSWORD=ac10-admin-pw",
                "CONFIGURE_PAGE_PASSWORD=ac10-cfg-pw",
                f"PUBLIC_API_TOKEN={api_token}",
                "PROXY_DEBRID_STREAM=True",
                "PROXY_DEBRID_STREAM_PASSWORD=ac10-proxy-pw",
                "STREMTHRU_URL=http://127.0.0.1:8091",
                "SCRAPE_TORRENTIO=false",
                "SCRAPE_ZILEAN=false",
                "SCRAPE_DMM=false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    comet_env.chmod(0o600)

    bundle_dir = tmp_path / "comet-bundle"
    live_digest = COMET_IMAGE.split("@", 1)[1]
    with extract_image_source(SubprocessRunner(), COMET_IMAGE) as image_src:
        write_override_bundle(
            repo_dir=image_src,
            state_dir=bundle_dir,
            result_format_style="plain",
            patch_episode_pack_results=True,
            gateway_addon_base_url=f"/comet/{gw_token}",
            gateway_enabled=True,
            image_digest=live_digest,
        )
    bundle_manifest = json.loads((bundle_dir / "bundle-manifest.json").read_text(encoding="utf-8"))

    def copy_service(name: str) -> dict[str, object]:
        src = repo_services[name]
        assert isinstance(src, dict)
        out: dict[str, object] = {"restart": "no", "network_mode": src["network_mode"]}
        for field in (
            "image",
            "command",
            "environment",
            "configs",
            "healthcheck",
            "cap_drop",
            "cap_add",
            "security_opt",
            "read_only",
            "tmpfs",
            "shm_size",
        ):
            if field in src and src[field] is not None:
                out[field] = src[field]
        return out

    pg_svc = copy_service("comet-postgres")
    pg_svc["volumes"] = [f"{pg_data}:/var/lib/postgresql/"]
    pg_svc["env_file"] = [str(pg_env)]
    pg_svc["depends_on"] = {"gluetun": {"condition": "service_started"}}

    stremthru_svc = copy_service("stremthru")
    stremthru_svc["env_file"] = [str(stremthru_env)]
    # Test-only CA + cert mount for offline IP-check HTTPS stub (fact 6).
    raw_st_env = stremthru_svc.get("environment")
    st_env: dict[str, object] = dict(raw_st_env) if isinstance(raw_st_env, dict) else {}
    st_env["SSL_CERT_FILE"] = "/certs/ca.pem"
    stremthru_svc["environment"] = st_env
    stremthru_svc["volumes"] = [f"{stremthru_data}:/app/data", f"{certs_dir}:/certs:ro"]
    stremthru_svc["depends_on"] = {
        "gluetun": {"condition": "service_started"},
        "ipcheck-stub": {"condition": "service_healthy"},
    }

    gw_svc = copy_service("comet-gateway")
    gw_svc["volumes"] = [f"{gw_cfg.state_dir}:/etc/nginx/stremioguard:ro"]
    gw_svc["depends_on"] = {"gluetun": {"condition": "service_started"}}

    stremio_svc = copy_service("stremio")
    stremio_svc["volumes"] = [f"{stremio_data}:/root/.stremio-server"]
    stremio_svc["depends_on"] = {"gluetun": {"condition": "service_started"}}

    comet_svc = copy_service("comet")
    comet_svc["image"] = COMET_IMAGE
    comet_svc["env_file"] = [str(comet_env)]
    comet_volumes = [f"{comet_data}:/app/data"]
    for out_name, container_path in bundle_manifest["outputs"].items():
        comet_volumes.append(f"{bundle_dir / out_name}:{container_path}:ro")
    comet_svc["volumes"] = comet_volumes
    comet_svc["depends_on"] = {
        "gluetun": {"condition": "service_started"},
        "comet-postgres": {"condition": "service_healthy"},
        "stremthru": {"condition": "service_healthy"},
    }

    pg_configs = pg_svc.get("configs")
    used_configs = {
        c["source"]: {"content": repo_configs[c["source"]]["content"]}
        for c in (pg_configs if isinstance(pg_configs, list) else [])
        if isinstance(c, dict) and c.get("source") in repo_configs
    }

    compose_doc: dict[str, object] = {
        "configs": used_configs,
        "networks": {"internal_net": {"external": True, "name": network_name}},
        "services": {
            "gluetun": {
                "image": BUSYBOX_IMAGE,
                "init": True,
                "command": ["sleep", "600"],
                "networks": ["internal_net"],
                "extra_hosts": [
                    "api.ipify.org:127.0.0.1",
                    "whatismyip.akamai.com:127.0.0.1",
                ],
            },
            "ipcheck-stub": {
                "image": COMET_IMAGE,
                "network_mode": "service:gluetun",
                "depends_on": {"gluetun": {"condition": "service_started"}},
                "entrypoint": ["/app/.venv/bin/python", "/stub.py"],
                "volumes": [f"{certs_dir}:/certs:ro", f"{stub_file}:/stub.py:ro"],
                "healthcheck": {
                    "test": [
                        "CMD",
                        "/app/.venv/bin/python",
                        "-c",
                        "import socket; s=socket.create_connection(('127.0.0.1', 443), 1); "
                        "s.close()",
                    ],
                    "interval": "1s",
                    "timeout": "2s",
                    "retries": 15,
                    "start_period": "0s",
                },
            },
            "comet-postgres": pg_svc,
            "stremthru": stremthru_svc,
            "comet-gateway": gw_svc,
            "stremio": stremio_svc,
            "comet": comet_svc,
        },
    }
    compose_path = tmp_path / "stack-compose.yml"
    compose_path.write_text(json.dumps(compose_doc, indent=2) + "\n", encoding="utf-8")

    network_created = False
    try:
        _docker("network", "create", "--internal", network_name)
        network_created = True
        up_res = _compose(project, compose_path, "up", "-d", check=False)
        assert up_res.returncode == 0, (up_res.stdout, up_res.stderr)

        cids = {
            svc: _compose(project, compose_path, "ps", "-q", svc).stdout.strip()
            for svc in (
                "gluetun",
                "comet-postgres",
                "stremthru",
                "comet-gateway",
                "stremio",
                "comet",
            )
        }
        assert all(cids.values()), cids

        boot_times: dict[str, float] = {}
        for svc in ("comet-postgres", "stremthru", "comet-gateway", "comet"):
            boot_times[svc] = _wait_healthy(cids[svc], timeout=120.0)

        def verify_stack_live(phase: str) -> None:
            # Stremio probes (fact 8)
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                try:
                    c1, _ = _http_probe_in_container(
                        cids["comet"], "http://127.0.0.1:11470/settings"
                    )
                    c2, _ = _http_probe_in_container(cids["comet"], "http://127.0.0.1:8080/")
                    if c1 == 200 and c2 == 200:
                        break
                except AssertionError:
                    pass
                time.sleep(0.5)
            else:
                raise AssertionError(f"{phase}: Stremio probes did not answer 200")

            # Gateway -> Comet manifest
            gw_code, gw_body = _http_probe_in_container(
                cids["comet"],
                f"http://127.0.0.1:8090/comet/{gw_token}/s/{api_token}/manifest.json",
            )
            assert gw_code == 200, (phase, gw_code, gw_body)
            manifest_json = json.loads(gw_body)
            assert "id" in manifest_json and "name" in manifest_json, manifest_json

            # Postgres active 127.0.0.1 connection + pg_hba_file_rules
            act = _docker(
                "exec",
                cids["comet-postgres"],
                "psql",
                "-U",
                "comet",
                "-d",
                "comet",
                "-t",
                "-A",
                "-c",
                "SELECT client_addr::text FROM pg_stat_activity WHERE client_addr IS NOT NULL;",
            ).stdout
            assert "127.0.0.1" in act, (phase, act)

            rules = _docker(
                "exec",
                cids["comet-postgres"],
                "psql",
                "-U",
                "comet",
                "-d",
                "comet",
                "-t",
                "-A",
                "-c",
                "SELECT type || '|' || coalesce(address,'') || '|' || auth_method "
                "FROM pg_hba_file_rules ORDER BY rule_number;",
            ).stdout.splitlines()
            assert [r.strip() for r in rules if r.strip()] == [
                "local||trust",
                "host|127.0.0.1|scram-sha-256",
                "host|::1|scram-sha-256",
            ]

            # StremThru routes from inside Comet
            st_health, _ = _http_probe_in_container(
                cids["comet"], "http://127.0.0.1:8091/v0/health"
            )
            assert st_health == 200
            st_check, _ = _http_probe_in_container(
                cids["comet"], "http://127.0.0.1:8091/v0/store/magnets/check"
            )
            assert st_check != 404, st_check

        verify_stack_live("initial")

        # Real reload_nginx() with Rules-of-engagement runner
        class _GatewayReloadRunner:
            def __init__(self) -> None:
                self._real = SubprocessRunner()

            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                if args == compose_command(gw_root, "ps", "-q", "comet-gateway"):
                    return subprocess.CompletedProcess(args, 0, f"{cids['comet-gateway']}\n", "")
                if args[:3] == ["docker", "exec", cids["comet-gateway"]]:
                    return self._real.run(
                        args, check=check, capture=capture, timeout=timeout, env=env, input=input
                    )
                raise AssertionError(f"Unexpected command in reload runner: {args}")

        gw_reload_mgr = CometGatewayManager(gw_cfg, runner=_GatewayReloadRunner())
        gw_reload_mgr.reload_nginx()

        # Verify docker inspect + /proc/1/status + read-only probe
        expected_inspect = {
            "comet": (["ALL"], set(), True, {"/tmp"}, 0),
            "stremthru": (["ALL"], set(), True, {"/tmp"}, 0),
            "comet-gateway": (
                ["ALL"],
                {"CHOWN", "SETGID", "SETUID"},
                True,
                {"/tmp", "/var/cache/nginx"},
                0xC1,
            ),
            "comet-postgres": (
                ["ALL"],
                {"CHOWN", "DAC_READ_SEARCH", "SETGID", "SETUID"},
                False,
                set(),
                0,
            ),
            "stremio": (["ALL"], {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}, False, set(), 0xC3),
        }
        for svc, (exp_drop, exp_add, exp_ro, exp_tmpfs, exp_capeff) in expected_inspect.items():
            raw_insp = json.loads(_docker("inspect", cids[svc]).stdout)[0]
            hc = raw_insp["HostConfig"]
            assert hc["CapDrop"] == exp_drop, (svc, hc["CapDrop"])
            actual_add = {c.removeprefix("CAP_") for c in (hc["CapAdd"] or [])}
            assert actual_add == exp_add, (svc, actual_add)
            assert hc["SecurityOpt"] == ["no-new-privileges:true"], (svc, hc["SecurityOpt"])
            assert bool(hc["ReadonlyRootfs"]) is exp_ro, (svc, hc["ReadonlyRootfs"])
            actual_tmpfs = set((hc.get("Tmpfs") or {}).keys()) | {
                m["Target"]
                for m in (hc.get("Mounts") or [])
                if isinstance(m, dict) and m.get("Type") == "tmpfs" and "Target" in m
            }
            assert actual_tmpfs == exp_tmpfs, (svc, hc.get("Tmpfs"), hc.get("Mounts"))

            status = _proc_1_status(cids[svc])
            assert status.get("NoNewPrivs") == "1", (svc, status)
            assert int(status["CapEff"], 16) == exp_capeff, (svc, status["CapEff"])

        for ro_svc in ("comet", "stremthru", "comet-gateway"):
            touch_res = _docker("exec", cids[ro_svc], "touch", "/probe", check=False)
            assert touch_res.returncode != 0
            assert "Read-only file system" in f"{touch_res.stdout}\n{touch_res.stderr}", (
                ro_svc,
                touch_res.stderr,
            )

        # Restart every service (owner, then ipcheck-stub, then namespace services so
        # network_mode: service:gluetun and StremThru's startup IP check never race)
        # and re-verify.
        restart_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        restart_gt = _compose(project, compose_path, "restart", "gluetun", check=False)
        assert restart_gt.returncode == 0, (restart_gt.stdout, restart_gt.stderr)
        restart_stub = _compose(project, compose_path, "restart", "ipcheck-stub", check=False)
        assert restart_stub.returncode == 0, (restart_stub.stdout, restart_stub.stderr)
        stub_cid = _compose(project, compose_path, "ps", "-q", "ipcheck-stub").stdout.strip()
        assert stub_cid
        stub_deadline = time.monotonic() + 10.0
        while time.monotonic() < stub_deadline:
            probe = _docker(
                "exec",
                stub_cid,
                "/app/.venv/bin/python",
                "-c",
                "import socket; s=socket.create_connection(('127.0.0.1', 443), 1); s.close()",
                check=False,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("ipcheck-stub did not bind 127.0.0.1:443 after restart")

        restart_res = _compose(
            project,
            compose_path,
            "restart",
            "comet-postgres",
            "stremthru",
            "comet-gateway",
            "stremio",
            "comet",
            check=False,
        )
        assert restart_res.returncode == 0, (restart_res.stdout, restart_res.stderr)
        restart_times: dict[str, float] = {}
        for svc in ("comet-postgres", "stremthru", "comet-gateway", "comet"):
            restart_times[svc] = _wait_healthy(cids[svc], timeout=120.0)

        verify_stack_live("after-restart")
        pg_logs_after = _docker("logs", "--since", restart_at, cids["comet-postgres"], check=False)
        combined_pg_logs = f"{pg_logs_after.stdout}\n{pg_logs_after.stderr}"
        assert "initdb" not in combined_pg_logs, combined_pg_logs

        print("\nAC-10 boot times:", boot_times)
        print("AC-10 restart times:", restart_times)
    finally:
        _compose(project, compose_path, "down", "-v", check=False)
        if network_created:
            _docker("network", "rm", network_name, check=False)
        _empty_subuid_dir(pg_data)
        _empty_subuid_dir(stremio_data)
        _empty_subuid_dir(comet_data)
        _empty_subuid_dir(stremthru_data)


def test_ac11_minimality_removing_each_hardening_item_fails(tmp_path: Path) -> None:
    """AC-11 (opt-in, INV-4): Removing any single capability or tmpfs from D3 breaks the service."""
    repo_services = _resolved_repo_compose()["services"]
    assert isinstance(repo_services, dict)
    suffix = uuid.uuid4().hex[:8]
    findings: list[str] = []

    def _first_error_line(text: str) -> str:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        filtered = [
            ln
            for ln in lines
            if ": info:" not in ln
            and not ln.startswith("chmod: ")
            and "hw accel profile:" not in ln
        ]
        for ln in filtered:
            low = ln.lower()
            if any(
                tok in low
                for tok in (
                    "error",
                    "denied",
                    "not permitted",
                    "read-only",
                    "failed",
                    "fatal",
                    "emerg",
                    "alert",
                )
            ):
                return ln
        return filtered[0] if filtered else (lines[0] if lines else "<no output>")

    # 1. comet-gateway ablations
    gw_root = tmp_path / "gw-ablate"
    gw_root.mkdir()
    (gw_root / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    gw_cfg = CometGatewayConfig.from_env(gw_root)
    gw_mgr = CometGatewayManager(gw_cfg)
    gw_mgr.add_token("ac11", make_default=True)
    gw_mgr.prepare_runtime()
    gw_base = dict(repo_services["comet-gateway"])  # type: ignore[arg-type]

    for missing in ("CHOWN", "SETGID", "SETUID", "/tmp", "/var/cache/nginx"):
        name = f"{PREFIX}ac11-gw-{missing.strip('/').replace('/', '_')}-{suffix}"
        caps = [c for c in gw_base["cap_add"] if c != missing]
        tmpfs = [t for t in gw_base["tmpfs"] if t != missing]
        cmd = [
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "-v",
            f"{gw_cfg.state_dir}:/etc/nginx/stremioguard:ro",
        ]
        for c in caps:
            cmd.extend(["--cap-add", c])
        for t in tmpfs:
            cmd.extend(["--tmpfs", t])
        cmd.extend([gw_base["image"], *gw_base["command"]])
        try:
            _docker(*cmd)
            deadline = time.monotonic() + 10.0
            failed = False
            reason = ""
            while time.monotonic() < deadline:
                running = _docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
                if running == "false":
                    logs = _docker("logs", name, check=False)
                    reason = _first_error_line(f"{logs.stdout}\n{logs.stderr}")
                    failed = True
                    break
                hc = _docker(
                    "exec",
                    name,
                    "curl",
                    "-fsS",
                    "-o",
                    "/dev/null",
                    "--max-time",
                    "2",
                    "http://127.0.0.1:8099/__sg_alive",
                    check=False,
                )
                if hc.returncode == 0:
                    time.sleep(0.3)
                    continue
                logs = _docker("logs", name, check=False)
                reason = _first_error_line(f"{logs.stdout}\n{logs.stderr}\n{hc.stderr}")
                failed = True
                break
            assert failed, f"comet-gateway unexpectedly survived without {missing}"
            findings.append(f"comet-gateway without {missing}: {reason}")
        finally:
            _docker("rm", "-f", "-v", name, check=False)

    # 2. comet-postgres ablations
    pg_base = dict(repo_services["comet-postgres"])  # type: ignore[arg-type]
    existing_pg = tmp_path / "pg-existing"
    existing_pg.mkdir()
    init_name = f"{PREFIX}ac11-pginit-{suffix}"
    try:
        init_cmd = [
            "run",
            "-d",
            "--name",
            init_name,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-v",
            f"{existing_pg}:/var/lib/postgresql/",
            "-e",
            "POSTGRES_USER=comet",
            "-e",
            "POSTGRES_PASSWORD=comet",
            "-e",
            "POSTGRES_DB=comet",
        ]
        for c in pg_base["cap_add"]:
            init_cmd.extend(["--cap-add", c])
        init_cmd.extend([pg_base["image"], "postgres", "-c", "listen_addresses=127.0.0.1"])
        _docker(*init_cmd)
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            if (
                _docker(
                    "exec", init_name, "pg_isready", "-U", "comet", "-d", "comet", check=False
                ).returncode
                == 0
            ):
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Baseline postgres init failed")
    finally:
        _docker("rm", "-f", "-v", init_name, check=False)

    for missing in ("CHOWN", "DAC_READ_SEARCH", "SETUID", "SETGID"):
        pg_dir = tmp_path / f"pg-fresh-{missing.lower()}" if missing == "CHOWN" else existing_pg
        pg_dir.mkdir(exist_ok=True)
        name = f"{PREFIX}ac11-pg-{missing}-{suffix}"
        caps = [c for c in pg_base["cap_add"] if c != missing]
        cmd = [
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-v",
            f"{pg_dir}:/var/lib/postgresql/",
            "-e",
            "POSTGRES_USER=comet",
            "-e",
            "POSTGRES_PASSWORD=comet",
            "-e",
            "POSTGRES_DB=comet",
        ]
        for c in caps:
            cmd.extend(["--cap-add", c])
        cmd.extend([pg_base["image"], "postgres", "-c", "listen_addresses=127.0.0.1"])
        try:
            _docker(*cmd)
            deadline = time.monotonic() + 15.0
            failed = False
            reason = ""
            while time.monotonic() < deadline:
                running = _docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
                if running == "false":
                    logs = _docker("logs", name, check=False)
                    reason = _first_error_line(f"{logs.stdout}\n{logs.stderr}")
                    failed = True
                    break
                time.sleep(0.4)
            assert failed, f"comet-postgres unexpectedly stayed running without {missing}"
            findings.append(f"comet-postgres without {missing}: {reason}")
        finally:
            _docker("rm", "-f", "-v", name, check=False)
            if missing == "CHOWN":
                _empty_subuid_dir(pg_dir)
    _empty_subuid_dir(existing_pg)

    # 3. stremio ablations
    stremio_base = dict(repo_services["stremio"])  # type: ignore[arg-type]
    for missing in ("CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID"):
        name = f"{PREFIX}ac11-stremio-{missing}-{suffix}"
        caps = [c for c in stremio_base["cap_add"] if c != missing]
        cmd = [
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-e",
            "NO_CORS=1",
            "-e",
            "AUTO_SERVER_URL=1",
            "-e",
            "CASTING_DISABLED=1",
        ]
        for c in caps:
            cmd.extend(["--cap-add", c])
        cmd.append(STREMIO_IMAGE)
        try:
            _docker(*cmd)
            deadline = time.monotonic() + 15.0
            failed = False
            reason = ""
            while time.monotonic() < deadline:
                running = _docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
                if running == "false":
                    logs = _docker("logs", name, check=False)
                    reason = _first_error_line(f"{logs.stdout}\n{logs.stderr}")
                    failed = True
                    break
                time.sleep(0.4)
            if not failed:
                # Check fact 8 probes
                p1 = _docker(
                    "run",
                    "--rm",
                    "--no-healthcheck",
                    "--network",
                    f"container:{name}",
                    "--entrypoint",
                    "/app/.venv/bin/python",
                    COMET_IMAGE,
                    "-c",
                    "import urllib.request; print("
                    "urllib.request.urlopen('http://127.0.0.1:8080/', timeout=2).status)",
                    check=False,
                )
                p2 = _docker(
                    "run",
                    "--rm",
                    "--no-healthcheck",
                    "--network",
                    f"container:{name}",
                    "--entrypoint",
                    "/app/.venv/bin/python",
                    COMET_IMAGE,
                    "-c",
                    "import urllib.request; print("
                    "urllib.request.urlopen('http://127.0.0.1:11470/settings', timeout=2).status)",
                    check=False,
                )
                if p1.returncode != 0 or p2.returncode != 0:
                    failed = True
                    logs = _docker("logs", name, check=False)
                    reason = _first_error_line(
                        f"{logs.stdout}\n{logs.stderr}\n{p1.stderr}\n{p2.stderr}"
                    )
            assert failed, f"stremio unexpectedly passed probes without {missing}"
            findings.append(f"stremio without {missing}: {reason}")
        finally:
            _docker("rm", "-f", "-v", name, check=False)

    print("\nAC-11 findings:\n" + "\n".join(findings))


def test_ac12_gateway_liveness_detects_worker_freeze_and_recovers(tmp_path: Path) -> None:
    """AC-12 (opt-in, INV-6): Liveness stays up without upstream, fails on freeze, recovers."""
    suffix = uuid.uuid4().hex[:8]
    project = f"{PREFIX}ac12-{suffix}"
    network_name = f"{PREFIX}ac12net-{suffix}"
    neighbour_name = f"{PREFIX}ac12nbr-{suffix}"

    gw_root = tmp_path / "gw-root"
    gw_root.mkdir()
    (gw_root / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    gw_cfg = CometGatewayConfig.from_env(gw_root)
    gw_mgr = CometGatewayManager(gw_cfg)
    gw_mgr.add_token("ac12", make_default=True)
    gw_mgr.prepare_runtime()

    stub_file = tmp_path / "http_stub.py"
    stub_file.write_text(_HTTP_STUB_PY, encoding="utf-8")
    stub_file.chmod(0o644)

    repo_gw = dict(_resolved_repo_compose()["services"]["comet-gateway"])  # type: ignore[dict-item]
    hc = dict(repo_gw["healthcheck"])
    hc["interval"] = "2s"
    hc["retries"] = 2
    hc["start_period"] = "1s"

    gw_svc: dict[str, object] = {
        "image": repo_gw["image"],
        "restart": "no",
        "network_mode": "service:owner",
        "depends_on": {"owner": {"condition": "service_started"}},
        "command": repo_gw["command"],
        "cap_drop": repo_gw["cap_drop"],
        "cap_add": repo_gw["cap_add"],
        "security_opt": repo_gw["security_opt"],
        "read_only": repo_gw["read_only"],
        "tmpfs": repo_gw["tmpfs"],
        "volumes": [f"{gw_cfg.state_dir}:/etc/nginx/stremioguard:ro"],
        "healthcheck": hc,
    }
    compose_doc = {
        "networks": {"internal_net": {"external": True, "name": network_name}},
        "services": {
            "owner": {
                "image": BUSYBOX_IMAGE,
                "command": ["sleep", "600"],
                "networks": ["internal_net"],
            },
            "upstream": {
                "image": COMET_IMAGE,
                "network_mode": "service:owner",
                "depends_on": {"owner": {"condition": "service_started"}},
                "entrypoint": ["/app/.venv/bin/python", "/stub.py"],
                "volumes": [f"{stub_file}:/stub.py:ro"],
            },
            "comet-gateway": gw_svc,
        },
    }
    compose_path = tmp_path / "ac12-compose.yml"
    compose_path.write_text(json.dumps(compose_doc, indent=2) + "\n", encoding="utf-8")

    network_created = False
    neighbour_created = False
    try:
        _docker("network", "create", "--internal", network_name)
        network_created = True
        up_res = _compose(project, compose_path, "up", "-d", check=False)
        assert up_res.returncode == 0, (up_res.stdout, up_res.stderr)
        owner_cid = _compose(project, compose_path, "ps", "-q", "owner").stdout.strip()
        up_cid = _compose(project, compose_path, "ps", "-q", "upstream").stdout.strip()
        gw_cid = _compose(project, compose_path, "ps", "-q", "comet-gateway").stdout.strip()
        assert owner_cid and up_cid and gw_cid

        t_initial = _wait_healthy(gw_cid, timeout=30.0)

        # (a) Stop upstream -> gateway stays healthy
        _compose(project, compose_path, "stop", "upstream")
        time.sleep(6.5)
        status_a = _docker("inspect", "--format", "{{.State.Health.Status}}", gw_cid).stdout.strip()
        assert status_a == "healthy", status_a

        # Find worker PID and UID inside gateway via /proc
        proc_out = _docker(
            "exec",
            gw_cid,
            "sh",
            "-c",
            'for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" != "1" ] && '
            '[ "$(cat "$p/comm" 2>/dev/null)" = "nginx" ] && '
            'awk -v pid="$pid" "/^Uid:/{print pid, \\$2}" "$p/status"; done; true',
        ).stdout
        worker_pid, worker_uid = None, None
        for line in proc_out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit() and parts[1] != "0":
                worker_pid, worker_uid = parts[0], parts[1]
                break
        assert worker_pid and worker_uid, proc_out

        # (b) Freeze worker as worker uid -> becomes unhealthy while nginx -t still exits 0
        t_freeze = time.monotonic()
        _docker("exec", "-u", worker_uid, gw_cid, "kill", "-STOP", worker_pid)
        deadline = t_freeze + 12.0
        t_unhealthy: float | None = None
        while time.monotonic() < deadline:
            st = _docker("inspect", "--format", "{{.State.Health.Status}}", gw_cid).stdout.strip()
            if st == "unhealthy":
                t_unhealthy = time.monotonic() - t_freeze
                break
            time.sleep(0.3)
        assert t_unhealthy is not None, "gateway did not become unhealthy after worker SIGSTOP"
        assert (
            _docker(
                "exec",
                gw_cid,
                "nginx",
                "-t",
                "-c",
                "/etc/nginx/stremioguard/nginx.conf",
                check=False,
            ).returncode
            == 0
        )

        # (c) Unfreeze worker -> healthy again
        t_cont = time.monotonic()
        _docker("exec", "-u", worker_uid, gw_cid, "kill", "-CONT", worker_pid)
        t_recovered = _wait_healthy(gw_cid, timeout=15.0)
        _ = t_cont

        # (d) Access log unchanged across 10 health probes
        _compose(project, compose_path, "start", "upstream")
        time.sleep(0.5)
        lines_before = len(_docker("logs", gw_cid).stdout.splitlines())
        for _ in range(10):
            hc_probe = _docker(
                "exec",
                gw_cid,
                "curl",
                "-fsS",
                "-o",
                "/dev/null",
                "http://127.0.0.1:8099/__sg_alive",
            )
            assert hc_probe.returncode == 0
        time.sleep(0.2)
        lines_after = len(_docker("logs", gw_cid).stdout.splitlines())
        assert lines_after == lines_before, (lines_before, lines_after)

        # (e) Neighbour on --internal network reaches 8090, refused on 8099
        owner_ip = _docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            owner_cid,
        ).stdout.strip()
        assert owner_ip
        _docker(
            "run",
            "-d",
            "--name",
            neighbour_name,
            "--network",
            network_name,
            BUSYBOX_IMAGE,
            "sleep",
            "120",
        )
        neighbour_created = True
        assert (
            _docker(
                "exec", neighbour_name, "nc", "-z", "-w", "2", owner_ip, "8090", check=False
            ).returncode
            == 0
        )
        assert (
            _docker(
                "exec", neighbour_name, "nc", "-z", "-w", "2", owner_ip, "8099", check=False
            ).returncode
            != 0
        )

        # (f) /__sg_alive on 127.0.0.1:8090 -> 403 and never proxied
        pub_code, _ = _http_probe_in_container(up_cid, "http://127.0.0.1:8090/__sg_alive")
        assert pub_code == 403
        _, rec_body = _http_probe_in_container(up_cid, "http://127.0.0.1:8000/__records")
        assert "/__sg_alive" not in json.loads(rec_body)

        print(
            f"\nAC-12 timings: initial_healthy={t_initial:.2f}s, "
            f"unhealthy_after_stop={t_unhealthy:.2f}s, recovered={t_recovered:.2f}s"
        )
    finally:
        if neighbour_created:
            _docker("rm", "-f", "-v", neighbour_name, check=False)
        _compose(project, compose_path, "down", "-v", check=False)
        if network_created:
            _docker("network", "rm", network_name, check=False)
