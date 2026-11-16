"""Opt-in real-Docker proofs for network boundary (AC-1 through AC-5).

Run with:
  STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -q tests/test_network_boundary_docker.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from stremioguard.config import SubprocessRunner, compose_command
from stremioguard.guard import DNS_BLOCK_RULE, GluetunGuard
from tests.conftest import make_config

PREFIX = os.environ.get("STREMIOGUARD_DOCKER_TEST_PREFIX", "sgfix8-")
REPO_ROOT = Path(__file__).resolve().parent.parent

GLUETUN_IMAGE = (
    "qmcgaw/gluetun@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027"
)
COMET_IMAGE = "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
NGINX_IMAGE = "nginx@sha256:713fc2ebfd92e8217db451477182ee91944b123d2b1ee9fd5a8c6e91ca6c3a11"
POSTGRES_IMAGE = "postgres@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395"
STREMTHRU_IMAGE = (
    "muniftanjim/stremthru@sha256:947cfcb2601c67f2f21eb11bd1ea1e555889cec9e0b347cefd0c63754b9c641a"
)
BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
STREMIO_IMAGE = "stremioguard-stremio:local"

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)


def _docker(
    *args: str, check: bool = True, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _compose(
    project: str, compose_file: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(compose_file), *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60.0,
    )


class _PsOverrideRunner:
    """Answers `compose ps -q gluetun` with the test container ID; passes other calls through."""

    def __init__(self, root_dir: Path, container_id: str) -> None:
        self._root_dir = root_dir
        self._container_id = container_id
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
        if args == compose_command(self._root_dir, "ps", "-q", "gluetun"):
            return subprocess.CompletedProcess(args, 0, f"{self._container_id}\n", "")
        return self._real.run(
            args, check=check, capture=capture, timeout=timeout, env=env, input=input
        )


_DNS53_SCRIPT = """\
import socket, struct, threading
TABLE = {
    "github.com": "1.0.0.1",
    "cloudflare.com": "1.0.0.1",
    "example.test": "1.0.0.1",
    "public.test": "1.0.0.1",
}
def answer(data):
    tid, fl, _ = struct.unpack(">HHH", data[:6])
    i = 12
    labels = []
    while data[i]:
        n = data[i]
        labels.append(data[i + 1 : i + 1 + n].decode())
        i += 1 + n
    qtype, _ = struct.unpack(">HH", data[i + 1 : i + 5])
    question = data[12 : i + 5]
    name = ".".join(labels).lower()
    ans = b""
    rcode = 0
    if qtype == 1 and name in TABLE:
        ans = b"\\xc0\\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(TABLE[name])
    elif name not in TABLE:
        rcode = 3
    hdr = struct.pack(">HHHHHH", tid, 0x8580 | rcode | (fl & 0x0100), 1, 1 if ans else 0, 0, 0)
    return hdr + question + ans
def tcp():
    t = socket.socket()
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("0.0.0.0", 53))
    t.listen(50)
    while True:
        c, _ = t.accept()
        try:
            while True:
                h = c.recv(2)
                if len(h) < 2:
                    break
                n = struct.unpack(">H", h)[0]
                d = b""
                while len(d) < n:
                    d += c.recv(n - len(d))
                r = answer(d)
                c.sendall(struct.pack(">H", len(r)) + r)
        except Exception:
            pass
        finally:
            c.close()
threading.Thread(target=tcp, daemon=True).start()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 8, 1)
s.bind(("0.0.0.0", 53))
while True:
    data, anc, _, addr = s.recvmsg(4096, 256)
    try:
        s.sendmsg([answer(data)], anc, 0, addr)
    except Exception:
        pass
"""

_TLS443_SCRIPT = """\
import socket, ssl, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/cfg/web.crt", "/cfg/web.key")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443))
s.listen(50)
def handle(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        t.settimeout(5)
        try:
            t.recv(1024)
        except Exception:
            pass
        t.close()
    except Exception:
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""

_PROBE_DIG_SCRIPT = """\
import random, socket, struct, sys
server, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
tcp = len(sys.argv) > 5 and sys.argv[5] == "tcp"
tid = random.randrange(65536)
q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
for label in name.rstrip(".").split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\\x00" + struct.pack(">HH", 1, 1)
try:
    if tcp:
        s = socket.create_connection((server, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(q)) + q)
        hdr = s.recv(2)
        if len(hdr) < 2:
            raise EOFError("short TCP DNS header")
        n = struct.unpack(">H", hdr)[0]
        data = b""
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server, port))
        data, _ = s.recvfrom(4096)
        s.close()
except OSError as exc:
    print(f"ERROR:{exc.errno}:{type(exc).__name__}:{exc}")
    sys.exit(2)
except Exception as exc:
    print(f"ERROR:NONE:{type(exc).__name__}:{exc}")
    sys.exit(2)
fl, _, an = struct.unpack(">HHH", data[2:8])[0], None, struct.unpack(">H", data[6:8])[0]
rcode = fl & 0xF
ips = []
i = 12
while data[i]:
    i += 1 + data[i]
i += 5
for _ in range(an):
    if data[i] & 0xC0 == 0xC0:
        i += 2
    else:
        while data[i]:
            i += 1 + data[i]
        i += 1
    t, _, _, ln = struct.unpack(">HHIH", data[i : i + 10])
    i += 10
    if t == 1 and ln == 4:
        ips.append(socket.inet_ntoa(data[i : i + 4]))
    i += ln
print(f"ANSWERED:rcode={rcode}:addrs={','.join(ips)}")
"""

_AFPACKET_SCRIPT = """\
import socket, struct, sys
dst_mac, dst_ip, port, src_ip = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.sendto(b"NORMAL-SOCKET\\n", (dst_ip, port))
    print("normal:sent")
except OSError as exc:
    print(f"normal:err:{exc.errno}:{exc}")
def csum(b):
    if len(b) % 2:
        b += b"\\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF
try:
    p = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    p.bind(("eth0", 0))
except OSError as exc:
    print(f"afpacket:err:{exc.errno}:{exc}")
    sys.exit(0)
src_mac = open("/sys/class/net/eth0/address").read().strip()
payload = b"AF_PACKET-BYPASS\\n"
udp = struct.pack("!HHHH", 40000, port, 8 + len(payload), 0) + payload
ip = struct.pack(
    "!BBHHHBBH4s4s",
    0x45,
    0,
    20 + len(udp),
    1,
    0,
    64,
    17,
    0,
    socket.inet_aton(src_ip),
    socket.inet_aton(dst_ip),
)
ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
d_mac = bytes.fromhex(dst_mac.replace(":", ""))
s_mac = bytes.fromhex(src_mac.replace(":", ""))
eth = d_mac + s_mac + b"\\x08\\x00"
p.send(eth + ip + udp)
print("afpacket:sent")
"""


def _generate_vpn_certs(cfg_dir: Path) -> None:
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "srv.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyAgreement\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    (cfg_dir / "cli.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyAgreement\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="utf-8",
    )
    (cfg_dir / "web.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyAgreement\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:10.9.0.1\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(cfg_dir / "ca.key"),
            "-out",
            str(cfg_dir / "ca.crt"),
            "-days",
            "1",
            "-subj",
            "/CN=t-ca",
        ],
        check=True,
        capture_output=True,
    )
    for name in ("server", "client", "web"):
        subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                str(cfg_dir / f"{name}.key"),
                "-out",
                str(cfg_dir / f"{name}.csr"),
                "-subj",
                f"/CN=t-{name}",
            ],
            check=True,
            capture_output=True,
        )
        ext = {"server": "srv.ext", "client": "cli.ext", "web": "web.ext"}[name]
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(cfg_dir / f"{name}.csr"),
                "-CA",
                str(cfg_dir / "ca.crt"),
                "-CAkey",
                str(cfg_dir / "ca.key"),
                "-CAcreateserial",
                "-out",
                str(cfg_dir / f"{name}.crt"),
                "-days",
                "1",
                "-extfile",
                str(cfg_dir / ext),
            ],
            check=True,
            capture_output=True,
        )
    for item in cfg_dir.iterdir():
        item.chmod(0o644)


def _repo_gluetun_compose_fragment() -> tuple[dict[str, object], dict[str, dict[str, str]]]:
    res = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            f"{PREFIX}config",
            "-f",
            str(REPO_ROOT / "docker-compose.yml"),
            "config",
            "--format",
            "json",
            "--no-env-resolution",
            "gluetun",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    data = json.loads(res.stdout)
    gluetun = data["services"]["gluetun"]
    configs = data.get("configs", {})
    referenced: dict[str, dict[str, str]] = {
        str(c["source"]): {"content": str(configs[c["source"]]["content"])}
        for c in gluetun.get("configs", [])
        if isinstance(c, dict) and c.get("source") in configs
    }
    return gluetun, referenced


def _build_harness_compose(
    *,
    work_dir: Path,
    network_name: str,
    gateway_ip: str,
    ovpn_dir: Path,
    extra_env_lines: list[str] | None = None,
    include_configs: bool = True,
    override_post_rules_content: str | None = None,
    restart_policy: str = "unless-stopped",
) -> Path:
    repo_gt, referenced_configs = _repo_gluetun_compose_fragment()
    env_lines = [
        "VPN_SERVICE_PROVIDER=custom",
        "VPN_TYPE=openvpn",
        "OPENVPN_CUSTOM_CONFIG=/gluetun/ovpn/client.conf",
        "HEALTH_TARGET_ADDRESSES=10.9.0.1:443",
        "HEALTH_ICMP_TARGET_IPS=10.9.0.1",
        "SSL_CERT_FILE=/gluetun/ovpn/ca.crt",
        "DNS_UPSTREAM_RESOLVER_TYPE=plain",
        "DNS_UPSTREAM_RESOLVERS=cloudflare",
        "BLOCK_MALICIOUS=off",
        "BLOCK_SURVEILLANCE=off",
        "BLOCK_ADS=off",
        "PUBLICIP_ENABLED=off",
        "UPDATER_PERIOD=0",
        "VERSION_INFORMATION=off",
        *(extra_env_lines or []),
    ]
    env_file = work_dir / "gluetun.env"
    env_file.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    gt_service: dict[str, object] = {
        "image": repo_gt["image"],
        "restart": restart_policy,
        "devices": repo_gt["devices"],
        "environment": repo_gt["environment"],
        "env_file": [str(env_file)],
        "volumes": [f"{ovpn_dir}:/gluetun/ovpn:ro"],
        "networks": ["test_net"],
        "entrypoint": [
            "sh",
            "-c",
            f"ip route add default via {gateway_ip} dev eth0 && exec /gluetun-entrypoint",
        ],
    }
    for field in ("cap_drop", "cap_add", "security_opt", "read_only", "tmpfs"):
        if field in repo_gt:
            gt_service[field] = repo_gt[field]
    compose_doc: dict[str, object] = {
        "services": {"gluetun": gt_service},
        "networks": {"test_net": {"external": True, "name": network_name}},
    }
    if include_configs:
        gt_service["configs"] = repo_gt["configs"]
        if override_post_rules_content is not None:
            for name in list(referenced_configs):
                if name.startswith("gluetun-post-rules"):
                    referenced_configs[name] = {"content": override_post_rules_content}
        compose_doc["configs"] = referenced_configs

    compose_path = work_dir / "docker-compose.yml"
    compose_path.write_text(json.dumps(compose_doc, indent=2) + "\n", encoding="utf-8")
    return compose_path


@contextmanager
def _vpn_server_sandbox(tmp_path: Path) -> Iterator[dict[str, str]]:
    suffix = uuid.uuid4().hex[:8]
    network = f"{PREFIX}net-{suffix}"
    vpn_name = f"{PREFIX}vpn-{suffix}"
    dns_name = f"{PREFIX}dns-{suffix}"
    tls_name = f"{PREFIX}tls-{suffix}"
    cfg_dir = tmp_path / "ovpn"
    _generate_vpn_certs(cfg_dir)

    (cfg_dir / "server.conf").write_text(
        "dev tun\nproto udp\nport 1194\ntopology subnet\n"
        "server 10.9.0.0 255.255.255.0\n"
        "ca /cfg/ca.crt\ncert /cfg/server.crt\nkey /cfg/server.key\n"
        'dh none\nkeepalive 5 30\npush "redirect-gateway def1"\nverb 3\n',
        encoding="utf-8",
    )
    (cfg_dir / "dns53.py").write_text(_DNS53_SCRIPT, encoding="utf-8")
    (cfg_dir / "tls443.py").write_text(_TLS443_SCRIPT, encoding="utf-8")
    (cfg_dir / "dig.py").write_text(_PROBE_DIG_SCRIPT, encoding="utf-8")
    (cfg_dir / "afpacket.py").write_text(_AFPACKET_SCRIPT, encoding="utf-8")
    for item in cfg_dir.iterdir():
        item.chmod(0o644)

    created_containers: list[str] = []
    network_created = False
    try:
        _docker("network", "create", "--internal", network)
        network_created = True
        gw = _docker(
            "network",
            "inspect",
            network,
            "--format",
            "{{(index .IPAM.Config 0).Gateway}}",
        ).stdout.strip()
        assert gw

        _docker(
            "run",
            "-d",
            "--name",
            vpn_name,
            "--network",
            network,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "-v",
            f"{cfg_dir}:/cfg:ro",
            "--entrypoint",
            "sh",
            GLUETUN_IMAGE,
            "-c",
            "ip addr add 1.1.1.1/32 dev lo && ip addr add 1.0.0.1/32 dev lo && "
            "iptables -P FORWARD DROP && exec openvpn2.6 --config /cfg/server.conf",
        )
        created_containers.append(vpn_name)

        vpn_ip = _docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            vpn_name,
        ).stdout.strip()
        assert vpn_ip

        (cfg_dir / "client.conf").write_text(
            f"client\ndev tun\nproto udp\nremote {vpn_ip} 1194\n"
            "nobind\nremote-cert-tls server\n"
            "ca /gluetun/ovpn/ca.crt\n"
            "cert /gluetun/ovpn/client.crt\n"
            "key /gluetun/ovpn/client.key\n",
            encoding="utf-8",
        )
        (cfg_dir / "client.conf").chmod(0o644)

        _docker(
            "run",
            "-d",
            "--name",
            dns_name,
            "--network",
            f"container:{vpn_name}",
            "-v",
            f"{cfg_dir}:/cfg:ro",
            "--entrypoint",
            "python",
            COMET_IMAGE,
            "-u",
            "/cfg/dns53.py",
        )
        created_containers.append(dns_name)

        _docker(
            "run",
            "-d",
            "--name",
            tls_name,
            "--network",
            f"container:{vpn_name}",
            "-v",
            f"{cfg_dir}:/cfg:ro",
            "--entrypoint",
            "python",
            COMET_IMAGE,
            "/cfg/tls443.py",
        )
        created_containers.append(tls_name)

        yield {
            "suffix": suffix,
            "network": network,
            "gateway": gw,
            "vpn_name": vpn_name,
            "vpn_ip": vpn_ip,
            "dns_name": dns_name,
            "tls_name": tls_name,
            "cfg_dir": str(cfg_dir),
        }
    finally:
        for name in reversed(created_containers):
            _docker("rm", "-f", "-v", name, check=False)
        if network_created:
            _docker("network", "rm", network, check=False)


def _wait_gluetun_ready(
    container_id: str,
    *,
    min_dns_ready_count: int = 1,
    timeout_seconds: float = 45.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        insp = _docker(
            "inspect",
            "--format",
            "{{.State.Health.Status}}",
            container_id,
            check=False,
        )
        logs = _docker("logs", container_id, check=False)
        combined = f"{logs.stdout}\n{logs.stderr}"
        ready_count = combined.count("[dns] ready")
        if insp.stdout.strip() == "healthy" and ready_count >= min_dns_ready_count:
            return
        time.sleep(0.5)
    logs = _docker("logs", container_id, check=False)
    raise AssertionError(
        f"gluetun {container_id} did not become healthy with [dns] ready ({min_dns_ready_count}):\n"
        f"{logs.stdout}\n{logs.stderr}"
    )


def _run_dig_probe(
    gluetun_id: str,
    cfg_dir: Path,
    server: str,
    port: int,
    name: str,
    *,
    tcp: bool = False,
    timeout: float = 1.0,
) -> tuple[int, str, float]:
    args = [
        "run",
        "--rm",
        "--network",
        f"container:{gluetun_id}",
        "-v",
        f"{cfg_dir}:/cfg:ro",
        "--entrypoint",
        "python",
        COMET_IMAGE,
        "/cfg/dig.py",
        server,
        str(port),
        name,
        str(timeout),
    ]
    if tcp:
        args.append("tcp")
    start = time.monotonic()
    res = _docker(*args, check=False, timeout=15.0)
    elapsed = time.monotonic() - start
    return res.returncode, f"{res.stdout}\n{res.stderr}".strip(), elapsed


def test_ac1_real_gluetun_dns_block_survives_reconnect_and_restart(tmp_path: Path) -> None:
    """AC-1 (INV-1, INV-3): DNS block holds across VPN reconnect and container restart."""
    with _vpn_server_sandbox(tmp_path) as sb:
        cfg_dir = Path(sb["cfg_dir"])
        proj_dir = tmp_path / "gt-main"
        proj_dir.mkdir()
        project = f"{PREFIX}ac1-{sb['suffix']}"
        compose_path = _build_harness_compose(
            work_dir=proj_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
        )

        nogt_dir = tmp_path / "gt-ctrl"
        nogt_dir.mkdir()
        nogt_project = f"{PREFIX}ac1ctrl-{sb['suffix']}"
        nogt_compose = _build_harness_compose(
            work_dir=nogt_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
            include_configs=False,
        )

        timings: list[str] = []
        try:
            _compose(project, compose_path, "up", "-d")
            gt_id = _compose(project, compose_path, "ps", "-q", "gluetun").stdout.strip()
            assert gt_id
            _wait_gluetun_ready(gt_id, min_dns_ready_count=1)

            def assert_blocked_phase(phase: str) -> None:
                # Rule first in OUTPUT
                ipt = _docker("exec", gt_id, "iptables", "-S", "OUTPUT").stdout
                output_lines = [
                    ln.strip() for ln in ipt.splitlines() if ln.strip().startswith("-A OUTPUT")
                ]
                assert output_lines and output_lines[0] == DNS_BLOCK_RULE, ipt

                # Real namespace_dns_block_active()
                guard = GluetunGuard(make_config(tmp_path), _PsOverrideRunner(tmp_path, gt_id))
                assert guard.namespace_dns_block_active() is True

                # DNAT ports from iptables-save -t nat
                nat = _docker("exec", gt_id, "iptables-save", "-t", "nat").stdout
                dnat_ports = sorted(set(re.findall(r"--to-destination 127\.0\.0\.11:(\d+)", nat)))
                assert dnat_ports, nat

                # (a) UDP and TCP to 127.0.0.11:53
                for proto_tcp in (False, True):
                    rc, out, elapsed = _run_dig_probe(
                        gt_id, cfg_dir, "127.0.0.11", 53, sb["vpn_name"], tcp=proto_tcp, timeout=1.0
                    )
                    proto = "TCP" if proto_tcp else "UDP"
                    timings.append(f"{phase} (a) 127.0.0.11:53 {proto}: {elapsed:.3f}s ({out})")
                    assert rc != 0 and "ANSWERED" not in out, out
                    assert "PermissionError" in out or "ConnectionRefusedError" in out, out
                    assert elapsed < 5.0

                # (b) UDP and TCP straight to resolver DNAT ports
                for dport_str in dnat_ports:
                    dport = int(dport_str)
                    for proto_tcp in (False, True):
                        rc, out, elapsed = _run_dig_probe(
                            gt_id,
                            cfg_dir,
                            "127.0.0.11",
                            dport,
                            sb["vpn_name"],
                            tcp=proto_tcp,
                            timeout=1.0,
                        )
                        proto = "TCP" if proto_tcp else "UDP"
                        timings.append(
                            f"{phase} (b) 127.0.0.11:{dport} {proto}: {elapsed:.3f}s ({out})"
                        )
                        assert rc != 0 and "ANSWERED" not in out, out
                        assert "PermissionError" in out or "ConnectionRefusedError" in out, out

                # (c) vpn_name through 127.0.0.1 returns no address
                rc_c, out_c, elapsed_c = _run_dig_probe(
                    gt_id, cfg_dir, "127.0.0.1", 53, sb["vpn_name"], timeout=2.0
                )
                timings.append(
                    f"{phase} (c) 127.0.0.1 {sb['vpn_name']}: {elapsed_c:.3f}s ({out_c})"
                )
                assert "addrs=" in out_c
                assert out_c.endswith("addrs="), out_c

                # (d) public name through 127.0.0.1 resolves through tunnel
                rc_d, out_d, elapsed_d = _run_dig_probe(
                    gt_id, cfg_dir, "127.0.0.1", 53, "github.com", timeout=3.0
                )
                timings.append(f"{phase} (d) 127.0.0.1 github.com: {elapsed_d:.3f}s ({out_d})")
                assert rc_d == 0 and "addrs=1.0.0.1" in out_d, out_d

            assert_blocked_phase("initial")

            # (e) Force VPN restart by stopping TLS health target until gluetun logs restarting VPN
            before_logs = _docker("logs", gt_id, check=False)
            before_restart_count = f"{before_logs.stdout}\n{before_logs.stderr}".count(
                "restarting VPN"
            )
            before_dns_ready = f"{before_logs.stdout}\n{before_logs.stderr}".count("[dns] ready")
            _docker("stop", "-t", "1", sb["tls_name"])
            stop_ts = time.monotonic()
            deadline = stop_ts + 360.0
            while time.monotonic() < deadline:
                cur_logs = _docker("logs", gt_id, check=False)
                if (
                    f"{cur_logs.stdout}\n{cur_logs.stderr}".count("restarting VPN")
                    > before_restart_count
                ):
                    timings.append(
                        f"phase (e) restarting VPN after {time.monotonic() - stop_ts:.1f}s"
                    )
                    break
                time.sleep(1.0)
            else:
                cur_logs = _docker("logs", gt_id, check=False)
                health_json = _docker(
                    "inspect", "--format", "{{json .State.Health}}", gt_id, check=False
                ).stdout
                raise AssertionError(
                    "gluetun never logged 'restarting VPN' after TLS target stopped:\n"
                    f"health={health_json}\n"
                    f"{cur_logs.stdout}\n{cur_logs.stderr}"
                )
            _docker("start", sb["tls_name"])
            _wait_gluetun_ready(gt_id, min_dns_ready_count=before_dns_ready, timeout_seconds=60.0)
            assert_blocked_phase("after-vpn-restart")

            # (f) docker restart of gluetun container
            before_logs_f = _docker("logs", gt_id, check=False)
            before_dns_ready_f = f"{before_logs_f.stdout}\n{before_logs_f.stderr}".count(
                "[dns] ready"
            )
            _docker("restart", gt_id)
            _wait_gluetun_ready(gt_id, min_dns_ready_count=before_dns_ready_f + 1)
            assert_blocked_phase("after-docker-restart")

            # (g) Control without configs: leak is observable & dns block is False
            _compose(nogt_project, nogt_compose, "up", "-d")
            nogt_id = _compose(nogt_project, nogt_compose, "ps", "-q", "gluetun").stdout.strip()
            assert nogt_id
            _wait_gluetun_ready(nogt_id, min_dns_ready_count=1)

            ctrl_guard = GluetunGuard(make_config(tmp_path), _PsOverrideRunner(tmp_path, nogt_id))
            assert ctrl_guard.namespace_dns_block_active() is False

            rc_ga, out_ga, elapsed_ga = _run_dig_probe(
                nogt_id, cfg_dir, "127.0.0.11", 53, sb["vpn_name"], timeout=2.0
            )
            timings.append(f"control (a) 127.0.0.11:53 UDP: {elapsed_ga:.3f}s ({out_ga})")
            assert rc_ga == 0 and f"addrs={sb['vpn_ip']}" in out_ga, out_ga

            rc_gc, out_gc, elapsed_gc = _run_dig_probe(
                nogt_id, cfg_dir, "127.0.0.1", 53, sb["vpn_name"], timeout=2.0
            )
            timings.append(f"control (c) 127.0.0.1 {sb['vpn_name']}: {elapsed_gc:.3f}s ({out_gc})")
            assert rc_gc == 0 and f"addrs={sb['vpn_ip']}" in out_gc, out_gc

            print("\nAC-1 timings:\n" + "\n".join(timings))
        finally:
            _compose(nogt_project, nogt_compose, "down", "-v", check=False)
            _compose(project, compose_path, "down", "-v", check=False)


def test_ac2_real_gluetun_pins_dns_and_firewall_over_env_file(tmp_path: Path) -> None:
    """AC-2 (opt-in, INV-4): pinned DNS_KEEP_NAMESERVER and FIREWALL pin win over env_file."""
    with _vpn_server_sandbox(tmp_path) as sb:
        cfg_dir = Path(sb["cfg_dir"])
        proj_dir = tmp_path / "gt-ac2"
        proj_dir.mkdir()
        project = f"{PREFIX}ac2-{sb['suffix']}"
        compose_path = _build_harness_compose(
            work_dir=proj_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
            extra_env_lines=[
                "DNS_KEEP_NAMESERVER=on",
                "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=off",
            ],
        )
        try:
            _compose(project, compose_path, "up", "-d")
            gt_id = _compose(project, compose_path, "ps", "-q", "gluetun").stdout.strip()
            assert gt_id
            _wait_gluetun_ready(gt_id)

            env_out = _docker(
                "run",
                "--rm",
                "--network",
                f"container:{gt_id}",
                "--entrypoint",
                "sh",
                COMET_IMAGE,
                "-c",
                "cat /etc/resolv.conf",
            ).stdout
            assert "nameserver 127.0.0.1" in env_out, env_out

            dns_keep = _docker("exec", gt_id, "printenv", "DNS_KEEP_NAMESERVER").stdout.strip()
            fw_pin = _docker(
                "exec", gt_id, "printenv", "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT"
            ).stdout.strip()
            assert dns_keep == "off"
            assert fw_pin == "on"

            ipt_lines = [
                ln.strip()
                for ln in _docker("exec", gt_id, "iptables", "-S", "OUTPUT").stdout.splitlines()
                if ln.strip()
            ]
            assert ipt_lines[0] == "-P OUTPUT DROP"
            assert ipt_lines[1] == DNS_BLOCK_RULE
        finally:
            _compose(project, compose_path, "down", "-v", check=False)


def test_ac3_invalid_post_rules_fails_closed(tmp_path: Path) -> None:
    """AC-3 (INV-1, fail closed): bad post-rules line makes gluetun exit non-zero."""
    with _vpn_server_sandbox(tmp_path) as sb:
        cfg_dir = Path(sb["cfg_dir"])
        proj_dir = tmp_path / "gt-ac3"
        proj_dir.mkdir()
        project = f"{PREFIX}ac3-{sb['suffix']}"
        compose_path = _build_harness_compose(
            work_dir=proj_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
            override_post_rules_content="iptables -I OUTPUT -d 127.0.0.11/32 -j NOSUCHTARGET\n",
            restart_policy="no",
        )
        try:
            _compose(project, compose_path, "up", "-d")
            gt_id = _compose(project, compose_path, "ps", "-q", "gluetun").stdout.strip()
            assert gt_id
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                state = _docker(
                    "inspect",
                    "--format",
                    "{{.State.Running}}|{{.State.ExitCode}}|{{.State.Health.Status}}",
                    gt_id,
                ).stdout.strip()
                running, exit_code, health = state.split("|", 2)
                assert health != "healthy"
                if running == "false":
                    assert int(exit_code) != 0
                    break
                time.sleep(0.3)
            else:
                raise AssertionError("gluetun did not exit on invalid post-rules")
            logs = _docker("logs", gt_id, check=False)
            combined = f"{logs.stdout}\n{logs.stderr}"
            assert "user defined post firewall rules" in combined, combined
        finally:
            _compose(project, compose_path, "down", "-v", check=False)


def test_ac4_cap_drop_net_raw_blocks_af_packet_bypass(tmp_path: Path) -> None:
    """AC-4 (opt-in, INV-2): cap_drop NET_RAW blocks AF_PACKET frame injection."""
    cfg_res = subprocess.run(
        [
            "docker",
            "compose",
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
    comet_svc = json.loads(cfg_res.stdout)["services"]["comet"]
    comet_cap_drop = comet_svc["cap_drop"]
    assert comet_cap_drop == ["ALL"]
    assert "NET_RAW" not in (comet_svc.get("cap_add") or [])

    with _vpn_server_sandbox(tmp_path) as sb:
        cfg_dir = Path(sb["cfg_dir"])
        proj_dir = tmp_path / "gt-ac4"
        proj_dir.mkdir()
        project = f"{PREFIX}ac4-{sb['suffix']}"
        compose_path = _build_harness_compose(
            work_dir=proj_dir,
            network_name=sb["network"],
            gateway_ip=sb["gateway"],
            ovpn_dir=cfg_dir,
        )
        sink_name = f"{PREFIX}sink-{sb['suffix']}"
        sink_created = False
        try:
            _compose(project, compose_path, "up", "-d")
            gt_id = _compose(project, compose_path, "ps", "-q", "gluetun").stdout.strip()
            assert gt_id
            _wait_gluetun_ready(gt_id)

            _docker(
                "run",
                "-d",
                "--name",
                sink_name,
                "--network",
                sb["network"],
                "--cap-add",
                "NET_ADMIN",
                BUSYBOX_IMAGE,
                "sh",
                "-c",
                "ip addr add 192.0.2.1/32 dev eth0 && "
                "while true; do nc -u -l -s 0.0.0.0 -p 19999 >> /tmp/sink.out; done",
            )
            sink_created = True
            time.sleep(0.5)
            sink_mac = _docker(
                "exec", sink_name, "cat", "/sys/class/net/eth0/address"
            ).stdout.strip()
            sink_ip = _docker(
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                sink_name,
            ).stdout.strip()
            gt_ip = _docker(
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                gt_id,
            ).stdout.strip()

            # Drop tun0 so 192.0.2.1 routes to eth0 and hits gluetun's OUTPUT DROP kill switch.
            _docker("exec", gt_id, "ip", "link", "del", "tun0")

            # (a) With compose's cap_drop=[NET_RAW]
            cap_drop_flags: list[str] = []
            for cap in comet_cap_drop:
                cap_drop_flags.extend(["--cap-drop", cap])
            res_a = _docker(
                "run",
                "--rm",
                "--network",
                f"container:{gt_id}",
                *cap_drop_flags,
                "-v",
                f"{cfg_dir}:/cfg:ro",
                "--entrypoint",
                "python",
                COMET_IMAGE,
                "/cfg/afpacket.py",
                sink_mac,
                "192.0.2.1",
                "19999",
                gt_ip,
            )
            assert "normal:err:1:" in res_a.stdout, res_a.stdout
            assert "afpacket:err:1:" in res_a.stdout, res_a.stdout
            time.sleep(0.3)
            sink_out_a = _docker("exec", sink_name, "cat", "/tmp/sink.out", check=False).stdout
            assert "AF_PACKET-BYPASS" not in sink_out_a

            # (b) Control: Docker's default capabilities.
            # On an --internal bridge, Docker's DOCKER-INTERNAL FORWARD rule drops
            # non-subnet 192.0.2.1 on the bridge, so we prove both: (1) normal->192.0.2.1
            # gets EPERM while AF_PACKET succeeds, and (2) an AF_PACKET frame to sink_ip
            # is delivered to the sink.
            res_b = _docker(
                "run",
                "--rm",
                "--network",
                f"container:{gt_id}",
                "-v",
                f"{cfg_dir}:/cfg:ro",
                "--entrypoint",
                "python",
                COMET_IMAGE,
                "/cfg/afpacket.py",
                sink_mac,
                "192.0.2.1",
                "19999",
                gt_ip,
            )
            assert "normal:err:1:" in res_b.stdout, res_b.stdout
            assert "afpacket:sent" in res_b.stdout, res_b.stdout

            res_b_l2 = _docker(
                "run",
                "--rm",
                "--network",
                f"container:{gt_id}",
                "--entrypoint",
                "python",
                COMET_IMAGE,
                "-c",
                "import socket, struct; "
                f"dst_mac, dst_ip, port, src_ip = {sink_mac!r}, {sink_ip!r}, 19999, {gt_ip!r}; "
                "p = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); p.bind(('eth0', 0)); "
                "src_mac = open('/sys/class/net/eth0/address').read().strip(); "
                "payload = b'AF_PACKET-BYPASS\\n'; "
                "udp = struct.pack('!HHHH', 40000, port, 8 + len(payload), 0) + payload; "
                "csum = lambda b: (~((lambda s: "
                "(s >> 16) + (s & 0xffff) + (((s >> 16) + (s & 0xffff)) >> 16))"
                "(sum(struct.unpack('!%dH' % (len(b) // 2), b))))) & 0xffff; "
                "ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, "
                "socket.inet_aton(src_ip), socket.inet_aton(dst_ip)); "
                "ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]; "
                "dmac = bytes.fromhex(dst_mac.replace(':', '')); "
                "smac = bytes.fromhex(src_mac.replace(':', '')); "
                "eth = dmac + smac + b'\\x08\\x00'; "
                "p.send(eth + ip + udp); print('afpacket:sent')",
            )
            assert "afpacket:sent" in res_b_l2.stdout, res_b_l2.stdout
            time.sleep(0.5)
            sink_out_b = _docker("exec", sink_name, "cat", "/tmp/sink.out", check=False).stdout
            assert "AF_PACKET-BYPASS" in sink_out_b, sink_out_b
        finally:
            if sink_created:
                _docker("rm", "-f", "-v", sink_name, check=False)
            _compose(project, compose_path, "down", "-v", check=False)


def test_ac5_namespace_images_behave_identically_with_net_raw_dropped(tmp_path: Path) -> None:
    """AC-5 (D3): namespace images behave identically with and without --cap-drop NET_RAW."""
    suffix = uuid.uuid4().hex[:8]
    outcomes: list[str] = []

    def run_pair(
        label: str,
        image: str,
        *,
        env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        probe_fn,
    ) -> None:
        results: dict[str, str] = {}
        for mode, drop_args in (("default", []), ("drop_net_raw", ["--cap-drop", "NET_RAW"])):
            name = f"{PREFIX}ac5-{label}-{mode}-{suffix}"
            cmd = ["run", "-d", "--name", name, "--network", "none", *drop_args]
            for k, v in (env or {}).items():
                cmd.extend(["-e", f"{k}={v}"])
            cmd.extend(extra_args or [])
            cmd.append(image)
            try:
                _docker(*cmd)
                results[mode] = probe_fn(name)
            finally:
                _docker("rm", "-f", "-v", name, check=False)
        outcomes.append(
            f"{label}: default={results['default']!r}, drop={results['drop_net_raw']!r}"
        )
        assert results["default"] == results["drop_net_raw"], outcomes[-1]

    def probe_comet(name: str) -> str:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            res = _docker(
                "exec",
                name,
                "/app/.venv/bin/python",
                "-c",
                "import urllib.request; print(urllib.request.urlopen("
                "'http://127.0.0.1:8000/health', timeout=2).read().decode())",
                check=False,
            )
            if res.returncode == 0 and '"status":"ok"' in res.stdout.replace(" ", ""):
                return "healthy"
            time.sleep(0.5)
        return "unhealthy"

    def probe_nginx(name: str) -> str:
        time.sleep(2.0)
        running = _docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
        return f"running={running}"

    def probe_postgres(name: str) -> str:
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            res = _docker("exec", name, "pg_isready", "-U", "postgres", check=False)
            if res.returncode == 0:
                return "ready"
            time.sleep(0.5)
        return "not-ready"

    def probe_state_or_error(name: str) -> str:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            state = _docker(
                "inspect", "--format", "{{.State.Running}}|{{.State.ExitCode}}", name
            ).stdout.strip()
            if state.startswith("false|"):
                break
            time.sleep(0.5)
        state = _docker(
            "inspect", "--format", "{{.State.Running}}|{{.State.ExitCode}}", name
        ).stdout.strip()
        logs = _docker("logs", name, check=False)
        lines = [ln.strip() for ln in f"{logs.stdout}\n{logs.stderr}".splitlines() if ln.strip()]
        err_line = next(
            (
                ln
                for ln in lines
                if "panic" in ln.lower() or "error" in ln.lower() or "err" in ln.lower()
            ),
            lines[0] if lines else "",
        )
        # Normalize timestamps or container IDs if any
        return f"{state}:{err_line[:120]}"

    run_pair("comet", COMET_IMAGE, probe_fn=probe_comet)
    run_pair("nginx", NGINX_IMAGE, probe_fn=probe_nginx)
    run_pair(
        "postgres", POSTGRES_IMAGE, env={"POSTGRES_PASSWORD": "testpw"}, probe_fn=probe_postgres
    )
    run_pair(
        "stremthru",
        STREMTHRU_IMAGE,
        env={"STREMTHRU_LISTEN_ADDR": "127.0.0.1:8091", "STREMTHRU_PEER_URI": "-"},
        probe_fn=probe_state_or_error,
    )
    run_pair(
        "stremio",
        STREMIO_IMAGE,
        env={"NO_CORS": "1", "AUTO_SERVER_URL": "1", "CASTING_DISABLED": "1"},
        probe_fn=probe_state_or_error,
    )
    print("\nAC-5 outcomes:\n" + "\n".join(outcomes))
