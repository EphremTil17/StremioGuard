"""Acceptance tests AC-1 through AC-13 and AC-15 (default) for handoff 0014."""

from __future__ import annotations

import ast
import http.server
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest import mock

import pytest
import typer
from loguru import logger

from stremioguard import cli as cli_mod
from stremioguard import comet_gateway as comet_gateway_mod
from stremioguard import config as config_mod
from stremioguard import env as env_mod
from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard import preflight as preflight_mod
from stremioguard import publishing as publishing_mod
from stremioguard import resolver as resolver_mod
from stremioguard.cli import context as cli_context
from stremioguard.guard import PROBE_REQUEST_HEADERS, GluetunGuard, PublicIPAssessment
from stremioguard.orchestrator import Orchestrator
from stremioguard.stacklock import stack_lock
from tests.conftest import (
    ACTIVE_STATUS_ARGS,
    PUBLIC_IPV4_ALT,
    PUBLIC_IPV4_EGRESS,
    PUBLIC_IPV4_HOST,
    PUBLIC_IPV4_STATION,
    PUBLIC_IPV6_HOST,
    FakeRunner,
    completed,
    compose_args_prefix,
    compose_stack_responses,
    make_comet_gateway_config,
    make_config,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"


def _run_bounded[T](fn: Callable[[], T], timeout_seconds: float, label: str) -> T:
    """Run ``fn`` on a daemon thread and fail the test if it does not finish in time."""
    outcome: list[tuple[bool, object]] = []

    def _target() -> None:
        try:
            outcome.append((True, fn()))
        except BaseException as exc:
            outcome.append((False, exc))

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)
    if thread.is_alive():
        pytest.fail(f"{label} hung past {timeout_seconds}s")
    ok, value = outcome[0]
    if not ok:
        assert isinstance(value, BaseException)
        raise value
    return value  # type: ignore[return-value]


# Allowed listener port range from Rules of engagement: 19400-19449 on 127.0.0.1.
_PORT_RANGE = range(19400, 19450)
_PORT_LOCK = threading.Lock()
_NEXT_PORT_OFFSET = 0


def _bind_allowed_tcp_socket() -> socket.socket:
    """Bind a listening TCP socket on 127.0.0.1 within the allowed 19400-19449 range."""
    global _NEXT_PORT_OFFSET
    with _PORT_LOCK:
        for offset in range(len(_PORT_RANGE)):
            idx = (_NEXT_PORT_OFFSET + offset) % len(_PORT_RANGE)
            port = _PORT_RANGE[idx]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen(16)
                _NEXT_PORT_OFFSET = (idx + 1) % len(_PORT_RANGE)
                return sock
            except OSError:
                sock.close()
    raise RuntimeError("No free port in 19400-19449")


@contextmanager
def _stub_http_server(
    handler_factory: Callable[[], type[http.server.BaseHTTPRequestHandler]],
) -> Iterator[str]:
    """Serve HTTP on 127.0.0.1 in 19400-19449 for the duration of the context."""
    sock = _bind_allowed_tcp_socket()
    port = sock.getsockname()[1]

    class _BoundServer(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def server_bind(self) -> None:  # pragma: no cover - socket already bound
            self.server_address = sock.getsockname()

    srv = _BoundServer.__new__(_BoundServer)
    http.server.HTTPServer.__init__(
        srv, ("127.0.0.1", port), handler_factory(), bind_and_activate=False
    )
    srv.socket = sock
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


@contextmanager
def _raw_capture_server(
    body: bytes,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> Iterator[tuple[str, list[bytes]]]:
    """Listen on 127.0.0.1 in 19400-19449, capture raw request heads, reply 200."""
    srv = _bind_allowed_tcp_socket()
    srv.settimeout(0.2)
    port = srv.getsockname()[1]
    captured: list[bytes] = []
    stop = threading.Event()

    def _serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                if ssl_context is not None:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                conn.settimeout(2.0)
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 16384:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                head, _, _ = buf.partition(b"\r\n\r\n")
                captured.append(head)
                resp = (
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii") + body
                conn.sendall(resp)
            except OSError:
                pass
            finally:
                with suppress(OSError):
                    conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    scheme = "https" if ssl_context is not None else "http"
    host = "localhost" if ssl_context is not None else "127.0.0.1"
    try:
        yield f"{scheme}://{host}:{port}/", captured
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=2)


def _create_localhost_cert(tmp_path: Path) -> tuple[Path, Path]:
    cert_file = tmp_path / "localhost.crt"
    key_file = tmp_path / "localhost.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert_file, key_file


# ---------------------------------------------------------------------------
# AC-1 (INV-1, D1): parse_public_ip() accepts only global unicast addresses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_ip",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.5",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fe80::1%eth0",
        "fc00::1",
        "fd00::1",
        "ff02::1",
        "ff0e::1",
        "2001:db8::1",
        "3fff::1",
        "2002:102:304::1",
        "fec0::1",
        "::1.2.3.4",
        "64:ff9b::1.2.3.4",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        f"{PUBLIC_IPV6_HOST}%eth0",
        f"::ffff:{PUBLIC_IPV4_HOST}%eth0",
        "",
        "   \t\r\n  ",
        f"{PUBLIC_IPV4_HOST} extra",
    ],
)
def test_ac1_parse_public_ip_rejects_non_public_and_non_address(bad_ip: str) -> None:
    """AC-1 (INV-1, D1): non-public, multicast, reserved, site-local, zoned -> None."""
    assert config_mod.parse_public_ip(bad_ip) is None


def test_ac1_parse_public_ip_accepts_public_and_unwraps_v4_mapped() -> None:
    """AC-1 (INV-1, D1, D3): canonical global unicast IPv4/IPv6 and ::ffff: mapped public IPv4."""
    assert config_mod.parse_public_ip(f"  {PUBLIC_IPV4_HOST}\n") == PUBLIC_IPV4_HOST
    assert config_mod.parse_public_ip(f"\t{PUBLIC_IPV6_HOST} ") == PUBLIC_IPV6_HOST
    assert config_mod.parse_public_ip(f" ::ffff:{PUBLIC_IPV4_HOST} ") == PUBLIC_IPV4_HOST


# ---------------------------------------------------------------------------
# AC-2 (INV-1, INV-2): public_ip_assessment rejects non-public probe answers
# ---------------------------------------------------------------------------


def test_ac2_public_ip_assessment_skips_non_public_answers_across_paths(tmp_path: Path) -> None:
    """AC-2 (INV-1, INV-2): real public_ip_assessment + public_ip_via_gluetun + public_ip."""
    egress_answers: dict[str, str] = {}
    host_answers: dict[str, bytes] = {}
    control_answer = {"body": ""}

    class _HostHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = host_answers[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    with _stub_http_server(lambda: _HostHandler) as base_url:
        url1 = f"{base_url}u1"
        url2 = f"{base_url}u2"
        cfg = make_config(tmp_path, ip_check_urls=(url1, url2), public_ip_timeout_seconds=2)
        prefix = compose_args_prefix(tmp_path)
        ps_gluetun = (*prefix, "ps", "-q", "gluetun")
        control_cmd = [
            "docker",
            "exec",
            "gluetun-cid",
            "timeout",
            "-s",
            "KILL",
            "2",
            "wget",
            "--tries=1",
            "--timeout=2",
            "-O-",
            "http://127.0.0.1:18080/v1/publicip/ip",
        ]

        class _ProbeRunner(FakeRunner):
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
                self.calls.append(args)
                self.envs.append(env)
                self.timeouts.append(timeout)
                self.inputs.append(input)
                if tuple(args) == ps_gluetun:
                    return completed(args, "gluetun-cid\n")
                if args == control_cmd:
                    return completed(args, control_answer["body"])
                if args[:4] == ["docker", "exec", "gluetun-cid", "timeout"] and "-qO-" in args:
                    return completed(args, egress_answers[args[-1]])
                return completed(args, "", "unstubbed", returncode=1)

        def run_case(
            e1: str, e2: str, h1: bytes, h2: bytes, ctrl: str = ""
        ) -> tuple[PublicIPAssessment, GluetunGuard, list[str]]:
            egress_answers["/u1"] = e1
            egress_answers["/u2"] = e2
            egress_answers[url1] = e1
            egress_answers[url2] = e2
            host_answers["/u1"] = h1
            host_answers["/u2"] = h2
            control_answer["body"] = ctrl
            guard = GluetunGuard(cfg, _ProbeRunner({}))
            warnings: list[str] = []
            with (
                mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
                mock.patch.object(guard, "warn", side_effect=warnings.append),
            ):
                verdict = guard.public_ip_assessment(force_probe=True)
            return verdict, guard, warnings

        # (a) Egress URL 1 answers 10.0.0.1, URL 2 answers P; host answers H
        verdict_a, guard_a, _ = run_case(
            "10.0.0.1\n", f"{PUBLIC_IPV4_EGRESS}\n", f"{PUBLIC_IPV4_HOST}\n".encode(), b"unused"
        )
        assert verdict_a == PublicIPAssessment.SAFE
        assert guard_a.last_observed_ip == PUBLIC_IPV4_EGRESS

        # (b) Egress URLs answer only non-public addresses; host answers H
        for bad_pair in (
            ("127.0.0.1\n", "::ffff:192.168.1.1\n"),
            (f"{PUBLIC_IPV6_HOST}%eth0\n", "10.0.0.1\n"),
        ):
            verdict_b, _, _ = run_case(
                bad_pair[0], bad_pair[1], f"{PUBLIC_IPV4_HOST}\n".encode(), b"unused"
            )
            assert verdict_b == PublicIPAssessment.UNKNOWN

        # (c) Egress P; host URL 1 answers 192.168.1.1, URL 2 answers P
        verdict_c, _, _ = run_case(
            f"{PUBLIC_IPV4_EGRESS}\n",
            f"{PUBLIC_IPV4_EGRESS}\n",
            b"192.168.1.1\n",
            f"{PUBLIC_IPV4_EGRESS}\n".encode(),
        )
        assert verdict_c == PublicIPAssessment.UNSAFE_DEFINITIVE

        # (d) Egress P; host answers only non-public addresses; no baseline
        verdict_d, _, _ = run_case(
            f"{PUBLIC_IPV4_EGRESS}\n",
            f"{PUBLIC_IPV4_EGRESS}\n",
            b"10.0.0.1\n",
            b"192.168.1.1\n",
        )
        assert verdict_d == PublicIPAssessment.UNKNOWN

        # (e) As (a), control server answers {"public_ip":"127.0.0.1"} -> SAFE, no snapshot warning
        verdict_e, guard_e, warnings_e = run_case(
            "10.0.0.1\n",
            f"{PUBLIC_IPV4_EGRESS}\n",
            f"{PUBLIC_IPV4_HOST}\n".encode(),
            b"unused",
            ctrl='{"public_ip":"127.0.0.1"}',
        )
        assert verdict_e == PublicIPAssessment.SAFE
        assert guard_e.last_observed_ip == PUBLIC_IPV4_EGRESS
        assert not any("Gluetun control server reports" in w for w in warnings_e)


# ---------------------------------------------------------------------------
# AC-3 (INV-1, INV-2): non-public home baselines never yield SAFE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("baseline_content", "expected"),
    [
        ("127.0.0.1\n", PublicIPAssessment.UNKNOWN),
        ("10.0.0.1\n", PublicIPAssessment.UNKNOWN),
        ("::ffff:192.168.1.1\n", PublicIPAssessment.UNKNOWN),
        ("203.0.113.5\n", PublicIPAssessment.UNKNOWN),
        (f"{PUBLIC_IPV4_HOST}\n", PublicIPAssessment.SAFE),
        (f"{PUBLIC_IPV4_EGRESS}\n", PublicIPAssessment.UNSAFE_DEFINITIVE),
    ],
)
def test_ac3_non_public_home_baseline_rejected(
    tmp_path: Path, baseline_content: str, expected: PublicIPAssessment
) -> None:
    """AC-3 (INV-1, INV-2): non-public home-ip counts as missing -> UNKNOWN."""
    cfg = make_config(tmp_path)
    cfg.home_ip_file.write_text(baseline_content, encoding="utf-8")
    guard = GluetunGuard(cfg, FakeRunner({}))
    with (
        mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
        mock.patch.object(guard, "public_ip_via_control_server", return_value=None),
        mock.patch.object(guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS),
        mock.patch.object(guard, "public_ip", return_value=None),
    ):
        assert guard.public_ip_assessment(force_probe=True) == expected


# ---------------------------------------------------------------------------
# AC-4 (D2, INV-1): record_home_ip() refuses non-public answers cleanly
# ---------------------------------------------------------------------------


def test_ac4_record_home_ip_refuses_all_non_public_and_saves_second_public(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4 (D2): all-non-public refuses and keeps sentinel; URL 2 public saves 0600."""
    answers = {"/u1": b"10.0.0.1\n", "/u2": b"192.168.1.1\n"}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = answers[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    with _stub_http_server(lambda: _Handler) as base_url:
        u1, u2 = f"{base_url}u1", f"{base_url}u2"
        sentinel = f"{PUBLIC_IPV4_ALT}\n".encode()
        cfg = make_config(tmp_path, ip_check_urls=(u1, u2), public_ip_timeout_seconds=2)
        cfg.home_ip_file.write_bytes(sentinel)
        guard = GluetunGuard(cfg, FakeRunner({}))
        orch = Orchestrator(guard)

        # (a) All non-public -> RuntimeError with D2 message, sentinel untouched
        with pytest.raises(
            RuntimeError, match="No IP-check service returned a public IPv4 address."
        ):
            orch.record_home_ip()
        assert cfg.home_ip_file.read_bytes() == sentinel

        # (c) Through _run_command -> exit 1, sentinel still untouched
        monkeypatch.setenv("IP_CHECK_URLS", f"{u1},{u2}")
        monkeypatch.setenv("PUBLIC_IP_TIMEOUT_SECONDS", "2")
        (tmp_path / ".env").write_text("", encoding="utf-8")
        monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: tmp_path)
        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: FakeRunner({}))
        with pytest.raises(typer.Exit) as excinfo:
            orchestrator_mod._run_command(lambda o: o.record_home_ip())
        assert excinfo.value.exit_code == 1
        assert cfg.home_ip_file.read_bytes() == sentinel

        # (b) URL 1 non-public, URL 2 public -> saves URL 2 at mode 0600
        answers["/u2"] = f"{PUBLIC_IPV4_HOST}\n".encode()
        orch.record_home_ip()
        assert cfg.home_ip_file.read_text(encoding="utf-8").strip() == PUBLIC_IPV4_HOST
        assert stat.S_IMODE(cfg.home_ip_file.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# AC-5 (INV-3, D4, D5): FIFO / symlink / directory / oversized / unreadable baseline
# ---------------------------------------------------------------------------


def test_ac5_public_ip_assessment_and_status_handle_unusable_baselines(tmp_path: Path) -> None:
    """AC-5 (INV-3, D4, D5): special/bad home-ip files never block, follow, or yield SAFE."""
    cfg = make_config(tmp_path)
    target_file = tmp_path / "real-home-ip"
    target_file.write_text(f"{PUBLIC_IPV4_HOST}\n", encoding="utf-8")

    def prepare_case(kind: str) -> None:
        p = cfg.home_ip_file
        if os.path.lexists(p):
            if p.is_dir() and not p.is_symlink():
                p.rmdir()
            else:
                p.unlink()
        if kind == "fifo":
            os.mkfifo(p)
        elif kind == "symlink_valid":
            p.symlink_to(target_file)
        elif kind == "dangling_symlink":
            p.symlink_to(tmp_path / "missing-target")
        elif kind == "directory":
            p.mkdir()
        elif kind == "empty":
            p.write_bytes(b"")
        elif kind == "oversized_padded":
            # Address FIRST so silent truncation at 256 bytes would still parse H (AC-23a).
            raw = PUBLIC_IPV4_HOST.encode("ascii")
            p.write_bytes(raw + (b" " * (300 - len(raw))))
            assert p.stat().st_size == 300
        elif kind == "non_utf8":
            p.write_bytes(b"\xff\xfe\x00\x80")
        elif kind == "mode_0000":
            p.write_text(f"{PUBLIC_IPV4_HOST}\n", encoding="utf-8")
            p.chmod(0o000)

    try:
        for kind in (
            "fifo",
            "symlink_valid",
            "dangling_symlink",
            "directory",
            "empty",
            "oversized_padded",
            "non_utf8",
            "mode_0000",
        ):
            prepare_case(kind)
            guard = GluetunGuard(cfg, FakeRunner({}))
            t0 = time.monotonic()
            with (
                mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
                mock.patch.object(guard, "public_ip_via_control_server", return_value=None),
                mock.patch.object(guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS),
                mock.patch.object(guard, "public_ip", return_value=None),
            ):
                verdict = _run_bounded(
                    lambda g=guard: g.public_ip_assessment(force_probe=True),
                    2.0,
                    f"AC-5 public_ip_assessment({kind})",
                )
            elapsed = time.monotonic() - t0
            assert elapsed < 2.0, f"{kind} took {elapsed:.2f}s"
            assert verdict == PublicIPAssessment.UNKNOWN, kind
            assert guard.home_ip_age_seconds() is None or kind in {
                "empty",
                "oversized_padded",
                "non_utf8",
                "mode_0000",
            }
            if kind in {"fifo", "symlink_valid", "dangling_symlink", "directory"}:
                assert guard.home_ip_age_seconds() is None
    finally:
        if (
            os.path.lexists(cfg.home_ip_file)
            and not cfg.home_ip_file.is_dir()
            and not cfg.home_ip_file.is_symlink()
        ):
            cfg.home_ip_file.chmod(0o600)

    # show_status() reports unusable for FIFO, symlink, and non-public baseline
    for status_kind in ("fifo", "symlink_valid", "non_public"):
        p = cfg.home_ip_file
        if os.path.lexists(p):
            p.unlink()
        if status_kind == "fifo":
            os.mkfifo(p)
        elif status_kind == "symlink_valid":
            p.symlink_to(target_file)
        else:
            p.write_text("10.0.0.1\n", encoding="utf-8")
        runner = FakeRunner(
            {
                ("docker", "compose", "version"): completed([]),
                ("docker", "ps", "--format", "{{.ID}}"): completed([]),
                ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
            }
        )
        guard = GluetunGuard(cfg, runner)
        orch = Orchestrator(guard)
        messages: list[str] = []
        sink_id = logger.add(lambda m, buf=messages: buf.append(str(m)), level="INFO")
        try:
            t0 = time.monotonic()
            _run_bounded(orch.show_status, 2.0, f"AC-5 show_status({status_kind})")
            assert time.monotonic() - t0 < 2.0
        finally:
            logger.remove(sink_id)
        joined = "\n".join(messages).lower()
        assert "unusable" in joined and "record-home-ip" in joined, (status_kind, joined)
        assert "days old" not in joined


# ---------------------------------------------------------------------------
# AC-6 (D5): record_home_ip() replaces FIFO/symlink safely, refuses directory
# ---------------------------------------------------------------------------


def test_ac6_record_home_ip_replaces_fifo_and_symlink_but_refuses_directory(
    tmp_path: Path,
) -> None:
    """AC-6 (D5): atomic rename replaces FIFO/symlink; directory fails unchanged."""
    cfg = make_config(tmp_path)
    guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(guard)
    sentinel = tmp_path / "sentinel-target"
    sentinel_bytes = b"SENTINEL_UNTOUCHED\n"
    sentinel.write_bytes(sentinel_bytes)

    with mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST):
        # FIFO at home_ip_file
        os.mkfifo(cfg.home_ip_file)
        t0 = time.monotonic()
        _run_bounded(orch.record_home_ip, 2.0, "AC-6 record_home_ip(fifo)")
        assert time.monotonic() - t0 < 2.0
        assert not cfg.home_ip_file.is_symlink()
        assert stat.S_ISREG(cfg.home_ip_file.lstat().st_mode)
        assert stat.S_IMODE(cfg.home_ip_file.stat().st_mode) == 0o600
        assert cfg.home_ip_file.read_text(encoding="utf-8").strip() == PUBLIC_IPV4_HOST

        # Symlink at home_ip_file
        cfg.home_ip_file.unlink()
        cfg.home_ip_file.symlink_to(sentinel)
        orch.record_home_ip()
        assert not cfg.home_ip_file.is_symlink()
        assert stat.S_ISREG(cfg.home_ip_file.lstat().st_mode)
        assert stat.S_IMODE(cfg.home_ip_file.stat().st_mode) == 0o600
        assert cfg.home_ip_file.read_text(encoding="utf-8").strip() == PUBLIC_IPV4_HOST
        assert sentinel.read_bytes() == sentinel_bytes

        # Directory containing a sentinel file
        cfg.home_ip_file.unlink()
        cfg.home_ip_file.mkdir()
        inner_sentinel = cfg.home_ip_file / "keep"
        inner_sentinel.write_bytes(sentinel_bytes)
        with pytest.raises(OSError):
            orch.record_home_ip()
        assert cfg.home_ip_file.is_dir()
        assert inner_sentinel.read_bytes() == sentinel_bytes


# ---------------------------------------------------------------------------
# AC-7 (INV-4, D6): resolve_nordvpn_endpoint() cache bounds & special files
# ---------------------------------------------------------------------------


def test_ac7_resolver_cache_age_bounds_and_invalid_forms(tmp_path: Path) -> None:
    """AC-7 (INV-4, D6): 2h stale cache ok on URLError; >24h/future/NaN/Inf/bad -> None."""
    cache_path = tmp_path / ".stremio" / "cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()

    def write_cache(payload: object) -> None:
        if os.path.lexists(cache_path):
            cache_path.unlink()
        if isinstance(payload, bytes):
            cache_path.write_bytes(payload)
        elif isinstance(payload, str):
            cache_path.write_text(payload, encoding="utf-8")
        else:
            cache_path.write_text(json.dumps(payload), encoding="utf-8")

    def base_obj(ts: object) -> dict[str, object]:
        return {
            "country": "United States",
            "city": "Denver",
            "hostname": "us1.nordvpn.com",
            "ip": PUBLIC_IPV4_STATION,
            "timestamp": ts,
        }

    with mock.patch.object(
        resolver_mod, "open_with_deadline", side_effect=urllib.error.URLError("offline")
    ):
        # 2 hours old -> returned
        write_cache(base_obj(now - 2 * 3600))
        assert resolver_mod.resolve_nordvpn_endpoint(
            country="United States", city="Denver", cache_path=cache_path
        ) == ("us1.nordvpn.com", PUBLIC_IPV4_STATION)

        # 25 hours old -> None
        write_cache(base_obj(now - 25 * 3600))
        assert (
            resolver_mod.resolve_nordvpn_endpoint(
                country="United States", city="Denver", cache_path=cache_path
            )
            is None
        )

        # 1 hour in future -> None
        write_cache(base_obj(now + 3600))
        assert (
            resolver_mod.resolve_nordvpn_endpoint(
                country="United States", city="Denver", cache_path=cache_path
            )
            is None
        )

        # NaN, Infinity, string, missing timestamp -> None
        for raw in (
            json.dumps(base_obj(0)).replace(": 0}", ": NaN}"),
            json.dumps(base_obj(0)).replace(": 0}", ": Infinity}"),
            base_obj("12345"),
            {
                "country": "United States",
                "city": "Denver",
                "hostname": "us1.nordvpn.com",
                "ip": PUBLIC_IPV4_STATION,
            },
        ):
            write_cache(raw)
            assert (
                resolver_mod.resolve_nordvpn_endpoint(
                    country="United States", city="Denver", cache_path=cache_path
                )
                is None
            )

        def _resolve() -> tuple[str, str] | None:
            return resolver_mod.resolve_nordvpn_endpoint(
                country="United States", city="Denver", cache_path=cache_path
            )

        # JSON list, non-UTF-8, oversized 100 KB padded -> None
        write_cache([base_obj(now - 2 * 3600)])
        assert _resolve() is None

        write_cache(b"\xff\xfe\x00")
        assert _resolve() is None

        padded = json.dumps(base_obj(now - 2 * 3600)) + (" " * 100_000)
        write_cache(padded)
        assert _resolve() is None

        # FIFO -> None within 2s
        cache_path.unlink()
        os.mkfifo(cache_path)
        t0 = time.monotonic()
        assert _run_bounded(_resolve, 2.0, "AC-7 resolve_nordvpn_endpoint(fifo)") is None
        assert time.monotonic() - t0 < 2.0

        # Symlink to valid 2h cache -> None
        real_cache = tmp_path / "real-cache.json"
        real_cache.write_text(json.dumps(base_obj(now - 2 * 3600)), encoding="utf-8")
        cache_path.unlink()
        cache_path.symlink_to(real_cache)
        assert _resolve() is None

    # Without force_refresh: 30m cache returned without live query; 1h future triggers live query
    cache_path.unlink()
    live_payload = [
        {
            "hostname": "us-live.nordvpn.com",
            "station": PUBLIC_IPV4_ALT,
            "status": "online",
            "load": 5,
            "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
        }
    ]
    live_bytes = json.dumps(live_payload).encode("utf-8")

    write_cache(base_obj(now - 1800))
    with mock.patch.object(
        resolver_mod, "open_with_deadline", return_value=(200, live_bytes)
    ) as m_open:
        assert resolver_mod.resolve_nordvpn_endpoint(
            country="United States", city="Denver", cache_path=cache_path
        ) == ("us1.nordvpn.com", PUBLIC_IPV4_STATION)
        m_open.assert_not_called()

    write_cache(base_obj(now + 3600))
    with mock.patch.object(
        resolver_mod, "open_with_deadline", return_value=(200, live_bytes)
    ) as m_open:
        assert resolver_mod.resolve_nordvpn_endpoint(
            country="United States", city="Denver", cache_path=cache_path
        ) == ("us-live.nordvpn.com", PUBLIC_IPV4_ALT)
        m_open.assert_called_once()


# ---------------------------------------------------------------------------
# AC-8 (D7): real _fetch_nordvpn_recommendations against stub server
# ---------------------------------------------------------------------------


def test_ac8_resolver_rejects_bad_api_bodies_caps_read_and_caches_valid_0600(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-8 (D7): bad/oversized API bodies fall back to 2h cache; valid writes 0600."""
    cache_path = tmp_path / ".stremio" / "cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cached_endpoint = ("us-cached.nordvpn.com", PUBLIC_IPV4_STATION)
    cache_payload = {
        "country": "United States",
        "city": "Denver",
        "hostname": cached_endpoint[0],
        "ip": cached_endpoint[1],
        "timestamp": time.time() - 2 * 3600,
    }
    cache_path.write_text(json.dumps(cache_payload), encoding="utf-8")

    mode = {"kind": "bytes", "body": b""}
    bytes_sent = {"total": 0}

    class _ApiHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if mode["kind"] == "endless":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                chunk = b"[" + (b" " * 65535)
                bytes_sent["total"] = 0
                try:
                    # Exceed 4 MiB + 1 byte, then continue streaming slowly until closed.
                    for _ in range(70):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        bytes_sent["total"] += len(chunk)
                    while True:
                        time.sleep(0.05)
                        self.wfile.write(b" " * 4096)
                        self.wfile.flush()
                        bytes_sent["total"] += 4096
                except OSError:
                    return
            payload = mode["body"]
            assert isinstance(payload, bytes)
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    def server_list(station: object) -> bytes:
        return json.dumps(
            [
                {
                    "hostname": "us-bad.nordvpn.com",
                    "station": station,
                    "status": "online",
                    "load": 10,
                    "locations": [
                        {"country": {"name": "United States", "city": {"name": "Denver"}}}
                    ],
                }
            ]
        ).encode("utf-8")

    with _stub_http_server(lambda: _ApiHandler) as base_url:
        monkeypatch.setattr(resolver_mod, "RECOMMENDATIONS_API_URL", f"{base_url}recs")

        bad_bodies: list[bytes] = [
            b"\xff\xfe\xfd",
            b"{not valid json",
            b'{"object": true}',
            b'[1, "two", null]',
            server_list("10.0.0.9"),
            server_list("::ffff:10.0.0.9"),
            server_list(f" {PUBLIC_IPV4_HOST} "),
            server_list(f"{PUBLIC_IPV6_HOST}%eth0"),
            server_list(12345),
        ]
        for bad in bad_bodies:
            mode["kind"] = "bytes"
            mode["body"] = bad
            res = resolver_mod.resolve_nordvpn_endpoint(
                country="United States",
                city="Denver",
                cache_path=cache_path,
                force_refresh=True,
            )
            assert res == cached_endpoint

        # Endless body > 4 MiB + 1 byte returns promptly (< 9s) and falls back to 2h cache
        mode["kind"] = "endless"
        t0 = time.monotonic()
        res_endless = _run_bounded(
            lambda: resolver_mod.resolve_nordvpn_endpoint(
                country="United States",
                city="Denver",
                cache_path=cache_path,
                force_refresh=True,
            ),
            9.0,
            "AC-8 resolve_nordvpn_endpoint(endless)",
        )
        elapsed = time.monotonic() - t0
        assert res_endless == cached_endpoint
        assert elapsed < 9.0
        # Client stopped reading right at 4 MiB + 1 byte (allowing socket buffers).
        assert bytes_sent["total"] <= resolver_mod.MAX_RECOMMENDATIONS_BYTES + 1024 * 1024

        # Valid list with one public station writes 0600 cache
        cache_path.unlink()
        mode["kind"] = "bytes"
        mode["body"] = json.dumps(
            [
                {
                    "hostname": "us-good.nordvpn.com",
                    "station": PUBLIC_IPV4_EGRESS,
                    "status": "online",
                    "load": 7,
                    "locations": [
                        {"country": {"name": "United States", "city": {"name": "Denver"}}}
                    ],
                }
            ]
        ).encode("utf-8")
        res_good = resolver_mod.resolve_nordvpn_endpoint(
            country="United States",
            city="Denver",
            cache_path=cache_path,
            force_refresh=True,
        )
        assert res_good == ("us-good.nordvpn.com", PUBLIC_IPV4_EGRESS)
        assert stat.S_IMODE(cache_path.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# AC-9 (Wiring): guard restarts & RunContext.env() with stale vs fresh cache
# ---------------------------------------------------------------------------


def test_ac9_wiring_guard_restarts_and_run_context_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-9: expired cache -> compose restart; 2h cache -> recreate; RunContext.env() clean."""
    (tmp_path / ".env").write_text(
        "VPN_SERVICE_PROVIDER=nordvpn\nSERVER_COUNTRIES=United States\nSERVER_CITIES=Denver\n",
        encoding="utf-8",
    )
    cache_path = tmp_path / ".stremio" / "nordvpn-endpoint-cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = compose_args_prefix(tmp_path)
    restart_cmd = [*prefix, "restart", "gluetun"]
    up_cmd = [*prefix, "up", "-d", "--no-deps", "--force-recreate", "gluetun"]

    with mock.patch.object(
        resolver_mod, "open_with_deadline", side_effect=urllib.error.URLError("down")
    ):
        # (a) 25-hour-old cache -> compose restart gluetun, no force-recreate
        cache_path.write_text(
            json.dumps(
                {
                    "country": "United States",
                    "city": "Denver",
                    "hostname": "us-old.nordvpn.com",
                    "ip": PUBLIC_IPV4_STATION,
                    "timestamp": time.time() - 25 * 3600,
                }
            ),
            encoding="utf-8",
        )
        runner_a = FakeRunner({tuple(restart_cmd): completed(restart_cmd)})
        guard_a = GluetunGuard(make_config(tmp_path), runner_a)
        assert guard_a.restart_gluetun() is True
        assert restart_cmd in runner_a.calls
        assert up_cmd not in runner_a.calls

        # (b) 2-hour-old cache -> up --force-recreate with cached station
        cache_path.write_text(
            json.dumps(
                {
                    "country": "United States",
                    "city": "Denver",
                    "hostname": "us-2h.nordvpn.com",
                    "ip": PUBLIC_IPV4_STATION,
                    "timestamp": time.time() - 2 * 3600,
                }
            ),
            encoding="utf-8",
        )
        runner_b = FakeRunner({tuple(up_cmd): completed(up_cmd)})
        guard_b = GluetunGuard(make_config(tmp_path), runner_b)
        assert guard_b.restart_gluetun() is True
        assert up_cmd in runner_b.calls
        env_b = runner_b.envs[runner_b.calls.index(up_cmd)]
        assert env_b is not None
        assert env_b["OPENVPN_ENDPOINT_IP"] == PUBLIC_IPV4_STATION
        assert env_b["WIREGUARD_ENDPOINT_IP"] == PUBLIC_IPV4_STATION

        # (c) restart_gluetun_relaxed -> both empty
        runner_c = FakeRunner({tuple(up_cmd): completed(up_cmd)})
        guard_c = GluetunGuard(make_config(tmp_path), runner_c)
        assert guard_c.restart_gluetun_relaxed() is True
        env_c = runner_c.envs[runner_c.calls.index(up_cmd)]
        assert env_c is not None
        assert env_c["OPENVPN_ENDPOINT_IP"] == ""
        assert env_c["WIREGUARD_ENDPOINT_IP"] == ""

        # (d) RunContext.env() with 25-hour-old cache -> neither key in env
        cache_path.write_text(
            json.dumps(
                {
                    "country": "United States",
                    "city": "Denver",
                    "hostname": "us-old.nordvpn.com",
                    "ip": PUBLIC_IPV4_STATION,
                    "timestamp": time.time() - 25 * 3600,
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.delenv("OPENVPN_ENDPOINT_IP", raising=False)
        monkeypatch.delenv("WIREGUARD_ENDPOINT_IP", raising=False)
        monkeypatch.setattr(cli_context, "ENV_FILE", tmp_path / ".env")
        monkeypatch.setattr(cli_context, "STATE_DIR", tmp_path / ".stremio")
        ctx = cli_context.RunContext.create()
        ctx_env = ctx.env()
        assert "OPENVPN_ENDPOINT_IP" not in ctx_env
        assert "WIREGUARD_ENDPOINT_IP" not in ctx_env


# ---------------------------------------------------------------------------
# AC-10 (INV-5, D8, D9): tracebacks hide locals across every sink and Typer app
# ---------------------------------------------------------------------------


def _run_py_script(
    script_path: Path,
    code: str,
    *,
    env_overrides: dict[str, str | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    script_path.write_text(code, encoding="utf-8")
    env = os.environ.copy()
    if env_overrides:
        for k, v in env_overrides.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
    return subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=15,
    )


def test_ac10_tracebacks_never_render_frame_locals_and_static_ast_check(tmp_path: Path) -> None:
    """AC-10 / AC-21 (INV-5, D8, D9): file-based subprocess proofs + positive controls + AST."""
    canary = "CANARY_FRAME_SECRET_0014_DO_NOT_LEAK"

    assert cli_mod.APP.pretty_exceptions_show_locals is False
    assert orchestrator_mod.app.pretty_exceptions_show_locals is False

    # (a) Orchestrator._tick() with STREMIO_BACKGROUND unset, real file sink & stdout sink
    log_file = tmp_path / "logs" / "run.log"
    pos_log_a = tmp_path / "pos_a.log"
    code_a = f"""
import os
from pathlib import Path
from loguru import logger
from stremioguard.config import Config
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import Orchestrator, configure_file_logging

root = Path({str(tmp_path)!r})
(root / ".stremio").mkdir(parents=True, exist_ok=True)
cfg = Config(
    root_dir=root,
    gluetun_healthy_timeout_seconds=1,
    watch_interval_seconds=1,
    watchdog_log_interval_seconds=300,
    public_ip_timeout_seconds=1,
    home_ip_file=root / ".stremio" / "home-ip",
    expected_vpn_ip=None,
    ip_check_urls=("https://example.test/ip",),
    install_missing=False,
    run_id="ac10a",
    log_file=Path({str(log_file)!r}),
    log_session=False,
    stremio_enabled=True,
    egress_probe_interval_seconds=300,
    public_ip_failure_threshold=3,
    vpn_recovery_budget_seconds=300,
    vpn_restart_cadence_seconds=45,
    vpn_lockout_file=root / ".stremio" / "vpn-lockout",
    server_countries=None,
    server_regions=None,
    server_cities=None,
    server_hostnames=None,
    server_categories=None,
)
configure_file_logging(cfg)
pos_path = os.environ.get("POS_LOG")
if pos_path:
    logger.add(pos_path, diagnose=True)

class BoomRunner:
    def run(self, *args, **kwargs):
        secret = os.environ["CANARY"]
        raise RuntimeError(f"boom {{len(secret)}}")

guard = GluetunGuard(cfg, BoomRunner())
orch = Orchestrator(guard)
assert orch._tick() is False
logger.complete()
"""
    script_a = tmp_path / "sub_a.py"
    res_a = _run_py_script(
        script_a,
        code_a,
        env_overrides={"STREMIO_BACKGROUND": None, "POS_LOG": None, "CANARY": canary},
    )
    assert res_a.returncode == 0, res_a.stderr
    file_text = log_file.read_text(encoding="utf-8")
    for output in (file_text, res_a.stdout):
        assert "Watchdog loop iteration encountered an error" in output
        assert "RuntimeError" in output
        assert canary not in output

    # Positive control for (a): same script with diagnose=True sink DOES show canary
    res_a_pos = _run_py_script(
        script_a,
        code_a,
        env_overrides={
            "STREMIO_BACKGROUND": None,
            "POS_LOG": str(pos_log_a),
            "CANARY": canary,
        },
    )
    assert res_a_pos.returncode == 0, res_a_pos.stderr
    assert canary in pos_log_a.read_text(encoding="utf-8")

    # (b) Importing only stremioguard.cli + positive control
    pos_log_b = tmp_path / "pos_b.log"
    code_b = """
import os
from loguru import logger
import stremioguard.cli
pos_path = os.environ.get("POS_LOG")
if pos_path:
    logger.add(pos_path, diagnose=True)
def inner():
    secret = os.environ["CANARY"]
    raise RuntimeError(f"boom {len(secret)}")
try:
    inner()
except RuntimeError:
    logger.exception("cli failed")
"""
    script_b = tmp_path / "sub_b.py"
    res_b = _run_py_script(script_b, code_b, env_overrides={"POS_LOG": None, "CANARY": canary})
    assert res_b.returncode == 0, res_b.stderr
    combined_b = res_b.stdout + res_b.stderr
    assert "RuntimeError" in combined_b and "Traceback" in combined_b
    assert canary not in combined_b

    res_b_pos = _run_py_script(
        script_b, code_b, env_overrides={"POS_LOG": str(pos_log_b), "CANARY": canary}
    )
    assert res_b_pos.returncode == 0, res_b_pos.stderr
    assert canary in pos_log_b.read_text(encoding="utf-8")

    # (c) Importing only stremioguard.resolver (package-level handler) + positive control
    pos_log_c = tmp_path / "pos_c.log"
    code_c = """
import os
from loguru import logger
import stremioguard.resolver
pos_path = os.environ.get("POS_LOG")
if pos_path:
    logger.add(pos_path, diagnose=True)
def inner():
    secret = os.environ["CANARY"]
    raise RuntimeError(f"boom {len(secret)}")
try:
    inner()
except RuntimeError:
    logger.exception("resolver failed")
"""
    script_c = tmp_path / "sub_c.py"
    res_c = _run_py_script(script_c, code_c, env_overrides={"POS_LOG": None, "CANARY": canary})
    assert res_c.returncode == 0, res_c.stderr
    combined_c = res_c.stdout + res_c.stderr
    assert "RuntimeError" in combined_c and "Traceback" in combined_c
    assert canary not in combined_c

    res_c_pos = _run_py_script(
        script_c, code_c, env_overrides={"POS_LOG": str(pos_log_c), "CANARY": canary}
    )
    assert res_c_pos.returncode == 0, res_c_pos.stderr
    assert canary in pos_log_c.read_text(encoding="utf-8")

    # (d) Unhandled exception on real CLI APP and real orchestrator app + positive control
    for idx, mod_attr in enumerate(("stremioguard.cli:APP", "stremioguard.orchestrator:app")):
        mod_name, attr_name = mod_attr.split(":")
        code_d = f"""
import os
import sys
import {mod_name} as m
typer_app = getattr(m, {attr_name!r})
@typer_app.command("canary-boom")
def _canary_boom():
    secret = os.environ["CANARY"]
    raise RuntimeError(f"boom {{len(secret)}}")
sys.argv = ["prog", "canary-boom"]
typer_app()
"""
        res_d = _run_py_script(
            tmp_path / f"sub_d_{idx}.py", code_d, env_overrides={"CANARY": canary}
        )
        assert res_d.returncode != 0
        assert "RuntimeError" in res_d.stderr
        assert canary not in res_d.stderr

    # Positive control for (d): fresh Typer(pretty_exceptions_show_locals=True) DOES show canary
    code_d_pos = """
import os
import sys
import typer
pos_app = typer.Typer(pretty_exceptions_show_locals=True)
@pos_app.command("canary-boom")
def _canary_boom():
    secret = os.environ["CANARY"]
    raise RuntimeError(f"boom {len(secret)}")
@pos_app.command("noop")
def _noop():
    pass
sys.argv = ["prog", "canary-boom"]
pos_app()
"""
    res_d_pos = _run_py_script(
        tmp_path / "sub_d_pos.py", code_d_pos, env_overrides={"CANARY": canary}
    )
    assert res_d_pos.returncode != 0
    assert canary in res_d_pos.stderr

    # (e) Static AST check: every logger.add(...) in src/ passes diagnose=False
    found: list[tuple[Path, int]] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"
            ):
                found.append((py_file.relative_to(REPO_ROOT), node.lineno))
                diagnose_kw = [kw for kw in node.keywords if kw.arg == "diagnose"]
                assert len(diagnose_kw) == 1, f"{py_file}:{node.lineno} missing diagnose=False"
                assert (
                    isinstance(diagnose_kw[0].value, ast.Constant)
                    and diagnose_kw[0].value.value is False
                ), f"{py_file}:{node.lineno} diagnose is not False"
    assert len(found) == 4, f"Expected 4 logger.add calls in src/, found {found}"


# ---------------------------------------------------------------------------
# AC-11 (INV-6, D10-D14): private modes from creation under umask 0002 & 0022
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("umask_value", [0o002, 0o022])
def test_ac11_modes_from_creation_without_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, umask_value: int
) -> None:
    """AC-11 (INV-6, D10-D14): every directory is 0700 and every file is 0600 from creation."""
    chmod_calls: list[tuple[str, object, int]] = []
    monkeypatch.setattr(os, "chmod", lambda p, m: chmod_calls.append(("os.chmod", p, m)))
    monkeypatch.setattr(os, "fchmod", lambda fd, m: chmod_calls.append(("os.fchmod", fd, m)))
    monkeypatch.setattr(Path, "chmod", lambda self, m: chmod_calls.append(("Path.chmod", self, m)))

    old_umask = os.umask(umask_value)
    try:
        # 1. stack_lock(root)
        r1 = tmp_path / "r1"
        r1.mkdir()
        with stack_lock(r1) as held:
            assert held is True
        assert stat.S_IMODE((r1 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE((r1 / ".stremio" / "stack.lock").stat().st_mode) == 0o600

        # 2. atomic_write_text(root/.stremio/a/b/f)
        r2 = tmp_path / "r2"
        r2.mkdir()
        f2 = r2 / ".stremio" / "a" / "b" / "f"
        env_mod.atomic_write_text(f2, "hello\n")
        for d in (r2 / ".stremio", r2 / ".stremio" / "a", r2 / ".stremio" / "a" / "b"):
            assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE(f2.stat().st_mode) == 0o600

        # 3. ensure_directory(root/.stremio/comet)
        r3 = tmp_path / "r3"
        r3.mkdir()
        env_mod.ensure_directory(r3 / ".stremio" / "comet")
        assert stat.S_IMODE((r3 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE((r3 / ".stremio" / "comet").stat().st_mode) == 0o700

        # 4. resolver cache write
        r4 = tmp_path / "r4"
        r4.mkdir()
        cache4 = r4 / ".stremio" / "nordvpn-endpoint-cache.json"
        live = [
            {
                "hostname": "us1.nordvpn.com",
                "station": PUBLIC_IPV4_STATION,
                "status": "online",
                "load": 10,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            }
        ]
        with mock.patch.object(resolver_mod, "_fetch_nordvpn_recommendations", return_value=live):
            resolver_mod.resolve_nordvpn_endpoint(
                country="United States", city="Denver", cache_path=cache4
            )
        assert stat.S_IMODE((r4 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE(cache4.stat().st_mode) == 0o600

        # 5. require_matching_daemon first daemon-id
        r5 = tmp_path / "r5"
        r5.mkdir()
        daemon_rec = r5 / ".stremio" / "daemon-id"
        daemon_runner = FakeRunner(
            {("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-xyz\n")}
        )
        preflight_mod.require_matching_daemon(daemon_runner, daemon_rec, warn=lambda _: None)
        assert stat.S_IMODE((r5 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE(daemon_rec.stat().st_mode) == 0o600

        # 6. _acquire_instance_lock()
        r6 = tmp_path / "r6"
        r6.mkdir()
        cfg6 = make_config(r6)
        # Remove pre-created .stremio from make_config so we test fresh directory creation too
        (r6 / ".stremio" / "docker-compose.bindings.yml").unlink()
        (r6 / ".stremio").rmdir()
        orch6 = Orchestrator(GluetunGuard(cfg6, FakeRunner({})))
        lock_file6 = orch6._acquire_instance_lock()
        try:
            assert stat.S_IMODE((r6 / ".stremio").stat().st_mode) == 0o700
            inst_lock = r6 / ".stremio" / "watchdog.instance.lock"
            assert stat.S_IMODE(inst_lock.stat().st_mode) == 0o600
        finally:
            lock_file6.close()

        # 7. gateway's _token_lock()
        r7 = tmp_path / "r7"
        r7.mkdir()
        gw_cfg = make_comet_gateway_config(r7)
        (r7 / ".stremio" / "comet-gateway").rmdir()
        (r7 / ".stremio").rmdir()
        gw_mgr = comet_gateway_mod.CometGatewayManager(gw_cfg)
        with gw_mgr._token_lock():
            pass
        assert stat.S_IMODE((r7 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE((r7 / ".stremio" / "comet-gateway").stat().st_mode) == 0o700
        assert stat.S_IMODE(gw_cfg.tokens_file.with_suffix(".lock").stat().st_mode) == 0o600

        # 8. ensure_gluetun_auth_config()
        r8 = tmp_path / "r8"
        r8.mkdir()
        auth8 = publishing_mod.ensure_gluetun_auth_config(r8)
        assert stat.S_IMODE((r8 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE(auth8.stat().st_mode) == 0o600

        # 9. StackPublisher override write (Comet disabled)
        r9 = tmp_path / "r9"
        r9.mkdir()
        (r9 / ".env").write_text(
            "STREMIO_BIND_ADDRS=127.0.0.1\nCOMET_ENABLED=0\n", encoding="utf-8"
        )
        (r9 / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
        pub9 = publishing_mod.StackPublisher(r9)
        pub9.publish()
        assert stat.S_IMODE((r9 / ".stremio").stat().st_mode) == 0o700
        assert stat.S_IMODE(pub9.compose_override_file.stat().st_mode) == 0o600

        # 10. configure_file_logging() with lowered RUN_LOG_ROTATION rotating >= 2 times
        r10 = tmp_path / "r10"
        r10.mkdir()
        log_path10 = r10 / "logs" / "stremio.log"
        cfg10 = make_config(r10, log_file=log_path10)
        monkeypatch.setattr(orchestrator_mod, "RUN_LOG_ROTATION", 200)
        orchestrator_mod.configure_file_logging(cfg10)
        for i in range(12):
            logger.info(f"rotation test line {i:02d} padding payload xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        logger.complete()
        log_files = sorted((r10 / "logs").iterdir())
        assert len(log_files) >= 3, f"Expected >=3 files (active + 2 rotated), got {log_files}"
        assert stat.S_IMODE((r10 / "logs").stat().st_mode) == 0o700
        for lf in log_files:
            assert stat.S_IMODE(lf.stat().st_mode) == 0o600, lf

        # 11. write_env_settings() on a new .env
        r11 = tmp_path / "r11"
        r11.mkdir()
        env11 = r11 / ".env"
        env11.write_text("", encoding="utf-8")
        env_mod.write_env_settings(env11, {"STREMIO_HOST_PORT": "11470"})
        assert stat.S_IMODE(env11.stat().st_mode) == 0o600
    finally:
        os.umask(old_umask)
        logger.remove()


# ---------------------------------------------------------------------------
# AC-12 (INV-7, D10): ensure_directory refuses symlinks & non-dirs safely
# ---------------------------------------------------------------------------


def test_ac12_ensure_directory_refuses_symlinks_and_files(tmp_path: Path) -> None:
    """AC-12 (INV-7, D10): refuses symlinks and files before creating anything; fixes 0755 dir."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    elsewhere.chmod(0o755)
    sentinel = elsewhere / "sentinel"
    sentinel.write_bytes(b"KEEP_ME")

    # (a) .stremio symlink to elsewhere -> ensure_directory(root/.stremio/comet)
    r_a = tmp_path / "ra"
    r_a.mkdir()
    (r_a / ".stremio").symlink_to(elsewhere)
    with pytest.raises(RuntimeError, match=r"\.stremio"):
        env_mod.ensure_directory(r_a / ".stremio" / "comet")
    assert not (elsewhere / "comet").exists()
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755
    assert sentinel.read_bytes() == b"KEEP_ME"

    # (b) ensure_directory(root/.stremio) with that symlink
    with pytest.raises(RuntimeError, match=r"\.stremio"):
        env_mod.ensure_directory(r_a / ".stremio")
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755
    assert sentinel.read_bytes() == b"KEEP_ME"

    # (c) logs a dangling symlink
    r_c = tmp_path / "rc"
    r_c.mkdir()
    (r_c / "logs").symlink_to(tmp_path / "nonexistent")
    with pytest.raises(RuntimeError, match="logs"):
        env_mod.ensure_directory(r_c / "logs")

    # (d) regular file at leaf
    r_d = tmp_path / "rd"
    r_d.mkdir()
    (r_d / "leaf").write_text("file", encoding="utf-8")
    with pytest.raises(RuntimeError, match="leaf"):
        env_mod.ensure_directory(r_d / "leaf")

    # (e) stack_lock(root) with .stremio a symlink
    with pytest.raises(RuntimeError, match=r"\.stremio"), stack_lock(r_a):
        pass
    assert not (elsewhere / "stack.lock").exists()
    assert not (r_a / ".stremio" / "stack.lock").exists()

    # (f) real .stremio at 0755 -> becomes 0700
    r_f = tmp_path / "rf"
    r_f.mkdir()
    (r_f / ".stremio").mkdir(mode=0o755)
    (r_f / ".stremio").chmod(0o755)
    env_mod.ensure_directory(r_f / ".stremio")
    assert stat.S_IMODE((r_f / ".stremio").stat().st_mode) == 0o700


# ---------------------------------------------------------------------------
# AC-13 (INV-8, D15): teardown tolerates failing helpers; start refuses early
# ---------------------------------------------------------------------------


def test_ac13_teardown_tolerates_logging_and_lock_failures_while_start_refuses_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-13 (INV-8, D15): teardown tolerates log/lock failures; start refuses early."""

    def reset_root(
        *,
        symlink_logs: bool = False,
        dir_as_log: bool = False,
        symlink_state: bool = False,
    ) -> Path:
        root = tmp_path / f"case_{symlink_logs}_{dir_as_log}_{symlink_state}"
        if root.exists():
            return root
        root.mkdir()
        (root / ".env").write_text("STREMIO_ENABLED=1\n", encoding="utf-8")
        if symlink_state:
            target = tmp_path / f"target_{root.name}"
            target.mkdir(exist_ok=True)
            (target / "docker-compose.bindings.yml").touch()
            (target / "daemon-id").write_text("daemon-a\n", encoding="utf-8")
            (root / ".stremio").symlink_to(target)
        else:
            (root / ".stremio").mkdir()
            (root / ".stremio" / "docker-compose.bindings.yml").touch()
            (root / ".stremio" / "daemon-id").write_text("daemon-a\n", encoding="utf-8")
        if symlink_logs:
            lt = tmp_path / f"log_target_{root.name}"
            lt.mkdir(exist_ok=True)
            (root / "logs").symlink_to(lt)
        elif dir_as_log:
            (root / "logs").mkdir()
            (root / "logs" / "bad.log").mkdir()
        return root

    monkeypatch.setattr(
        orchestrator_mod.Config,
        "from_env",
        staticmethod(lambda r, env_file=None: make_config(r, log_file=r / "logs" / "bad.log")),
    )

    for case in ("symlink_logs", "dir_as_log", "symlink_state"):
        root = reset_root(
            symlink_logs=(case == "symlink_logs"),
            dir_as_log=(case == "dir_as_log"),
            symlink_state=(case == "symlink_state"),
        )
        prefix_c = compose_args_prefix(root)
        stop_c = [*prefix_c, "stop", "stremio"]

        def build_runner(p: list[str] = prefix_c, s: list[str] = stop_c) -> FakeRunner:
            return FakeRunner(
                {
                    ("docker", "compose", "version"): completed([]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed([]),
                    ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
                    (*p, "config", "--services"): completed([], "stremio\n"),
                    (*p, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                        completed([], "stremio\n"),
                        completed([], ""),
                    ],
                    tuple(s): completed(s),
                }
            )

        monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda r=root: r)

        # (1) stop (teardown=True, lock="preferred") -> attempts compose stop, warns, exits 0
        runner_stop = build_runner()
        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda r=runner_stop: r)
        warnings: list[str] = []
        sink_id = logger.add(lambda m, buf=warnings: buf.append(str(m)), level="WARNING")
        try:

            def _stop(o: Orchestrator) -> None:
                o.guard.require_commands()
                if not o.guard.stop_active_services():
                    raise RuntimeError("not stopped")

            orchestrator_mod._run_command(_stop, teardown=True, lock="preferred")
        finally:
            logger.remove(sink_id)
        assert stop_c in runner_stop.calls
        assert warnings, f"Expected warning for {case}"

        # (2) fail-safe (teardown=True, deployed=True, lock="preferred") -> attempts compose stop
        runner_fs = build_runner()
        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda r=runner_fs: r)
        warnings_fs: list[str] = []
        sink_id = logger.add(lambda m, buf=warnings_fs: buf.append(str(m)), level="WARNING")
        try:
            orchestrator_mod._run_command(
                lambda o: o.fail_safe(), teardown=True, deployed=True, lock="preferred"
            )
        finally:
            logger.remove(sink_id)
        assert stop_c in runner_fs.calls
        assert warnings_fs, f"Expected warning for fail-safe {case}"

    # Also verify stop failure -> exit 1 (0007 rule) when stack_lock raises RuntimeError
    root_fail = reset_root(symlink_state=True)
    prefix_f = compose_args_prefix(root_fail)
    stop_f = [*prefix_f, "stop", "stremio"]
    runner_fail = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
            (*prefix_f, "config", "--services"): completed([], "stremio\n"),
            (*prefix_f, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): completed(
                [], "stremio\n"
            ),
            tuple(stop_f): completed(stop_f, returncode=1),
        }
    )
    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: root_fail)
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_fail)
    with pytest.raises(typer.Exit) as excinfo:
        orchestrator_mod._run_command(
            lambda o: o.fail_safe(), teardown=True, deployed=True, lock="preferred"
        )
    assert excinfo.value.exit_code == 1
    assert stop_f in runner_fail.calls

    # start (lock="required") with .stremio a symlink -> exit 1 naming path, no docker compose calls
    bad_root = reset_root(symlink_state=True)
    runner_start = FakeRunner({})
    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: bad_root)
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_start)
    errors: list[str] = []
    sink_id = logger.add(lambda m: errors.append(str(m)), level="ERROR")
    try:
        with pytest.raises(typer.Exit) as excinfo:
            orchestrator_mod._run_command(lambda o: o.start_active_services(), lock="required")
    finally:
        logger.remove(sink_id)
    assert excinfo.value.exit_code == 1
    assert any(".stremio" in e for e in errors)
    assert runner_start.calls == []


# ---------------------------------------------------------------------------
# AC-15 default-suite (INV-10, D16): HTTP/HTTPS request heads and wget argv
# ---------------------------------------------------------------------------


def test_ac15_default_probe_request_heads_and_wget_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-15 (INV-10, D16): host HTTP/HTTPS heads match D16 order; wget uses shared headers."""
    expected_header_lines = [f"{k}: {v}".encode("ascii") for k, v in PROBE_REQUEST_HEADERS]

    # HTTP capture
    with _raw_capture_server(f"{PUBLIC_IPV4_HOST}\n".encode()) as (http_url, captured_http):
        guard = GluetunGuard(make_config(tmp_path, ip_check_urls=(http_url,)), FakeRunner({}))
        assert guard.public_ip() == PUBLIC_IPV4_HOST
        assert len(captured_http) == 1
        lines = captured_http[0].split(b"\r\n")
        assert lines[0] == b"GET / HTTP/1.1"
        assert lines[1].lower().startswith(b"host: 127.0.0.1:")
        assert lines[2:] == expected_header_lines
        assert b"stremio" not in captured_http[0].lower()

    # HTTPS capture
    cert_file, key_file = _create_localhost_cert(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_file))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    with _raw_capture_server(f"{PUBLIC_IPV4_HOST}\n".encode(), ssl_context=ctx) as (
        https_url,
        captured_https,
    ):
        guard = GluetunGuard(make_config(tmp_path, ip_check_urls=(https_url,)), FakeRunner({}))
        assert guard.public_ip() == PUBLIC_IPV4_HOST
        assert len(captured_https) == 1
        lines = captured_https[0].split(b"\r\n")
        assert lines[0] == b"GET / HTTP/1.1"
        assert lines[1].lower().startswith(b"host: localhost:")
        assert lines[2:] == expected_header_lines
        assert b"stremio" not in captured_https[0].lower()

    # In-gluetun wget argv built by public_ip_via_gluetun()
    runner = FakeRunner(
        {
            **compose_stack_responses(tmp_path),
        }
    )
    guard_exec = GluetunGuard(
        make_config(tmp_path, ip_check_urls=("https://api.ipify.org",)), runner
    )
    guard_exec.public_ip_via_gluetun()
    exec_calls = [c for c in runner.calls if c[:2] == ["docker", "exec"]]
    assert len(exec_calls) == 1
    argv = exec_calls[0]
    timeout_idx = argv.index("--timeout=1")
    qo_idx = argv.index("-qO-")
    expected_flags = [f"--header={k}: {v}" for k, v in PROBE_REQUEST_HEADERS]
    assert argv[timeout_idx + 1 : qo_idx] == expected_flags


# ---------------------------------------------------------------------------
# AC-19 (INV-4, D20): deeply nested JSON never raises out of resolver
# ---------------------------------------------------------------------------


def test_ac19_resolver_handles_deeply_nested_json_without_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-19 (INV-4, D20): RecursionError from deeply nested JSON never escapes resolver."""
    cache_path = tmp_path / ".stremio" / "cache.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cached_endpoint = ("us-cached.nordvpn.com", PUBLIC_IPV4_STATION)
    valid_cache = {
        "country": "United States",
        "city": "Denver",
        "hostname": cached_endpoint[0],
        "ip": cached_endpoint[1],
        "timestamp": time.time() - 2 * 3600,
    }
    deep_api_body = ("[" * 200_000 + "]" * 200_000).encode("ascii")
    deep_cache_body = ("[" * 30_000 + "]" * 30_000).encode("ascii")
    assert len(deep_api_body) < resolver_mod.MAX_RECOMMENDATIONS_BYTES
    assert len(deep_cache_body) < resolver_mod.CACHE_MAX_BYTES

    api_body = {"payload": deep_api_body}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = api_body["payload"]
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    with _stub_http_server(lambda: _Handler) as base_url:
        monkeypatch.setattr(resolver_mod, "RECOMMENDATIONS_API_URL", f"{base_url}recs")

        # (a) force_refresh=True, stub serves 400 KB deeply nested JSON, valid 2h cache -> 2h cache
        cache_path.write_text(json.dumps(valid_cache), encoding="utf-8")
        assert (
            resolver_mod.resolve_nordvpn_endpoint(
                country="United States",
                city="Denver",
                cache_path=cache_path,
                force_refresh=True,
            )
            == cached_endpoint
        )

        # (b) API failing and cache holding 60 KB deeply nested JSON -> None
        cache_path.write_bytes(deep_cache_body)
        with mock.patch.object(
            resolver_mod, "open_with_deadline", side_effect=urllib.error.URLError("down")
        ):
            assert (
                resolver_mod.resolve_nordvpn_endpoint(
                    country="United States",
                    city="Denver",
                    cache_path=cache_path,
                )
                is None
            )

        # (c) no force_refresh, nested cache, stub serving valid list -> API's server
        cache_path.write_bytes(deep_cache_body)
        api_body["payload"] = json.dumps(
            [
                {
                    "hostname": "us-live.nordvpn.com",
                    "station": PUBLIC_IPV4_EGRESS,
                    "status": "online",
                    "load": 5,
                    "locations": [
                        {"country": {"name": "United States", "city": {"name": "Denver"}}}
                    ],
                }
            ]
        ).encode("utf-8")
        assert resolver_mod.resolve_nordvpn_endpoint(
            country="United States",
            city="Denver",
            cache_path=cache_path,
        ) == ("us-live.nordvpn.com", PUBLIC_IPV4_EGRESS)


# ---------------------------------------------------------------------------
# AC-20 (INV-8, D19): stop always attempts stop even if require_commands fails
# ---------------------------------------------------------------------------


def test_ac20_stop_always_attempts_stop_even_when_require_commands_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-20 (INV-8, D19): symlinked .stremio or daemon mismatch runs compose stop, then exits 1."""
    # (a) .stremio is a symlink to a real directory and no daemon-id
    root_a = tmp_path / "root_a"
    root_a.mkdir()
    target_a = tmp_path / "target_a"
    target_a.mkdir()
    (target_a / "docker-compose.bindings.yml").touch()
    (root_a / ".stremio").symlink_to(target_a)
    (root_a / ".env").write_text("STREMIO_ENABLED=1\n", encoding="utf-8")

    prefix_a = compose_args_prefix(root_a)
    stop_a = [*prefix_a, "stop", "stremio"]
    runner_a = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
            (*prefix_a, "config", "--services"): completed([], "stremio\n"),
            (*prefix_a, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                completed([], "stremio\n"),
                completed([], ""),
            ],
            tuple(stop_a): completed(stop_a),
        }
    )
    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: root_a)
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_a)
    monkeypatch.setattr(
        orchestrator_mod.Config,
        "from_env",
        staticmethod(lambda r, env_file=None: make_config(r)),
    )
    errors_a: list[str] = []
    sink_a = logger.add(lambda m, buf=errors_a: buf.append(str(m)), level="ERROR")
    try:
        with pytest.raises(typer.Exit) as exc_a:
            orchestrator_mod.stop()
    finally:
        logger.remove(sink_a)
    assert exc_a.value.exit_code == 1
    assert stop_a in runner_a.calls
    assert any(".stremio" in msg for msg in errors_a)

    # (b) real .stremio whose daemon-id holds a different daemon ID than the fake reports
    root_b = tmp_path / "root_b"
    root_b.mkdir()
    (root_b / ".stremio").mkdir()
    (root_b / ".stremio" / "docker-compose.bindings.yml").touch()
    (root_b / ".stremio" / "daemon-id").write_text("daemon-old\n", encoding="utf-8")
    (root_b / ".env").write_text("STREMIO_ENABLED=1\n", encoding="utf-8")

    prefix_b = compose_args_prefix(root_b)
    stop_b = [*prefix_b, "stop", "stremio"]
    runner_b = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-new\n"),
            (*prefix_b, "config", "--services"): completed([], "stremio\n"),
            (*prefix_b, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                completed([], "stremio\n"),
                completed([], ""),
            ],
            tuple(stop_b): completed(stop_b),
        }
    )
    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: root_b)
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_b)
    errors_b: list[str] = []
    sink_b = logger.add(lambda m, buf=errors_b: buf.append(str(m)), level="ERROR")
    try:
        with pytest.raises(typer.Exit) as exc_b:
            orchestrator_mod.stop()
    finally:
        logger.remove(sink_b)
    assert exc_b.value.exit_code == 1
    assert stop_b in runner_b.calls
    assert any("different Docker daemon" in msg for msg in errors_b)

    # (c) normal stop -> exits 0
    (root_b / ".stremio" / "daemon-id").write_text("daemon-new\n", encoding="utf-8")
    runner_c = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-new\n"),
            (*prefix_b, "config", "--services"): completed([], "stremio\n"),
            (*prefix_b, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                completed([], "stremio\n"),
                completed([], ""),
            ],
            tuple(stop_b): completed(stop_b),
        }
    )
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_c)
    orchestrator_mod.stop()
    assert stop_b in runner_c.calls


# ---------------------------------------------------------------------------
# AC-22 (INV-6, D12, lesson I13): final file modes with real chmod/fchmod
# ---------------------------------------------------------------------------


def test_ac22_final_modes_without_chmod_mocks(tmp_path: Path) -> None:
    """AC-22 (INV-6, D12): final modes under umask 0022 with real os.chmod/os.fchmod."""
    old_umask = os.umask(0o022)
    try:
        # 1. ensure_gluetun_auth_config()
        r1 = tmp_path / "r1"
        r1.mkdir()
        auth = publishing_mod.ensure_gluetun_auth_config(r1)
        assert stat.S_IMODE(auth.stat().st_mode) == 0o600

        # 2. StackPublisher.publish() override
        r2 = tmp_path / "r2"
        r2.mkdir()
        (r2 / ".env").write_text(
            "STREMIO_BIND_ADDRS=127.0.0.1\nCOMET_ENABLED=0\n", encoding="utf-8"
        )
        (r2 / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
        pub = publishing_mod.StackPublisher(r2)
        pub.publish()
        assert stat.S_IMODE(pub.compose_override_file.stat().st_mode) == 0o600

        # 3. require_matching_daemon() daemon-id
        r3 = tmp_path / "r3"
        r3.mkdir()
        daemon_rec = r3 / ".stremio" / "daemon-id"
        daemon_runner = FakeRunner(
            {("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-abc\n")}
        )
        preflight_mod.require_matching_daemon(daemon_runner, daemon_rec, warn=lambda _: None)
        assert stat.S_IMODE(daemon_rec.stat().st_mode) == 0o600

        # 4. resolve_nordvpn_endpoint() cache
        r4 = tmp_path / "r4"
        r4.mkdir()
        cache4 = r4 / ".stremio" / "nordvpn-endpoint-cache.json"
        live = [
            {
                "hostname": "us1.nordvpn.com",
                "station": PUBLIC_IPV4_STATION,
                "status": "online",
                "load": 10,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            }
        ]
        with mock.patch.object(resolver_mod, "_fetch_nordvpn_recommendations", return_value=live):
            resolver_mod.resolve_nordvpn_endpoint(
                country="United States", city="Denver", cache_path=cache4
            )
        assert stat.S_IMODE(cache4.stat().st_mode) == 0o600

        # 5. record_home_ip() home-ip
        r5 = tmp_path / "r5"
        r5.mkdir()
        cfg5 = make_config(r5)
        guard5 = GluetunGuard(cfg5, FakeRunner({}))
        orch5 = Orchestrator(guard5)
        with mock.patch.object(guard5, "public_ip", return_value=PUBLIC_IPV4_HOST):
            orch5.record_home_ip()
        assert stat.S_IMODE(cfg5.home_ip_file.stat().st_mode) == 0o600
    finally:
        os.umask(old_umask)
