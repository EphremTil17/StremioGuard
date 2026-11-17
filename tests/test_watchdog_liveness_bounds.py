"""Acceptance tests AC-7 through AC-11 and AC-13 (branch checks) for handoff 0015."""

from __future__ import annotations

import ast
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import pytest
from loguru import logger

from stremioguard import alerts as alerts_mod
from stremioguard import httpdeadline as httpdeadline_mod
from stremioguard import resolver as resolver_mod
from stremioguard.cli import supervisor as supervisor_mod
from stremioguard.cli.supervisor import WATCHDOG_SEC, WATCHDOG_STEP_MARGIN_SECONDS
from stremioguard.config import (
    DOCKER_QUERY_TIMEOUT_SECONDS,
    PUBLIC_IP_TIMEOUT_MAX_SECONDS,
    WATCHDOG_MUTATION_TIMEOUT_SECONDS,
    Config,
)
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import HEARTBEAT_SLEEP_CHUNK_SECONDS, Orchestrator
from stremioguard.sdnotify import notify
from tests.conftest import PUBLIC_IPV4_STATION, completed

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"


def _run_bounded[T](fn: Callable[[], T], timeout_seconds: float, label: str) -> T:
    """Run ``fn`` on a daemon thread and fail if it exceeds ``timeout_seconds``."""
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
        pytest.fail(f"{label} exceeded bounded wait ({timeout_seconds}s)")
    ok, value = outcome[0]
    if not ok:
        assert isinstance(value, BaseException)
        raise value
    return value  # type: ignore[return-value]


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


def _open_socket_inodes() -> set[str]:
    inodes: set[str] = set()
    for entry in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{entry}")
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[len("socket:[") : -1])
    return inodes


def _client_sockets_to_port(port: int) -> list[str]:
    """Return open socket inodes in this process connected to remote ``port``."""
    open_inodes = _open_socket_inodes()
    matches: list[str] = []
    target_hex = f"{port:04X}"
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proc_file).read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            rem_addr = parts[2]
            inode = parts[9]
            if ":" not in rem_addr:
                continue
            _, rem_port_hex = rem_addr.rsplit(":", 1)
            if rem_port_hex.upper() == target_hex and inode in open_inodes:
                matches.append(inode)
    return matches


def _deadline_threads() -> list[threading.Thread]:
    return [
        t for t in threading.enumerate() if t.name == "stremioguard-http-deadline" and t.is_alive()
    ]


@contextmanager
def _raw_tls_stub(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[socket.socket, ssl.SSLContext, threading.Event], None],
) -> Iterator[int]:
    """Listen on 127.0.0.1:0 with TLS cert trusted via SSL_CERT_FILE."""
    cert_file, key_file = _create_localhost_cert(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_file))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.2)
    port = int(srv.getsockname()[1])
    stop = threading.Event()
    conns: list[threading.Thread] = []

    def _accept_loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            t = threading.Thread(target=handler, args=(conn, ctx, stop), daemon=True)
            t.start()
            conns.append(t)

    accept_thread = threading.Thread(target=_accept_loop, daemon=True)
    accept_thread.start()
    try:
        yield port
    finally:
        stop.set()
        with suppress(OSError):
            srv.close()
        accept_thread.join(timeout=2.0)
        for t in conns:
            t.join(timeout=2.0)


def _read_http_request(sock: socket.socket) -> None:
    sock.settimeout(2.0)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    content_length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            with suppress(ValueError):
                content_length = int(line.split(b":", 1)[1].strip())
    while len(rest) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk


# ---------------------------------------------------------------------------
# AC-7: notify() never blocks, AST audit of notify() calls and constants
# ---------------------------------------------------------------------------


def test_ac07_notify_full_queue_returns_false_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-7(a): notify() returns False within 1s when receiver queue is full."""
    max_qlen = int(Path("/proc/sys/net/unix/max_dgram_qlen").read_text(encoding="utf-8").strip())
    sock_path = tmp_path / "notify.sock"
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    senders: list[socket.socket] = []
    try:
        receiver.bind(str(sock_path))
        queued = 0
        while queued < max_qlen:
            sender = socket.socket(
                socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC
            )
            sender.connect(str(sock_path))
            senders.append(sender)
            while True:
                try:
                    sender.send(b"X")
                    queued += 1
                except BlockingIOError:
                    break
            if queued >= max_qlen:
                break
        # Verify a fresh non-blocking sender cannot enqueue another datagram.
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
        senders.append(probe)
        probe.connect(str(sock_path))
        with pytest.raises(BlockingIOError):
            probe.send(b"X")

        monkeypatch.setenv("NOTIFY_SOCKET", str(sock_path))
        result = _run_bounded(lambda: notify("WATCHDOG=1"), 1.0, "notify on full queue")
        assert result is False
    finally:
        for s in senders:
            with suppress(OSError):
                s.close()
        with suppress(OSError):
            receiver.close()


def test_ac07_ast_notify_call_sites_and_no_timeout_extension() -> None:
    """AC-7(c): AST check of all notify() call sites and forbidden strings in src/."""
    found_calls: list[tuple[str, str, str]] = []

    class _Visitor(ast.NodeVisitor):
        def __init__(self, filename: str) -> None:
            self.filename = filename
            self.fn_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.fn_stack.append(node.name)
            self.generic_visit(node)
            self.fn_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.fn_stack.append(node.name)
            self.generic_visit(node)
            self.fn_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            is_notify = (isinstance(node.func, ast.Name) and node.func.id == "notify") or (
                isinstance(node.func, ast.Attribute) and node.func.attr == "notify"
            )
            if is_notify:
                assert len(node.args) == 1 and not node.keywords, (self.filename, node.lineno)
                arg = node.args[0]
                assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), (
                    self.filename,
                    node.lineno,
                )
                fn_name = self.fn_stack[-1] if self.fn_stack else "<module>"
                found_calls.append((self.filename, fn_name, arg.value))
            self.generic_visit(node)

    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        source = py_file.read_text(encoding="utf-8")
        assert "EXTEND_TIMEOUT_USEC" not in source, py_file
        assert "WATCHDOG_USEC" not in source, py_file
        tree = ast.parse(source, filename=str(py_file))
        _Visitor(py_file.name).visit(tree)

    expected = {
        ("orchestrator.py", "watch_stremio", "READY=1"),
        ("orchestrator.py", "_tick", "WATCHDOG=1"),
        ("orchestrator.py", "_sleep", "WATCHDOG=1"),
        ("orchestrator.py", "_step_heartbeat", "WATCHDOG=1"),
    }
    assert len(found_calls) == len(expected), found_calls
    assert set(found_calls) == expected


# ---------------------------------------------------------------------------
# AC-8: NordVPN resolver wall-clock deadline over HTTPS
# ---------------------------------------------------------------------------


def test_ac08_resolver_https_deadline_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-8(a)-(g): resolver honors wall-clock bound over HTTPS and cleans up."""

    # (a) Trickled body: 200 OK headers with Content-Length: 100000, 1 byte / 0.3s
    def trickle_handler(conn: socket.socket, ctx: ssl.SSLContext, stop: threading.Event) -> None:
        with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
            _read_http_request(tls)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n")
            while not stop.wait(0.3):
                tls.sendall(b"[")

    with _raw_tls_stub(tmp_path, monkeypatch, trickle_handler) as port:
        monkeypatch.setattr(
            resolver_mod,
            "RECOMMENDATIONS_API_URL",
            f"https://localhost:{port}/v1/servers/recommendations",
        )
        start = time.monotonic()
        with pytest.raises((TimeoutError, OSError)):
            _run_bounded(
                lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
                3.0,
                "AC-8(a) trickled body",
            )
        assert time.monotonic() - start < 3.0
        time.sleep(0.2)
        assert _deadline_threads() == []
        assert _client_sockets_to_port(port) == []

        # (g) resolve_nordvpn_endpoint falls back to 2-hour-old cache on timeout
        cache_path = tmp_path / ".stremio" / "nordvpn-cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps(
                {
                    "country": "United States",
                    "city": "Denver",
                    "hostname": "us-cached.nordvpn.com",
                    "ip": PUBLIC_IPV4_STATION,
                    "timestamp": time.time() - 2 * 3600,
                }
            ),
            encoding="utf-8",
        )
        start_g = time.monotonic()
        ep = _run_bounded(
            lambda: resolver_mod.resolve_nordvpn_endpoint(
                "United States",
                "Denver",
                cache_path=cache_path,
                timeout_seconds=2,
                force_refresh=True,
            ),
            3.0,
            "AC-8(g) stale cache fallback",
        )
        assert time.monotonic() - start_g < 3.0
        assert ep == ("us-cached.nordvpn.com", PUBLIC_IPV4_STATION)

    # (b) Handshake completed, then silence
    def silent_after_tls(conn: socket.socket, ctx: ssl.SSLContext, stop: threading.Event) -> None:
        with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
            _read_http_request(tls)
            stop.wait(10.0)

    with _raw_tls_stub(tmp_path, monkeypatch, silent_after_tls) as port:
        monkeypatch.setattr(
            resolver_mod,
            "RECOMMENDATIONS_API_URL",
            f"https://localhost:{port}/v1/servers/recommendations",
        )
        with pytest.raises((TimeoutError, OSError)):
            _run_bounded(
                lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
                3.0,
                "AC-8(b) silence after handshake",
            )
        time.sleep(0.2)
        assert _deadline_threads() == []
        assert _client_sockets_to_port(port) == []

    # (c) TCP accepted, TLS handshake never answered
    def stalled_handshake(conn: socket.socket, _ctx: ssl.SSLContext, stop: threading.Event) -> None:
        with suppress(OSError), conn:
            stop.wait(10.0)

    with _raw_tls_stub(tmp_path, monkeypatch, stalled_handshake) as port:
        monkeypatch.setattr(
            resolver_mod,
            "RECOMMENDATIONS_API_URL",
            f"https://localhost:{port}/v1/servers/recommendations",
        )
        with pytest.raises((TimeoutError, OSError)):
            _run_bounded(
                lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
                3.0,
                "AC-8(c) stalled TLS handshake",
            )
        time.sleep(0.2)
        assert _deadline_threads() == []
        assert _client_sockets_to_port(port) == []

    # (d) Blocked getaddrinfo
    dns_gate = threading.Event()
    real_getaddrinfo = socket.getaddrinfo

    def blocked_getaddrinfo(
        host: object, port_arg: object, *args: object, **kwargs: object
    ) -> list[Any]:
        if host == "localhost":
            dns_gate.wait(timeout=15.0)
        return real_getaddrinfo(host, port_arg, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "getaddrinfo", blocked_getaddrinfo)
    monkeypatch.setattr(
        resolver_mod,
        "RECOMMENDATIONS_API_URL",
        "https://localhost:1/v1/servers/recommendations",
    )
    baseline_sockets = _open_socket_inodes()
    try:
        with pytest.raises(TimeoutError):
            _run_bounded(
                lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
                3.0,
                "AC-8(d) blocked DNS",
            )
        workers = _deadline_threads()
        assert _client_sockets_to_port(1) == []
    finally:
        dns_gate.set()
    for w in workers:
        w.join(timeout=2.0)
        assert not w.is_alive()
    assert _open_socket_inodes() - baseline_sockets == set()
    monkeypatch.setattr(socket, "getaddrinfo", real_getaddrinfo)

    # (e) Fast valid response & HTTP 500, and (f) proxy env vars ignored
    payload = json.dumps([{"hostname": "us1.nordvpn.com", "station": PUBLIC_IPV4_STATION}]).encode()
    mode = {"status": 200}

    def fast_handler(conn: socket.socket, ctx: ssl.SSLContext, _stop: threading.Event) -> None:
        with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
            _read_http_request(tls)
            if mode["status"] == 200:
                tls.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n"
                    "Connection: close\r\n\r\n".encode()
                    + payload
                )
            else:
                tls.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")

    with _raw_tls_stub(tmp_path, monkeypatch, fast_handler) as port:
        monkeypatch.setattr(
            resolver_mod,
            "RECOMMENDATIONS_API_URL",
            f"https://localhost:{port}/v1/servers/recommendations",
        )
        res = _run_bounded(
            lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
            2.0,
            "AC-8(e) 200 OK",
        )
        assert res == [{"hostname": "us1.nordvpn.com", "station": PUBLIC_IPV4_STATION}]

        # (f) Closed proxy env vars must not be used
        closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed_sock.bind(("127.0.0.1", 0))
        closed_port = closed_sock.getsockname()[1]
        closed_sock.close()
        monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{closed_port}")
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{closed_port}")
        res_proxy = _run_bounded(
            lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
            2.0,
            "AC-8(f) proxy ignored",
        )
        assert res_proxy == res

        mode["status"] = 500
        with pytest.raises(urllib.error.HTTPError):
            _run_bounded(
                lambda: resolver_mod._fetch_nordvpn_recommendations(timeout_seconds=2),
                2.0,
                "AC-8(e) 500",
            )


# ---------------------------------------------------------------------------
# AC-9: send_alert() wall-clock deadline, exception handling and URL redaction
# ---------------------------------------------------------------------------


def test_ac09_alert_deadline_and_url_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-9(a)-(f): send_alert() obeys total bound, swallows HTTPException, never logs URL."""
    monkeypatch.setattr(alerts_mod, "ALERT_TIMEOUT_SECONDS", 1.0)
    canary = "canary-secret-webhook-token-9981"
    logs: list[str] = []
    sink_id = logger.add(lambda m: logs.append(str(m)), level="DEBUG")
    try:
        # (a) Trickled status line
        def trickle_status(conn: socket.socket, ctx: ssl.SSLContext, stop: threading.Event) -> None:
            with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
                _read_http_request(tls)
                for byte in (b"HTTP/1.1 200 OK\r\n\r\n"[i : i + 1] for i in range(19)):
                    if stop.wait(0.3):
                        break
                    tls.sendall(byte)

        with _raw_tls_stub(tmp_path, monkeypatch, trickle_status) as port:
            logs.clear()
            ok = _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:{port}/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(a) trickled status",
            )
            assert ok is False
            assert any("Alert could not be delivered (TimeoutError)." in line for line in logs), (
                logs
            )
            assert all(canary not in line for line in logs)

        # (b) Silence after handshake
        def silent(conn: socket.socket, ctx: ssl.SSLContext, stop: threading.Event) -> None:
            with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
                _read_http_request(tls)
                stop.wait(10.0)

        with _raw_tls_stub(tmp_path, monkeypatch, silent) as port:
            logs.clear()
            ok = _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:{port}/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(b) silence",
            )
            assert ok is False
            assert any("Alert could not be delivered (TimeoutError)." in line for line in logs), (
                logs
            )
            assert all(canary not in line for line in logs)

        # (c) Stalled TLS handshake
        def no_tls(conn: socket.socket, _ctx: ssl.SSLContext, stop: threading.Event) -> None:
            with suppress(OSError), conn:
                stop.wait(10.0)

        with _raw_tls_stub(tmp_path, monkeypatch, no_tls) as port:
            logs.clear()
            ok = _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:{port}/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(c) no handshake",
            )
            assert ok is False
            assert any("Alert could not be delivered (TimeoutError)." in line for line in logs), (
                logs
            )
            assert all(canary not in line for line in logs)

        # (d) Blocked DNS
        dns_gate = threading.Event()
        real_getaddrinfo = socket.getaddrinfo

        def blocked_getaddrinfo(
            host: object, port_arg: object, *args: object, **kwargs: object
        ) -> list[Any]:
            if host == "localhost":
                dns_gate.wait(timeout=15.0)
            return real_getaddrinfo(host, port_arg, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(socket, "getaddrinfo", blocked_getaddrinfo)
        try:
            logs.clear()
            ok = _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:1/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(d) blocked DNS",
            )
            assert ok is False
            assert any("Alert could not be delivered (TimeoutError)." in line for line in logs), (
                logs
            )
            assert all(canary not in line for line in logs)
        finally:
            dns_gate.set()
            for w in _deadline_threads():
                w.join(timeout=2.0)
        monkeypatch.setattr(socket, "getaddrinfo", real_getaddrinfo)

        # (e) Malformed status line (BadStatusLine)
        def bad_status(conn: socket.socket, ctx: ssl.SSLContext, _stop: threading.Event) -> None:
            with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
                _read_http_request(tls)
                tls.sendall(b"NOT_HTTP_AT_ALL\r\n\r\n")

        with _raw_tls_stub(tmp_path, monkeypatch, bad_status) as port:
            logs.clear()
            ok = _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:{port}/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(e) BadStatusLine",
            )
            assert ok is False
            assert any("Alert could not be delivered (BadStatusLine)." in line for line in logs)
            assert all(canary not in line for line in logs)

        # (f) 204 -> True, 500 -> False
        status_code = {"code": 204}

        def status_handler(
            conn: socket.socket, ctx: ssl.SSLContext, _stop: threading.Event
        ) -> None:
            with suppress(OSError, ssl.SSLError), ctx.wrap_socket(conn, server_side=True) as tls:
                _read_http_request(tls)
                header = f"HTTP/1.1 {status_code['code']} Status\r\nContent-Length: 0\r\n\r\n"
                tls.sendall(header.encode())

        with _raw_tls_stub(tmp_path, monkeypatch, status_handler) as port:
            assert _run_bounded(
                lambda: alerts_mod.send_alert(
                    f"https://localhost:{port}/{canary}", title="t", message="m"
                ),
                2.0,
                "AC-9(f) 204",
            )
            status_code["code"] = 500
            assert (
                _run_bounded(
                    lambda: alerts_mod.send_alert(
                        f"https://localhost:{port}/{canary}", title="t", message="m"
                    ),
                    2.0,
                    "AC-9(f) 500",
                )
                is False
            )
    finally:
        logger.remove(sink_id)


# ---------------------------------------------------------------------------
# AC-10: Static bounds
# ---------------------------------------------------------------------------


def test_ac10_static_step_bounds() -> None:
    """AC-10 (INV-7, D9): every step bound + grace <= margin ceiling."""
    limit = WATCHDOG_SEC - WATCHDOG_STEP_MARGIN_SECONDS
    assert limit >= DOCKER_QUERY_TIMEOUT_SECONDS
    assert limit >= WATCHDOG_MUTATION_TIMEOUT_SECONDS
    assert limit >= PUBLIC_IP_TIMEOUT_MAX_SECONDS + 2
    assert limit >= resolver_mod.DEFAULT_TIMEOUT_SECONDS + httpdeadline_mod.JOIN_GRACE_SECONDS
    assert limit >= alerts_mod.ALERT_TIMEOUT_SECONDS + httpdeadline_mod.JOIN_GRACE_SECONDS
    assert WATCHDOG_SEC > 2 * HEARTBEAT_SLEEP_CHUNK_SECONDS


# ---------------------------------------------------------------------------
# AC-11: Wiring through Orchestrator.watch_stremio() on a real AF_UNIX socket
# ---------------------------------------------------------------------------


class _LoopDone(BaseException):
    pass


def test_ac11_watch_stremio_real_socket_wiring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-11: watch_stremio() attaches step heartbeats and emits READY=1 + WATCHDOG=1."""
    sock_path = tmp_path / "notify.sock"
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    receiver.bind(str(sock_path))
    monkeypatch.setenv("NOTIFY_SOCKET", str(sock_path))

    state_dir = tmp_path / ".stremio"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "docker-compose.bindings.yml").touch()
    (state_dir / "compose.base.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (state_dir / "env.snapshot").touch()
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "VPN_SERVICE_PROVIDER=nordvpn\n"
        "SERVER_COUNTRIES=United States\n"
        "SERVER_CITIES=Denver\n"
        "STREMIO_ENABLED=1\n",
        encoding="utf-8",
    )

    cfg = Config(
        root_dir=tmp_path,
        gluetun_healthy_timeout_seconds=60,
        watch_interval_seconds=10,
        watchdog_log_interval_seconds=300,
        public_ip_timeout_seconds=5,
        home_ip_file=state_dir / "home-ip",
        expected_vpn_ip=None,
        ip_check_urls=("https://api.ipify.org",),
        install_missing=False,
        run_id="ac11-run",
        log_file=None,
        log_session=False,
        stremio_enabled=True,
        egress_probe_interval_seconds=300,
        public_ip_failure_threshold=3,
        vpn_recovery_budget_seconds=300,
        vpn_restart_cadence_seconds=45,
        vpn_lockout_file=state_dir / "vpn-lockout",
        server_countries="United States",
        server_regions=None,
        server_cities="Denver",
        server_hostnames=None,
        server_categories=None,
        env_file=tmp_path / ".env",
        alert_url=None,
    )

    received: list[str] = []
    drained_at_stop: list[str] = []

    def _drain() -> list[str]:
        items: list[str] = []
        while True:
            try:
                items.append(receiver.recv(1024).decode("utf-8"))
            except BlockingIOError:
                break
        received.extend(items)
        return items

    runner_calls = 0

    class _OutageRunner:
        def run(self, args: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
            nonlocal runner_calls
            runner_calls += 1
            if args[-3:] == ["ps", "-q", "gluetun"]:
                return completed(args, "gluetun-cid\n")
            if (
                args[:3] == ["docker", "inspect", "--format"]
                and "{{.State.Health.Status}}" in args[3]
            ):
                return completed(args, "unhealthy|2026-11-16T00:00:00Z\n")
            if "--status" in args and "running" in args:
                return completed(args, "" if runner_calls > 3 else "stremio\n")
            if "stop" in args and args[:2] == ["docker", "compose"]:
                drained_at_stop.extend(_drain())
                return completed(args)
            if args[:2] == ["docker", "logs"]:
                return completed(args, "")
            if "up" in args and args[:2] == ["docker", "compose"]:
                return completed(args)
            raise AssertionError(f"Unexpected command: {args}")

    resolver_calls = 0

    def _fake_resolver(*_a: object, **_kw: object) -> list[dict[str, object]]:
        nonlocal resolver_calls
        resolver_calls += 1
        return [
            {
                "hostname": "us1.nordvpn.com",
                "station": PUBLIC_IPV4_STATION,
                "status": "online",
                "load": 10,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            }
        ]

    def _stop_sleep(*_a: object, **_kw: object) -> None:
        raise _LoopDone()

    monkeypatch.setattr(resolver_mod, "_fetch_nordvpn_recommendations", _fake_resolver)
    monkeypatch.setattr(Orchestrator, "_sleep", staticmethod(_stop_sleep))

    guard = GluetunGuard(cfg, _OutageRunner(), frozen=True)
    monkeypatch.setattr(guard, "require_commands", lambda: None)
    orch = Orchestrator(guard)

    try:
        with pytest.raises(_LoopDone):
            orch.watch_stremio()
        _drain()
    finally:
        receiver.close()

    assert received[0] == "READY=1"
    assert "WATCHDOG=1" in drained_at_stop
    assert resolver_calls == 1
    assert received.count("WATCHDOG=1") == runner_calls + resolver_calls + 1


# ---------------------------------------------------------------------------
# AC-13: Session metadata marker and README documentation
# ---------------------------------------------------------------------------


def test_ac13_session_metadata_marker_and_readme(tmp_path: Path) -> None:
    """AC-13 (D10): _log_session_start logs ceiling marker; README documents step heartbeats."""
    cfg = Config(
        root_dir=tmp_path,
        gluetun_healthy_timeout_seconds=60,
        watch_interval_seconds=10,
        watchdog_log_interval_seconds=300,
        public_ip_timeout_seconds=8,
        home_ip_file=tmp_path / ".stremio" / "home-ip",
        expected_vpn_ip=None,
        ip_check_urls=("https://api.ipify.org",),
        install_missing=False,
        run_id="marker-test",
        log_file=None,
        log_session=True,
        stremio_enabled=True,
        egress_probe_interval_seconds=300,
        public_ip_failure_threshold=3,
        vpn_recovery_budget_seconds=300,
        vpn_restart_cadence_seconds=45,
        vpn_lockout_file=tmp_path / ".stremio" / "vpn-lockout",
        server_countries=None,
        server_regions=None,
        server_cities=None,
        server_hostnames=None,
        server_categories=None,
    )
    logged: list[str] = []
    sink_id = logger.add(lambda m: logged.append(str(m)), level="INFO")
    try:
        Orchestrator(GluetunGuard(cfg, frozen=True))
    finally:
        logger.remove(sink_id)
    assert any("tick_heartbeat_ceiling_seconds=3600" in line for line in logged)

    # Unit rendering sanity
    assert f"WatchdogSec={WATCHDOG_SEC}" in supervisor_mod.render_watchdog_unit()
    assert WATCHDOG_STEP_MARGIN_SECONDS == 60
