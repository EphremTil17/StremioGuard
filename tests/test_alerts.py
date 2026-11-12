"""Tests for best-effort operator alerts.

Delivery is checked against a real HTTP server on loopback, so the request
that leaves the process (method, headers, body) is what is asserted.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest
from loguru import logger

from stremioguard import alerts
from stremioguard.alerts import send_alert, valid_alert_url


@pytest.fixture
def log_messages() -> Iterator[list[str]]:
    messages: list[str] = []
    sink = logger.add(lambda message: messages.append(str(message)), level="DEBUG")
    try:
        yield messages
    finally:
        logger.remove(sink)


@contextmanager
def _server(status: int = 200, delay: float = 0.0) -> Iterator[tuple[str, list[dict]]]:
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            length = int(self.headers.get("Content-Length", "0"))
            received.append(
                {
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": self.rfile.read(length).decode("utf-8"),
                }
            )
            time.sleep(delay)
            self.send_response(status)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True  # do not wait for a deliberately slow handler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/secret-topic-xyz", received
    finally:
        server.shutdown()
        server.server_close()


def _closed_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}/secret-topic-xyz"


@pytest.mark.parametrize("url", [None, ""])
def test_unset_url_sends_nothing_and_returns_false(url: str | None) -> None:
    with mock.patch.object(alerts.urllib.request, "build_opener") as opener:
        assert send_alert(url, title="t", message="m") is False
    opener.assert_not_called()


def test_connection_error_returns_false_and_never_logs_the_url(
    log_messages: list[str],
) -> None:
    url = _closed_port_url()
    assert send_alert(url, title="Locked out", message="body") is False
    assert any("could not be delivered" in m for m in log_messages)
    assert not any("secret-topic-xyz" in m or "127.0.0.1" in m for m in log_messages)


def test_delivers_one_post_with_ntfy_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    # The alert must leave directly, not through a proxy from the environment.
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    with _server() as (url, received):
        assert send_alert(url, title="StremioGuard locked out ✓", message="Stopped. ✓") is True
    assert len(received) == 1
    request = received[0]
    assert request["path"] == "/secret-topic-xyz"
    assert request["body"] == "Stopped. ✓"
    assert request["headers"]["Priority"] == "urgent"
    # Non-ASCII in a header would raise inside http.client; it is replaced.
    assert request["headers"]["Title"] == "StremioGuard locked out ?"


def test_rejected_or_slow_endpoint_returns_false(
    monkeypatch: pytest.MonkeyPatch, log_messages: list[str]
) -> None:
    with _server(status=500) as (url, received):
        assert send_alert(url, title="t", message="m", urgent=False) is False
    assert received[0]["headers"]["Priority"] == "default"
    monkeypatch.setattr(alerts, "ALERT_TIMEOUT_SECONDS", 0.3)
    with _server(delay=2.0) as (url, _):
        started = time.monotonic()
        assert send_alert(url, title="t", message="m") is False
        assert time.monotonic() - started < 1.5
    assert not any("secret-topic-xyz" in m for m in log_messages)


def test_valid_alert_url() -> None:
    assert valid_alert_url("https://ntfy.sh/topic")
    assert valid_alert_url("http://10.0.0.2:8080/hook")
    assert not valid_alert_url("ntfy.sh/topic")
    assert not valid_alert_url("file:///etc/passwd")
    assert not valid_alert_url("https://")
