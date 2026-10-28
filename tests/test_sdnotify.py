"""sd_notify against a real datagram socket, the way systemd receives it."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from stremioguard.sdnotify import notify


def test_notify_is_a_noop_outside_systemd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert notify("READY=1") is False


def test_notify_delivers_to_a_path_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "notify.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        server.bind(str(path))
        monkeypatch.setenv("NOTIFY_SOCKET", str(path))
        assert notify("WATCHDOG=1") is True
        assert server.recv(64) == b"WATCHDOG=1"


def test_notify_delivers_to_an_abstract_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    name = f"stremioguard-test-{id(monkeypatch)}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        server.bind("\0" + name)
        monkeypatch.setenv("NOTIFY_SOCKET", "@" + name)
        assert notify("READY=1") is True
        assert server.recv(64) == b"READY=1"


def test_notify_swallows_an_unreachable_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "missing.sock"))
    assert notify("WATCHDOG=1") is False
