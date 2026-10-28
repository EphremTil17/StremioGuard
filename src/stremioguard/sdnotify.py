"""Minimal sd_notify(3) client for the systemd-supervised watchdog.

Speaks the datagram protocol directly so the watchdog needs no extra
dependency. Outside systemd (tests, a foreground run) NOTIFY_SOCKET is unset
and every call is a no-op.
"""

from __future__ import annotations

import os
import socket


def notify(state: str) -> bool:
    """Send ``state`` (e.g. ``READY=1`` or ``WATCHDOG=1``) to the service manager.

    Returns whether the message was delivered. A failure is not raised: a
    missed heartbeat is exactly what systemd's WatchdogSec= exists to act on,
    so the manager, not this process, decides what an unreachable socket means.
    """
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(address)
            sock.sendall(state.encode("utf-8"))
    except OSError:
        return False
    return True
