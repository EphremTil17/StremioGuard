"""One lock for everything that starts, stops or recreates containers.

The watchdog and the CLI both drive the same Compose project. Without a
shared lock a `./stremio comet update apply` and a watchdog auto-start can
run `compose up` on the same service at once, and a `./stremio start` can
recreate gluetun while the watchdog is restarting it.

The lock is a kernel `flock` on `.stremio/stack.lock`: it is released when
the holder exits, however it exits, so it can never go stale.
"""

from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from stremioguard.env import ensure_directory

STACK_LOCK_NAME = "stack.lock"
_POLL_SECONDS = 0.2
# path -> [file descriptor, depth]. flock conflicts between two descriptors of
# the same process, so a nested acquisition must reuse the first one.
_HELD: dict[str, list[int]] = {}


def stack_lock_path(root_dir: Path) -> Path:
    return root_dir / ".stremio" / STACK_LOCK_NAME


def _try_lock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


@contextmanager
def stack_lock(root_dir: Path, *, wait_seconds: float = 0.0) -> Iterator[bool]:
    """Hold the stack lock for the block; yield whether it was acquired.

    Waits up to ``wait_seconds`` for another holder. The caller decides what
    an unacquired lock means: a start must not proceed, a stop must.
    """
    path = stack_lock_path(root_dir)
    key = str(path)
    held = _HELD.get(key)
    if held is not None:
        held[1] += 1
        try:
            yield True
        finally:
            held[1] -= 1
        return

    ensure_directory(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    acquired = False
    try:
        deadline = time.monotonic() + wait_seconds
        acquired = _try_lock(fd)
        while not acquired and time.monotonic() < deadline:
            time.sleep(_POLL_SECONDS)
            acquired = _try_lock(fd)
        if acquired:
            _HELD[key] = [fd, 1]
        yield acquired
    finally:
        if acquired:
            _HELD.pop(key, None)
        # Closing the descriptor releases the flock.
        os.close(fd)


@contextmanager
def required_stack_lock(root_dir: Path, *, wait_seconds: float, purpose: str) -> Iterator[None]:
    """Hold the lock or refuse: for commands that start or recreate containers."""
    with stack_lock(root_dir, wait_seconds=wait_seconds) as acquired:
        if not acquired:
            raise RuntimeError(
                f"Another StremioGuard command is changing the stack; refusing to {purpose} "
                f"at the same time (waited {int(wait_seconds)}s). Retry when it finishes."
            )
        yield
