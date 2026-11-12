"""Tests for the stack lock: a kernel flock shared by the CLI and the watchdog.

Every assertion is about the kernel's view of the lock (whether another open
file description, or another process, can take it), not about which Python
function ran.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from stremioguard import stacklock
from stremioguard.stacklock import required_stack_lock, stack_lock, stack_lock_path


def _lock_is_free(root: Path) -> bool:
    """Whether a fresh open file description can take the lock right now."""
    path = stack_lock_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


@contextmanager
def _held_elsewhere(root: Path) -> Iterator[None]:
    """Hold the lock through a separate open file, as another command would."""
    path = stack_lock_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        yield
    finally:
        os.close(fd)


def test_second_holder_is_refused(tmp_path: Path) -> None:
    with _held_elsewhere(tmp_path), stack_lock(tmp_path) as held:
        assert held is False
    with stack_lock(tmp_path) as held:
        assert held is True
        assert not _lock_is_free(tmp_path)
    assert _lock_is_free(tmp_path)


def test_holder_in_another_process_is_refused_until_it_exits(tmp_path: Path) -> None:
    path = stack_lock_path(tmp_path)
    path.parent.mkdir(parents=True)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl, os, sys\n"
            f"fd = os.open({str(path)!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('locked', flush=True)\n"
            "sys.stdin.read()\n",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == "locked"
        with stack_lock(tmp_path, wait_seconds=0.3) as held:
            assert held is False
    finally:
        assert child.stdin is not None
        child.stdin.close()
        child.wait(timeout=10)
    # The kernel released it when the holder exited; no stale lock remains.
    with stack_lock(tmp_path) as held:
        assert held is True


def test_reentrant_acquisition_in_process(tmp_path: Path) -> None:
    with stack_lock(tmp_path) as outer:
        assert outer is True
        with stack_lock(tmp_path, wait_seconds=0) as inner:
            # A second descriptor in this process would conflict with the
            # first; the nested call must reuse it instead.
            assert inner is True
            with required_stack_lock(tmp_path, wait_seconds=0, purpose="nest"):
                assert not _lock_is_free(tmp_path)
        # Leaving the inner block must not release the outer hold.
        assert not _lock_is_free(tmp_path)
    assert _lock_is_free(tmp_path)
    assert stacklock._HELD == {}


def test_required_stack_lock_raises_after_waiting(tmp_path: Path) -> None:
    ran = []
    started = time.monotonic()
    with (
        _held_elsewhere(tmp_path),
        pytest.raises(RuntimeError, match="refusing to restart Comet"),
        required_stack_lock(tmp_path, wait_seconds=0.5, purpose="restart Comet"),
    ):
        ran.append(True)
    assert ran == []
    assert time.monotonic() - started >= 0.5
    assert stacklock._HELD == {}


def test_wait_acquires_once_the_other_holder_releases(tmp_path: Path) -> None:
    path = stack_lock_path(tmp_path)
    path.parent.mkdir(parents=True)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl, os, time\n"
            f"fd = os.open({str(path)!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('locked', flush=True)\n"
            "time.sleep(0.5)\n",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == "locked"
        with stack_lock(tmp_path, wait_seconds=10) as held:
            assert held is True
    finally:
        child.wait(timeout=10)


def test_lock_is_released_when_the_body_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError), stack_lock(tmp_path):
        raise ValueError("boom")
    assert _lock_is_free(tmp_path)
    assert stacklock._HELD == {}


def test_child_processes_do_not_inherit_the_lock(tmp_path: Path) -> None:
    # `docker compose` children can outlive a command; if they inherited the
    # descriptor they would keep the stack locked after it exited. This checks
    # the outcome only: Python already makes the descriptor non-inheritable
    # (PEP 446), so dropping O_CLOEXEC alone would not make it fail.
    with stack_lock(tmp_path) as held:
        assert held is True
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            stdin=subprocess.PIPE,
            close_fds=False,
        )
    try:
        assert _lock_is_free(tmp_path)
    finally:
        assert child.stdin is not None
        child.stdin.close()
        child.wait(timeout=10)
