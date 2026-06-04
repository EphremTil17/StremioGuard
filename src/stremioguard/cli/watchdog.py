from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import typer
from loguru import logger

from stremioguard.cli.context import (
    LOG_DIR,
    PID_FILE,
    ROOT_DIR,
    STATE_DIR,
    UV_CACHE,
    RunContext,
)
from stremioguard.env import fail

WATCHDOG_CMDLINE_MARKERS = ("stremioguard.orchestrator", "stremio-vpn")


def _require_uv() -> None:
    if shutil.which("uv"):
        return
    fail(
        "uv is required to run this project. Run ./stremio, which bootstraps uv "
        "automatically, or install it manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def _uv_command(*args: str) -> list[str]:
    return ["uv", "--cache-dir", str(UV_CACHE), "run", *args]


def _guard_command(*args: str) -> list[str]:
    return _uv_command("python", "-m", "stremioguard.orchestrator", *args)


def run_guard(*args: str, context: RunContext | None = None, file_logging: bool = True) -> None:
    _require_uv()
    context = context or RunContext.create()
    if file_logging:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            _guard_command(*args), check=True, env=context.env(file_logging=file_logging)
        )
    except subprocess.CalledProcessError as error:
        raise typer.Exit(error.returncode or 1) from None


def _pid_is_our_watchdog(pid: int) -> bool:
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        cmdline = cmdline_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return "watchdog" in cmdline and any(marker in cmdline for marker in WATCHDOG_CMDLINE_MARKERS)


def _watchdog_pids() -> list[int]:
    discovered: list[int] = []
    seen: set[int] = set()

    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            pid = None
        if pid is not None:
            try:
                os.kill(pid, 0)
            except OSError:
                pass
            else:
                if _pid_is_our_watchdog(pid):
                    discovered.append(pid)
                    seen.add(pid)

    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except (FileNotFoundError, PermissionError, OSError):
        return discovered

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in seen:
            continue
        if _pid_is_our_watchdog(pid):
            discovered.append(pid)
            seen.add(pid)

    return sorted(discovered)


def _watchdog_pid() -> int | None:
    pids = _watchdog_pids()
    return pids[0] if pids else None


def _wait_for_exit(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, 0)
    except OSError:
        return True
    return False


def _start_watchdog(context: RunContext) -> None:
    _require_uv()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    pids = _watchdog_pids()
    if pids:
        PID_FILE.write_text(f"{pids[0]}\n", encoding="utf-8")
        logger.info(f"Watchdog already running with PID {pids[0]}.")
        return

    logger.info(f"Starting background watchdog. Logs: {context.log_file}")
    with context.log_file.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            _guard_command("watchdog"),
            cwd=ROOT_DIR,
            env=context.env(background=True),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")
    logger.success(f"Watchdog started with PID {process.pid}.")


def _stop_watchdog() -> None:
    pids = _watchdog_pids()
    if not pids:
        PID_FILE.unlink(missing_ok=True)
        return

    logger.info(f"Stopping background watchdog PID(s) {', '.join(str(pid) for pid in pids)}.")
    remaining: list[int] = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue

    for pid in pids:
        if not _wait_for_exit(pid, 5):
            remaining.append(pid)

    if remaining:
        logger.warning(
            "Watchdog PID(s) "
            f"{', '.join(str(pid) for pid in remaining)} did not exit after SIGTERM; "
            "sending SIGKILL."
        )
        stuck: list[int] = []
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                continue
            if not _wait_for_exit(pid, 3):
                stuck.append(pid)
        if stuck:
            PID_FILE.write_text(f"{stuck[0]}\n", encoding="utf-8")
            logger.error(
                "Watchdog PID(s) "
                f"{', '.join(str(pid) for pid in stuck)} did not exit after SIGKILL; "
                "leaving PID file in place."
            )
            return

    PID_FILE.unlink(missing_ok=True)


def _latest_log() -> Path | None:
    if not LOG_DIR.exists():
        return None
    logs = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    return logs[0] if logs else None
