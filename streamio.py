#!/usr/bin/env python3
"""Public Streamio orchestration CLI."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

import typer
from loguru import logger

APP = typer.Typer(help="Start and guard Stremio behind NordVPN.", no_args_is_help=False)

ROOT_DIR = Path(__file__).resolve().parent
GUARD = ROOT_DIR / "bin" / "stremio-vpn"
LOG_DIR = ROOT_DIR / "logs"
PID_FILE = ROOT_DIR / ".streamio-watchdog.pid"
UV_CACHE = ROOT_DIR / ".uv-cache"

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
    "<cyan>streamio</cyan> | <level>{message}</level>",
    level="INFO",
    colorize=sys.stdout.isatty(),
)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    log_file: Path

    @classmethod
    def create(cls) -> RunContext:
        run_id = os.environ.get("STREAMIO_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = Path(os.environ.get("STREAMIO_LOG_FILE", LOG_DIR / f"streamio-{run_id}.log"))
        return cls(run_id=run_id, log_file=log_file)

    def env(self, *, background: bool = False, file_logging: bool = True) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("INSTALL_MISSING_DEPS", "1")
        env["STREAMIO_RUN_ID"] = self.run_id
        if file_logging:
            env["STREAMIO_LOG_FILE"] = str(self.log_file)
            env["STREAMIO_LOG_SESSION"] = "1"
        else:
            env.pop("STREAMIO_LOG_FILE", None)
            env["STREAMIO_LOG_SESSION"] = "0"
        if background:
            env["STREAMIO_BACKGROUND"] = "1"
        return env


def fail(message: str) -> NoReturn:
    logger.error(message)
    raise typer.Exit(1)


def require_uv() -> None:
    if shutil.which("uv"):
        return
    fail(
        "uv is required to run this project. Run ./streamio, which bootstraps uv "
        "automatically, or install it manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def uv_command(*args: str) -> list[str]:
    return ["uv", "--cache-dir", str(UV_CACHE), "run", *args]


def guard_command(*args: str) -> list[str]:
    return uv_command("python", str(GUARD), *args)


def run_guard(
    *args: str,
    context: RunContext | None = None,
    file_logging: bool = True,
) -> None:
    require_uv()
    context = context or RunContext.create()
    if file_logging:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(guard_command(*args), check=True, env=context.env(file_logging=file_logging))


WATCHDOG_CMDLINE_MARKER = "stremio-vpn"


def _pid_is_our_watchdog(pid: int) -> bool:
    """Confirm the PID corresponds to our watchdog and not a recycled unrelated process."""
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        cmdline = cmdline_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return WATCHDOG_CMDLINE_MARKER in cmdline and "watchdog" in cmdline


def watchdog_pid() -> int | None:
    if not PID_FILE.exists():
        return None

    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except ValueError:
        return None

    try:
        os.kill(pid, 0)
    except OSError:
        return None

    if not _pid_is_our_watchdog(pid):
        return None
    return pid


def start_watchdog(context: RunContext) -> None:
    require_uv()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    pid = watchdog_pid()
    if pid:
        logger.info(f"Watchdog already running with PID {pid}.")
        return

    logger.info(f"Starting background watchdog. Logs: {context.log_file}")
    with context.log_file.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            guard_command("watchdog"),
            cwd=ROOT_DIR,
            env=context.env(background=True),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")
    logger.success(f"Watchdog started with PID {process.pid}.")


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


def stop_watchdog() -> None:
    pid = watchdog_pid()
    if not pid:
        PID_FILE.unlink(missing_ok=True)
        return

    logger.info(f"Stopping background watchdog PID {pid}.")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        PID_FILE.unlink(missing_ok=True)
        return

    if _wait_for_exit(pid, 5):
        PID_FILE.unlink(missing_ok=True)
        return

    logger.warning(f"Watchdog PID {pid} did not exit after SIGTERM; sending SIGKILL.")
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        PID_FILE.unlink(missing_ok=True)
        return

    if not _wait_for_exit(pid, 3):
        logger.error(f"Watchdog PID {pid} did not exit after SIGKILL; leaving PID file in place.")
        return

    PID_FILE.unlink(missing_ok=True)


def latest_log() -> Path | None:
    if not LOG_DIR.exists():
        return None

    logs = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


@APP.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start Stremio when no command is provided."""
    if ctx.invoked_subcommand is None:
        start()


@APP.command()
def start() -> None:
    """Initialize if needed, start Stremio, and launch the watchdog."""
    context = RunContext.create()
    run_guard("start", context=context)
    start_watchdog(context)


@APP.command()
def restart() -> None:
    """Reset/build/start Stremio and relaunch the watchdog."""
    context = RunContext.create()
    stop_watchdog()
    run_guard("reset", context=context)
    start_watchdog(context)


@APP.command()
def stop() -> None:
    """Stop the watchdog and Stremio."""
    stop_watchdog()
    run_guard("stop", file_logging=False)


@APP.command()
def status() -> None:
    """Show VPN, public IP, and container status."""
    run_guard("status", file_logging=False)


@APP.command()
def logs(lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show.")) -> None:
    """Tail the latest run log."""
    log_file = latest_log()
    if not log_file:
        fail(f"No run logs found in {LOG_DIR}.")

    logger.info(f"Tailing {log_file}")
    subprocess.run(["tail", "-n", str(lines), "-f", str(log_file)], check=False)


@APP.command("record-home-ip")
def record_home_ip() -> None:
    """Save current public IP as leak-detection baseline."""
    run_guard("record-home-ip", file_logging=False)


@APP.command()
def check() -> None:
    """Run Ruff, Pyright, and pytest through uv."""
    require_uv()
    subprocess.run(uv_command("ruff", "format", "--check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("ruff", "check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("pyright"), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("pytest"), check=True, cwd=ROOT_DIR)


if __name__ == "__main__":
    APP()
