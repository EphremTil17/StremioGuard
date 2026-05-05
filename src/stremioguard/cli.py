"""Public Stremio orchestration CLI."""

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

import typer
from loguru import logger

from stremioguard.comet import CometManager, prompt_comet_setup
from stremioguard.config import CometConfig, Config
from stremioguard.env import (
    env_flag_enabled,
    env_needs_init,
    fail,
    read_env_provider,
    write_env_setting,
)
from stremioguard.init import (
    configure_external_access,
    configure_optional_stremio_settings,
    print_manual_setup_pointer,
    prompt_provider,
)
from stremioguard.nordvpn import configure_nordvpn

APP = typer.Typer(
    help="Start and guard Stremio behind the gluetun VPN container.",
    no_args_is_help=False,
)
COMET_APP = typer.Typer(help="Manage the modular Comet playback-proxy subsystem.")
APP.add_typer(COMET_APP, name="comet")

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = ROOT_DIR / "logs"
STATE_DIR = ROOT_DIR / ".stremio"
PID_FILE = STATE_DIR / "watchdog.pid"
UV_CACHE = ROOT_DIR / ".uv-cache"
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE = ROOT_DIR / ".env.example"
WATCHDOG_CMDLINE_MARKER = "stremio-vpn"

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
    "<cyan>stremio</cyan> | <level>{message}</level>",
    level="INFO",
    colorize=sys.stdout.isatty(),
)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    log_file: Path

    @classmethod
    def create(cls) -> RunContext:
        run_id = os.environ.get("STREMIO_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = Path(os.environ.get("STREMIO_LOG_FILE", LOG_DIR / f"stremio-{run_id}.log"))
        return cls(run_id=run_id, log_file=log_file)

    def env(self, *, background: bool = False, file_logging: bool = True) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("INSTALL_MISSING_DEPS", "1")
        env["STREMIO_RUN_ID"] = self.run_id
        if file_logging:
            env["STREMIO_LOG_FILE"] = str(self.log_file)
            env["STREMIO_LOG_SESSION"] = "1"
        else:
            env.pop("STREMIO_LOG_FILE", None)
            env["STREMIO_LOG_SESSION"] = "0"
        if background:
            env["STREMIO_BACKGROUND"] = "1"
        return env


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
    return WATCHDOG_CMDLINE_MARKER in cmdline and "watchdog" in cmdline


def _watchdog_pid() -> int | None:
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

    pid = _watchdog_pid()
    if pid:
        logger.info(f"Watchdog already running with PID {pid}.")
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
    pid = _watchdog_pid()
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


def _latest_log() -> Path | None:
    if not LOG_DIR.exists():
        return None
    logs = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


def _comet_manager() -> CometManager:
    return CometManager(CometConfig.from_env(ROOT_DIR))


def _comet_enabled() -> bool:
    return CometConfig.from_env(ROOT_DIR).enabled


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _warn_for_optional_stremio_settings() -> None:
    patches_enabled = env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=ENV_FILE)
    skip_hw_probe_enabled = env_flag_enabled("STREMIO_SKIP_HW_PROBE", True, env_path=ENV_FILE)

    if not patches_enabled:
        logger.warning(
            "STREMIO_APPLY_PATCHES=0. Running the upstream Stremio image behavior without "
            "the local compatibility fixes. Use `./stremio restart` after changing this "
            "setting so Docker rebuilds the image."
        )
    elif not skip_hw_probe_enabled:
        logger.warning(
            "STREMIO_SKIP_HW_PROBE=0. /device-info may re-run hardware probe checks and "
            "add noisy reconnect logs."
        )


@APP.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start Stremio when no command is provided."""
    if ctx.invoked_subcommand is None:
        if env_needs_init(ENV_FILE):
            if is_interactive():
                logger.info(".env not configured; running first-time setup.")
                init()
                return
            fail(".env missing or WIREGUARD_PRIVATE_KEY unpopulated. Run `./stremio init`.")
        start()


@APP.command()
def init() -> None:
    """First-time setup: create .env, configure VPN credentials, then start."""
    if not is_interactive():
        fail("`init` needs an interactive terminal (stdin/stdout must be a TTY).")

    if not ENV_FILE.exists():
        if not ENV_EXAMPLE.exists():
            fail(f"{ENV_EXAMPLE.name} not found; cannot bootstrap .env.")
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        logger.success(f"Created {ENV_FILE.name} from {ENV_EXAMPLE.name}.")
    else:
        logger.info(f"{ENV_FILE.name} already exists.")

    configure_external_access(ENV_FILE)
    configure_optional_stremio_settings(ENV_FILE)
    existing_comet = CometConfig.from_env(ROOT_DIR).enabled
    if typer.confirm(
        "Configure the optional Comet playback-proxy subsystem?",
        default=existing_comet,
    ):
        prompt_comet_setup(CometConfig.from_env(ROOT_DIR))
    elif existing_comet:
        write_env_setting(ENV_FILE, "COMET_ENABLED", "0")
        logger.info("Comet disabled in .env. The unified stack will skip it on the next start.")

    logger.info("Pulling the latest VPN container image...")
    run_guard("pull", file_logging=False)

    provider = prompt_provider(read_env_provider(ENV_FILE))
    if provider == "nordvpn":
        logger.info("Walking through NordVPN credential setup.")
        configure_nordvpn(ENV_FILE)
        logger.info("Setup complete. Restarting Stremio so Docker reloads the updated VPN config.")
        restart()
        return

    print_manual_setup_pointer()


@APP.command()
def start() -> None:
    """Initialize if needed, start Stremio, and launch the watchdog."""
    _warn_for_optional_stremio_settings()
    comet_manager = _comet_manager() if _comet_enabled() else None
    if comet_manager is not None:
        comet_manager.prepare_runtime()
    context = RunContext.create()
    run_guard("start", context=context)
    if comet_manager is not None:
        comet_manager.start()
    _start_watchdog(context)


@APP.command()
def restart() -> None:
    """Reset/build/start Stremio and relaunch the watchdog."""
    _warn_for_optional_stremio_settings()
    comet_manager = _comet_manager() if _comet_enabled() else None
    if comet_manager is not None:
        comet_manager.prepare_runtime()
    context = RunContext.create()
    _stop_watchdog()
    run_guard("reset", context=context)
    if comet_manager is not None:
        comet_manager.start()
    _start_watchdog(context)


@APP.command()
def stop() -> None:
    """Stop the watchdog and Stremio."""
    _stop_watchdog()
    if _comet_enabled():
        _comet_manager().stop()
    run_guard("stop", file_logging=False)


@APP.command()
def status() -> None:
    """Show VPN, public IP, and container status."""
    run_guard("status", file_logging=False)
    if _comet_enabled():
        logger.info("--- Comet ---")
        _comet_manager().status()


@APP.command()
def logs(lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show.")) -> None:
    """Tail the latest run log."""
    log_file = _latest_log()
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
    _require_uv()
    subprocess.run(_uv_command("ruff", "format", "--check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("ruff", "check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pyright"), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pytest"), check=True, cwd=ROOT_DIR)


@COMET_APP.command("install")
def comet_install() -> None:
    """Clone/pin Comet and write local runtime configuration."""
    config = CometConfig.from_env(ROOT_DIR)
    if not is_interactive():
        fail("`./stremio comet install` needs an interactive terminal.")
    prompt_comet_setup(config)
    manager = CometManager(CometConfig.from_env(ROOT_DIR))
    manager.install()
    logger.success("Comet is installed and configured locally.")


@COMET_APP.command("update")
def comet_update() -> None:
    """Fetch Comet upstream refs and re-checkout the pinned commit."""
    manager = _comet_manager()
    manager.fetch_and_checkout_pinned()
    logger.success("Comet checkout refreshed to the pinned commit.")


@COMET_APP.command("start")
def comet_start() -> None:
    """Start the Comet stack managed by StremioGuard."""
    manager = _comet_manager()
    manager.start()


@COMET_APP.command("stop")
def comet_stop() -> None:
    """Stop the Comet stack."""
    manager = _comet_manager()
    manager.stop()


@COMET_APP.command("status")
def comet_status() -> None:
    """Show Comet repo and container status."""
    manager = _comet_manager()
    manager.status()


@COMET_APP.command("doctor")
def comet_doctor() -> None:
    """Validate the local Comet proxy deployment."""
    manager = _comet_manager()
    manager.doctor()


@COMET_APP.command("probe-playback")
def comet_probe_playback(
    url: str = typer.Option(..., "--url", help="Comet playback URL to probe."),
) -> None:
    """Probe a Comet playback URL to verify it stays on the proxy path."""
    manager = _comet_manager()
    result = manager.probe_playback(url, expect_proxy=manager.config.proxy_debrid_stream)
    logger.info(
        f"Playback probe classification={result.classification} "
        f"status={result.status_code} location={result.location or '-'} "
        f"content_type={result.content_type or '-'}"
    )


@COMET_APP.command("logs")
def comet_logs(
    lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show."),
) -> None:
    """Tail the Comet service logs."""
    manager = _comet_manager()
    manager.prepare_runtime()
    root_config = Config.from_env()
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(root_config.compose_file),
            "-f",
            str(root_config.compose_override_file),
            "logs",
            "-f",
            "--tail",
            str(lines),
            manager.config.service_name,
            manager.config.postgres_service_name,
        ],
        check=False,
    )


if __name__ == "__main__":
    APP()
