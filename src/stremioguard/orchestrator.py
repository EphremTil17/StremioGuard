"""Stremio lifecycle management, watchdog loop, and daemon CLI."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable

import typer
from loguru import logger

from stremioguard.config import Config, docker_daemon_help, docker_permission_help
from stremioguard.guard import GluetunGuard

app = typer.Typer(help="Guard Stremio behind the gluetun VPN container.", no_args_is_help=True)

logger.remove()
if os.environ.get("STREMIO_BACKGROUND") != "1":
    logger.add(
        sys.stdout,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
        "<cyan>stremio-vpn</cyan> | <level>{message}</level>",
        level="INFO",
        colorize=sys.stdout.isatty(),
    )


class Orchestrator:
    def __init__(self, guard: GluetunGuard) -> None:
        self.guard = guard
        self.started_at = time.monotonic()
        self.summary_started_at = self.started_at
        self.last_public_ip: str | None = None
        self.vpn_drop_count = 0
        self.public_ip_failure_count = 0
        self.checks_since_summary = 0
        self.auto_starts_since_summary = 0
        self.container_missing_since_summary = 0
        self.vpn_drops_since_summary = 0
        self.public_ip_failures_since_summary = 0
        if self.guard.config.log_session:
            self._log_session_start()

    def elapsed_seconds(self) -> int:
        return int(time.monotonic() - self.started_at)

    def _log_session_start(self) -> None:
        cfg = self.guard.config
        self.guard.log(
            "Session metadata "
            f"run_id={cfg.run_id} "
            f"service={cfg.service_name} "
            f"container={cfg.container_name} "
            f"gluetun_container={cfg.gluetun_container_name} "
            f"watch_interval_seconds={cfg.watch_interval_seconds} "
            f"watchdog_log_interval_seconds={cfg.watchdog_log_interval_seconds}"
        )

    def setup_stremio(self, *, reset: bool = True) -> None:
        g = self.guard
        g.ensure_data_dir()
        if reset:
            g.log("Resetting Compose instance without deleting stremio-data.")
            g.compose("down", "--remove-orphans", check=False, capture=False)
        g.preflight()
        g.log(
            f"Running: docker compose -f {g.config.compose_file} "
            f"-f {g.config.compose_override_file} build {g.config.service_name}"
        )
        g.compose("build", g.config.service_name, capture=False)
        g.log(f"Starting {g.config.service_name}.")
        g.log(
            f"Running: docker compose -f {g.config.compose_file} "
            f"-f {g.config.compose_override_file} up -d {g.config.service_name}"
        )
        g.compose("up", "-d", g.config.service_name, capture=False)
        g.success("Stremio is running behind gluetun.")

    def start_stremio(self) -> None:
        if not self.guard.compose_instance_exists():
            self.guard.log("No Compose instance found; running first-time setup.")
            self.setup_stremio(reset=False)
            return

        g = self.guard
        g.ensure_data_dir()
        g.preflight()
        g.log(f"Starting {g.config.service_name}.")
        g.log(
            f"Running: docker compose -f {g.config.compose_file} "
            f"-f {g.config.compose_override_file} up -d {g.config.service_name}"
        )
        g.compose("up", "-d", g.config.service_name, capture=False)
        g.success("Stremio is running behind gluetun.")

    def watch_stremio(self) -> None:
        self.guard.require_commands()
        self.guard.log(
            f"Watching gluetun and {self.guard.config.container_name} "
            f"every {self.guard.config.watch_interval_seconds}s."
        )
        while True:
            self.watch_once()
            time.sleep(self.guard.config.watch_interval_seconds)

    def watch_once(self) -> None:
        g = self.guard
        self.checks_since_summary += 1

        if not g.gluetun_healthy():
            g.warn("Gluetun is not healthy. Stopping Stremio.")
            self.vpn_drop_count += 1
            self.vpn_drops_since_summary += 1
            g.stop_stremio()
            self._maybe_log_summary()
            return

        if not g.public_ip_safe():
            self.last_public_ip = g.last_observed_ip or self.last_public_ip
            g.warn("Public IP check failed. Stopping Stremio.")
            self.public_ip_failure_count += 1
            self.public_ip_failures_since_summary += 1
            g.stop_stremio()
            self._maybe_log_summary()
            return

        self.last_public_ip = g.last_observed_ip or self.last_public_ip

        if not g.container_running():
            g.log("Gluetun healthy; starting Stremio.")
            self.auto_starts_since_summary += 1
            g.compose("up", "-d", g.config.service_name, capture=False)

        self._maybe_log_summary()

    def _maybe_log_summary(self) -> None:
        now = time.monotonic()
        interval = self.guard.config.watchdog_log_interval_seconds
        if interval > 0 and now - self.summary_started_at < interval:
            return

        summary_seconds = int(now - self.summary_started_at)
        self.guard.log(
            "Watchdog summary "
            f"window_seconds={summary_seconds} "
            f"checks={self.checks_since_summary} "
            f"last_public_ip={self.last_public_ip or 'unavailable'} "
            f"auto_starts={self.auto_starts_since_summary} "
            f"container_missing={self.container_missing_since_summary} "
            f"vpn_drops={self.vpn_drops_since_summary} "
            f"public_ip_failures={self.public_ip_failures_since_summary} "
            f"uptime_seconds={self.elapsed_seconds()}"
        )
        self.summary_started_at = now
        self.checks_since_summary = 0
        self.auto_starts_since_summary = 0
        self.container_missing_since_summary = 0
        self.vpn_drops_since_summary = 0
        self.public_ip_failures_since_summary = 0

    def show_status(self) -> None:
        g = self.guard
        g.require_commands()
        logger.info("--- Gluetun ---")
        logger.info("healthy" if g.gluetun_healthy() else "not healthy / not running")
        logger.info("--- Public IP (via gluetun) ---")
        logger.info(g.public_ip_via_gluetun() or "unavailable")
        logger.info("--- Container ---")
        result = g.runner.run(
            [
                "docker",
                "ps",
                "--filter",
                f"name=^/{g.config.container_name}$",
                "--format",
                "table {{.Names}}\t{{.Status}}\t{{.Ports}}",
            ],
            check=False,
        )
        g.log_lines((result.stdout or "").rstrip())

    def record_home_ip(self) -> None:
        g = self.guard
        if g.gluetun_healthy():
            raise RuntimeError(
                "Gluetun is healthy; refusing to record a VPN IP as the home baseline. "
                "Stop gluetun first (`docker compose stop gluetun`), then rerun."
            )

        ip = g.public_ip()
        if not ip:
            raise RuntimeError("Could not determine public IP.")

        if g.config.expected_vpn_ip and ip == g.config.expected_vpn_ip:
            raise RuntimeError(
                f"Observed IP {ip} matches EXPECTED_VPN_IP; refusing to save it as the home "
                "baseline. Disconnect any active VPN and rerun."
            )

        if g.config.home_ip_file.exists():
            previous = g.config.home_ip_file.read_text(encoding="utf-8").strip()
            if previous and previous != ip:
                g.warn(f"Overwriting existing home IP baseline {previous} with {ip}.")

        g.config.home_ip_file.parent.mkdir(parents=True, exist_ok=True)
        g.config.home_ip_file.write_text(f"{ip}\n", encoding="utf-8")
        g.log(f"Saved {ip} to {g.config.home_ip_file}.")


def configure_file_logging(config: Config) -> None:
    if not config.log_file:
        return
    config.log_file.parent.mkdir(parents=True, exist_ok=True)
    logger.add(
        config.log_file,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | stremio-vpn | {message}",
        level="INFO",
        rotation="10 MB",
        retention="30 days",
        enqueue=True,
    )
    logger.info(f"Writing run log to {config.log_file}")


def _run_command(action: Callable[[Orchestrator], None]) -> None:
    config = Config.from_env()
    configure_file_logging(config)
    guard = GluetunGuard(config)
    orch = Orchestrator(guard)
    try:
        action(orch)
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        raise typer.Exit(130) from None
    except subprocess.CalledProcessError as error:
        detail = f"{error.stdout or ''}\n{error.stderr or ''}".strip()
        help_text = docker_permission_help(detail)
        if help_text is None and error.cmd and str(error.cmd[0]) == "docker":
            help_text = docker_daemon_help(guard.runner)
        if help_text:
            guard.warn(help_text)
        else:
            guard.warn(
                f"Command failed with exit status {error.returncode}: "
                f"{' '.join(str(part) for part in error.cmd)}"
            )
            if detail:
                logger.error(detail)
        raise typer.Exit(1) from None
    except RuntimeError as error:
        logger.error(str(error))
        raise typer.Exit(1) from None


@app.command(hidden=True)
def reset() -> None:
    """Reset/build/start the Compose instance safely."""
    _run_command(lambda o: o.setup_stremio(reset=True))


@app.command(hidden=True)
def pull() -> None:
    """Pull the latest gluetun image."""
    def _pull(o: Orchestrator) -> None:
        o.guard.require_commands()
        o.guard.log(f"Pulling latest image for {o.guard.config.gluetun_container_name}.")
        o.guard.compose("pull", o.guard.config.gluetun_container_name, capture=False)

    _run_command(_pull)


@app.command()
def start() -> None:
    """Initialize if needed and start Stremio."""
    _run_command(lambda o: o.start_stremio())


@app.command(hidden=True)
def watchdog() -> None:
    """Run the watchdog loop and auto-start Stremio when gluetun is healthy."""
    _run_command(lambda o: o.watch_stremio())


@app.command()
def stop() -> None:
    """Stop Stremio."""

    def _stop(o: Orchestrator) -> None:
        o.guard.require_commands()
        o.guard.stop_stremio()

    _run_command(_stop)


@app.command()
def status() -> None:
    """Show gluetun, public IP, and container status."""
    _run_command(lambda o: o.show_status())


@app.command("record-home-ip")
def record_home_ip() -> None:
    """Save current public IP as leak-detection baseline."""
    _run_command(lambda o: o.record_home_ip())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
