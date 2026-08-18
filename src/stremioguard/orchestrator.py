"""Stremio lifecycle management, watchdog loop, and daemon CLI."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable

import typer
from loguru import logger

from stremioguard.config import (
    CIRCUIT_BREAKER_EXIT_CODE,
    DEFAULT_VPN_FAILOVER_ESCALATION_RATIO,
    CometConfig,
    Config,
    docker_daemon_help,
    docker_permission_help,
)
from stremioguard.guard import GluetunGuard, PublicIPAssessment

app = typer.Typer(
    help="Guard Stremio behind the gluetun VPN container.",
    no_args_is_help=True,
    context_settings={"color": True},
)

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
        self.consecutive_loop_errors = 0
        self.consecutive_ip_unknowns = 0
        self.loop_error_count = 0
        self.loop_errors_since_summary = 0
        self.outage_started_at: float | None = None
        self.outage_start_wall: float | None = None
        self.last_auth_check_wall: float | None = None
        self.last_restart_at: float = 0.0
        self.escalation_triggered: bool = False
        if self.guard.config.log_session:
            self._log_session_start()

    def elapsed_seconds(self) -> int:
        return int(time.monotonic() - self.started_at)

    def _log_session_start(self) -> None:
        cfg = self.guard.config
        self.guard.log(
            "Session metadata "
            f"run_id={cfg.run_id} "
            f"deployment_profile={self.guard.deployment_profile()} "
            f"gluetun_service={cfg.gluetun_container_name} "
            f"watch_interval_seconds={cfg.watch_interval_seconds} "
            f"watchdog_log_interval_seconds={cfg.watchdog_log_interval_seconds}"
        )

    def setup_active_services(self, *, reset: bool = True) -> None:
        g = self.guard
        if g.config.stremio_enabled:
            g.ensure_data_dir()
        services = g.enabled_runtime_services()
        if reset:
            g.log("Resetting Compose instance.")
            g.compose(
                "down",
                "--remove-orphans",
                "--timeout",
                "10",
                check=False,
                capture=False,
            )
            time.sleep(2)
        if g.preflight(allow_recovery=True, defer_vpn_recovery=True) is False:
            return
        g.log(f"Building services: {', '.join(services)}.")
        g.compose_fresh("build", *services, capture=False)
        g.log(f"Starting services: {', '.join(services)}.")
        g.compose_fresh("up", "-d", *services, capture=False)
        g.success("Active services are running behind gluetun.")
        self._comet_update_advisory()

    def start_active_services(self) -> None:
        if not self.guard.compose_instance_exists():
            self.guard.log("No Compose instance found; running first-time setup.")
            self.setup_active_services(reset=False)
            return

        g = self.guard
        if g.config.stremio_enabled:
            g.ensure_data_dir()
        if g.preflight(allow_recovery=False, defer_vpn_recovery=True) is False:
            return
        services = g.enabled_runtime_services()
        g.log(f"Starting services: {', '.join(services)}.")
        g.compose_fresh("up", "-d", *services, capture=False)
        g.success("Active services are running behind gluetun.")
        self._comet_update_advisory()

    def _comet_update_advisory(self) -> None:
        # Plan 5.2: advisory-only, runs AFTER services are up so it can never
        # delay a start/restart. Deferred import to avoid a circular import
        # (orchestrator -> comet.manager -> publishing -> config), matching
        # guard.preflight()'s existing pattern. The whole body is guarded, not
        # just the manager call: CometConfig.from_env raises on a bad
        # mid-flight .env edit, and no advisory path may fail a start that
        # already succeeded.
        try:
            comet_config = CometConfig.from_env(self.guard.config.root_dir)
            if not comet_config.enabled:
                return
            from stremioguard.comet import CometManager

            CometManager(comet_config, self.guard.runner).advisory_update_check()
        except Exception:
            logger.opt(exception=True).debug("Comet update advisory skipped due to an error.")

    def watch_stremio(self) -> None:
        self.guard.require_commands()
        self.guard.log(
            "Watching gluetun and active services: "
            f"{', '.join(self.guard.enabled_public_services())} "
            f"every {self.guard.config.watch_interval_seconds}s."
        )
        while True:
            try:
                self.watch_once()
                self.consecutive_loop_errors = 0
            except (typer.Exit, SystemExit, KeyboardInterrupt):
                raise
            except Exception:
                logger.exception("Watchdog loop iteration encountered an error.")
                self.consecutive_loop_errors += 1
                self.loop_error_count += 1
                self.loop_errors_since_summary += 1
                if self.consecutive_loop_errors >= 3:
                    self.guard.warn(
                        f"Watchdog has encountered {self.consecutive_loop_errors} consecutive "
                        "loop errors. Attempting to stop active services to fail closed."
                    )
                    try:
                        self.guard.stop_active_services()
                    except Exception:
                        logger.exception(
                            "Failed to stop active services during loop error fallback."
                        )
            time.sleep(self.guard.config.watch_interval_seconds)

    def _trip_circuit_breaker(self, reason: str) -> None:
        elapsed = (
            time.monotonic() - self.outage_started_at if self.outage_started_at is not None else 0.0
        )
        self.guard.warn(
            f"Circuit breaker tripped ({reason}). "
            "Persisting lockout marker and initiating fail-closed stack shutdown."
        )
        # Attempt to write atomic lockout marker BEFORE stopping containers.
        # Guarded so that filesystem/disk errors cannot bypass container shutdown or exit 78.
        try:
            self.guard.write_vpn_lockout(reason=reason, outage_duration_seconds=elapsed)
        except Exception:
            logger.exception("Failed to write VPN lockout marker during circuit breaker trip.")
        finally:
            try:
                self.guard.stop_active_services()
            finally:
                try:
                    self.guard.stop_gluetun()
                finally:
                    raise typer.Exit(code=CIRCUIT_BREAKER_EXIT_CODE)

    def _handle_unhealthy_ip_assessment(
        self, assessment: PublicIPAssessment, services: list[str]
    ) -> None:
        g = self.guard
        if assessment == PublicIPAssessment.UNSAFE_DEFINITIVE:
            self.last_public_ip = g.last_observed_ip or self.last_public_ip
            g.warn("Definitive leak / unsafe IP detected. Stopping active services immediately.")
            self.public_ip_failure_count += 1
            self.public_ip_failures_since_summary += 1
            self.consecutive_ip_unknowns = 0
            g.stop_active_services(services=services)
            self._maybe_log_summary()
        elif assessment == PublicIPAssessment.UNKNOWN:
            self.consecutive_ip_unknowns += 1
            limit = self.guard.config.public_ip_failure_threshold
            g.warn(
                f"Public IP check returned UNKNOWN "
                f"({self.consecutive_ip_unknowns}/{limit} consecutive failures)."
            )
            if self.consecutive_ip_unknowns >= self.guard.config.public_ip_failure_threshold:
                self.last_public_ip = g.last_observed_ip or self.last_public_ip
                g.warn(
                    f"Public IP check has failed {self.consecutive_ip_unknowns} consecutive times. "
                    "Stopping active services to fail closed."
                )
                self.public_ip_failure_count += 1
                self.public_ip_failures_since_summary += 1
                g.stop_active_services(services=services)
            self._maybe_log_summary()

    def watch_once(self) -> None:
        g = self.guard
        self.checks_since_summary += 1
        services = g.enabled_runtime_services()

        if not g.gluetun_healthy():
            budget = g.config.vpn_recovery_budget_seconds
            now_mono = time.monotonic()
            now_wall = time.time()

            if self.outage_started_at is None:
                self.outage_started_at = now_mono
                self.outage_start_wall = now_wall
                self.last_auth_check_wall = now_wall
                self.last_restart_at = now_mono
                self.vpn_drop_count += 1
                self.vpn_drops_since_summary += 1
                g.warn(
                    "Gluetun is not healthy. Outage detected; entering recovery window "
                    f"(budget: {budget}s)."
                )
                g.stop_active_services(services=services)
                # Bounded tail scan on tick 1 to catch the auth rejection that triggered the outage:
                if g.gluetun_auth_failed(lines=100, since_epoch=None):
                    self._trip_circuit_breaker(reason="auth_rejected")

                # Restart Gluetun (best-effort candidate reselection)
                g.restart_gluetun()
                self._maybe_log_summary()
                return

            # Incremental bounded log check since previous probe
            check_since = self.last_auth_check_wall or self.outage_start_wall
            self.last_auth_check_wall = now_wall
            if g.gluetun_auth_failed(since_epoch=check_since):
                self._trip_circuit_breaker(reason="auth_rejected")

            elapsed = now_mono - self.outage_started_at
            if elapsed >= budget:
                self._trip_circuit_breaker(reason="recovery_budget_exhausted")

            # Check for hybrid failover escalation (at 50% of budget)
            has_narrow_filter = bool(
                g.config.server_cities
                or g.config.server_hostnames
                or g.config.server_regions
                or g.config.server_categories
            )
            if (
                has_narrow_filter
                and not self.escalation_triggered
                and elapsed >= (budget * DEFAULT_VPN_FAILOVER_ESCALATION_RATIO)
            ):
                country = g.config.server_countries or "United States"
                g.warn(
                    f"Preferred location did not recover within {int(elapsed)}s. "
                    f"Escalating to broad country pool ({country})."
                )
                g.restart_gluetun_relaxed()
                self.escalation_triggered = True
                self.last_restart_at = now_mono
                self._maybe_log_summary()
                return

            # Check restart cadence
            if now_mono - self.last_restart_at >= g.config.vpn_restart_cadence_seconds:
                self.last_restart_at = now_mono
                if self.escalation_triggered:
                    g.restart_gluetun_relaxed()
                else:
                    g.restart_gluetun()

            self._maybe_log_summary()
            return

        # Gluetun is healthy
        if self.outage_started_at is not None:
            assessment = g.public_ip_assessment()
            if assessment != PublicIPAssessment.SAFE:
                self._handle_unhealthy_ip_assessment(assessment, services)
                return

            g.clear_vpn_lockout()
            if self.escalation_triggered:
                g.log("Gluetun recovered under broad country fallback. Resuming active services.")
            else:
                g.log("Gluetun has recovered and is healthy. Resuming active services.")

            self.outage_started_at = None
            self.outage_start_wall = None
            self.last_auth_check_wall = None
            self.last_restart_at = 0.0
            self.escalation_triggered = False

            if not g.container_running(services=services):
                self.auto_starts_since_summary += 1
                g.compose_fresh("up", "-d", "--build", *services, check=False, capture=False)

            self.last_public_ip = g.last_observed_ip or self.last_public_ip
            self._maybe_log_summary()
            return

        # Normal steady-state monitoring
        assessment = g.public_ip_assessment()
        if assessment != PublicIPAssessment.SAFE:
            self._handle_unhealthy_ip_assessment(assessment, services)
            return

        self.consecutive_ip_unknowns = 0
        self.last_public_ip = g.last_observed_ip or self.last_public_ip

        if not g.container_running(services=services):
            g.log("Gluetun healthy; starting active services.")
            self.auto_starts_since_summary += 1
            g.compose_fresh("up", "-d", "--build", *services, check=False, capture=False)

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
            f"loop_errors={self.loop_errors_since_summary} "
            f"uptime_seconds={self.elapsed_seconds()}"
        )
        self.summary_started_at = now
        self.checks_since_summary = 0
        self.auto_starts_since_summary = 0
        self.container_missing_since_summary = 0
        self.vpn_drops_since_summary = 0
        self.public_ip_failures_since_summary = 0
        self.loop_errors_since_summary = 0

    def show_status(self) -> None:
        g = self.guard
        g.require_commands()
        logger.info(f"--- Active Profile: {g.deployment_profile()} ---")
        logger.info("--- Gluetun ---")
        logger.info("healthy" if g.gluetun_healthy() else "not healthy / not running")
        logger.info("--- Public IP (via gluetun) ---")
        logger.info(g.public_ip_via_gluetun() or "unavailable")
        logger.info("--- Home IP baseline ---")
        age = g.home_ip_age_seconds()
        if age is None:
            logger.info("not recorded (run `./stremio record-home-ip`)")
        else:
            logger.info(f"{int(age // 86400)} days old")
        logger.info("--- Containers ---")
        for service in g.enabled_runtime_services():
            result = g.compose("ps", service, check=False)
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
    except (typer.Exit, SystemExit):
        raise
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
    """Reset/build/start active services safely."""
    _run_command(lambda o: o.setup_active_services(reset=True))


@app.command(hidden=True)
def pull() -> None:
    """Pull the latest gluetun image."""

    def _pull(o: Orchestrator) -> None:
        o.guard.require_commands()
        o.guard.log("Pulling latest image for the gluetun service.")
        o.guard.compose("pull", "gluetun", capture=False)

    _run_command(_pull)


@app.command()
def start() -> None:
    """Initialize if needed and start active services."""
    _run_command(lambda o: o.start_active_services())


@app.command(hidden=True)
def watchdog() -> None:
    """Run the watchdog loop and auto-start active services when gluetun is healthy."""
    _run_command(lambda o: o.watch_stremio())


@app.command()
def stop() -> None:
    """Stop active services."""

    def _stop(o: Orchestrator) -> None:
        o.guard.require_commands()
        o.guard.stop_active_services()

    _run_command(_stop)


@app.command()
def status() -> None:
    """Show gluetun, public IP, and container status."""
    _run_command(lambda o: o.show_status())


@app.command("record-home-ip")
def record_home_ip() -> None:
    """Save current public IP as leak-detection baseline."""
    _run_command(lambda o: o.record_home_ip())


@app.command()
def unlock() -> None:
    """Clear active VPN circuit breaker lockout."""

    def _unlock(o: Orchestrator) -> None:
        o.guard.clear_vpn_lockout()

    _run_command(_unlock)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
