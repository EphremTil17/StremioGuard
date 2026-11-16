from __future__ import annotations

import subprocess

import typer
from loguru import logger

from stremioguard.cli import supervisor
from stremioguard.cli.commands.general import is_interactive
from stremioguard.cli.context import ROOT_DIR, _comet_manager
from stremioguard.comet import CometManager, prompt_comet_setup
from stremioguard.comet.database import rotate_postgres_password
from stremioguard.config import CometConfig, Config, compose_command
from stremioguard.env import env_file_value, fail
from stremioguard.stacklock import required_stack_lock

ROTATE_LOCK_WAIT_SECONDS = 60


def comet_install(
    deep: bool = typer.Option(
        False,
        "--deep",
        help=(
            "Also boot the candidate image ephemerally with no network access and "
            "check /health before accepting it."
        ),
    ),
) -> None:
    """Pin/validate the Comet runtime image and write local configuration."""
    config = CometConfig.from_env(ROOT_DIR)
    if not is_interactive():
        fail("`./stremio comet install` needs an interactive terminal.")
    # Detect if reverse-proxied from existing env values:
    env_file = ROOT_DIR / ".env"
    ext_url = env_file_value(env_file, "EXTERNAL_BASE_URL")
    comet_gateway_url = env_file_value(env_file, "COMET_GATEWAY_PUBLIC_BASE_URL")
    comet_url = env_file_value(env_file, "COMET_PUBLIC_BASE_URL")

    if (
        (ext_url is not None and ext_url.strip() != "")
        or (comet_gateway_url is not None and comet_gateway_url.strip() != "")
        or (comet_url is not None and comet_url.strip() != "")
    ):
        is_proxied = True
    else:
        typer.echo("How will clients reach your Comet proxy?")
        typer.echo("  1) LAN + Tailscale only — no public domain  [default]")
        typer.echo("  2) Reverse-proxied behind a domain (NPM, Caddy, Traefik, raw nginx)")
        choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
        is_proxied = choice in {"2", "proxy", "domain", "reverse-proxy"}

    prompt_comet_setup(config, is_proxied=is_proxied)
    manager = CometManager(CometConfig.from_env(ROOT_DIR))
    manager.install(deep=deep)
    logger.success("Comet is installed and configured locally.")


def comet_start() -> None:
    """Start the Comet stack managed by StremioGuard."""
    supervisor.require_supervised_stack()
    manager = _comet_manager()
    manager.start()


def comet_stop() -> None:
    """Stop the Comet stack."""
    running = supervisor.watchdog_running()
    if running is None:
        fail(
            "Could not verify whether the watchdog is running (systemd user manager is "
            "unavailable); refusing to stop Comet alone because an active watchdog would "
            "restart it. Run `./stremio stop` or retry with the systemd user bus reachable."
        )
    if running:
        try:
            stremio_enabled = Config.from_env(ROOT_DIR).stremio_enabled
        except (RuntimeError, ValueError):
            stremio_enabled = None
        if stremio_enabled is False:
            fail(
                "The watchdog is running and would immediately restart Comet. "
                "Use `./stremio stop` to stop the stack."
            )
        if stremio_enabled is True:
            fail(
                "The watchdog is running and would immediately restart Comet. "
                "To drop Comet while keeping Stremio running, set COMET_ENABLED=0 in .env "
                "and run `./stremio start` (or run `./stremio stop` to stop the whole stack)."
            )
        fail(
            "The watchdog is running and would immediately restart Comet. "
            "Run `./stremio stop` (or set COMET_ENABLED=0 and run `./stremio start`)."
        )
    manager = _comet_manager()
    manager.stop()


def comet_status() -> None:
    """Show Comet repo and container status."""
    manager = _comet_manager()
    manager.status()


def comet_doctor() -> None:
    """Validate the local Comet proxy deployment."""
    manager = _comet_manager()
    manager.doctor()


def comet_log_canary() -> None:
    """Prove no log sink records addon request paths (exit 1 unless every sink passes)."""
    manager = _comet_manager()
    if not manager.log_canary().passed:
        raise typer.Exit(1)


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


def comet_logs(
    lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show."),
) -> None:
    """Tail the Comet service logs."""
    manager = _comet_manager()
    subprocess.run(
        compose_command(
            ROOT_DIR, "logs", "-f", "--tail", str(lines), *manager.config.runtime_services
        ),
        check=False,
    )


def comet_rotate_db_password() -> None:
    """Rotate Comet's Postgres password offline (requires the stack to be stopped)."""
    try:
        manager = _comet_manager()
    except (RuntimeError, ValueError) as error:
        fail(str(error))
    if not manager.config.enabled:
        fail("Comet is disabled (`COMET_ENABLED=0`); cannot rotate its Postgres password.")
    running = supervisor.watchdog_running()
    if running is None:
        fail(
            "Could not verify whether the watchdog is running (systemd user manager is "
            "unavailable); refusing to rotate the Postgres password because an active "
            "watchdog could start Postgres during rotation."
        )
    if running:
        fail(
            "The watchdog is running and could restart Postgres during rotation. "
            "Run `./stremio stop` first."
        )
    try:
        with required_stack_lock(
            ROOT_DIR,
            wait_seconds=ROTATE_LOCK_WAIT_SECONDS,
            purpose="rotate the Comet Postgres password",
        ):
            rotate_postgres_password(manager)
    except RuntimeError as error:
        fail(str(error))


def register(app: typer.Typer) -> None:
    app.command("install")(comet_install)
    app.command("start")(comet_start)
    app.command("stop")(comet_stop)
    app.command("status")(comet_status)
    app.command("doctor")(comet_doctor)
    app.command("log-canary")(comet_log_canary)
    app.command("probe-playback")(comet_probe_playback)
    app.command("logs")(comet_logs)
    app.command("rotate-db-password")(comet_rotate_db_password)
