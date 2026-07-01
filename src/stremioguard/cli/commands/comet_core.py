from __future__ import annotations

import subprocess

import typer
from loguru import logger

from stremioguard.cli.commands.general import is_interactive
from stremioguard.cli.context import ROOT_DIR, _comet_manager
from stremioguard.comet import CometManager, prompt_comet_setup
from stremioguard.config import CometConfig, Config
from stremioguard.env import env_file_value, fail


def comet_install() -> None:
    """Clone/pin Comet and write local runtime configuration."""
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
    manager.install()
    logger.success("Comet is installed and configured locally.")


def comet_update() -> None:
    """Fetch Comet upstream refs and re-checkout the pinned commit."""
    manager = _comet_manager()
    manager.fetch_and_checkout_pinned()
    logger.success("Comet checkout refreshed to the pinned commit.")


def comet_start() -> None:
    """Start the Comet stack managed by StremioGuard."""
    manager = _comet_manager()
    manager.start()


def comet_stop() -> None:
    """Stop the Comet stack."""
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


def comet_vendor_sync() -> None:
    """Sync the Comet vendor checkout to the pinned commit (for maintainers)."""
    manager = _comet_manager()
    manager.fetch_and_checkout_pinned()
    logger.success("Synced Comet vendor checkout.")


def register(app: typer.Typer) -> None:
    app.command("install")(comet_install)
    app.command("update")(comet_update)
    app.command("start")(comet_start)
    app.command("stop")(comet_stop)
    app.command("status")(comet_status)
    app.command("doctor")(comet_doctor)
    app.command("probe-playback")(comet_probe_playback)
    app.command("logs")(comet_logs)
    app.command("vendor-sync", hidden=True)(comet_vendor_sync)
