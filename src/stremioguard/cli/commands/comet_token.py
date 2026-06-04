from __future__ import annotations

import subprocess

import typer
from loguru import logger

from stremioguard.cli.context import (
    _comet_enabled,
    _comet_gateway_manager,
    _comet_manager,
)
from stremioguard.comet_gateway import CometGatewayManager
from stremioguard.config import Config
from stremioguard.env import fail


def _refresh_comet_gateway_after_token_change(manager: CometGatewayManager) -> None:
    # The token gate itself is already enforced by the token CRUD call (which
    # rewrites tokens.map and nginx.conf). Regenerating the full Comet override
    # bundle here only refreshes the configure-page install URL, so a drifted
    # scraper/stream patch must never block a token operation like revoke.
    if _comet_enabled():
        comet_manager = _comet_manager()
        if comet_manager.repo_exists():
            try:
                comet_manager.write_stack_override_file()
            except RuntimeError as error:
                logger.warning(
                    "Token gate updated, but refreshing the Comet override bundle failed: "
                    f"{error} Configure-page install links may be stale until the next "
                    "`./stremio restart`."
                )
    if manager.container_running():
        manager.reload_nginx()
        logger.info("Comet gateway config reloaded.")
    else:
        logger.info("Comet gateway is not running; token changes apply on next start.")


def comet_token_add(
    label: str = typer.Argument(..., help='Token label (e.g., "Shared Addon").'),
    make_default: bool = typer.Option(False, "--default", help="Make this the default token."),
) -> None:
    """Generate a new Comet gateway token."""
    manager = _comet_gateway_manager()
    token_id, token_value = manager.add_token(label, make_default=make_default)
    logger.success(f"Token created: {token_id} ({label})")
    typer.echo(f"  Addon base: {manager.addon_base_url(token_value)}")
    typer.echo(f"  Token: {token_value}")
    _refresh_comet_gateway_after_token_change(manager)


def comet_token_revoke(
    token_id: str = typer.Argument(..., help="Token ID to revoke."),
) -> None:
    """Revoke a Comet gateway token."""
    manager = _comet_gateway_manager()
    try:
        label = manager.revoke_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Token {token_id} ({label}) revoked.")
    _refresh_comet_gateway_after_token_change(manager)


def comet_token_list() -> None:
    """Show all active Comet gateway tokens."""
    manager = _comet_gateway_manager()
    tokens = manager.list_tokens()
    if not tokens:
        logger.info("No tokens configured.")
        return
    for token in tokens:
        default_marker = "default" if token["default"] else ""
        typer.echo(
            f"  {token['id']}  {token['label']:<20}  {default_marker:<8}  "
            f"{manager.addon_base_url(token['token'])}"
        )


def comet_token_rotate(
    token_id: str = typer.Argument(..., help="Token ID to rotate."),
) -> None:
    """Rotate a Comet gateway token and keep the same label/default status."""
    manager = _comet_gateway_manager()
    try:
        new_id, new_token = manager.rotate_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Token rotated: {new_id}")
    typer.echo(f"  New addon base: {manager.addon_base_url(new_token)}")
    typer.echo(f"  New Token: {new_token}")
    _refresh_comet_gateway_after_token_change(manager)


def comet_token_use(
    token_id: str = typer.Argument(..., help="Token ID to make the default."),
) -> None:
    """Select the default token used by Comet configure-page install links."""
    manager = _comet_gateway_manager()
    try:
        label = manager.use_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Default Comet gateway token is now {token_id} ({label}).")
    _refresh_comet_gateway_after_token_change(manager)


def comet_token_url(
    token_id: str = typer.Argument(..., help="Token ID to use in the rewritten URL."),
    manifest: str = typer.Option(..., "--manifest", help="Existing Comet manifest URL."),
) -> None:
    """Rewrite an existing Comet manifest URL to use a selected gateway token."""
    _gateway_manager = _comet_gateway_manager()
    try:
        typer.echo(_gateway_manager.rewrite_manifest_url(manifest, token_id))
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    except ValueError as error:
        fail(str(error))


def comet_gateway_logs(
    lines: int = typer.Option(100, "--lines", "-n", help="Number of log lines to show first."),
) -> None:
    """Tail the Comet gateway logs."""
    manager = _comet_gateway_manager()
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
        ],
        check=False,
    )


def register(token_app: typer.Typer, comet_app: typer.Typer) -> None:
    token_app.command("add")(comet_token_add)
    token_app.command("revoke")(comet_token_revoke)
    token_app.command("list")(comet_token_list)
    token_app.command("rotate")(comet_token_rotate)
    token_app.command("use")(comet_token_use)
    token_app.command("url")(comet_token_url)
    comet_app.command("gateway-logs")(comet_gateway_logs)
