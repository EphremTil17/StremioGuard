from __future__ import annotations

import subprocess
from typing import NoReturn

import typer
from loguru import logger

from stremioguard.cli.context import (
    ROOT_DIR,
    _comet_gateway_manager,
)
from stremioguard.comet_gateway import CometGatewayManager
from stremioguard.config import compose_command
from stremioguard.env import fail


def _fail_gateway_not_applied(reason: str, *, old_token_still_works: bool = False) -> NoReturn:
    old_token_note = " The old token still works." if old_token_still_works else ""
    fail(
        f"{reason} The change is saved in tokens.json, but it is NOT active in the "
        f"running gateway.{old_token_note} Run `./stremio comet gateway-reload` or "
        "`./stremio restart` to apply it."
    )


def _refresh_comet_gateway_after_token_change(
    manager: CometGatewayManager, *, old_token_still_works: bool = False
) -> None:
    # The token gate is the token map, which the token CRUD call has already
    # rewritten; reloading nginx is what makes it take effect. Nothing is
    # republished here: a token change must never deploy unrelated .env or
    # compose edits. The configure page's install link lives in the patch
    # bundle and follows the default token at the next `./stremio restart`.
    running = manager.container_running()
    if running is True:
        try:
            manager.reload_nginx()
        except (RuntimeError, subprocess.SubprocessError, OSError) as error:
            _fail_gateway_not_applied(
                f"Failed to reload Comet gateway ({error}).",
                old_token_still_works=old_token_still_works,
            )
        logger.info("Comet gateway config reloaded.")
    elif running is False:
        logger.info("Comet gateway is not running; token changes apply on next start.")
    else:
        _fail_gateway_not_applied(
            "Could not determine whether the Comet gateway container is running.",
            old_token_still_works=old_token_still_works,
        )


def comet_token_add(
    label: str = typer.Argument(..., help='Token label (e.g., "Shared Addon").'),
    make_default: bool = typer.Option(False, "--default", help="Make this the default token."),
) -> None:
    """Generate a new Comet gateway token."""
    manager = _comet_gateway_manager()
    try:
        token_id, token_value = manager.add_token(label, make_default=make_default)
    except RuntimeError as error:
        fail(str(error))
    _refresh_comet_gateway_after_token_change(manager)
    logger.success(f"Token created: {token_id} ({label})")
    typer.echo(f"  Addon base: {manager.addon_base_url(token_value)}")
    typer.echo(f"  Token: {token_value}")


def comet_token_revoke(
    token_id: str = typer.Argument(..., help="Token ID to revoke."),
) -> None:
    """Revoke a Comet gateway token."""
    manager = _comet_gateway_manager()
    try:
        label = manager.revoke_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    except RuntimeError as error:
        fail(str(error))
    _refresh_comet_gateway_after_token_change(manager, old_token_still_works=True)
    logger.success(f"Token {token_id} ({label}) revoked.")


def comet_token_list() -> None:
    """Show all active Comet gateway tokens."""
    manager = _comet_gateway_manager()
    try:
        tokens = manager.list_tokens()
    except RuntimeError as error:
        fail(str(error))
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
    except RuntimeError as error:
        fail(str(error))
    _refresh_comet_gateway_after_token_change(manager, old_token_still_works=True)
    logger.success(f"Token rotated: {new_id}")
    typer.echo(f"  New addon base: {manager.addon_base_url(new_token)}")
    typer.echo(f"  New Token: {new_token}")


def comet_token_use(
    token_id: str = typer.Argument(..., help="Token ID to make the default."),
) -> None:
    """Select the default token used by Comet configure-page install links."""
    manager = _comet_gateway_manager()
    try:
        label = manager.use_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    except RuntimeError as error:
        fail(str(error))
    _refresh_comet_gateway_after_token_change(manager)
    logger.success(f"Default Comet gateway token is now {token_id} ({label}).")


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
    except (ValueError, RuntimeError) as error:
        fail(str(error))


def comet_gateway_logs(
    lines: int = typer.Option(100, "--lines", "-n", help="Number of log lines to show first."),
) -> None:
    """Tail the Comet gateway logs."""
    manager = _comet_gateway_manager()
    subprocess.run(
        compose_command(ROOT_DIR, "logs", "-f", "--tail", str(lines), manager.config.service_name),
        check=False,
    )


def comet_gateway_reload() -> None:
    """Re-render and reload the running Comet gateway config."""
    manager = _comet_gateway_manager()
    try:
        manager.write_nginx_configs()
    except RuntimeError as error:
        fail(str(error))
    running = manager.container_running()
    if running is False:
        fail("Comet gateway container is not running; cannot reload nginx.")
    if running is None:
        fail(
            "Could not determine whether the Comet gateway container is running; "
            "run `./stremio restart` to apply the config."
        )
    try:
        manager.reload_nginx()
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        fail(f"Failed to reload Comet gateway: {error}")
    logger.success("Comet gateway config reloaded.")


def register(token_app: typer.Typer, comet_app: typer.Typer) -> None:
    token_app.command("add")(comet_token_add)
    token_app.command("revoke")(comet_token_revoke)
    token_app.command("list")(comet_token_list)
    token_app.command("rotate")(comet_token_rotate)
    token_app.command("use")(comet_token_use)
    token_app.command("url")(comet_token_url)
    comet_app.command("gateway-logs")(comet_gateway_logs)
    comet_app.command("gateway-reload")(comet_gateway_reload)
