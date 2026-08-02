from __future__ import annotations

import os
import sys

import typer
from loguru import logger

from stremioguard.cli.commands import register_all_commands
from stremioguard.cli.commands.general import (
    init,
    is_interactive,
    start,
)
from stremioguard.cli.context import ENV_FILE
from stremioguard.config import MANAGED_STACK_ENV
from stremioguard.env import env_needs_init, fail

# Lets the compose gate know the stack is being started through this CLI. Set
# at import so every compose subprocess inherits it, including the background
# watchdog, whose environment is copied from this process.
os.environ.setdefault(MANAGED_STACK_ENV, "1")

__all__ = [
    "APP",
    "COMET_APP",
    "COMET_TOKEN_APP",
    "COMET_UPDATE_APP",
]

APP = typer.Typer(
    help="Start and guard Stremio behind the gluetun VPN container.",
    no_args_is_help=False,
)
COMET_APP = typer.Typer(
    help="Manage the modular Comet playback-proxy subsystem.",
)
APP.add_typer(COMET_APP, name="comet")
COMET_TOKEN_APP = typer.Typer(
    help="Manage token-gated Comet addon access.",
)
COMET_APP.add_typer(COMET_TOKEN_APP, name="token")
COMET_UPDATE_APP = typer.Typer(
    help="Check for, validate, and apply Comet image updates.",
)
COMET_APP.add_typer(COMET_UPDATE_APP, name="update")

# Setup default console logging formatting
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
    "<cyan>stremio</cyan> | <level>{message}</level>",
    level="INFO",
    colorize=sys.stdout.isatty(),
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


# Register subcommands on the Typer application instances
register_all_commands(APP, COMET_APP, COMET_TOKEN_APP, COMET_UPDATE_APP)

if __name__ == "__main__":
    APP()
