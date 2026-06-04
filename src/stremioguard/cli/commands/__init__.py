from __future__ import annotations

import typer

from stremioguard.cli.commands import comet_core, comet_token, general


def register_all_commands(app: typer.Typer, comet_app: typer.Typer, token_app: typer.Typer) -> None:
    general.register(app)
    comet_core.register(comet_app)
    comet_token.register(token_app, comet_app)
