from __future__ import annotations

import shutil
import subprocess

import typer

from stremioguard.cli.context import LOG_DIR, UV_CACHE, RunContext
from stremioguard.env import fail


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
