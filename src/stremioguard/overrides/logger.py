"""Stop Comet's startup log from printing half of every secret."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

# Fixed width, so the log does not reveal a secret's length either.
REDACTED = "********"


def render_logger_override(repo_dir: Path) -> str:
    """Make `censor` and the API-token preview reveal nothing.

    Upstream's `censor` keeps the first half of its input, so the startup log
    carried half of the debrid API key (TorBox scraper), the admin and
    configure-page passwords and database credentials; the protected API
    prefix showed ten characters of the public API token.
    """
    source_file = repo_dir / "comet" / "core" / "logger.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet logger file not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")
    error = "Unable to redact Comet's startup log; its secret masking has changed."
    content = replace_first_matching(
        content,
        (
            (
                '    half = len(text) // 2\n    return text[:half] + "*" * (len(text) - half)\n',
                f'    return "{REDACTED}"  # StremioGuard: reveal no part of a secret\n',
            ),
        ),
        error=error,
    )
    return replace_first_matching(
        content,
        (
            (
                'f"{token_value[:6]}...{token_value[-4:]}"',
                f'"{REDACTED}"  # StremioGuard: no token preview',
            ),
        ),
        error=error,
    )
