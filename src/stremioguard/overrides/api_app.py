"""Harden API key management in Comet's per-request API log."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching


def render_api_app_override(repo_dir: Path) -> str:
    """Log the matched route template instead of the concrete request path.

    Addon paths embed configuration parameters. Upstream's own `_metrics_route`
    reduces a request to its route template with token parameters abstracted,
    preserving endpoint observability while hardening API key management.
    """
    source_file = repo_dir / "comet" / "api" / "app.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet API app file not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")
    if "def _metrics_route(request: Request) -> str:" not in content:
        raise RuntimeError(
            "Unable to apply API route template override for API key management hardening; "
            "Comet no longer defines _metrics_route."
        )

    return replace_first_matching(
        content,
        (
            (
                'f"{method} {request.url.path} - {status_code} - {process_time:.2f}s",',
                'f"{method} {_metrics_route(request)} - {status_code} - {process_time:.2f}s",',
            ),
        ),
        error=(
            "Unable to apply API route template override for API key management hardening; "
            "Comet's request log line has changed."
        ),
    )
