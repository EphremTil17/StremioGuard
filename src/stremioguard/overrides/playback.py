"""Route Comet's /playback proxy through StremioGuard's stream guard (security hardening)."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

_IMPORT_ANCHOR = "import mediaflow_proxy.utils.http_utils\n"
_GUARD_IMPORT = (
    "from comet.stremioguard_stream_guard import (  # StremioGuard: stream proxy hardening\n"
    "    safe_proxy_headers as _sg_safe_proxy_headers,\n"
    ")\n"
)
_HEADERS_ANCHOR = "            mediaflow_proxy.utils.http_utils.get_proxy_headers(request),\n"
_HEADERS_PATCHED = "            _sg_safe_proxy_headers(request),\n"


def render_playback_override(repo_dir: Path) -> str:
    """Build the proxy's headers from the request's own headers, never its query string.

    Importing the guard also installs its public-address-only connector and
    its error redaction into the proxy library, before any stream is served.
    """
    source_file = repo_dir / "comet" / "api" / "endpoints" / "playback.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet playback endpoint not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")
    error = "Unable to harden Comet's stream proxy; its playback endpoint has changed."
    content = replace_first_matching(
        content, ((_IMPORT_ANCHOR, _IMPORT_ANCHOR + _GUARD_IMPORT),), error=error
    )
    return replace_first_matching(content, ((_HEADERS_ANCHOR, _HEADERS_PATCHED),), error=error)
