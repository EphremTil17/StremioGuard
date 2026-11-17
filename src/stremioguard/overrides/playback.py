"""Route Comet's /playback proxy through StremioGuard's stream guard (security hardening)."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

_IMPORT_ANCHOR = "import mediaflow_proxy.utils.http_utils\n"
_GUARD_IMPORT = (
    "from comet.stremioguard_stream_guard import (  # StremioGuard: stream proxy hardening\n"
    "    admission_key as _sg_admission_key,\n"
    "    safe_proxy_headers as _sg_safe_proxy_headers,\n"
    ")\n"
)
_HEADERS_ANCHOR = "            mediaflow_proxy.utils.http_utils.get_proxy_headers(request),\n"
_HEADERS_PATCHED = "            _sg_safe_proxy_headers(request),\n"
# Only the stream-slot count changes: the `ip` Comet hands to debrid services
# stays as upstream computes it.
_ADMISSION_ANCHOR = "            media_id=torrent_name,\n            ip=ip,\n"
_ADMISSION_PATCHED = (
    "            media_id=torrent_name,\n            ip=_sg_admission_key(request, ip),\n"
)


def render_playback_override(repo_dir: Path) -> str:
    """Build the proxy's headers from the request's own headers, never its query string.

    Importing the guard also installs its public-address-only connector and
    its error redaction into the proxy library, before any stream is served.
    Concurrent proxied streams are counted per gateway token, not in the one
    pool every gateway client would otherwise share.
    """
    source_file = repo_dir / "comet" / "api" / "endpoints" / "playback.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet playback endpoint not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")
    error = "Unable to harden Comet's stream proxy; its playback endpoint has changed."
    content = replace_first_matching(
        content, ((_IMPORT_ANCHOR, _IMPORT_ANCHOR + _GUARD_IMPORT),), error=error
    )
    content = replace_first_matching(content, ((_HEADERS_ANCHOR, _HEADERS_PATCHED),), error=error)
    return replace_first_matching(content, ((_ADMISSION_ANCHOR, _ADMISSION_PATCHED),), error=error)
