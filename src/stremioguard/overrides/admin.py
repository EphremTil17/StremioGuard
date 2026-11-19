"""Preserve Secure cookie flag on Comet's admin login behind TLS termination."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

_SECURE_HELPER = """\
def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    if forwarded_proto in ("http", "https"):
        return forwarded_proto == "https"
    return request.url.scheme == "https"


"""

_HELPER_ANCHOR = "def create_admin_session():\n"
_COOKIE_ANCHOR = '        secure=request.url.scheme == "https",\n'
_COOKIE_PATCHED = "        secure=_is_secure_request(request),\n"


def render_admin_override(repo_dir: Path) -> str:
    """Honor X-Forwarded-Proto when setting Comet's admin_session Secure flag.

    Upstream checks only `request.url.scheme == "https"`. When Comet's loopback
    port sits behind TLS termination (such as a Cloudflare Access owner portal),
    Comet receives plain HTTP from the tunnel and would otherwise omit `Secure`
    from `admin_session`.
    """
    admin_file = repo_dir / "comet" / "api" / "endpoints" / "admin.py"
    if not admin_file.exists():
        raise RuntimeError(f"Comet admin endpoint file not found at {admin_file}.")
    content = admin_file.read_text(encoding="utf-8")
    error = "Unable to apply managed Comet admin cookie patch; upstream admin endpoint has changed."
    if "_is_secure_request(" not in content:
        content = replace_first_matching(
            content,
            ((_HELPER_ANCHOR, _SECURE_HELPER + _HELPER_ANCHOR),),
            error=error,
            expected=1,
        )
    return replace_first_matching(
        content,
        ((_COOKIE_ANCHOR, _COOKIE_PATCHED),),
        error=error,
        expected=1,
    )
