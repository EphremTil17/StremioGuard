from __future__ import annotations

from pathlib import Path


def render_config_override(repo_dir: Path) -> str:
    config_file = repo_dir / "comet" / "api" / "endpoints" / "config.py"
    if not config_file.exists():
        raise RuntimeError(f"Comet config endpoint file not found at {config_file}.")
    content = config_file.read_text(encoding="utf-8")

    marker = "def _next_url(request: Request):\n"
    if "_forwarded_prefix(" not in content:
        helper = """
def _forwarded_prefix(request: Request) -> str:
    prefix = request.headers.get("x-forwarded-prefix", "").strip().rstrip("/")
    if not prefix:
        return ""
    return prefix if prefix.startswith("/") else f"/{prefix}"


def _prefixed_path(request: Request, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    prefix = _forwarded_prefix(request)
    if prefix and not normalized_path.startswith(f"{prefix}/") and normalized_path != prefix:
        return f"{prefix}{normalized_path}"
    return normalized_path


def _sanitize_next_url_for_request(request: Request, next_url: str | None):
    sanitized = _sanitize_next_url(next_url)
    if sanitized == "/configure":
        return _prefixed_path(request, "/configure")
    return sanitized


def _is_secure_request(request: Request) -> bool:
    return (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https"


"""
        if marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet config-prefix patch; upstream "
                "next-url helper has changed."
            )
        content = content.replace(marker, helper + marker, 1)

    original_next = """def _next_url(request: Request):
    return (
        f"{request.url.path}?{request.url.query}"
        if request.url.query
        else request.url.path
    )
"""
    replacement_next = """def _next_url(request: Request):
    path = _prefixed_path(request, request.url.path)
    return f"{path}?{request.url.query}" if request.url.query else path
"""
    if replacement_next not in content:
        if original_next not in content:
            raise RuntimeError(
                "Unable to apply managed Comet config-prefix patch; upstream "
                "next-url body has changed."
            )
        content = content.replace(original_next, replacement_next, 1)

    replacements = {
        '"form_action": "/configure/login",': (
            '"form_action": _prefixed_path(request, "/configure/login"),'
        ),
        '"next_url": _sanitize_next_url(next_url),': (
            '"next_url": _sanitize_next_url_for_request(request, next_url),'
        ),
        "return RedirectResponse(_sanitize_next_url(next_url), status_code=303)": (
            "return RedirectResponse("
            "_sanitize_next_url_for_request(request, next_url), status_code=303)"
        ),
        'next_url=_sanitize_next_url(next_url), error="Invalid password"': (
            'next_url=_sanitize_next_url_for_request(request, next_url), error="Invalid password"'
        ),
        "response = RedirectResponse(_sanitize_next_url(next_url), status_code=303)": (
            "response = RedirectResponse("
            "_sanitize_next_url_for_request(request, next_url), status_code=303)"
        ),
        'secure=request.url.scheme == "https",': "secure=_is_secure_request(request),",
        'return RedirectResponse("/configure", status_code=303)': (
            'return RedirectResponse(_prefixed_path(request, "/configure"), status_code=303)'
        ),
    }
    for before, after in replacements.items():
        content = content.replace(before, after)
    return content
