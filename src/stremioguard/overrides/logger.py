"""Stop Comet's startup log from printing half of every secret."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

# Fixed width, so the log does not reveal a secret's length either.
REDACTED = "********"


_UPSTREAM_CENSOR_URL = """\
def censor_url(url: str):
    if not url:
        return url
    if "://" in url:
        try:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                auth, host = rest.split("@", 1)
                if ":" in auth:
                    user, password = auth.split(":", 1)
                    return f"{scheme}://{user}:{censor(password)}@{host}"
        except Exception:
            pass
    return url
"""

_PATCHED_CENSOR_URL = f"""\
def censor_url(url: str):
    if not url:
        return url
    prefix = ""
    rest = url
    if "://" in url:
        scheme, candidate_rest = url.split("://", 1)
        if not any(ch in scheme for ch in ("/", "?", "#")):
            prefix = f"{{scheme}}://"
            rest = candidate_rest
    cut_candidates = [idx for idx in (rest.find("?"), rest.find("#")) if idx != -1]
    cutoff = min(cut_candidates) if cut_candidates else len(rest)
    at_idx = rest.rfind("@", 0, cutoff)
    if at_idx == -1:
        return url
    userinfo = rest[:at_idx]
    suffix = rest[at_idx:]
    if ":" in userinfo:
        user, _ = userinfo.split(":", 1)
        masked = f"{{user}}:{REDACTED}"
    else:
        masked = "{REDACTED}"
    return f"{{prefix}}{{masked}}{{suffix}}"
"""


def render_logger_override(repo_dir: Path) -> str:
    """Make `censor`, `censor_url` and the API-token preview reveal nothing.

    Upstream's `censor` keeps the first half of its input, so the startup log
    carried half of the debrid API key (TorBox scraper), the admin and
    configure-page passwords and database credentials; the protected API
    prefix showed ten characters of the public API token; and `censor_url`
    only masked URLs carrying a `://` scheme.
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
    content = replace_first_matching(
        content,
        ((_UPSTREAM_CENSOR_URL, _PATCHED_CENSOR_URL),),
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
