"""Comet's startup log must not carry any part of a secret."""

from __future__ import annotations

from pathlib import Path

import pytest

from stremioguard.overrides.logger import REDACTED, render_logger_override

# The upstream shape of the two masking sites in comet/core/logger.py.
UPSTREAM = """\
def censor(text: str):
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    half = len(text) // 2
    return text[:half] + "*" * (len(text) - half)


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


def startup(token_value):
    token_preview = (
        f"{token_value[:6]}...{token_value[-4:]}"
        if len(token_value) > 10
        else censor(token_value)
    )
    return token_preview
"""


def _render(tmp_path: Path, source: str) -> str:
    target = tmp_path / "comet" / "core" / "logger.py"
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    return render_logger_override(tmp_path)


def test_redacted_logger_reveals_no_part_of_a_secret(tmp_path: Path) -> None:
    namespace: dict[str, object] = {}
    exec(_render(tmp_path, UPSTREAM), namespace)  # noqa: S102 - our own rendered test source
    key = "748246ff-70d3-42ff-0000-123456789abc"
    censor = namespace["censor"]
    startup = namespace["startup"]
    assert callable(censor) and callable(startup)
    assert censor(key) == REDACTED
    assert startup(key) == REDACTED
    assert "748246" not in f"{censor(key)}{startup(key)}"


def test_render_is_idempotent(tmp_path: Path) -> None:
    once = _render(tmp_path, UPSTREAM)
    (tmp_path / "comet" / "core" / "logger.py").write_text(once, encoding="utf-8")
    assert render_logger_override(tmp_path) == once


def test_changed_upstream_masking_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="secret masking has changed"):
        _render(tmp_path, UPSTREAM.replace("half = len(text) // 2", "half = 3"))


def test_ac8_censor_url_masks_credentials_with_or_without_scheme(tmp_path: Path) -> None:
    """AC-8: censor_url masks userinfo on schemed and scheme-less URLs without leaking secrets."""
    rendered = _render(tmp_path, UPSTREAM)
    namespace: dict[str, object] = {}
    exec(rendered, namespace)  # noqa: S102 - our own rendered test source
    censor_url = namespace["censor_url"]
    assert callable(censor_url)

    pw_plain = "SGF9FAKE-AbCdEfGhIjKlMnOp"
    pw_quoted = "SGF9FAKE-QrStUv%40WxYz%23"
    pw_at_colon = "SGF9FAKE-User@Part:More@Colon"
    token = "SGF9FAKE-SecretBearerToken"
    pw_query = "SGF9FAKE-QueryPassWord"
    secrets_parts = [
        pw_plain.removeprefix("SGF9FAKE-"),
        pw_quoted.removeprefix("SGF9FAKE-"),
        pw_at_colon.removeprefix("SGF9FAKE-"),
        token.removeprefix("SGF9FAKE-"),
        pw_query.removeprefix("SGF9FAKE-"),
    ]

    cases = [
        (f"comet:{pw_plain}@127.0.0.1:5432/comet", f"comet:{REDACTED}@127.0.0.1:5432/comet"),
        (
            f"postgresql://comet:{pw_plain}@h:5432/comet",
            f"postgresql://comet:{REDACTED}@h:5432/comet",
        ),
        (
            f"postgresql://comet:{pw_quoted}@h:5432/comet",
            f"postgresql://comet:{REDACTED}@h:5432/comet",
        ),
        (f"comet:{pw_at_colon}@h/db", f"comet:{REDACTED}@h/db"),
        (f"https://{token}@host/path", f"https://{REDACTED}@host/path"),
        ("https://host/torrentio/abc", "https://host/torrentio/abc"),
        (f"http://user:{pw_query}@host/p?x=a@b", f"http://user:{REDACTED}@host/p?x=a@b"),
        ("", ""),
        (None, None),
    ]
    for raw, expected in cases:
        out = censor_url(raw)
        assert out == expected
        if isinstance(out, str):
            for part in secrets_parts:
                for idx in range(len(part) - 3):
                    assert part[idx : idx + 4] not in out

    with pytest.raises(RuntimeError, match="secret masking has changed"):
        _render(tmp_path / "changed", UPSTREAM.replace('if "@" in rest:', 'if ":" in rest:'))

    (tmp_path / "comet" / "core" / "logger.py").write_text(rendered, encoding="utf-8")
    assert render_logger_override(tmp_path) == rendered
