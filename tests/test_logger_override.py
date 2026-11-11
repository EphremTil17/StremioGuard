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
