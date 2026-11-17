"""Comet's startup log must not carry any part of a secret."""

from __future__ import annotations

from pathlib import Path

import pytest

from stremioguard.overrides.logger import REDACTED, render_logger_override

# Upstream's two scraper log lines, built in pieces (each is one long line upstream).
_TIMEOUT_LINE = (
    'f"Timeout while getting torrents for {media_id} with {scraper_name} '
    '({censor_url(scraper_url)})"'
)
_EXCEPTION_LINE = (
    'f"Exception while getting torrents for {media_id} with {scraper_name} '
    "({censor_url(scraper_url)}), you are most likely being "
    'ratelimited{api_password_missing}: {error}"'
)


# The upstream shape of the two masking sites in comet/core/logger.py.
UPSTREAM = """\
import sys

from comet.utils.parsing import associate_urls_credentials


def handlers():
    return [
            {
                "sink": sys.stderr,
            }
    ]


def add_capture(logger, loguru_handler):
    logger.add(
    loguru_handler.write,
    )


def log_scraper_error(
    scraper_name: str, scraper_url: str, media_id: str, error: Exception
):
    api_password_missing = ""
    error_str = str(error).lower()
    is_timeout = "timeout" in error_str or "timeout" in type(error).__name__.lower()

    if is_timeout:
        LINES.append(
            @@TIMEOUT_LINE@@
        )
    else:
        LINES.append(
            @@EXCEPTION_LINE@@
        )


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
""".replace("@@TIMEOUT_LINE@@", _TIMEOUT_LINE).replace("@@EXCEPTION_LINE@@", _EXCEPTION_LINE)


@pytest.fixture(autouse=True)
def _fake_comet_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixture imports Comet's parsing helper; give exec() a stand-in."""
    import sys
    import types

    for name in ("comet", "comet.utils"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    parsing = types.ModuleType("comet.utils.parsing")
    parsing.associate_urls_credentials = lambda urls, passwords: []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "comet.utils.parsing", parsing)
    # The rendered logger routes the standard library's root logger into loguru;
    # keep that out of the test process.
    import logging

    monkeypatch.setattr(logging.getLogger(), "handlers", list(logging.getLogger().handlers))


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


def test_every_sink_writes_through_the_scrubber(tmp_path: Path) -> None:
    rendered = _render(tmp_path, UPSTREAM)
    assert '"sink": _sg_scrubbed_sink(sys.stderr),' in rendered
    assert "_sg_scrubbed_sink(loguru_handler.write)," in rendered
    assert '"sink": sys.stderr,' not in rendered
    assert "\n    loguru_handler.write,\n" not in rendered
    # Inserted after the imports, so it exists before any sink is configured.
    assert rendered.index("def _sg_scrubbed_sink") < rendered.index("def handlers")


def test_scraper_errors_never_log_a_bare_key_or_a_url_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "sgcanaryTORBOXkey0123456789"
    monkeypatch.setenv("TORBOX_API_KEY", key)
    lines: list[str] = []
    namespace: dict[str, object] = {"LINES": lines}
    exec(_render(tmp_path, UPSTREAM), namespace)  # noqa: S102 - our own rendered test source
    log_scraper_error = namespace["log_scraper_error"]
    assert callable(log_scraper_error)

    class HTTPFailure(Exception):
        status = 502

        def __str__(self) -> str:
            return "502, message='Bad Gateway', url='https://addon.example/eyJrZXkiOiJ4In0/stream/a.json'"

    log_scraper_error("TorBox", key, "tt1", ConnectionError("unreachable"))
    log_scraper_error("Debridio", f"torbox|{key}", "tt2", HTTPFailure())
    log_scraper_error(
        "Torrentio", "https://u:p4ssw0rd99@torrentio.example:8443/cfg=x/", "tt3", TimeoutError()
    )
    joined = "\n".join(lines)
    assert key not in joined
    assert "eyJrZXkiOiJ4In0" not in joined and "p4ssw0rd99" not in joined and "cfg=x" not in joined
    assert lines[0].endswith(
        "with TorBox, you are most likely being ratelimited: ConnectionError: unreachable"
    )
    assert "with Debridio, you are" in lines[1]
    assert (
        "HTTPFailure (HTTP 502): 502, message='Bad Gateway', url='https://addon.example'"
        in lines[1]
    )
    assert (
        lines[2]
        == "Timeout while getting torrents for tt3 with Torrentio (https://torrentio.example:8443)"
    )


def test_changed_sink_setup_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="secret masking has changed"):
        _render(tmp_path, UPSTREAM.replace('"sink": sys.stderr,', '"sink": sys.stdout,'))
    with pytest.raises(RuntimeError, match="secret masking has changed"):
        _render(tmp_path / "b", UPSTREAM.replace("    loguru_handler.write,", "    handler.write,"))
    with pytest.raises(RuntimeError, match="secret masking has changed"):
        _render(tmp_path / "c", UPSTREAM.replace("({censor_url(scraper_url)})", "({scraper_url})"))
