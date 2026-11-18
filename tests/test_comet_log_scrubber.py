"""The scrubber inserted into Comet's logger, tested as plain Python."""

from __future__ import annotations

import importlib
import sys
import types
import urllib.parse
from collections.abc import Iterator

import pytest

MODULE = "stremioguard.overrides.comet_log_scrubber"


@pytest.fixture
def scrubber(monkeypatch: pytest.MonkeyPatch) -> Iterator[types.ModuleType]:
    for name in list(__import__("os").environ):
        if name.rsplit("_", 1)[-1] in {"KEY", "TOKEN", "PASSWORD", "SECRET", "AUTH", "APIKEY"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delitem(sys.modules, "comet.core.models", raising=False)
    sys.modules.pop(MODULE, None)
    module = importlib.import_module(MODULE)
    yield module
    sys.modules.pop(MODULE, None)


def _sink_output(module: types.ModuleType, text: str) -> str:
    written: list[str] = []
    module._sg_scrubbed_sink(written.append)(text)
    return "".join(written)


def test_credential_settings_are_masked_in_every_form(
    scrubber: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "sg/canary+key=1&x"
    monkeypatch.setenv("TORBOX_API_KEY", secret)
    monkeypatch.setenv("PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY", "sgcanaryDEBRIDkey01")
    monkeypatch.setenv("DATABASE_URL", "postgresql://comet:sg%40canaryDB1@127.0.0.1/comet")
    line = (
        f"raw {secret} twice {secret}{secret} quoted {urllib.parse.quote(secret, safe='')} "
        f"plus {urllib.parse.quote_plus(secret)} debrid sgcanaryDEBRIDkey01 "
        "db sg%40canaryDB1 decoded sg@canaryDB1\n"
    )
    out = _sink_output(scrubber, line)
    for leak in ("canary", "sg%40", "sg%2F"):
        assert leak not in out
    assert out.startswith("raw ******** twice ****************")
    assert out.endswith("\n")


def test_non_credential_settings_and_short_values_are_left_alone(
    scrubber: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TORRENTIO_URL", "https://torrentio.strem.fun")
    monkeypatch.setenv("SHORT_KEY", "abc")
    out = _sink_output(scrubber, "scraping https://torrentio.strem.fun abc\n")
    assert out == "scraping https://torrentio.strem.fun abc\n"


def test_values_from_comets_settings_are_masked_once_resolved(
    scrubber: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Settings:
        model_fields = {
            "PUBLIC_API_TOKEN": None,
            "MEDIAFUSION_API_PASSWORD": None,
            "LOG_LEVEL": None,
        }
        PUBLIC_API_TOKEN = "sgcanaryAPItoken0001"
        MEDIAFUSION_API_PASSWORD = ["sgcanaryMFpw00001", "sgcanaryMFpw00002"]
        LOG_LEVEL = "DEBUG-LEVEL-VALUE"

    models = types.ModuleType("comet.core.models")
    models.settings = Settings()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "comet.core.models", models)
    # Before the API prefix exists the set is rebuilt on every line ...
    assert "sgcanaryAPItoken0001" not in _sink_output(scrubber, "t sgcanaryAPItoken0001")
    assert scrubber._sg_secrets_final is False
    models.STREMIO_API_PREFIX = "/s/x"  # type: ignore[attr-defined]
    out = _sink_output(scrubber, "t sgcanaryAPItoken0001 sgcanaryMFpw00002 DEBUG-LEVEL-VALUE")
    assert out == "t ******** ******** DEBUG-LEVEL-VALUE"
    # ... and frozen once it does.
    assert scrubber._sg_secrets_final is True


def test_a_failing_scrub_withholds_the_line_instead_of_writing_it(
    scrubber: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> tuple[str, ...]:
        raise RuntimeError("settings unreadable")

    monkeypatch.setattr(scrubber, "_sg_current_secrets", broken)
    out = _sink_output(scrubber, "raw sgcanarySECRETvalue\n")
    assert out == scrubber._SG_WITHHELD
    monkeypatch.undo()


def test_stream_targets_are_written_and_flushed(scrubber: types.ModuleType) -> None:
    class Stream:
        def __init__(self) -> None:
            self.parts: list[str] = []
            self.flushed = 0

        def write(self, text: str) -> None:
            self.parts.append(text)

        def flush(self) -> None:
            self.flushed += 1

    stream = Stream()
    scrubber._sg_scrubbed_sink(stream)("line\n")
    assert stream.parts == ["line\n"] and stream.flushed == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sgcanaryTORBOXkey0123456789", ""),
        ("torbox|sgcanaryDEBRIDIOkey1", ""),
        (
            "https://torrentio.strem.fun/opt=realdebrid=KEY/manifest.json",
            " (https://torrentio.strem.fun)",
        ),
        ("http://user:pw@jackett.example:9117/api?apikey=KEY", " (http://jackett.example:9117)"),
        ("https://[::1", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_scraper_origin_is_scheme_and_host_or_nothing(
    scrubber: types.ModuleType, value: object, expected: str
) -> None:
    assert scrubber._sg_scraper_origin(value) == expected


def test_error_text_keeps_no_url_path_query_or_userinfo(scrubber: types.ModuleType) -> None:
    class Failure(Exception):
        status_code = 429

        def __str__(self) -> str:
            return (
                "429 for url='https://u:pw@api.example/v1/eyJjZmciOjF9?token=T' "
                "and URL('http://other.example/p/q')"
            )

    text = scrubber._sg_describe_error(Failure())
    assert text == (
        "Failure (HTTP 429): 429 for url='https://api.example' and URL('http://other.example')"
    )
    assert scrubber._sg_describe_error(ValueError()) == "ValueError"


def test_noted_config_keys_are_masked_in_every_form(scrubber: types.ModuleType) -> None:
    key = "sg/caller+key=1&x"
    scrubber._sg_note_secret_values([key, "short", None, 42])
    line = (
        f"raw {key} quoted {urllib.parse.quote(key, safe='')} "
        f"plus {urllib.parse.quote_plus(key)} short\n"
    )
    out = _sink_output(scrubber, line)
    assert "caller" not in out and "sg%2F" not in out
    assert out == "raw ******** quoted ******** plus ******** short\n"


def test_noted_keys_are_bounded_and_the_least_recently_seen_is_dropped(
    scrubber: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Room for two keys (a plain key's quoted forms are the key itself).
    monkeypatch.setattr(scrubber, "_SG_MAX_NOTED_SECRETS", 2)
    scrubber._sg_note_secret_values(["sgcallerKEY0001"])
    scrubber._sg_note_secret_values(["sgcallerKEY0002"])
    scrubber._sg_note_secret_values(["sgcallerKEY0001"])  # seen again: now the most recent
    scrubber._sg_note_secret_values(["sgcallerKEY0003"])
    assert len(scrubber._sg_noted) == 2
    out = _sink_output(scrubber, "sgcallerKEY0001 sgcallerKEY0002 sgcallerKEY0003")
    assert out == "******** sgcallerKEY0002 ********"
