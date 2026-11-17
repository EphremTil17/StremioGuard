"""Security hardening: Comet trusts only plain forwarded prefixes and hosts."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from stremioguard.overrides.config import _PREFIX_HELPERS


class _Headers(dict):
    def get(self, key, default=None):  # type: ignore[override]
        return super().get(key.lower(), default)


def _request(**headers: str) -> SimpleNamespace:
    return SimpleNamespace(
        headers=_Headers({k.replace("_", "-").lower(): v for k, v in headers.items()}),
        url=SimpleNamespace(scheme="http", netloc="127.0.0.1:8000"),
    )


@pytest.fixture(scope="module")
def prefix_helpers() -> dict[str, object]:
    namespace: dict[str, object] = {"Request": object, "_sanitize_next_url": lambda url: url}
    exec(_PREFIX_HELPERS, namespace)  # noqa: S102 - our own helper source
    return namespace


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("/comet/GwTok3n_A-b", "/comet/GwTok3n_A-b"),
        ("comet/tok", "/comet/tok"),
        ("/comet/tok/", "/comet/tok"),
        ("", ""),
        ("//evil.example", ""),
        ("/\\evil.example", ""),
        ("https://evil.example", ""),
        ("/%2F%2Fevil.example", ""),
        ("/comet/tok?x=1", ""),
        ("/comet/../admin", ""),
        ("/comet/./x", ""),
        ("/comet/v1.2", "/comet/v1.2"),
        ("/a b", ""),
        ("/first, /second", "/first"),
    ],
)
def test_only_plain_path_prefixes_are_trusted(
    prefix_helpers: dict[str, object], header: str, expected: str
) -> None:
    forwarded_prefix = prefix_helpers["_forwarded_prefix"]
    assert callable(forwarded_prefix)
    assert forwarded_prefix(_request(x_forwarded_prefix=header)) == expected


def test_prefixed_redirect_targets_stay_on_this_site(prefix_helpers: dict[str, object]) -> None:
    prefixed_path = prefix_helpers["_prefixed_path"]
    assert callable(prefixed_path)
    for hostile in ("//evil.example", "/\\evil.example", "https://evil.example"):
        target = prefixed_path(_request(x_forwarded_prefix=hostile), "/configure")
        assert target == "/configure"


def _external_base():  # type: ignore[no-untyped-def]
    source = (
        Path(__file__).resolve().parent.parent / "src/stremioguard/overrides/stream.py"
    ).read_text(encoding="utf-8")
    match = re.search(r"def _forwarded_external_base\(request\) -> str:\n(?:(?: .*)?\n)+", source)
    assert match is not None
    namespace: dict[str, object] = {}
    exec(match.group(0), namespace)  # noqa: S102 - our own helper source
    helper = namespace["_forwarded_external_base"]
    assert callable(helper)
    return helper


@pytest.mark.parametrize(
    ("host", "prefix", "expected"),
    [
        ("comet.example.com", "/comet/tok", "https://comet.example.com/comet/tok"),
        ("comet.example.com:8443", "", "https://comet.example.com:8443"),
        ("[2001:db8::1]:443", "/p", "https://[2001:db8::1]:443/p"),
        ("evil.example/x", "/p", "http://127.0.0.1:8000"),
        ("evil.example@other", "", "http://127.0.0.1:8000"),
        ("a b", "", "http://127.0.0.1:8000"),
        ("comet.example.com", "//evil.example", "https://comet.example.com"),
        ("comet.example.com", "/p?x", "https://comet.example.com"),
    ],
)
def test_stream_links_use_only_plain_forwarded_hosts_and_prefixes(
    host: str, prefix: str, expected: str
) -> None:
    request = _request(x_forwarded_proto="https", x_forwarded_host=host, x_forwarded_prefix=prefix)
    assert _external_base()(request) == expected
