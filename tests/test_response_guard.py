"""Adversarial ASGI tests for StremioGuardResponseGuard (AC-1, AC-2, AC-15)."""

from __future__ import annotations

import ast
import asyncio
import gzip
import json
import sys
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

import pytest

from stremioguard.overrides.response_guard import StremioGuardResponseGuard


def _http_scope(
    path: str,
    *,
    raw_path: bytes | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": path,
        "raw_path": path.encode("utf-8") if raw_path is None else raw_path,
        "query_string": b"",
        "headers": list(headers or []),
    }


async def _run_asgi(
    app: Any, scope: dict[str, Any]
) -> tuple[int, list[tuple[bytes, bytes]], list[bytes]]:
    status = 0
    headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status, headers
        if message["type"] == "http.response.start":
            status = int(message["status"])
            headers = list(message.get("headers") or ())
        elif message["type"] == "http.response.body":
            chunks.append(bytes(message.get("body", b"")))

    await app(scope, receive, send)
    return status, headers, chunks


def _header_map(headers: list[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    return {k.lower(): v for k, v in headers}


def test_ac1_guard_module_imports_only_standard_library() -> None:
    """AC-1: the guard module imports only the standard library (checked from its AST)."""
    guard_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "stremioguard"
        / "overrides"
        / "response_guard.py"
    )
    tree = ast.parse(guard_path.read_text(encoding="utf-8"), filename=str(guard_path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"relative import disallowed: {ast.dump(node)}"
            assert node.module is not None
            imported.add(node.module.split(".")[0])
    non_stdlib = imported - sys.stdlib_module_names - {"__future__"}
    assert not non_stdlib, f"non-stdlib imports found: {sorted(non_stdlib)}"


def test_ac1_ab_filters_p2p_and_strips_hybrid_fields_single_and_chunked() -> None:
    """AC-1 (a), (b): strips P2P entries and torrent fields across single or 3-chunk bodies."""
    payload = {
        "streams": [
            {"name": "only-ih", "infoHash": "0123456789abcdef0123456789abcdef01234567"},
            {
                "name": "hybrid",
                "url": "https://comet.example/playback/1",
                "infoHash": "0123456789abcdef0123456789abcdef01234567",
                "fileIdx": 0,
                "sources": ["tracker:udp://t.example:80"],
                "announce": ["udp://t.example:80"],
            },
            {"name": "lower-ih", "infohash": "0123456789abcdef0123456789abcdef01234567"},
            {"name": "mag-url", "url": " MAGNET:?xt=urn:btih:0123"},
            {"name": "mag-ext", "externalUrl": "magnet:?xt=urn:btih:0123"},
            {"name": "yt-ih", "ytId": "dQw4w9WgXcQ", "infoHash": "0123"},
            {"name": "plain", "url": "https://comet.example/playback/2"},
            "raw-string-entry",
        ]
    }
    raw = json.dumps(payload).encode("utf-8")
    cut1 = len(raw) // 3
    cut2 = (2 * len(raw)) // 3
    splits = [
        [raw],
        [raw[:cut1], raw[cut1:cut2], raw[cut2:]],
    ]

    for parts in splits:

        async def inner(
            scope: Any, receive: Any, send: Any, *, body_parts: list[bytes] = parts
        ) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json; charset=utf-8"),
                        (b"content-length", str(len(raw)).encode("ascii")),
                        (b"etag", b'"abc123"'),
                    ],
                }
            )
            for idx, part in enumerate(body_parts):
                await send(
                    {
                        "type": "http.response.body",
                        "body": part,
                        "more_body": idx < len(body_parts) - 1,
                    }
                )

        guard = StremioGuardResponseGuard(inner)
        status, headers, chunks = asyncio.run(
            _run_asgi(guard, _http_scope("/stream/movie/tt1.json"))
        )
        body = b"".join(chunks)
        hmap = _header_map(headers)

        assert status == 200
        assert b"etag" not in hmap
        assert hmap[b"content-length"] == str(len(body)).encode("ascii")
        assert json.loads(body) == {
            "streams": [
                {"name": "hybrid", "url": "https://comet.example/playback/1"},
                {"name": "plain", "url": "https://comet.example/playback/2"},
                "raw-string-entry",
            ]
        }


def test_ac1_cd_unchanged_json_and_non_stream_objects_preserve_bytes_and_headers() -> None:
    """AC-1 (c), (d): clean streams with etag and non-stream JSON objects pass byte-identical."""
    bodies = [
        json.dumps({"streams": [{"name": "ok", "url": "https://comet.example/1"}]}).encode("utf-8"),
        json.dumps({"streams": "x"}).encode("utf-8"),
        json.dumps([1, {"infoHash": "keep-non-object-root"}]).encode("utf-8"),
        json.dumps({"metas": [{"id": "tt1", "infoHash": "keep-non-streams"}]}).encode("utf-8"),
    ]
    for raw in bodies:
        orig_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode("ascii")),
            (b"etag", b'"keep-me"'),
        ]

        async def inner(
            scope: Any,
            receive: Any,
            send: Any,
            *,
            body: bytes = raw,
            hdrs: list[tuple[bytes, bytes]] = orig_headers,
        ) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": list(hdrs)})
            await send({"type": "http.response.body", "body": body, "more_body": False})

        guard = StremioGuardResponseGuard(inner)
        status, headers, chunks = asyncio.run(
            _run_asgi(guard, _http_scope("/catalog/movie/top.json"))
        )
        assert status == 200
        assert headers == orig_headers
        assert b"".join(chunks) == raw


def test_ac1_e_non_json_streams_without_buffering() -> None:
    """AC-1 (e): video/mp4 chunks forward in order before the next chunk is produced."""
    produced = [b"chunk0-", b"chunk1-", b"chunk2-", b"chunk3-", b"chunk4"]

    async def exercise() -> None:
        chunk_ack = asyncio.Event()
        received_chunks: list[bytes] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"video/mp4")],
                }
            )
            for idx, chunk in enumerate(produced):
                if idx > 0:
                    await asyncio.wait_for(chunk_ack.wait(), timeout=2.0)
                    chunk_ack.clear()
                await send(
                    {
                        "type": "http.response.body",
                        "body": chunk,
                        "more_body": idx < len(produced) - 1,
                    }
                )

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def outer_send(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.body":
                received_chunks.append(bytes(message["body"]))
                chunk_ack.set()

        guard = StremioGuardResponseGuard(inner)
        await asyncio.wait_for(
            guard(_http_scope("/playback/1"), receive, outer_send),
            timeout=2.0,
        )
        assert received_chunks == produced

    asyncio.run(exercise())


def test_ac1_fg_compressed_and_malformed_and_empty_json() -> None:
    """AC-1 (f), (g): gzipped JSON -> 502; malformed JSON with infoHash -> 502; others unchanged."""
    gzip_p2p = gzip.compress(
        b'{"streams":[{"name":"p2p","infoHash":"0123456789abcdef0123456789abcdef01234567"}]}'
    )
    cases = [
        (
            [(b"content-type", b"application/json"), (b"content-encoding", b"gzip")],
            gzip_p2p,
            502,
            b'{"detail":"Bad Gateway"}',
        ),
        (
            [(b"content-type", b"application/json")],
            b'{"streams": [{"infoHash": "abc"',
            502,
            b'{"detail":"Bad Gateway"}',
        ),
        (
            [(b"content-type", b"application/json")],
            b'{"broken": true',
            200,
            b'{"broken": true',
        ),
        (
            [(b"content-type", b"application/json")],
            b"",
            200,
            b"",
        ),
    ]
    for resp_headers, raw, expected_status, expected_body in cases:

        async def inner(
            scope: Any,
            receive: Any,
            send: Any,
            *,
            hdrs: list[tuple[bytes, bytes]] = resp_headers,
            body: bytes = raw,
        ) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": list(hdrs)})
            await send({"type": "http.response.body", "body": body, "more_body": False})

        guard = StremioGuardResponseGuard(inner)
        status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope("/stream/movie/tt1.json")))
        body = b"".join(chunks)
        assert status == expected_status
        assert body == expected_body
        assert b"infoHash" not in body


def test_ac15_encoded_json_returns_502() -> None:
    """AC-15: real gzip P2P payload and marker-free br payload both return 502 Bad Gateway."""
    cases = [
        (
            b"gzip",
            gzip.compress(
                b'{"streams":[{"name":"p2p","infoHash":"0123456789abcdef0123456789abcdef01234567"}]}'
            ),
        ),
        (
            b"br",
            b"\x01\x02\x03\xfe\xffarbitrary-compressed-bytes",
        ),
    ]
    for encoding, raw in cases:

        async def inner(
            scope: Any,
            receive: Any,
            send: Any,
            *,
            enc: bytes = encoding,
            body: bytes = raw,
        ) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-encoding", enc),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body, "more_body": False})

        guard = StremioGuardResponseGuard(inner)
        status, headers, chunks = asyncio.run(
            _run_asgi(guard, _http_scope("/stream/movie/tt1.json"))
        )
        body = b"".join(chunks)
        hmap = _header_map(headers)
        assert status == 502
        assert body == b'{"detail":"Bad Gateway"}'
        assert hmap[b"content-length"] == str(len(body)).encode("ascii")


def test_ac1_hi_strips_accept_encoding_and_passes_non_http_scopes_untouched() -> None:
    """AC-1 (h), (i): strips accept-encoding, preserves other headers; non-http keeps scope."""
    seen_headers: list[tuple[bytes, bytes]] = []
    seen_scopes: list[dict[str, Any]] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen_scopes.append(scope)
        if scope["type"] == "http":
            seen_headers.extend(scope["headers"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    http_scope = _http_scope(
        "/health",
        headers=[
            (b"host", b"comet.example"),
            (b"Accept-Encoding", b"gzip, br"),
            (b"x-custom", b"value"),
        ],
    )
    asyncio.run(_run_asgi(guard, http_scope))
    assert seen_headers == [(b"host", b"comet.example"), (b"x-custom", b"value")]

    for scope_type in ("websocket", "lifespan"):
        non_http = {"type": scope_type, "asgi": {"version": "3.0"}}
        asyncio.run(_run_asgi(guard, non_http))
        assert seen_scopes[-1] is non_http


def test_ac1_j_concurrent_requests_do_not_share_buffers() -> None:
    """AC-1 (j): two concurrent requests interleaving chunks stay isolated."""

    async def exercise() -> None:
        turn_a = asyncio.Event()
        turn_b = asyncio.Event()

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            tag = scope["path"].lstrip("/")
            if tag == "a":
                payload = json.dumps(
                    {
                        "streams": [
                            {"name": "a-p2p", "infoHash": "111"},
                            {"name": "a-ok", "url": "https://a/1"},
                        ]
                    }
                ).encode()
                mid = len(payload) // 2
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send({"type": "http.response.body", "body": payload[:mid], "more_body": True})
                turn_b.set()
                await turn_a.wait()
                await send(
                    {"type": "http.response.body", "body": payload[mid:], "more_body": False}
                )
            else:
                await turn_b.wait()
                payload = json.dumps(
                    {
                        "streams": [
                            {"name": "b-p2p", "infoHash": "222"},
                            {"name": "b-ok", "url": "https://b/1"},
                        ]
                    }
                ).encode()
                mid = len(payload) // 2
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send({"type": "http.response.body", "body": payload[:mid], "more_body": True})
                turn_a.set()
                await send(
                    {"type": "http.response.body", "body": payload[mid:], "more_body": False}
                )

        guard = StremioGuardResponseGuard(inner)
        res_a, res_b = await asyncio.gather(
            _run_asgi(guard, _http_scope("/a")),
            _run_asgi(guard, _http_scope("/b")),
        )
        assert json.loads(b"".join(res_a[2])) == {
            "streams": [{"name": "a-ok", "url": "https://a/1"}]
        }
        assert json.loads(b"".join(res_b[2])) == {
            "streams": [{"name": "b-ok", "url": "https://b/1"}]
        }

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("path", "raw_path"),
    [
        ("/torznab/api", None),
        ("/s/TOK/torznab/api", None),
        ("/s/TOK/TorZnab/api", None),
        ("/s/TOK/torznab/api/", None),
        ("/s/TOK//torznab/api", None),
        ("/s/TOK/torznab", None),
        ("/s/TOK/torznab/api", b"/s/TOK/%74orznab/api"),
        ("/s/TOK/%74orznab/api", b"/s/TOK/%74orznab/api"),
    ],
)
def test_ac2_torznab_paths_return_404_without_calling_inner_app(
    path: str, raw_path: bytes | None
) -> None:
    """AC-2: torznab segments in any case or encoding return 404 without hitting inner app."""
    called = False

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"should-not-run", "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, headers, chunks = asyncio.run(_run_asgi(guard, _http_scope(path, raw_path=raw_path)))
    body = b"".join(chunks)
    hmap = _header_map(headers)

    assert not called
    assert status == 404
    assert body == b'{"detail":"Not Found"}'
    assert hmap[b"content-type"] == b"application/json"
    assert hmap[b"content-length"] == str(len(body)).encode("ascii")


@pytest.mark.parametrize(
    "path",
    [
        "/s/TOK/torznabx/api",
        "/s/TOK/xtorznab",
        "/s/TOK/stream/movie/torznab.json",
    ],
)
def test_ac2_torznab_near_misses_reach_inner_app(path: str) -> None:
    """AC-2: near-miss paths where no segment equals torznab reach the inner app."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope(path)))
    assert status == 200
    assert b"".join(chunks) == b"ok"
    assert seen == [path]


def _p2p_stream_payload() -> bytes:
    return json.dumps(
        {
            "streams": [
                {"name": "p2p", "infoHash": "0123456789abcdef0123456789abcdef01234567"},
                {"name": "http", "url": "https://comet.example/playback/1"},
            ]
        }
    ).encode("utf-8")


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-type", b"application/json; charset=utf-8")],
        [(b"content-type", b"Application/JSON")],
        [(b"content-type", b"text/json")],
        [(b"content-type", b"application/vnd.stremio+json")],
        [],
        [(b"content-type", b"")],
        [(b"content-type", b"text/plain; charset=utf-8")],
        [(b"content-type", b"text/html"), (b"content-type", b"application/json")],
    ],
)
def test_ac18_abh_filters_p2p_across_json_missing_empty_and_text_plain(
    headers: list[tuple[bytes, bytes]],
) -> None:
    """AC-18 (a), (b), (h): filters P2P streams for JSON subtypes, missing/empty, text/plain."""
    raw = _p2p_stream_payload()

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [*headers, (b"content-length", str(len(raw)).encode("ascii"))],
            }
        )
        await send({"type": "http.response.body", "body": raw, "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, resp_headers, chunks = asyncio.run(
        _run_asgi(guard, _http_scope("/stream/movie/tt1.json"))
    )
    body = b"".join(chunks)
    assert status == 200
    assert json.loads(body) == {
        "streams": [{"name": "http", "url": "https://comet.example/playback/1"}]
    }
    assert _header_map(resp_headers)[b"content-length"] == str(len(body)).encode("ascii")


def test_ac18_b_bom_and_one_byte_chunks_without_content_type() -> None:
    """AC-18 (b): UTF-8 BOM + whitespace and 1-byte whitespace-prefixed chunks are filtered."""
    raw = _p2p_stream_payload()
    variants = [
        [b"\xef\xbb\xbf  \t\r\n" + raw],
        [bytes([b]) for b in b" \t\n" + raw],
        [b"\xef", b"\xbb", b"\xbf", b" ", raw],
    ]
    for parts in variants:

        async def inner(
            scope: Any, receive: Any, send: Any, *, body_parts: list[bytes] = parts
        ) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            for idx, part in enumerate(body_parts):
                await send(
                    {
                        "type": "http.response.body",
                        "body": part,
                        "more_body": idx < len(body_parts) - 1,
                    }
                )

        guard = StremioGuardResponseGuard(inner)
        status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope("/stream/movie/tt1.json")))
        assert status == 200
        assert json.loads(b"".join(chunks)) == {
            "streams": [{"name": "http", "url": "https://comet.example/playback/1"}]
        }


def test_ac18_c_no_content_type_with_gzip_encoding_returns_502() -> None:
    """AC-18 (c): no content-type with real gzip.compress() P2P body and gzip encoding -> 502."""
    compressed = gzip.compress(_p2p_stream_payload())

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-encoding", b"gzip")],
            }
        )
        await send({"type": "http.response.body", "body": compressed, "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope("/stream/movie/tt1.json")))
    assert status == 502
    assert b"".join(chunks) == b'{"detail":"Bad Gateway"}'


@pytest.mark.parametrize(
    ("status_code", "produced"),
    [
        (200, [b"\x1aE\xdf\xa3-0", b"chunk1", b"chunk2", b"chunk3", b"chunk4"]),
        (206, [b'{"streams":[{"infoHash"', b':"0123"', b',"url":"x"', b"}]}", b""]),
    ],
)
def test_ac18_de_sniff_non_json_and_206_stream_unbuffered(
    status_code: int, produced: list[bytes]
) -> None:
    """AC-18 (d), (e): binary and 206 bodies forward each chunk before the next is produced."""

    async def exercise() -> None:
        chunk_ack = asyncio.Event()
        received_chunks: list[bytes] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            await send({"type": "http.response.start", "status": status_code, "headers": []})
            for idx, chunk in enumerate(produced):
                if idx > 0:
                    await asyncio.wait_for(chunk_ack.wait(), timeout=2.0)
                    chunk_ack.clear()
                await send(
                    {
                        "type": "http.response.body",
                        "body": chunk,
                        "more_body": idx < len(produced) - 1,
                    }
                )

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def outer_send(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.body":
                received_chunks.append(bytes(message["body"]))
                chunk_ack.set()

        guard = StremioGuardResponseGuard(inner)
        await asyncio.wait_for(
            guard(_http_scope("/stream/1"), receive, outer_send),
            timeout=2.0,
        )
        assert received_chunks == produced

    asyncio.run(exercise())


@pytest.mark.parametrize("media_type", [b"video/mp4", b"application/octet-stream"])
def test_ac18_f_binary_types_are_not_inspected(media_type: bytes) -> None:
    """AC-18 (f): binary content types pass P2P-shaped bytes through unchanged."""
    raw = _p2p_stream_payload()

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", media_type)],
            }
        )
        await send({"type": "http.response.body", "body": raw, "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope("/playback/1")))
    assert status == 200
    assert b"".join(chunks) == raw


@pytest.mark.parametrize("body", [b"", b"  \t\r\n  "])
def test_ac18_g_undecided_empty_and_whitespace_bodies_unchanged(body: bytes) -> None:
    """AC-18 (g): no content-type with empty or whitespace-only body passes unchanged."""

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    guard = StremioGuardResponseGuard(inner)
    status, _, chunks = asyncio.run(_run_asgi(guard, _http_scope("/health")))
    assert status == 200
    assert b"".join(chunks) == body
