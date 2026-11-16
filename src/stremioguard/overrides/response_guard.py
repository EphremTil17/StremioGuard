"""Pure-ASGI response guard that strips P2P streams and blocks torznab.

Runs inside the Comet container with standard-library imports only.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from typing import Any
from urllib.parse import unquote

_NOT_FOUND_BODY = b'{"detail":"Not Found"}'
_BAD_GATEWAY_BODY = b'{"detail":"Bad Gateway"}'
_STRIP_KEYS = frozenset({"infohash", "fileidx", "sources", "announce"})


def _is_torznab_path(path: str) -> bool:
    return any(unquote(segment).lower() == "torznab" for segment in path.split("/"))


def _extract_media_type(headers: Sequence[tuple[bytes, bytes]]) -> bytes:
    for name, value in headers:
        if name.lower() == b"content-type":
            return value.split(b";", 1)[0].strip().lower()
    return b""


def _has_non_identity_encoding(headers: Sequence[tuple[bytes, bytes]]) -> bool:
    for name, value in headers:
        if name.lower() == b"content-encoding" and value.strip().lower() != b"identity":
            return True
    return False


def _filter_stream_entry(entry: Any) -> tuple[bool, Any, bool]:
    if not isinstance(entry, dict):
        return True, entry, False

    has_infohash = False
    has_http_url = False
    has_strip_key = False

    for key, value in entry.items():
        if not isinstance(key, str):
            continue
        lowered = key.lower()
        if (
            lowered in ("url", "externalurl")
            and isinstance(value, str)
            and value.lstrip().lower().startswith("magnet:")
        ):
            return False, None, True
        if (
            lowered == "url"
            and isinstance(value, str)
            and value.lower().startswith(("http://", "https://"))
        ):
            has_http_url = True
        if lowered == "infohash":
            has_infohash = True
        if lowered in _STRIP_KEYS:
            has_strip_key = True

    if not has_infohash:
        return True, entry, False
    if not has_http_url:
        return False, None, True
    if not has_strip_key:
        return True, entry, False

    cleaned = {
        key: value
        for key, value in entry.items()
        if not (isinstance(key, str) and key.lower() in _STRIP_KEYS)
    }
    return True, cleaned, True


def _filter_payload(payload: Any) -> tuple[Any, bool]:
    if not isinstance(payload, dict) or not isinstance(payload.get("streams"), list):
        return payload, False

    changed = False
    filtered_streams: list[Any] = []
    for item in payload["streams"]:
        keep, transformed, item_changed = _filter_stream_entry(item)
        if item_changed:
            changed = True
        if keep:
            filtered_streams.append(transformed)

    if not changed:
        return payload, False

    updated = dict(payload)
    updated["streams"] = filtered_streams
    return updated, True


async def _send_json_response(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    status: int,
    body: bytes,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_passthrough(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    start_message: MutableMapping[str, Any],
    raw_body: bytes,
) -> None:
    await send(start_message)
    await send({"type": "http.response.body", "body": raw_body, "more_body": False})


class StremioGuardResponseGuard:
    """Outermost ASGI middleware blocking torznab and P2P stream entries."""

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if _is_torznab_path(str(scope.get("path") or "")):
            await _send_json_response(send, 404, _NOT_FOUND_BODY)
            return

        inner_scope = dict(scope)
        raw_headers = scope.get("headers") or ()
        inner_scope["headers"] = [
            (name, value) for name, value in raw_headers if name.lower() != b"accept-encoding"
        ]

        passthrough: bool | None = None
        start_message: MutableMapping[str, Any] | None = None
        body_chunks: list[bytes] = []

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal passthrough, start_message
            msg_type = message.get("type")

            if msg_type == "http.response.start":
                headers = message.get("headers") or ()
                if _extract_media_type(headers) != b"application/json":
                    passthrough = True
                    await send(message)
                    return
                passthrough = False
                start_message = message
                return

            if msg_type == "http.response.body":
                if passthrough or start_message is None:
                    await send(message)
                    return
                chunk = message.get("body", b"")
                if chunk:
                    body_chunks.append(chunk)
                if message.get("more_body", False):
                    return

                resp_headers: list[tuple[bytes, bytes]] = list(start_message.get("headers") or ())
                if _has_non_identity_encoding(resp_headers):
                    await _send_json_response(send, 502, _BAD_GATEWAY_BODY)
                    return

                raw_body = b"".join(body_chunks)
                if not raw_body:
                    await _send_passthrough(send, start_message, raw_body)
                    return

                try:
                    parsed = json.loads(raw_body)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    lowered = raw_body.lower()
                    if b"infohash" in lowered or b"magnet:" in lowered:
                        await _send_json_response(send, 502, _BAD_GATEWAY_BODY)
                    else:
                        await _send_passthrough(send, start_message, raw_body)
                    return

                filtered, changed = _filter_payload(parsed)
                if not changed:
                    await _send_passthrough(send, start_message, raw_body)
                    return

                new_body = json.dumps(filtered, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
                new_headers = [
                    (name, value)
                    for name, value in resp_headers
                    if name.lower() not in (b"content-length", b"etag")
                ]
                new_headers.append((b"content-length", str(len(new_body)).encode("ascii")))
                new_start = dict(start_message)
                new_start["headers"] = new_headers
                await send(new_start)
                await send({"type": "http.response.body", "body": new_body, "more_body": False})
                return

            await send(message)

        await self.app(inner_scope, receive, send_wrapper)
