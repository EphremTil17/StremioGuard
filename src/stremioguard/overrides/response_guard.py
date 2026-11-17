"""Pure-ASGI response guard that strips P2P streams, blocks torznab and paces logins.

Runs inside the Comet container with standard-library imports only.

Security hardening for edge cases:

- An entry counts as P2P when it has an infoHash, a magnet URL, or a
  non-empty `sources` list (trackers): P2P fields are stripped, and an entry
  with no HTTP URL left is dropped. Top-level `sources` lists (another addon
  format) are filtered the same way as `streams`.
- Password attempts are paced per login page: `/configure/login` and
  `/admin/login` each have an in-process budget (6 a minute, 5 at once;
  excess gets 429), so guessing is paced on every path to Comet, the host's
  own loopback port included. They are separate because every client
  reaches Comet from the same address: guesses at the public configure page
  must not lock the owner out of the admin dashboard.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from typing import Any
from urllib.parse import unquote

_NOT_FOUND_BODY = b'{"detail":"Not Found"}'
_BAD_GATEWAY_BODY = b'{"detail":"Bad Gateway"}'
_STRIP_KEYS = frozenset({"infohash", "fileidx", "sources", "announce"})
_UTF8_BOM = b"\xef\xbb\xbf"
_JSON_WHITESPACE = frozenset(b" \t\n\r")
_LIST_KEYS = ("streams", "sources")
_LOGIN_PATHS = frozenset({"/configure/login", "/admin/login"})
_LOGIN_RATE_PER_SECOND = 6 / 60
_LOGIN_BURST = 5.0
_TOO_MANY_LOGINS_BODY = b'{"detail":"Too many login attempts; wait a minute and try again."}'


class _LoginBudget:
    """A token bucket shared by every attempt at one login page in this process."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._tokens = _LOGIN_BURST
        self._updated = clock()

    def allow(self) -> bool:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(_LOGIN_BURST, self._tokens + elapsed * _LOGIN_RATE_PER_SECOND)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


_LOGIN_BUDGETS = {path: _LoginBudget() for path in _LOGIN_PATHS}


def _is_torznab_path(path: str) -> bool:
    return any(unquote(segment).lower() == "torznab" for segment in path.split("/"))


def _extract_media_types(headers: Sequence[tuple[bytes, bytes]]) -> list[bytes]:
    types: list[bytes] = []
    for name, value in headers:
        if name.lower() == b"content-type":
            types.append(value.split(b";", 1)[0].strip().lower())
    return types


def _is_json_media_type(media_type: bytes) -> bool:
    if b"/" not in media_type:
        return False
    main, subtype = media_type.split(b"/", 1)
    if not main or not subtype:
        return False
    return subtype == b"json" or (subtype.endswith(b"+json") and len(subtype) > len(b"+json"))


def _classify_response(status: int, headers: Sequence[tuple[bytes, bytes]]) -> str:
    media_types = _extract_media_types(headers)
    if any(_is_json_media_type(media) for media in media_types):
        return "inspect"
    if status != 206 and (
        not media_types
        or all(not media for media in media_types)
        or any(media == b"text/plain" for media in media_types)
    ):
        return "inspect" if _has_non_identity_encoding(headers) else "sniff"
    return "passthrough"


def _has_non_identity_encoding(headers: Sequence[tuple[bytes, bytes]]) -> bool:
    for name, value in headers:
        if name.lower() == b"content-encoding" and value.strip().lower() != b"identity":
            return True
    return False


def _filter_stream_entry(entry: Any) -> tuple[bool, Any, bool]:
    if not isinstance(entry, dict):
        return True, entry, False

    has_infohash = False
    has_p2p_sources = False
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
        if lowered == "sources" and value:
            has_p2p_sources = True
        if lowered in _STRIP_KEYS:
            has_strip_key = True

    if not (has_infohash or has_p2p_sources):
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
    if not isinstance(payload, dict):
        return payload, False

    updated = dict(payload)
    changed = False
    for list_key in _LIST_KEYS:
        items = payload.get(list_key)
        if not isinstance(items, list):
            continue
        filtered: list[Any] = []
        for item in items:
            keep, transformed, item_changed = _filter_stream_entry(item)
            if item_changed:
                changed = True
            if keep:
                filtered.append(transformed)
        updated[list_key] = filtered

    if not changed:
        return payload, False
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

        login_budget = _LOGIN_BUDGETS.get(str(scope.get("path") or "").rstrip("/"))
        if (
            login_budget is not None
            and str(scope.get("method") or "").upper() == "POST"
            and not login_budget.allow()
        ):
            await _send_json_response(send, 429, _TOO_MANY_LOGINS_BODY)
            return

        inner_scope = dict(scope)
        raw_headers = scope.get("headers") or ()
        inner_scope["headers"] = [
            (name, value) for name, value in raw_headers if name.lower() != b"accept-encoding"
        ]

        mode: str | None = None
        start_message: MutableMapping[str, Any] | None = None
        body_chunks: list[bytes] = []
        sniff_buf = bytearray()
        sniff_pos = 0
        bom_checked = False

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal mode, start_message, sniff_pos, bom_checked
            msg_type = message.get("type")

            if msg_type == "http.response.start":
                headers = message.get("headers") or ()
                status = int(message.get("status", 0))
                mode = _classify_response(status, headers)
                if mode == "passthrough":
                    await send(message)
                    return
                start_message = message
                return

            if msg_type == "http.response.body":
                if mode == "passthrough" or start_message is None:
                    await send(message)
                    return
                chunk = message.get("body", b"")
                more_body = bool(message.get("more_body", False))

                if mode == "sniff":
                    if chunk:
                        sniff_buf.extend(chunk)
                    if not bom_checked:
                        if len(sniff_buf) < len(_UTF8_BOM) and _UTF8_BOM.startswith(
                            bytes(sniff_buf)
                        ):
                            if more_body:
                                return
                            mode = "passthrough"
                            held = bytes(sniff_buf)
                            sniff_buf.clear()
                            await send(start_message)
                            await send(
                                {"type": "http.response.body", "body": held, "more_body": False}
                            )
                            return
                        bom_checked = True
                        if sniff_buf.startswith(_UTF8_BOM):
                            sniff_pos = len(_UTF8_BOM)

                    while sniff_pos < len(sniff_buf) and sniff_buf[sniff_pos] in _JSON_WHITESPACE:
                        sniff_pos += 1

                    if sniff_pos == len(sniff_buf):
                        if more_body:
                            return
                        mode = "passthrough"
                        held = bytes(sniff_buf)
                        sniff_buf.clear()
                        await send(start_message)
                        await send({"type": "http.response.body", "body": held, "more_body": False})
                        return

                    if sniff_buf[sniff_pos] in (ord("{"), ord("[")):
                        mode = "inspect"
                        body_chunks.append(bytes(sniff_buf))
                        sniff_buf.clear()
                        if more_body:
                            return
                    else:
                        mode = "passthrough"
                        held = bytes(sniff_buf)
                        sniff_buf.clear()
                        await send(start_message)
                        await send(
                            {
                                "type": "http.response.body",
                                "body": held,
                                "more_body": more_body,
                            }
                        )
                        return
                else:
                    if chunk:
                        body_chunks.append(chunk)
                    if more_body:
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
