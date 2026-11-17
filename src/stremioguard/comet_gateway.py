"""Token-managed gateway for Comet addon access."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from stremioguard.config import (
    COMET_GATEWAY_CONTAINER_PORT,
    COMET_GATEWAY_HEALTH_PORT,
    COMET_PORT,
    DOCKER_QUERY_TIMEOUT_SECONDS,
    Runner,
    SubprocessRunner,
    compose_command,
    service_container_id,
)
from stremioguard.env import atomic_write_text, ensure_directory

# COMET_GATEWAY_CONTAINER_PORT is re-exported from config, where the registry
# of ports in gluetun's shared namespace lives (config.NAMESPACE_PORTS).
__all__ = ["COMET_GATEWAY_CONTAINER_PORT", "CometGatewayConfig", "CometGatewayManager"]
# The gateway's state directory, mounted read-only. A directory, not single
# files: a file bind mount pins the inode it started with, so an atomically
# replaced tokens.map would never reach nginx and revoked tokens kept working.
GATEWAY_CONFIG_DIR = "/etc/nginx/stremioguard"

_TOKEN_VALUE_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,256}\Z")
_TOKEN_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

# Comet's IP_PROXY_HEADERS from comet/utils/network.py in
# g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea.
_COMET_IP_PROXY_HEADERS = (
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Real-IP",
    "X-Client-IP",
    "DO-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-Forwarded-For",
    "X-Forwarded",
    "Forwarded-For",
    "Forwarded",
    "X-AppEngine-User-IP",
    "CF-Pseudo-IPv4",
    "X-AIOStreams-User-IP",
)


# Token-lock depth per lock file, per thread (see `_token_lock`).
_HELD_TOKEN_LOCKS = threading.local()


def _copy_tokens(tokens: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    return {token_id: dict(entry) for token_id, entry in tokens.items()}


@dataclass(frozen=True)
class CometGatewayConfig:
    root_dir: Path
    env_file: Path
    state_dir: Path
    tokens_file: Path
    nginx_conf_file: Path
    tokens_map_file: Path
    service_name: str
    container_name: str
    host_port: int
    bind_addresses: tuple[str, ...]
    public_base_url: str | None
    token_length: int
    enabled: bool

    @classmethod
    def from_env(
        cls, root_dir: Path | None = None, *, env_file: Path | None = None
    ) -> CometGatewayConfig:
        from stremioguard.config import CometConfig

        comet = CometConfig.from_env(root_dir, env_file=env_file)
        state_dir = comet.root_dir / ".stremio" / "comet-gateway"
        return cls(
            root_dir=comet.root_dir,
            env_file=comet.env_file,
            state_dir=state_dir,
            tokens_file=state_dir / "tokens.json",
            nginx_conf_file=state_dir / "nginx.conf",
            tokens_map_file=state_dir / "tokens.map",
            service_name="comet-gateway",
            container_name="comet-gateway",
            host_port=comet.gateway_host_port,
            bind_addresses=comet.bind_addresses,
            public_base_url=comet.gateway_public_base_url,
            token_length=comet.gateway_token_length,
            enabled=comet.gateway_enabled,
        )


class CometGatewayManager:
    def __init__(self, config: CometGatewayConfig, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()

    # ── Token storage ──────────────────────────────────────────────

    def _state_error(self, detail: str) -> RuntimeError:
        return RuntimeError(
            f"Malformed gateway token state in {self.config.tokens_file} ({detail}); "
            "fix it, or move the file aside and add the tokens again."
        )

    def load_state(self) -> dict[str, object]:
        try:
            content = self.config.tokens_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"default": None, "tokens": {}}
        except (OSError, UnicodeDecodeError) as error:
            raise self._state_error(f"unreadable file: {error}") from error
        if not content.strip():
            raise self._state_error("file is empty")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as error:
            raise self._state_error(f"invalid JSON: {error.msg}") from error
        if not isinstance(data, dict):
            raise self._state_error("top-level JSON value must be an object")
        default_id = data.get("default")
        if default_id is not None and not isinstance(default_id, str):
            raise self._state_error("'default' must be null or a string")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise self._state_error("'tokens' must be an object")
        tokens = data["tokens"]
        for tid, entry in tokens.items():
            if not isinstance(tid, str) or not isinstance(entry, dict):
                raise self._state_error("'tokens' must map string IDs to objects")
        return {
            "default": default_id,
            "tokens": tokens,
        }

    def save_state(self, state: dict[str, object]) -> None:
        ensure_directory(self.config.state_dir)
        payload = json.dumps(state, indent=2) + "\n"
        atomic_write_text(self.config.tokens_file, payload, mode=0o600)

    def load_tokens(self) -> dict[str, dict[str, object]]:
        return self.load_state()["tokens"]  # type: ignore[return-value]

    def default_token_id(self) -> str | None:
        default_id = self.load_state().get("default")
        return str(default_id) if default_id else None

    def default_token(self) -> str | None:
        state = self.load_state()
        default_id = state.get("default")
        tokens = state.get("tokens", {})
        if not isinstance(default_id, str) or not isinstance(tokens, dict):
            return None
        entry = tokens.get(default_id)
        if not isinstance(entry, dict):
            return None
        token = entry.get("token")
        return str(token) if token else None

    def _oldest_token_id(self, tokens: dict[str, dict[str, object]]) -> str | None:
        if not tokens:
            return None
        return sorted(
            tokens,
            key=lambda tid: str(tokens[tid].get("created", "")),
        )[0]

    @contextmanager
    def _token_lock(self) -> Iterator[None]:
        """Serialize every read-modify-write of the token files.

        Reentrant within a thread: a token command that holds the lock calls
        `write_nginx_configs()`, which takes it too, and a second `flock` on a
        new open file description would wait on itself forever. Other threads
        and processes wait for the holder.
        """
        ensure_directory(self.config.state_dir)
        lock_path = self.config.tokens_file.with_suffix(".lock")
        key = str(lock_path.resolve())
        held: dict[str, int] = _HELD_TOKEN_LOCKS.__dict__.setdefault("depth", {})
        if held.get(key, 0):
            held[key] += 1
            try:
                yield
            finally:
                held[key] -= 1
            return
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            lock_file = os.fdopen(fd, "a+", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            held[key] = 1
            try:
                yield
            finally:
                held.pop(key, None)
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _commit_tokens(
        self, before: dict[str, dict[str, object]], state: dict[str, object]
    ) -> None:
        """Save a token change so that no failure can leave an unlisted token admitted.

        First the map admits only tokens present before *and* after the
        change, so a revocation takes effect before tokens.json changes; then
        tokens.json is saved; then the map admits the new state, so an added
        token works only once it is listed. A failure at any step leaves every
        token admitted-and-listed, denied-and-listed or gone, and a failed
        revoke can simply be run again. Callers hold the token lock.
        """
        after = state["tokens"]
        assert isinstance(after, dict)
        kept = {
            token_id: entry
            for token_id, entry in after.items()
            if isinstance(entry, dict)
            and token_id in before
            and before[token_id].get("token") == entry.get("token")
        }
        ensure_directory(self.config.state_dir)
        atomic_write_text(self.config.tokens_map_file, self.render_tokens_map(kept), mode=0o600)
        self.save_state(state)
        self.write_nginx_configs()

    def _create_token_in_state(
        self,
        state: dict[str, object],
        label: str,
        *,
        make_default: bool,
    ) -> tuple[str, str]:
        tokens = state["tokens"]  # type: ignore[assignment]
        assert isinstance(tokens, dict)
        token_id = secrets.token_hex(3)
        while token_id in tokens:
            token_id = secrets.token_hex(3)
        raw = secrets.token_urlsafe(self.config.token_length + 4)
        token_value = raw[: self.config.token_length]
        tokens[token_id] = {
            "label": label,
            "token": token_value,
            "created": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        if make_default or not state.get("default"):
            state["default"] = token_id
        return token_id, token_value

    def _validated_tokens(self, tokens: dict[str, dict[str, object]]) -> list[tuple[str, str]]:
        validated: list[tuple[str, str]] = []
        for token_id, entry in tokens.items():
            if not _TOKEN_ID_PATTERN.fullmatch(token_id):
                raise RuntimeError(
                    f"Invalid gateway token ID {token_id!r} in {self.config.tokens_file}; "
                    "fix it, or move the file aside and add the tokens again."
                )
            token = entry.get("token")
            if not isinstance(token, str) or not _TOKEN_VALUE_PATTERN.fullmatch(token):
                raise RuntimeError(
                    f"Invalid gateway token for ID {token_id!r} in {self.config.tokens_file}; "
                    "fix it, or move the file aside and add the tokens again."
                )
            validated.append((token_id, token))
        return validated

    # ── Token CRUD ─────────────────────────────────────────────────

    def add_token(self, label: str, *, make_default: bool = False) -> tuple[str, str]:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            self._validated_tokens(tokens)  # type: ignore[arg-type]
            before = _copy_tokens(tokens)
            token_id, token_value = self._create_token_in_state(
                state, label, make_default=make_default
            )
            self._commit_tokens(before, state)
            return token_id, token_value

    def revoke_token(self, token_id: str) -> str:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            self._validated_tokens(tokens)  # type: ignore[arg-type]
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            entry = tokens[token_id]
            assert isinstance(entry, dict)
            label = str(entry.get("label", ""))
            before = _copy_tokens(tokens)
            del tokens[token_id]
            if state.get("default") == token_id:
                state["default"] = self._oldest_token_id(tokens)  # type: ignore[arg-type]
            self._commit_tokens(before, state)
            return label

    def rotate_token(self, token_id: str) -> tuple[str, str]:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            self._validated_tokens(tokens)  # type: ignore[arg-type]
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            entry = tokens[token_id]
            assert isinstance(entry, dict)
            label = str(entry.get("label", ""))
            was_default = state.get("default") == token_id
            before = _copy_tokens(tokens)
            del tokens[token_id]
            state["default"] = (
                self._oldest_token_id(tokens) if was_default else state.get("default")
            )
            new_id, new_value = self._create_token_in_state(state, label, make_default=was_default)
            self._commit_tokens(before, state)
            return new_id, new_value

    def use_token(self, token_id: str) -> str:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            self._validated_tokens(tokens)  # type: ignore[arg-type]
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            before = _copy_tokens(tokens)
            state["default"] = token_id
            self._commit_tokens(before, state)
            entry = tokens[token_id]
            assert isinstance(entry, dict)
            return str(entry.get("label", ""))

    def list_tokens(self) -> list[dict[str, str]]:
        state = self.load_state()
        default_id = state.get("default")
        tokens = state["tokens"]  # type: ignore[assignment]
        assert isinstance(tokens, dict)
        rows: list[dict[str, str]] = []
        for tid, entry in tokens.items():
            assert isinstance(entry, dict)
            rows.append(
                {
                    "id": str(tid),
                    "label": str(entry.get("label", "")),
                    "token": str(entry.get("token", "")),
                    "created": str(entry.get("created", "")),
                    "default": "yes" if tid == default_id else "",
                }
            )
        return rows

    # ── URL helpers ────────────────────────────────────────────────

    def public_base_url(self) -> str:
        if self.config.public_base_url:
            return self.config.public_base_url.rstrip("/")
        addr = self.config.bind_addresses[0] if self.config.bind_addresses else "127.0.0.1"
        return f"http://{addr}:{self.config.host_port}"

    def addon_base_url(self, token: str) -> str:
        return f"{self.public_base_url()}/comet/{token}"

    def rewrite_manifest_url(self, manifest_url: str, token_id: str) -> str:
        tokens = self.load_tokens()
        if token_id not in tokens:
            raise KeyError(f"Token ID {token_id!r} not found")
        token = str(tokens[token_id].get("token", ""))
        parsed = urllib.parse.urlparse(manifest_url)
        path_parts = [part for part in parsed.path.split("/") if part]
        if (
            not path_parts
            or path_parts[-1] != "manifest.json"
            or not parsed.path.endswith("/manifest.json")
        ):
            raise ValueError(
                "Expected a Stremio manifest URL ending in /manifest.json "
                "(ChillLink /manifest URLs are not served through the gateway)"
            )
        if path_parts[:1] == ["comet"] and len(path_parts) >= 3:
            comet_path = "/" + "/".join(path_parts[2:])
        else:
            comet_path = "/" + "/".join(path_parts)
        return f"{self.addon_base_url(token)}{comet_path}"

    # ── Nginx config generation ────────────────────────────────────

    def render_tokens_map(self, tokens: dict[str, dict[str, object]] | None = None) -> str:
        validated = self._validated_tokens(self.load_tokens() if tokens is None else tokens)
        lines = [
            "# Generated by ./stremio; do not edit by hand.",
            "map $gateway_token $token_valid {",
            "    default 0;",
        ]
        for _, token in validated:
            lines.append(f'    "~^{token}$" 1;')
        lines.append("}")
        # The token's ID, for the access log. The ID is what `./stremio comet
        # token list` shows and is not a credential, so a request can be
        # attributed to a token (and that token revoked) without the log ever
        # holding the token itself.
        lines.extend(["map $gateway_token $gateway_token_id {", '    default "-";'])
        for token_id, token in validated:
            lines.append(f'    "~^{token}$" "{token_id}";')
        lines.append("}")
        return "\n".join(lines) + "\n"

    def render_nginx_conf(self) -> str:
        # Accept any URL-safe token length here so previously issued tokens keep
        # routing through the tokens.map lookup even if COMET_GATEWAY_TOKEN_LENGTH
        # changes; tokens.map is the authoritative gate.
        token_re = "[A-Za-z0-9_-]+"
        api_prefix = r"/s/[A-Za-z0-9_-]+"
        seg = r"(?!(?:\.\.?)(?:/|$))(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$&'()*+,=:@-])+"
        seg_prefix = r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$&'()*+,=:@-])+"
        public_mask_rule = (
            r"~^(?<mrh>\S+\s/(?:configure(?:/[^\s?]*)?|static/[^\s?]*|health))"
            r'(?:\?\S*)?(?<mrt>\s+\S+)$ "${mrh}${mrt}";'
        )
        clear_ip_headers = "\n".join(
            f'            proxy_set_header {header} "";' for header in _COMET_IP_PROXY_HEADERS
        )
        return f"""\
# Generated by ./stremio; do not edit by hand.
worker_processes 1;
# Hardened API key management: Nginx attaches the client request line to
# request-context error logs, which can carry configuration parameters.
# Setting error_log to crit keeps upstream connection failures out of error_log
# while the structured access_log safely records masked upstream statuses and timings.
error_log /var/log/nginx/error.log crit;
pid /tmp/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    # Extract the token and raw path from $request_uri (never from decoded/normalized $uri)
    # so percent-encoded or traversal forms never match a token or smuggle a path.
    map $request_uri $gateway_token {{
        ~^/comet/(?<gt>{token_re})(?:[/?]|$) $gt;
        default "";
    }}

    map $request_uri $raw_comet_path {{
        ~^/comet/{token_re}(?<rcp>/[^?]*)(?:\\?.*)?$ $rcp;
        default "";
    }}

    # Exact addon allowlist (case-sensitive, raw path up to ?).
    map $raw_comet_path $comet_route_action {{
        ""  redirect;
        "/" redirect;
        "~(?:%(?:2[FfEe]|5[Cc])|[;#\\x5c])" deny;
        "~^{api_prefix}(?:/{seg})?/manifest\\.json$" proxy;
        "~^{api_prefix}(?:/{seg})?/stream/{seg}/{seg_prefix}\\.json$" proxy;
        "~^{api_prefix}/{seg}/playback/{seg}/{seg}/{seg}/{seg}/{seg}$" proxy;
        "~^(?:{api_prefix})?(?:/{seg})?/configure$" proxy;
        "~^/configure/login$" proxy;
        default deny;
    }}

    include {GATEWAY_CONFIG_DIR}/tokens.map;

    # Rate-limit denials without throttling valid token traffic. A plain `return 403`
    # runs in the rewrite phase, BEFORE limit_req's preaccess phase, so the limiter
    # would never fire; instead denied requests rewrite to an internal location (or
    # fall into `location /`) whose `deny all` rejects in the access phase AFTER limit_req.
    # Valid tokens never enter those locations, so authenticated playback (with its
    # bursty range requests during seeks) is never throttled.
    #
    # These zones are keyed by client address, but behind rootless Docker's
    # port forwarder (and behind a reverse proxy) every client arrives from
    # the same address, so each zone is in practice ONE shared bucket. That
    # is the safe direction for the invalid-token limiter (a guesser cannot
    # spread across addresses); keying on X-Forwarded-For instead would let
    # any client pick its own bucket. $remote_addr in the log is likewise not
    # a client identity; `tid=` is what attributes a request.
    limit_req_zone $binary_remote_addr zone=gateway_auth:1m rate=5r/s;
    limit_req_zone $binary_remote_addr zone=gateway_admin:1m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=gateway_fail:1m rate=5r/s;

    # Password guessing on the configure-page login: every POST to
    # /configure/login, public or under a token, draws from one strict bucket
    # (6 a minute, 5 in a burst). Every other request has an empty key, which
    # limit_req never counts. Behind the port forwarder all clients share the
    # bucket, so a guesser also slows the owner's own login; that is the
    # intended trade.
    map "$request_method $request_uri" $login_limit_key {{
        "~^POST /(?:comet/{token_re}/)?configure/login(?:\\?.*)?$" $binary_remote_addr;
        default "";
    }}
    limit_req_zone $login_limit_key zone=gateway_login:1m rate=6r/m;

    # Mask request paths before they reach the access log. After /comet/ the
    # line carries the gateway token AND the base64 Comet config blob, which
    # can embed debrid API keys, so everything up to the protocol field is
    # replaced. Any other path is masked too (a raw Comet addon URL sent here
    # is refused but would otherwise be logged whole); only the public gateway
    # UI/health paths stay readable (with query strings stripped). First matching regex wins.
    map $request $request_masked {{
        ~^(?<mrh>\\S+\\s\\S*/comet/).+?(?<mrt>\\s+HTTP/\\S+)$ "${{mrh}}***${{mrt}}";
        ~^(?<mrh>\\S+\\s)\\S*(?:%|/\\.\\.).*?(?<mrt>\\s+HTTP/\\S+)$ "${{mrh}}***${{mrt}}";
        {public_mask_rule}
        ~^(?<mrh>\\S+\\s/)(?:\\?\\S*)?(?<mrt>\\s+\\S+)$ "${{mrh}}${{mrt}}";
        ~^(?<mrh>\\S+\\s/).+?(?<mrt>\\s+HTTP/\\S+)$ "${{mrh}}***${{mrt}}";
        ~^(?<mrh>\\S+\\s).+$ "${{mrh}}***";
        default $request;
    }}

    log_format main '$remote_addr [$time_local] "$request_masked" $status $body_bytes_sent '
                    'tid=$gateway_token_id '
                    'upstream=$upstream_status urt=$upstream_response_time rt=$request_time';
    access_log /var/log/nginx/access.log main;

    # No nginx version in the Server header or in error pages. On every
    # response, error pages included (`always`), and replacing any copy from
    # Comet: no MIME sniffing, no framing of the configure page, and no
    # Referer to other sites (addon and configure URLs carry the token).
    # No location sets its own add_header, so all of them inherit these.
    server_tokens off;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header X-Frame-Options;
    proxy_hide_header Referrer-Policy;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "same-origin" always;

    map $http_x_forwarded_proto $pass_x_forwarded_proto {{
        ~*^\\s*https(?:[\\s,]|$) https;
        ~*^\\s*http(?:[\\s,]|$)  http;
        default                  $scheme;
    }}

    map $http_host $valid_host {{
        default 0;
        "~^(?:[A-Za-z0-9._-]+|\\[[0-9A-Fa-f:.]+\\])(?::[0-9]{{1,5}})?$" 1;
    }}

    server {{
        listen {COMET_GATEWAY_CONTAINER_PORT};
        server_name _;
        absolute_redirect off;
        set $comet_upstream http://127.0.0.1:{COMET_PORT};

        if ($valid_host = 0) {{
            return 400;
        }}

        location ^~ /comet/ {{
            limit_req zone=gateway_login burst=5 nodelay;
            if ($token_valid = 0) {{
                rewrite ^ /__sg_invalid_token last;
            }}
            if ($comet_route_action = "redirect") {{
                return 302 /comet/$gateway_token/configure;
            }}
            if ($comet_route_action != "proxy") {{
                rewrite ^ /__sg_forbidden last;
            }}
            if ($raw_comet_path = "") {{
                return 400;
            }}

            proxy_pass $comet_upstream$raw_comet_path$is_args$args;
            proxy_http_version 1.1;
            proxy_set_header Upgrade "";
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Prefix /comet/$gateway_token;
            # Clear all 14 headers from Comet's comet/utils/network.py (IP_PROXY_HEADERS)
            # at sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea.
{clear_ip_headers}
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location = /__sg_invalid_token {{
            internal;
            limit_req zone=gateway_auth burst=10 nodelay;
            deny all;
        }}

        location = /__sg_forbidden {{
            internal;
            limit_req zone=gateway_fail burst=3 nodelay;
            deny all;
        }}

        location ~ "^/(?:configure(?:/|$)|static/|health(?:/|$))" {{
            limit_req zone=gateway_login burst=5 nodelay;
            limit_req zone=gateway_admin burst=20 nodelay;
            proxy_pass $comet_upstream$request_uri;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Prefix "";
{clear_ip_headers}
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location = / {{
            limit_req zone=gateway_admin burst=20 nodelay;
            proxy_pass $comet_upstream$request_uri;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Prefix "";
{clear_ip_headers}
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location / {{
            limit_req zone=gateway_fail burst=3 nodelay;
            deny all;
        }}
    }}

    server {{
        listen 127.0.0.1:{COMET_GATEWAY_HEALTH_PORT};
        access_log off;

        location = /__sg_alive {{
            return 204;
        }}

        location / {{
            return 404;
        }}
    }}
}}
"""

    def write_nginx_configs(self) -> None:
        # Under the token lock, so tokens.map always renders the tokens.json
        # that is current when it is written: a reload or start that read the
        # tokens before a revoke can no longer write the revoked token back.
        with self._token_lock():
            nginx_conf = self.render_nginx_conf()
            tokens_map = self.render_tokens_map()
            ensure_directory(self.config.state_dir)
            # These files carry live gateway tokens; write them atomically at 0600
            # (the nginx container runs as root and can still read the bind mounts).
            atomic_write_text(self.config.nginx_conf_file, nginx_conf, mode=0o600)
            atomic_write_text(self.config.tokens_map_file, tokens_map, mode=0o600)

    # ── Compose lifecycle ──────────────────────────────────────────

    def prepare_runtime(self) -> None:
        ensure_directory(self.config.state_dir)
        self.write_nginx_configs()

    def service_container_id(self) -> str | None:
        return service_container_id(self.runner, self.config.root_dir, self.config.service_name)

    def status(self) -> None:
        container_id = self.service_container_id()
        result = (
            self.runner.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container_id or ""],
                check=False,
            )
            if container_id
            else None
        )
        state = (result.stdout or "").strip() if result and result.returncode == 0 else "not found"
        logger.info(f"Comet gateway container: {state}")
        logger.info(f"Active tokens: {len(self.load_tokens())}")
        logger.info(f"Default token: {self.default_token_id() or '-'}")
        logger.info(f"Public base URL: {self.public_base_url()}")

    def reload_nginx(self) -> None:
        """Apply the config and token map to the running gateway and prove they landed.

        A reload only helps if nginx reads the new files; the state directory is
        mounted (not single files, which keep the inode they started with), and
        the in-container hashes are compared before claiming success. The token
        lock is held throughout, so no token change lands between the write,
        the check and the reload.
        """
        with self._token_lock():
            self._reload_nginx_locked()

    def _reload_nginx_locked(self) -> None:
        self.write_nginx_configs()
        container_id = self.service_container_id()
        if not container_id:
            raise RuntimeError("Comet gateway container is not running; cannot reload nginx.")
        nginx = ["docker", "exec", container_id, "nginx", "-c", f"{GATEWAY_CONFIG_DIR}/nginx.conf"]
        self.runner.run([*nginx, "-t"], check=True, timeout=DOCKER_QUERY_TIMEOUT_SECONDS)
        for filename, host_file in (
            ("nginx.conf", self.config.nginx_conf_file),
            ("tokens.map", self.config.tokens_map_file),
        ):
            expected = hashlib.sha256(host_file.read_bytes()).hexdigest()
            container_path = f"{GATEWAY_CONFIG_DIR}/{filename}"
            seen = self.runner.run(
                ["docker", "exec", container_id, "sha256sum", container_path],
                check=True,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
            if (seen.stdout or "").split(" ", 1)[0].strip() != expected:
                raise RuntimeError(
                    f"The gateway container does not see the updated {filename}; "
                    "run `./stremio restart` so the running gateway uses the current config."
                )
        self.runner.run([*nginx, "-s", "reload"], check=True, timeout=DOCKER_QUERY_TIMEOUT_SECONDS)

    def container_running(self) -> bool | None:
        """Whether the gateway container is running, or ``None`` if Docker did not answer."""
        try:
            ps_result = self.runner.run(
                compose_command(self.config.root_dir, "ps", "-q", self.config.service_name),
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if ps_result.returncode != 0:
            return None
        container_id = next(
            (line.strip() for line in (ps_result.stdout or "").splitlines() if line.strip()),
            None,
        )
        if not container_id:
            return False
        try:
            result = self.runner.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if result.returncode != 0:
            return None
        state = (result.stdout or "").strip().lower()
        if state == "true":
            return True
        if state == "false":
            return False
        return None
