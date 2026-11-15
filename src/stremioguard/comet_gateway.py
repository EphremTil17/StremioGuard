"""Token-managed gateway for Comet addon access."""

from __future__ import annotations

import fcntl
import hashlib
import json
import secrets
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from stremioguard.config import (
    COMET_GATEWAY_CONTAINER_PORT,
    COMET_PORT,
    Runner,
    SubprocessRunner,
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

    def load_state(self) -> dict[str, object]:
        if not self.config.tokens_file.exists():
            return {"default": None, "tokens": {}}
        content = self.config.tokens_file.read_text(encoding="utf-8")
        data = json.loads(content)
        return {
            "default": data.get("default"),
            "tokens": data.get("tokens", {}),
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
        ensure_directory(self.config.state_dir)
        lock_path = self.config.tokens_file.with_suffix(".lock")
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

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

    # ── Token CRUD ─────────────────────────────────────────────────

    def add_token(self, label: str, *, make_default: bool = False) -> tuple[str, str]:
        with self._token_lock():
            state = self.load_state()
            token_id, token_value = self._create_token_in_state(
                state, label, make_default=make_default
            )
            self.save_state(state)
            self.write_nginx_configs()
            return token_id, token_value

    def revoke_token(self, token_id: str) -> str:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            entry = tokens[token_id]
            assert isinstance(entry, dict)
            label = str(entry.get("label", ""))
            del tokens[token_id]
            if state.get("default") == token_id:
                state["default"] = self._oldest_token_id(tokens)  # type: ignore[arg-type]
            self.save_state(state)
            self.write_nginx_configs()
            return label

    def rotate_token(self, token_id: str) -> tuple[str, str]:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            entry = tokens[token_id]
            assert isinstance(entry, dict)
            label = str(entry.get("label", ""))
            was_default = state.get("default") == token_id
            del tokens[token_id]
            state["default"] = (
                self._oldest_token_id(tokens) if was_default else state.get("default")
            )
            new_id, new_value = self._create_token_in_state(state, label, make_default=was_default)
            self.save_state(state)
            self.write_nginx_configs()
            return new_id, new_value

    def use_token(self, token_id: str) -> str:
        with self._token_lock():
            state = self.load_state()
            tokens = state["tokens"]  # type: ignore[assignment]
            assert isinstance(tokens, dict)
            if token_id not in tokens:
                raise KeyError(f"Token ID {token_id!r} not found")
            state["default"] = token_id
            self.save_state(state)
            self.write_nginx_configs()
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
        if not path_parts or path_parts[-1] not in {"manifest.json", "manifest"}:
            raise ValueError("Expected a Comet manifest URL ending in manifest.json or manifest")
        if path_parts[:1] == ["comet"] and len(path_parts) >= 3:
            comet_path = "/" + "/".join(path_parts[2:])
        else:
            comet_path = "/" + "/".join(path_parts)
        return f"{self.addon_base_url(token)}{comet_path}"

    # ── Nginx config generation ────────────────────────────────────

    def render_tokens_map(self) -> str:
        tokens = self.load_tokens()
        lines = [
            "# Generated by ./stremio; do not edit by hand.",
            "map $gateway_token $token_valid {",
            "    default 0;",
        ]
        for entry in tokens.values():
            token = entry.get("token", "")
            if token:
                lines.append(f'    "{token}" 1;')
        lines.append("}")
        # The token's ID, for the access log. The ID is what `./stremio comet
        # token list` shows and is not a credential, so a request can be
        # attributed to a token (and that token revoked) without the log ever
        # holding the token itself.
        lines.extend(["map $gateway_token $gateway_token_id {", '    default "-";'])
        for token_id, entry in tokens.items():
            token = entry.get("token", "")
            if token:
                lines.append(f'    "{token}" "{token_id}";')
        lines.append("}")
        return "\n".join(lines) + "\n"

    def render_nginx_conf(self) -> str:
        # Accept any URL-safe token length here so previously issued tokens keep
        # routing through the tokens.map lookup even if COMET_GATEWAY_TOKEN_LENGTH
        # changes; tokens.map is the authoritative gate.
        token_re = "[A-Za-z0-9_-]+"
        public_mask_rule = (
            r"~^(?<mrh>\S+\s/(?:configure(?:/[^\s?]*)?|static/[^\s?]*|health))"
            r'(?:\?\S*)?(?<mrt>\s+\S+)$ "${mrh}${mrt}";'
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
    include {GATEWAY_CONFIG_DIR}/tokens.map;

    # Rate-limit only invalid-token requests. A plain `return 403` inside the
    # token locations would run in the rewrite phase, BEFORE limit_req's
    # preaccess phase, so the limiter would never fire; instead invalid tokens
    # are rewritten to an internal location whose `deny all` rejects in the
    # access phase, which runs AFTER limit_req. Valid tokens never enter that
    # location, so authenticated playback (with its bursty range requests
    # during seeks) is never throttled.
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

    map $http_x_forwarded_proto $pass_x_forwarded_proto {{
        ~*^\\s*https(?:[\\s,]|$) https;
        ~*^\\s*http(?:[\\s,]|$)  http;
        default                  $scheme;
    }}

    map $http_host $redirect_host {{
        default $http_host;
        ""      $host;
    }}

    # Preserve raw percent-encoding (e.g. %20 in /playback/...) and query params
    # when forwarding behind /comet/<token>, because nginx decodes regex URI
    # captures and proxy_pass with variables does not re-encode whitespace.
    map $request_uri $raw_comet_uri {{
        ~^/comet/{token_re}(?<rcu>/.*)$ $rcu;
        default "";
    }}

    server {{
        listen {COMET_GATEWAY_CONTAINER_PORT};
        server_name _;
        set $comet_upstream http://127.0.0.1:{COMET_PORT};

        location ~ "^/comet/(?<gateway_token>{token_re})(?<comet_uri>/.*)$" {{
            if ($token_valid = 0) {{
                rewrite ^ /__sg_invalid_token last;
            }}
            if ($comet_uri ~* "^/+(?:admin|kodi)(?:/|$)") {{
                return 403 "Forbidden\\n";
            }}
            if ($raw_comet_uri = "") {{
                return 400;
            }}

            proxy_pass $comet_upstream$raw_comet_uri;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Prefix /comet/$gateway_token;
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location ~ "^/comet/(?<gateway_token>{token_re})$" {{
            if ($token_valid = 0) {{ rewrite ^ /__sg_invalid_token last; }}
            return 301 $pass_x_forwarded_proto://$redirect_host/comet/$gateway_token/;
        }}

        location = /__sg_invalid_token {{
            internal;
            limit_req zone=gateway_auth burst=10 nodelay;
            deny all;
        }}

        location ~ "^/(?:configure(?:/|$)|static/|health(?:/|$))" {{
            limit_req zone=gateway_admin burst=20 nodelay;
            proxy_pass $comet_upstream$request_uri;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $host;
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
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto $pass_x_forwarded_proto;
            proxy_set_header X-Forwarded-Host $host;
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location / {{
            limit_req zone=gateway_fail burst=3 nodelay;
            return 403 "Forbidden\\n";
        }}
    }}
}}
"""

    def write_nginx_configs(self) -> None:
        ensure_directory(self.config.state_dir)
        # These files carry live gateway tokens; write them atomically at 0600
        # (the nginx container runs as root and can still read the bind mounts).
        atomic_write_text(self.config.nginx_conf_file, self.render_nginx_conf(), mode=0o600)
        atomic_write_text(self.config.tokens_map_file, self.render_tokens_map(), mode=0o600)

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
        """Apply the token map to the running gateway and prove it landed.

        A reload only helps if nginx reads the new file; the state directory is
        mounted (not single files, which keep the inode they started with), and
        the in-container hash is compared before claiming success.
        """
        self.write_nginx_configs()
        container_id = self.service_container_id()
        if not container_id:
            raise RuntimeError("Comet gateway container is not running; cannot reload nginx.")
        nginx = ["docker", "exec", container_id, "nginx", "-c", f"{GATEWAY_CONFIG_DIR}/nginx.conf"]
        self.runner.run([*nginx, "-t"], check=True)
        expected = hashlib.sha256(self.config.tokens_map_file.read_bytes()).hexdigest()
        seen = self.runner.run(
            ["docker", "exec", container_id, "sha256sum", f"{GATEWAY_CONFIG_DIR}/tokens.map"],
            check=True,
        )
        if (seen.stdout or "").split(" ", 1)[0] != expected:
            raise RuntimeError(
                "The gateway container does not see the updated token map; "
                "run `./stremio restart` so revoked tokens stop working."
            )
        self.runner.run([*nginx, "-s", "reload"], check=True)

    def container_running(self) -> bool:
        container_id = self.service_container_id()
        if not container_id:
            return False
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            check=False,
        )
        return result.returncode == 0 and (result.stdout or "").strip().lower() == "true"
