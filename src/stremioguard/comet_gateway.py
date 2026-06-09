"""Token-managed gateway for Comet addon access."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from stremioguard.config import GENERATED_COMPOSE_FILE, Runner, SubprocessRunner, _parse_ipv4_csv
from stremioguard.env import env_file_value, env_flag_enabled

DEFAULT_COMET_GATEWAY_HOST_PORT = 18001
DEFAULT_COMET_GATEWAY_TOKEN_LENGTH = 8
# NOTE: the gateway runs in gluetun's network namespace, where Stremio's own
# nginx already owns 8080 (web UI) and Comet owns 8000. 8090 is free there.
COMET_GATEWAY_CONTAINER_PORT = 8090


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
    def from_env(cls, root_dir: Path | None = None) -> CometGatewayConfig:
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = root_dir / ".env"
        state_dir = root_dir / ".stremio" / "comet-gateway"

        raw_port = env_file_value(env_file, "COMET_GATEWAY_HOST_PORT")
        host_port = DEFAULT_COMET_GATEWAY_HOST_PORT
        if raw_port not in {None, ""}:
            assert raw_port is not None
            try:
                host_port = int(raw_port)
            except ValueError as error:
                raise RuntimeError(
                    f"Invalid COMET_GATEWAY_HOST_PORT value: {raw_port!r}"
                ) from error
            if host_port < 1 or host_port > 65535:
                raise RuntimeError(
                    f"Invalid COMET_GATEWAY_HOST_PORT value: {raw_port!r}; expected 1-65535"
                )

        raw_length = env_file_value(env_file, "COMET_GATEWAY_TOKEN_LENGTH")
        token_length = DEFAULT_COMET_GATEWAY_TOKEN_LENGTH
        if raw_length not in {None, ""}:
            assert raw_length is not None
            try:
                token_length = int(raw_length)
            except ValueError as error:
                raise RuntimeError(
                    f"Invalid COMET_GATEWAY_TOKEN_LENGTH value: {raw_length!r}"
                ) from error
            if token_length < 4 or token_length > 32:
                raise RuntimeError(
                    f"Invalid COMET_GATEWAY_TOKEN_LENGTH value: {raw_length!r}; expected 4-32"
                )

        return cls(
            root_dir=root_dir,
            env_file=env_file,
            state_dir=state_dir,
            tokens_file=state_dir / "tokens.json",
            nginx_conf_file=state_dir / "nginx.conf",
            tokens_map_file=state_dir / "tokens.map",
            service_name="comet-gateway",
            container_name="comet-gateway",
            host_port=host_port,
            bind_addresses=tuple(
                _parse_ipv4_csv(
                    env_file_value(env_file, "STREMIO_BIND_ADDRS"),
                    default=["127.0.0.1"],
                )
            ),
            public_base_url=(env_file_value(env_file, "COMET_GATEWAY_PUBLIC_BASE_URL") or None),
            token_length=token_length,
            enabled=env_flag_enabled("COMET_GATEWAY_ENABLED", True, env_path=env_file),
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
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state, indent=2) + "\n"
        fd = os.open(
            str(self.config.tokens_file),
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
        except BaseException:
            os.close(fd)
            raise

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

    # ── Token CRUD ─────────────────────────────────────────────────

    def add_token(self, label: str, *, make_default: bool = False) -> tuple[str, str]:
        state = self.load_state()
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
        self.save_state(state)
        self.write_nginx_configs()
        return token_id, token_value

    def revoke_token(self, token_id: str) -> str:
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
        state["default"] = self._oldest_token_id(tokens) if was_default else state.get("default")
        self.save_state(state)
        return self.add_token(label, make_default=was_default)

    def use_token(self, token_id: str) -> str:
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
        return "\n".join(lines) + "\n"

    def render_nginx_conf(self) -> str:
        # Tokens are always generated at exactly token_length, so match that
        # precisely; the tokens.map lookup is the authoritative gate either way.
        token_re = f"[A-Za-z0-9_-]{{{self.config.token_length}}}"
        return f"""\
# Generated by ./stremio; do not edit by hand.
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/tokens.map;

    limit_req_zone $binary_remote_addr zone=gateway_fail:1m rate=5r/s;

    log_format main '$remote_addr [$time_local] "$request" $status $body_bytes_sent';
    access_log /var/log/nginx/access.log main;

    map $http_x_forwarded_proto $pass_x_forwarded_proto {{
        default $http_x_forwarded_proto;
        ""      $scheme;
    }}

    server {{
        listen {COMET_GATEWAY_CONTAINER_PORT};
        server_name _;
        set $comet_upstream http://127.0.0.1:8000;

        location ~ "^/comet/(?<gateway_token>{token_re})(?<comet_uri>/.*)$" {{
            if ($token_valid = 0) {{
                return 403;
            }}

            proxy_pass $comet_upstream$comet_uri$is_args$args;
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
            if ($token_valid = 0) {{ return 403; }}
            return 301 $scheme://$host/comet/$gateway_token/;
        }}

        location ~ "^/(?:configure(?:/|$)|static/|health(?:/|$)|admin(?:/|$))" {{
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
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.nginx_conf_file.write_text(self.render_nginx_conf(), encoding="utf-8")
        self.config.tokens_map_file.write_text(self.render_tokens_map(), encoding="utf-8")

    # ── Compose lifecycle ──────────────────────────────────────────

    def root_compose_file(self) -> Path:
        return self.config.root_dir / "docker-compose.yml"

    def root_override_file(self) -> Path:
        return self.config.root_dir / GENERATED_COMPOSE_FILE

    def _compose_command(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self.root_compose_file()),
            "-f",
            str(self.root_override_file()),
            *args,
        ]

    def compose(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.runner.run(self._compose_command(*args), check=check, capture=capture)

    def prepare_runtime(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.write_nginx_configs()

    def start(self) -> None:
        self.prepare_runtime()
        self.compose("up", "-d", self.config.service_name)
        logger.success(f"Comet gateway started on port {self.config.host_port}.")

    def stop(self) -> None:
        self.compose("stop", self.config.service_name, check=False)
        logger.info("Comet gateway stopped.")

    def status(self) -> None:
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", self.config.container_name],
            check=False,
        )
        state = (result.stdout or "").strip() if result.returncode == 0 else "not found"
        logger.info(f"Comet gateway container: {state}")
        logger.info(f"Active tokens: {len(self.load_tokens())}")
        logger.info(f"Default token: {self.default_token_id() or '-'}")
        logger.info(f"Public base URL: {self.public_base_url()}")

    def reload_nginx(self) -> None:
        self.write_nginx_configs()
        self.runner.run(
            ["docker", "exec", self.config.container_name, "nginx", "-s", "reload"],
            check=True,
        )

    def container_running(self) -> bool:
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", self.config.container_name],
            check=False,
        )
        return result.returncode == 0 and (result.stdout or "").strip().lower() == "true"
