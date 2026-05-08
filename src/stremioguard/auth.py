"""Token-based authentication proxy for remote Stremio access."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from stremioguard.config import GENERATED_COMPOSE_FILE, Runner, SubprocessRunner, _parse_ipv4_csv
from stremioguard.env import env_file_value

DEFAULT_AUTH_HOST_PORT = 11471
DEFAULT_AUTH_TOKEN_LENGTH = 8
AUTH_CONTAINER_PORT = 8080


@dataclass(frozen=True)
class AuthConfig:
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
    domain: str | None
    token_length: int
    enabled: bool

    @classmethod
    def from_env(cls, root_dir: Path | None = None) -> AuthConfig:
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = root_dir / ".env"
        state_dir = root_dir / ".stremio" / "auth"

        raw_port = env_file_value(env_file, "AUTH_HOST_PORT")
        host_port = DEFAULT_AUTH_HOST_PORT
        if raw_port not in {None, ""}:
            assert raw_port is not None
            try:
                host_port = int(raw_port)
            except ValueError as error:
                raise RuntimeError(f"Invalid AUTH_HOST_PORT value: {raw_port!r}") from error
            if host_port < 1 or host_port > 65535:
                raise RuntimeError(f"Invalid AUTH_HOST_PORT value: {raw_port!r}; expected 1-65535")

        bind_addresses = tuple(
            _parse_ipv4_csv(
                env_file_value(env_file, "STREMIO_BIND_ADDRS"),
                default=["127.0.0.1"],
            )
        )

        domain = env_file_value(env_file, "AUTH_DOMAIN") or None
        if domain is None:
            external_url = env_file_value(env_file, "EXTERNAL_BASE_URL") or ""
            if "://" in external_url:
                host_part = external_url.split("://", 1)[1].rstrip("/")
                if ":" in host_part:
                    host_part = host_part.rsplit(":", 1)[0]
                if host_part:
                    domain = host_part

        raw_length = env_file_value(env_file, "AUTH_TOKEN_LENGTH")
        token_length = DEFAULT_AUTH_TOKEN_LENGTH
        if raw_length not in {None, ""}:
            assert raw_length is not None
            try:
                token_length = int(raw_length)
            except ValueError as error:
                raise RuntimeError(f"Invalid AUTH_TOKEN_LENGTH value: {raw_length!r}") from error
            if token_length < 4 or token_length > 32:
                raise RuntimeError(
                    f"Invalid AUTH_TOKEN_LENGTH value: {raw_length!r}; expected 4-32"
                )

        return cls(
            root_dir=root_dir,
            env_file=env_file,
            state_dir=state_dir,
            tokens_file=state_dir / "tokens.json",
            nginx_conf_file=state_dir / "nginx.conf",
            tokens_map_file=state_dir / "tokens.map",
            service_name="auth-proxy",
            container_name="auth-proxy",
            host_port=host_port,
            bind_addresses=bind_addresses,
            domain=domain,
            token_length=token_length,
            enabled=(env_file_value(env_file, "AUTH_ENABLED") or "0").strip().lower()
            in {"1", "true", "yes", "on"},
        )


class AuthManager:
    def __init__(self, config: AuthConfig, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()

    # ── Token storage ──────────────────────────────────────────────

    def load_tokens(self) -> dict[str, dict[str, object]]:
        if not self.config.tokens_file.exists():
            return {}
        content = self.config.tokens_file.read_text(encoding="utf-8")
        data = json.loads(content)
        return data.get("tokens", {})

    def save_tokens(self, tokens: dict[str, dict[str, object]]) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"tokens": tokens}, indent=2) + "\n"
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

    # ── Token CRUD ─────────────────────────────────────────────────

    def add_token(self, label: str) -> tuple[str, str]:
        tokens = self.load_tokens()
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
        self.save_tokens(tokens)
        self.write_nginx_configs()
        return token_id, token_value

    def revoke_token(self, token_id: str) -> str:
        tokens = self.load_tokens()
        if token_id not in tokens:
            raise KeyError(f"Token ID {token_id!r} not found")
        label = str(tokens[token_id].get("label", ""))
        del tokens[token_id]
        self.save_tokens(tokens)
        self.write_nginx_configs()
        return label

    def rotate_token(self, token_id: str) -> tuple[str, str]:
        tokens = self.load_tokens()
        if token_id not in tokens:
            raise KeyError(f"Token ID {token_id!r} not found")
        label = str(tokens[token_id].get("label", ""))
        del tokens[token_id]
        self.save_tokens(tokens)
        return self.add_token(label)

    def list_tokens(self) -> list[dict[str, str]]:
        tokens = self.load_tokens()
        return [
            {
                "id": tid,
                "label": str(entry.get("label", "")),
                "token": str(entry.get("token", "")),
                "created": str(entry.get("created", "")),
            }
            for tid, entry in tokens.items()
        ]

    # ── Nginx config generation ────────────────────────────────────

    def render_tokens_map(self) -> str:
        tokens = self.load_tokens()
        lines = [
            "# Generated by ./stremio; do not edit by hand.",
            "map $token_from_uri $token_valid {",
            "    default 0;",
        ]
        for entry in tokens.values():
            token = entry.get("token", "")
            if token:
                lines.append(f'    "{token}" 1;')
        lines.append("}")
        return "\n".join(lines) + "\n"

    def render_nginx_conf(self) -> str:
        min_len = self.config.token_length
        max_len = self.config.token_length + 4
        token_re = f"[A-Za-z0-9_-]{{{min_len},{max_len}}}"
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

    limit_req_zone $binary_remote_addr zone=auth_fail:1m rate=5r/s;

    log_format main '$remote_addr [$time_local] "$request" $status $body_bytes_sent';
    access_log /var/log/nginx/access.log main;

    server {{
        listen {AUTH_CONTAINER_PORT};
        server_name _;
        resolver 127.0.0.11 valid=10s ipv6=off;
        set $upstream http://gluetun:11470;

        location ~ "^/(?<auth_token>{token_re})(?<remaining_uri>/.*)$" {{
            set $token_from_uri $auth_token;

            if ($token_valid = 0) {{
                return 403;
            }}

            proxy_pass $upstream$remaining_uri$is_args$args;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-For "";
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Prefix /$auth_token;
            proxy_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            client_max_body_size 0;
        }}

        location ~ "^/(?<auth_token>{token_re})$" {{
            set $token_from_uri $auth_token;
            if ($token_valid = 0) {{ return 403; }}
            return 301 $scheme://$host/$auth_token/;
        }}

        location / {{
            limit_req zone=auth_fail burst=3 nodelay;
            return 403 "Forbidden\\n";
        }}
    }}
}}
"""

    def write_nginx_configs(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.nginx_conf_file.write_text(self.render_nginx_conf(), encoding="utf-8")
        self.config.tokens_map_file.write_text(self.render_tokens_map(), encoding="utf-8")

    # ── Display helpers ────────────────────────────────────────────

    def full_url(self, token: str) -> str:
        if self.config.domain:
            return f"https://{self.config.domain}/{token}/"
        addr = self.config.bind_addresses[0] if self.config.bind_addresses else "127.0.0.1"
        return f"http://{addr}:{self.config.host_port}/{token}/"

    def upstream_snippet(self) -> str:
        addr = self.config.bind_addresses[0] if self.config.bind_addresses else "127.0.0.1"
        return (
            f"Point your reverse proxy upstream at "
            f"http://{addr}:{self.config.host_port}\n"
            f"(was http://{addr}:11470 for direct Stremio access)"
        )

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
        logger.success(f"Auth proxy started on port {self.config.host_port}.")

    def stop(self) -> None:
        self.compose("stop", self.config.service_name, check=False)
        logger.info("Auth proxy stopped.")

    def status(self) -> None:
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", self.config.container_name],
            check=False,
        )
        state = (result.stdout or "").strip() if result.returncode == 0 else "not found"
        token_count = len(self.load_tokens())
        logger.info(f"Auth proxy container: {state}")
        logger.info(f"Active tokens: {token_count}")
        if self.config.domain:
            logger.info(f"Domain: {self.config.domain}")
        logger.info(self.upstream_snippet())

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
