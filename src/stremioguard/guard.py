"""GluetunGuard — verification core, compose interaction, and preflight checks."""

from __future__ import annotations

import ipaddress
import os
import subprocess
import time
import urllib.error
import urllib.request

from loguru import logger

from stremioguard.config import (
    CometConfig,
    Config,
    Runner,
    SubprocessRunner,
    parse_public_ip,
)
from stremioguard.env import env_file_value
from stremioguard.preflight import require_docker, verify_bind_addresses
from stremioguard.publishing import render_stack_compose_override

DEFAULT_STREMIO_HOST_PORT = 11470
DEFAULT_STREMIO_CONTAINER_PORT = 11470


class GluetunGuard:
    def __init__(self, config: Config, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()
        self._env_path = self.config.root_dir / ".env"
        self.last_observed_ip: str | None = None

    def log(self, message: str) -> None:
        logger.info(message)

    def warn(self, message: str) -> None:
        logger.warning(message)

    def success(self, message: str) -> None:
        logger.success(message)

    def log_lines(self, text: str) -> None:
        for line in text.splitlines() or [""]:
            logger.info(line)

    def bind_addresses(self) -> list[str]:
        raw = env_file_value(self._env_path, "STREMIO_BIND_ADDRS")
        if raw is None:
            raw = "127.0.0.1"

        addresses: list[str] = []
        for item in raw.split(","):
            candidate = item.strip()
            if not candidate:
                continue
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError as error:
                raise RuntimeError(f"Invalid STREMIO_BIND_ADDRS value: {candidate!r}") from error
            if ip.version != 4:
                raise RuntimeError(
                    f"Only IPv4 bind addresses are supported for Stremio publishing: {candidate}"
                )
            normalized = str(ip)
            if normalized not in addresses:
                addresses.append(normalized)

        return addresses

    def env_port(self, key: str, default: int) -> int:
        raw = env_file_value(self._env_path, key)
        if raw is None or raw == "":
            return default
        try:
            port = int(raw)
        except ValueError as error:
            raise RuntimeError(f"Invalid {key} value: {raw!r}") from error
        if port < 1 or port > 65535:
            raise RuntimeError(f"Invalid {key} value: {raw!r}; expected 1-65535")
        return port

    def stremio_host_port(self) -> int:
        return self.env_port("STREMIO_HOST_PORT", DEFAULT_STREMIO_HOST_PORT)

    def stremio_container_port(self) -> int:
        return self.env_port("STREMIO_CONTAINER_PORT", DEFAULT_STREMIO_CONTAINER_PORT)

    def write_compose_override(self) -> None:
        addresses = self.bind_addresses()
        host_port = self.stremio_host_port()
        container_port = self.stremio_container_port()
        comet_config = CometConfig.from_env(self.config.root_dir)
        content = render_stack_compose_override(
            bind_addresses=addresses,
            stremio_host_port=host_port,
            stremio_container_port=container_port,
            comet_config=comet_config if comet_config.enabled else None,
        )
        self.config.compose_override_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.compose_override_file.write_text(content, encoding="utf-8")

    def require_commands(self) -> None:
        require_docker(
            self.runner,
            install_missing=self.config.install_missing,
            log=self.log,
            warn=self.warn,
        )

    def compose(
        self, *args: str, check: bool = True, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.write_compose_override()
        return self.runner.run(self._compose_command(*args), check=check, capture=capture)

    def _compose_command(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self.config.compose_file),
            "-f",
            str(self.config.compose_override_file),
            *args,
        ]

    def gluetun_healthy(self) -> bool:
        result = self.runner.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                self.config.gluetun_container_name,
            ],
            check=False,
        )
        return result.returncode == 0 and (result.stdout or "").strip() == "healthy"

    def gluetun_recent_logs(self, lines: int = 20) -> str:
        result = self.runner.run(
            ["docker", "logs", "--tail", str(lines), self.config.gluetun_container_name],
            check=False,
        )
        parts = [p for p in (result.stdout or "", result.stderr or "") if p.strip()]
        return "\n".join(parts).strip()

    def wait_for_gluetun_healthy(self) -> None:
        deadline = time.monotonic() + self.config.gluetun_healthy_timeout_seconds
        while time.monotonic() < deadline:
            if self.gluetun_healthy():
                self.log("Gluetun is healthy.")
                return
            time.sleep(2)

        recent = self.gluetun_recent_logs()
        if recent:
            self.warn("Last gluetun log lines:")
            self.log_lines(recent)

        auth_markers = ("AUTH_FAILED", "Your credentials might be wrong", "authentication failure")
        if any(m in recent for m in auth_markers):
            raise RuntimeError(
                "Gluetun VPN credentials were rejected (AUTH_FAILED). "
                "Re-run `./stremio init` to update your VPN credentials."
            )

        raise RuntimeError(
            f"Gluetun did not become healthy within "
            f"{self.config.gluetun_healthy_timeout_seconds}s. "
            "Check the log lines above or run `docker logs gluetun` for details."
        )

    def public_ip(self) -> str | None:
        for url in self.config.ip_check_urls:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "stremio-vpn-guard/1"})
                with urllib.request.urlopen(
                    request, timeout=self.config.public_ip_timeout_seconds
                ) as response:
                    body = response.read(128).decode("utf-8", errors="replace")
            except (OSError, urllib.error.URLError, TimeoutError):
                continue
            ip = parse_public_ip(body)
            if ip:
                return ip
        return None

    def public_ip_via_gluetun(self) -> str | None:
        for url in self.config.ip_check_urls:
            result = self.runner.run(
                [
                    "docker",
                    "exec",
                    self.config.gluetun_container_name,
                    "wget",
                    "-qO-",
                    "--timeout",
                    str(self.config.public_ip_timeout_seconds),
                    url,
                ],
                check=False,
                timeout=self.config.public_ip_timeout_seconds + 2,
            )
            if result.returncode == 0:
                ip = parse_public_ip(result.stdout or "")
                if ip:
                    return ip
        return None

    def public_ip_safe(self, *, log_observation: bool = False) -> bool:
        ip = self.public_ip_via_gluetun()
        if not ip:
            self.warn("Could not determine public IP via gluetun.")
            return False

        if log_observation:
            self.log(f"Observed public IP: {ip}")
        elif self.last_observed_ip and self.last_observed_ip != ip:
            self.log(f"Public IP changed from {self.last_observed_ip} to {ip}.")
        self.last_observed_ip = ip

        if self.config.expected_vpn_ip and ip != self.config.expected_vpn_ip:
            self.warn(f"Public IP does not match EXPECTED_VPN_IP={self.config.expected_vpn_ip}.")
            return False

        if self.config.home_ip_file.exists():
            home_ip = self.config.home_ip_file.read_text(encoding="utf-8").strip()
            if home_ip and ip == home_ip:
                self.warn(f"Public IP matches saved home IP baseline ({home_ip}); possible leak.")
                return False

        return True

    def check_bind_addresses(self) -> None:
        if os.environ.get("SKIP_BIND_PREFLIGHT") == "1":
            self.log("SKIP_BIND_PREFLIGHT=1 is set; skipping bind address validation.")
            return
        verify_bind_addresses(self.runner, self.bind_addresses(), log=self.log, warn=self.warn)

    def preflight(self) -> None:
        self.require_commands()
        if not self._env_path.exists():
            raise RuntimeError(
                f".env not found at {self._env_path}. Run `./stremio init` for guided "
                "first-time setup, or copy .env.example to .env and populate the "
                "chosen VPN credentials manually (see README.md → First-time setup)."
            )
        self.check_bind_addresses()
        self.log(f"Ensuring {self.config.gluetun_container_name} is running.")
        self.compose("up", "-d", self.config.gluetun_container_name, capture=False)
        self.wait_for_gluetun_healthy()
        if not self.public_ip_safe(log_observation=True):
            raise RuntimeError("Public IP check failed via gluetun; refusing to start Stremio.")

    def ensure_data_dir(self) -> None:
        data_dir = self.config.root_dir / "stremio-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.log(f"Using Stremio data directory: {data_dir}")

    def compose_instance_exists(self) -> bool:
        self.write_compose_override()
        result = self.runner.run(
            self._compose_command("ps", "-a", "-q", self.config.service_name), check=False
        )
        return bool((result.stdout or "").strip())

    def container_running(self) -> bool:
        result = self.runner.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.config.container_name],
            check=False,
        )
        return result.returncode == 0 and (result.stdout or "").strip() == "true"

    def stop_stremio(self) -> None:
        self.log(f"Stopping {self.config.service_name}.")
        self.compose("stop", self.config.service_name, check=False)
        self.success(f"{self.config.service_name} is stopped.")
