"""Config dataclass, runner protocol, and Docker helper utilities."""

from __future__ import annotations

import ipaddress
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

GENERATED_COMPOSE_FILE = ".stremio/docker-compose.bindings.yml"
DEFAULT_STREMIO_HOST_PORT = 11470
DEFAULT_STREMIO_CONTAINER_PORT = 11470


def parse_public_ip(text: str) -> str | None:
    candidate = text.strip()
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


class Runner(Protocol):
    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


class SubprocessRunner:
    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            check=check,
            text=True,
            capture_output=capture,
            timeout=timeout,
        )


def docker_permission_help(output: str) -> str | None:
    normalized = output.lower()
    if "permission denied" not in normalized:
        return None
    if "/var/run/docker.sock" not in normalized and "docker api" not in normalized:
        return None
    return (
        "Permission error: Docker is installed, but this user is not authorized to run it "
        "without sudo permissions.\n"
        "Try `docker ps` to confirm, then add your user to the `docker` group or "
        "enable Docker Desktop WSL integration for this distro. After changing group "
        "membership, start a fresh shell or restart WSL and try again.\n"
        "If you need a one-off bypass, run `sudo ./stremio`."
    )


def docker_daemon_help(runner: Runner) -> str | None:
    result = runner.run(["docker", "ps", "--format", "{{.ID}}"], check=False)
    detail = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
    return docker_permission_help(detail)


@dataclass(frozen=True)
class Config:
    root_dir: Path
    compose_file: Path
    compose_override_file: Path
    service_name: str
    container_name: str
    gluetun_container_name: str
    gluetun_healthy_timeout_seconds: int
    watch_interval_seconds: int
    watchdog_log_interval_seconds: int
    public_ip_timeout_seconds: int
    home_ip_file: Path
    expected_vpn_ip: str | None
    ip_check_urls: tuple[str, ...]
    install_missing: bool
    run_id: str
    log_file: Path | None
    log_session: bool

    @classmethod
    def from_env(cls) -> Config:
        root_dir = Path(__file__).resolve().parent.parent.parent
        run_id = os.environ.get("STREMIO_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = os.environ.get("STREMIO_LOG_FILE")
        return cls(
            root_dir=root_dir,
            compose_file=Path(os.environ.get("COMPOSE_FILE", root_dir / "docker-compose.yml")),
            compose_override_file=Path(
                os.environ.get("COMPOSE_OVERRIDE_FILE", root_dir / GENERATED_COMPOSE_FILE)
            ),
            service_name=os.environ.get("SERVICE_NAME", "stremio"),
            container_name=os.environ.get("CONTAINER_NAME", "stremio-server"),
            gluetun_container_name=os.environ.get("GLUETUN_CONTAINER_NAME", "gluetun"),
            gluetun_healthy_timeout_seconds=int(
                os.environ.get("GLUETUN_HEALTHY_TIMEOUT_SECONDS", "60")
            ),
            watch_interval_seconds=int(os.environ.get("WATCH_INTERVAL_SECONDS", "10")),
            watchdog_log_interval_seconds=int(
                os.environ.get("WATCHDOG_LOG_INTERVAL_SECONDS", "300")
            ),
            public_ip_timeout_seconds=int(os.environ.get("PUBLIC_IP_TIMEOUT_SECONDS", "8")),
            home_ip_file=Path(os.environ.get("HOME_IP_FILE", root_dir / ".stremio" / "home-ip")),
            expected_vpn_ip=os.environ.get("EXPECTED_VPN_IP") or None,
            install_missing=os.environ.get("INSTALL_MISSING_DEPS", "0") in {"1", "true", "yes"},
            run_id=run_id,
            log_file=Path(log_file) if log_file else None,
            log_session=os.environ.get("STREMIO_LOG_SESSION", "1") != "0",
            ip_check_urls=tuple(
                url.strip()
                for url in os.environ.get(
                    "IP_CHECK_URLS",
                    "https://api.ipify.org,https://icanhazip.com,https://ifconfig.me/ip",
                ).split(",")
                if url.strip()
            ),
        )
