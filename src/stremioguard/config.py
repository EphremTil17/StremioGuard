"""Config dataclass, runner protocol, and Docker helper utilities."""

from __future__ import annotations

import ipaddress
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from stremioguard.env import env_file_value

GENERATED_COMPOSE_FILE = ".stremio/docker-compose.bindings.yml"
DEFAULT_STREMIO_HOST_PORT = 11470
DEFAULT_STREMIO_CONTAINER_PORT = 11470
DEFAULT_COMET_HOST_PORT = 18000


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


def _parse_ipv4_csv(raw: str | None, *, default: list[str]) -> list[str]:
    if raw is None:
        return default
    values: list[str] = []
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError as error:
            raise RuntimeError(f"Invalid IP address value: {candidate!r}") from error
        if ip.version != 4:
            raise RuntimeError(f"Only IPv4 addresses are supported here: {candidate}")
        normalized = str(ip)
        if normalized not in values:
            values.append(normalized)
    return values


@dataclass(frozen=True)
class CometConfig:
    root_dir: Path
    env_file: Path
    vendor_dir: Path
    lock_file: Path
    repo_dir: Path
    compose_source_file: Path
    state_dir: Path
    runtime_env_file: Path
    data_dir: Path
    postgres_data_dir: Path
    service_name: str
    postgres_service_name: str
    container_name: str
    postgres_container_name: str
    host_port: int
    bind_addresses: tuple[str, ...]
    public_base_url: str | None
    proxy_debrid_stream: bool
    proxy_max_connections: int
    healthcheck_interval_seconds: int
    configure_page_password: str | None
    scrape_torrentio: str
    torrentio_url: str
    scrape_zilean: str
    zilean_url: str
    result_format_style: str
    patch_episode_pack_results: bool
    default_debrid_service: str
    default_debrid_apikey: str | None
    enabled: bool

    @classmethod
    def from_env(cls, root_dir: Path | None = None) -> CometConfig:
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = root_dir / ".env"
        raw_host_port = env_file_value(env_file, "COMET_HOST_PORT")
        host_port = DEFAULT_COMET_HOST_PORT
        if raw_host_port not in {None, ""}:
            assert raw_host_port is not None
            try:
                host_port = int(raw_host_port)
            except ValueError as error:
                raise RuntimeError(f"Invalid COMET_HOST_PORT value: {raw_host_port!r}") from error
            if host_port < 1 or host_port > 65535:
                raise RuntimeError(
                    f"Invalid COMET_HOST_PORT value: {raw_host_port!r}; expected 1-65535"
                )

        bind_addresses = tuple(
            _parse_ipv4_csv(
                env_file_value(env_file, "STREMIO_BIND_ADDRS"),
                default=["127.0.0.1"],
            )
        )
        public_base_url = env_file_value(env_file, "COMET_PUBLIC_BASE_URL") or None
        proxy_enabled = (
            (env_file_value(env_file, "COMET_PROXY_DEBRID_STREAM") or "1").strip().lower()
        )
        proxy_max_connections_raw = env_file_value(env_file, "COMET_PROXY_MAX_CONNECTIONS")
        proxy_max_connections = -1
        if proxy_max_connections_raw not in {None, ""}:
            assert proxy_max_connections_raw is not None
            try:
                proxy_max_connections = int(proxy_max_connections_raw)
            except ValueError as error:
                raise RuntimeError(
                    f"Invalid COMET_PROXY_MAX_CONNECTIONS value: {proxy_max_connections_raw!r}"
                ) from error
        healthcheck_interval_raw = env_file_value(env_file, "COMET_HEALTHCHECK_INTERVAL_SECONDS")
        healthcheck_interval_seconds = 300
        if healthcheck_interval_raw not in {None, ""}:
            assert healthcheck_interval_raw is not None
            try:
                healthcheck_interval_seconds = int(healthcheck_interval_raw)
            except ValueError as error:
                raise RuntimeError(
                    "Invalid COMET_HEALTHCHECK_INTERVAL_SECONDS value: "
                    f"{healthcheck_interval_raw!r}"
                ) from error
            if healthcheck_interval_seconds < 1:
                raise RuntimeError(
                    "Invalid COMET_HEALTHCHECK_INTERVAL_SECONDS value: "
                    f"{healthcheck_interval_raw!r}; expected >= 1"
                )
        configure_page_password = env_file_value(env_file, "COMET_CONFIGURE_PAGE_PASSWORD") or None
        scrape_torrentio = (env_file_value(env_file, "COMET_SCRAPE_TORRENTIO") or "live").strip()
        torrentio_url = (
            env_file_value(env_file, "COMET_TORRENTIO_URL") or "https://torrentio.strem.fun"
        ).strip()
        scrape_zilean = (env_file_value(env_file, "COMET_SCRAPE_ZILEAN") or "live").strip()
        zilean_url = (
            env_file_value(env_file, "COMET_ZILEAN_URL")
            or "https://zileanfortheweebs.midnightignite.me"
        ).strip()
        result_format_style = (
            (env_file_value(env_file, "COMET_RESULT_FORMAT_STYLE") or "plain").strip().lower()
        )
        if result_format_style not in {"plain", "emoji"}:
            raise RuntimeError(
                "Invalid COMET_RESULT_FORMAT_STYLE value: "
                f"{result_format_style!r}; expected 'plain' or 'emoji'"
            )
        patch_episode_pack_results = (
            env_file_value(env_file, "COMET_PATCH_EPISODE_PACK_RESULTS") or "1"
        ).strip().lower() in {"1", "true", "yes", "on"}
        return cls(
            root_dir=root_dir,
            env_file=env_file,
            vendor_dir=root_dir / "vendor",
            lock_file=root_dir / "vendor" / "comet.lock.json",
            repo_dir=root_dir / "vendor" / "comet",
            compose_source_file=root_dir / "vendor" / "comet" / "deployment" / "docker-compose.yml",
            state_dir=root_dir / ".stremio" / "comet",
            runtime_env_file=root_dir / ".stremio" / "comet" / ".env",
            data_dir=root_dir / ".stremio" / "comet" / "data",
            postgres_data_dir=root_dir / ".stremio" / "comet" / "postgres-data",
            service_name="comet",
            postgres_service_name="comet-postgres",
            container_name="comet",
            postgres_container_name="comet-postgres",
            host_port=host_port,
            bind_addresses=bind_addresses,
            public_base_url=public_base_url,
            proxy_debrid_stream=proxy_enabled not in {"0", "false", "no", "off"},
            proxy_max_connections=proxy_max_connections,
            healthcheck_interval_seconds=healthcheck_interval_seconds,
            configure_page_password=configure_page_password,
            scrape_torrentio=scrape_torrentio,
            torrentio_url=torrentio_url,
            scrape_zilean=scrape_zilean,
            zilean_url=zilean_url,
            result_format_style=result_format_style,
            patch_episode_pack_results=patch_episode_pack_results,
            default_debrid_service=(
                env_file_value(env_file, "COMET_DEFAULT_DEBRID_SERVICE") or "realdebrid"
            ).strip(),
            default_debrid_apikey=env_file_value(env_file, "COMET_DEFAULT_DEBRID_APIKEY") or None,
            enabled=(env_file_value(env_file, "COMET_ENABLED") or "0").strip().lower()
            in {"1", "true", "yes", "on"},
        )
