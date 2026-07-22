"""Config dataclass, runner protocol, and Docker helper utilities."""

from __future__ import annotations

import ipaddress
import os
import subprocess
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from stremioguard.env import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    DEFAULT_STREMIO_HOST_PORT,
    env_file_value,
    env_flag_enabled,
    env_int_value,
)

GENERATED_COMPOSE_FILE = ".stremio/docker-compose.bindings.yml"
# Set by the CLI before it shells out to compose, and required by an
# interpolation guard in docker-compose.yml. A bare `docker compose up` runs
# without the generated override — no Postgres credentials and no bind mount
# for the real data directory — so the guard turns that into an immediate,
# explanatory error instead of a container that quietly initializes an empty
# database. Deliberately not placed in `.env`, which compose would auto-load.
MANAGED_STACK_ENV = "STREMIOGUARD_MANAGED"
DEFAULT_COMET_HOST_PORT = 18000
DEFAULT_COMET_GATEWAY_HOST_PORT = 18001


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


def _tunable_int(env_file: Path, key: str, default: int, *, minimum: int = 1) -> int:
    """Read a watchdog tunable from the environment or .env, first match wins.

    Accepts both the STREMIO_-prefixed and bare names so `KEY=5 ./stremio start`
    and a persistent .env line both work.
    """
    raw = (
        os.environ.get(f"STREMIO_{key}")
        or os.environ.get(key)
        or env_file_value(env_file, f"STREMIO_{key}")
        or env_file_value(env_file, key)
    )
    if raw in {None, ""}:
        return default
    assert raw is not None
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"Invalid {key} value: {raw!r}") from error
    if value < minimum:
        raise RuntimeError(f"Invalid {key} value: {raw!r}; expected >= {minimum}")
    return value


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
    stremio_enabled: bool
    ip_crosscheck_interval_seconds: int
    public_ip_failure_threshold: int

    @classmethod
    def from_env(cls, root_dir: Path | None = None) -> Config:
        # Optional root mirrors CometConfig.from_env, so callers (and tests)
        # can point at a directory other than the installed checkout.
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = root_dir / ".env"
        stremio_enabled = env_flag_enabled("STREMIO_ENABLED", True, env_path=env_file)
        comet_enabled = env_flag_enabled("COMET_ENABLED", False, env_path=env_file)
        if not stremio_enabled and not comet_enabled:
            raise RuntimeError(
                "Invalid configuration: both STREMIO_ENABLED and COMET_ENABLED are set to 0. "
                "At least one service must be enabled in your .env file."
            )

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
            stremio_enabled=stremio_enabled,
            ip_check_urls=tuple(
                url.strip()
                for url in os.environ.get(
                    "IP_CHECK_URLS",
                    "https://api.ipify.org,https://icanhazip.com,https://ifconfig.me/ip",
                ).split(",")
                if url.strip()
            ),
            ip_crosscheck_interval_seconds=_tunable_int(
                env_file, "IP_CROSSCHECK_INTERVAL_SECONDS", 300
            ),
            public_ip_failure_threshold=_tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3),
        )


def _validate_public_url(value: str | None, *, key: str) -> None:
    if not value:
        return
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(f"Invalid {key} value: {value!r}; expected an absolute HTTP(S) URL")


def _validate_image_repository(value: str, *, key: str) -> str:
    # StremioGuard pins the Comet image by digest itself (`<repo>@<digest>`)
    # and resolves updates against `<repo>:latest`, so a tag or digest baked
    # into the repository override would produce invalid references.
    name_part = value.rsplit("/", 1)[-1]
    if "@" in value or ":" in name_part:
        raise RuntimeError(
            f"Invalid {key} value: {value!r}; expected a repository name without a tag "
            "or digest (e.g. 'g0ldyy/comet'). StremioGuard manages the digest pin."
        )
    return value


def parse_ipv4_csv(raw: str | None, *, default: list[str]) -> list[str]:
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
    image: str = "g0ldyy/comet"
    stremio_host_port: int = DEFAULT_STREMIO_HOST_PORT
    stremio_container_port: int = DEFAULT_STREMIO_CONTAINER_PORT
    gateway_host_port: int = DEFAULT_COMET_GATEWAY_HOST_PORT
    gateway_public_base_url: str | None = None
    gateway_token_length: int = 8
    gateway_enabled: bool = False

    @classmethod
    def from_env(cls, root_dir: Path | None = None) -> CometConfig:
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = root_dir / ".env"
        host_port = env_int_value(
            env_file, "COMET_HOST_PORT", DEFAULT_COMET_HOST_PORT, minimum=1, maximum=65535
        )
        stremio_host_port = env_int_value(
            env_file, "STREMIO_HOST_PORT", DEFAULT_STREMIO_HOST_PORT, minimum=1, maximum=65535
        )
        stremio_container_port = env_int_value(
            env_file,
            "STREMIO_CONTAINER_PORT",
            DEFAULT_STREMIO_CONTAINER_PORT,
            minimum=1,
            maximum=65535,
        )
        gateway_host_port = env_int_value(
            env_file,
            "COMET_GATEWAY_HOST_PORT",
            DEFAULT_COMET_GATEWAY_HOST_PORT,
            minimum=1,
            maximum=65535,
        )
        comet_enabled = env_flag_enabled("COMET_ENABLED", False, env_path=env_file)
        gateway_enabled = env_flag_enabled(
            "COMET_GATEWAY_ENABLED", comet_enabled, env_path=env_file
        )
        gateway_public_base_url = env_file_value(env_file, "COMET_GATEWAY_PUBLIC_BASE_URL") or None
        gateway_token_length = env_int_value(
            env_file, "COMET_GATEWAY_TOKEN_LENGTH", 8, minimum=4, maximum=32
        )
        public_base_url = env_file_value(env_file, "COMET_PUBLIC_BASE_URL") or None
        _validate_public_url(public_base_url, key="COMET_PUBLIC_BASE_URL")
        _validate_public_url(
            gateway_public_base_url,
            key="COMET_GATEWAY_PUBLIC_BASE_URL",
        )

        bind_addresses = tuple(
            parse_ipv4_csv(
                env_file_value(env_file, "STREMIO_BIND_ADDRS"),
                default=["127.0.0.1"],
            )
        )
        if "0.0.0.0" in bind_addresses and len(bind_addresses) > 1:
            raise RuntimeError(
                "STREMIO_BIND_ADDRS cannot combine 0.0.0.0 with specific bind addresses"
            )
        configured_ports = [
            (stremio_host_port, "STREMIO_HOST_PORT"),
            (host_port, "COMET_HOST_PORT"),
        ]
        if gateway_enabled:
            configured_ports.append((gateway_host_port, "COMET_GATEWAY_HOST_PORT"))
        for index, (port, key) in enumerate(configured_ports):
            for other_port, other_key in configured_ports[index + 1 :]:
                if port == other_port:
                    raise RuntimeError(f"Port collision: {key} and {other_key} both use {port}")
        if gateway_enabled and not comet_enabled:
            raise RuntimeError("COMET_GATEWAY_ENABLED requires COMET_ENABLED=1")

        proxy_debrid_stream = env_flag_enabled("COMET_PROXY_DEBRID_STREAM", True, env_path=env_file)
        proxy_max_connections = env_int_value(env_file, "COMET_PROXY_MAX_CONNECTIONS", -1)
        healthcheck_interval_seconds = env_int_value(
            env_file, "COMET_HEALTHCHECK_INTERVAL_SECONDS", 300, minimum=1
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
        patch_episode_pack_results = env_flag_enabled(
            "COMET_PATCH_EPISODE_PACK_RESULTS", True, env_path=env_file
        )
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
            proxy_debrid_stream=proxy_debrid_stream,
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
            enabled=comet_enabled,
            image=_validate_image_repository(
                (env_file_value(env_file, "COMET_IMAGE") or "g0ldyy/comet").strip(),
                key="COMET_IMAGE",
            ),
            stremio_host_port=stremio_host_port,
            stremio_container_port=stremio_container_port,
            gateway_host_port=gateway_host_port,
            gateway_public_base_url=gateway_public_base_url,
            gateway_token_length=gateway_token_length,
            gateway_enabled=gateway_enabled,
        )
