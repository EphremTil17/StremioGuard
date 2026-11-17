"""Config dataclass, runner protocol, and Docker helper utilities."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from stremioguard.digests import require_image_digest
from stremioguard.env import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    DEFAULT_STREMIO_HOST_PORT,
    env_file_value,
    env_flag_enabled,
    env_int_value,
)

# Marks compose invocations as coming from this CLI. The `use-stremio-start-
# instead` gate in docker-compose.yml reads it when its container runs, so an
# unset value stops `docker compose up` while leaving `logs`, `ps` and `config`
# working. Setting it by hand is the documented override.
MANAGED_STACK_ENV = "STREMIOGUARD_MANAGED"
GENERATED_COMPOSE_FILE = ".stremio/docker-compose.bindings.yml"
# gluetun's share of .env (see publishing.render_gluetun_env).
GLUETUN_ENV_FILE = ".stremio/gluetun.env"
# The published generation: what `./stremio start|restart` last deployed. Every
# compose call and the watchdog read these, never the working tree's
# docker-compose.yml or .env, so an edit or a `git pull` changes nothing until
# the next deliberate start (see publishing.StackPublisher).
PUBLISHED_COMPOSE_FILE = ".stremio/compose.base.yml"
PUBLISHED_ENV_FILE = ".stremio/env.snapshot"
# Bound on a Docker query (ps, inspect, exec). A wedged daemon must surface as
# a failed check, not as a watchdog that blocks until systemd kills it.
DOCKER_QUERY_TIMEOUT_SECONDS = 30
# Bound on one watchdog-driven `compose up/stop`; below the unit's WatchdogSec.
WATCHDOG_MUTATION_TIMEOUT_SECONDS = 240
# Bound on one teardown `compose stop` (fail-safe / `./stremio stop`).
TEARDOWN_MUTATION_TIMEOUT_SECONDS = 120
# Hard ceiling on a single IP probe step so operator-configured timeouts
# cannot exceed WatchdogSec - WATCHDOG_STEP_MARGIN_SECONDS.
PUBLIC_IP_TIMEOUT_MAX_SECONDS = 60
# While a failure persists, repeat its warning at most this often.
REPEAT_WARNING_SECONDS = 300
DEFAULT_COMET_HOST_PORT = 18000
DEFAULT_COMET_GATEWAY_HOST_PORT = 18001
CIRCUIT_BREAKER_EXIT_CODE = 78
DEFAULT_VPN_RECOVERY_BUDGET_SECONDS = 300
DEFAULT_VPN_RESTART_CADENCE_SECONDS = 45
DEFAULT_VPN_FAILOVER_ESCALATION_RATIO = 0.5
LOCKOUT_FILE_NAME = "vpn-lockout"

# Comet reaches every debrid service through StremThru. Ours runs in gluetun's
# namespace on loopback (docker-compose.yml sets the same listen address) and
# is never published, so the debrid key in each request only leaves the host
# towards the debrid service itself, through the tunnel.
STREMTHRU_SERVICE = "stremthru"
STREMTHRU_PORT = 8091
STREMTHRU_INTERNAL_URL = f"http://127.0.0.1:{STREMTHRU_PORT}"
COMET_GATEWAY_SERVICE = "comet-gateway"
COMET_PORT = 8000
COMET_GATEWAY_CONTAINER_PORT = 8090
COMET_GATEWAY_HEALTH_PORT = 8099
# Every service shares gluetun's network namespace, so they also share one
# port space: two listeners on the same port collide whatever address each
# binds. This is the registry; tests/test_config.py checks docker-compose.yml
# against it. Add a service's port here before giving it one.
NAMESPACE_PORTS: dict[str, int] = {
    "stremio web UI (image's nginx)": 8080,
    "stremio streaming server": 11470,
    "stremio streaming server (https)": 12470,
    "comet": COMET_PORT,
    "comet-gateway": COMET_GATEWAY_CONTAINER_PORT,
    "comet-gateway health (loopback)": COMET_GATEWAY_HEALTH_PORT,
    "comet-postgres": 5432,
    "stremthru": STREMTHRU_PORT,
    "gluetun control server": 18080,
    "gluetun health server": 9999,
}
# Comet's per-scraper context: `true` is Comet's alias for `both`; `off` is
# accepted and stored as `false`. Comet silently disables a scraper on any
# other value, so a typo is rejected here instead.
SCRAPE_MODES = frozenset({"live", "background", "both", "true", "false"})
DEFAULT_DMM_INGEST_INTERVAL_SECONDS = 7 * 24 * 3600

# Watchdog tunables: read by `_tunable_int` from the process environment
# (bare or STREMIO_-prefixed) or from .env.
TUNABLE_KEYS = (
    "WATCH_INTERVAL_SECONDS",
    "WATCHDOG_LOG_INTERVAL_SECONDS",
    "EGRESS_PROBE_INTERVAL_SECONDS",
    "PUBLIC_IP_FAILURE_THRESHOLD",
    "VPN_RECOVERY_BUDGET_SECONDS",
    "VPN_RESTART_CADENCE_SECONDS",
    "MAX_AUTO_STARTS_PER_HOUR",
)
# Every process-environment key Config.from_env reads. The systemd-supervised
# watchdog does not inherit the shell that ran `./stremio start`, so the CLI
# forwards exactly these across that boundary; tests/test_config.py fails if a
# new `os.environ` read is added without listing it here.
CONFIG_ENV_KEYS = (
    "STREMIO_RUN_ID",
    "STREMIO_LOG_FILE",
    "STREMIO_LOG_SESSION",
    "GLUETUN_HEALTHY_TIMEOUT_SECONDS",
    "PUBLIC_IP_TIMEOUT_SECONDS",
    "EXPECTED_VPN_IP",
    "INSTALL_MISSING_DEPS",
    "IP_CHECK_URLS",
    *TUNABLE_KEYS,
    *(f"STREMIO_{key}" for key in TUNABLE_KEYS),
)


def parse_public_ip(text: str) -> str | None:
    """Parse ``text`` as a canonical global unicast IPv4 or IPv6 address.

    Unwraps ``::ffff:`` IPv4-mapped IPv6 addresses first, then rejects any
    non-global, multicast, reserved, IPv6 site-local, or zone-suffixed address.
    """
    candidate = text.strip()
    if not candidate:
        return None
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id is not None:
            return None
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return None
    return str(ip)


def missing_published_files(root_dir: Path) -> list[Path]:
    """Published generation files required before the stack can run from it."""
    candidates = (
        root_dir / GENERATED_COMPOSE_FILE,
        root_dir / PUBLISHED_COMPOSE_FILE,
        root_dir / PUBLISHED_ENV_FILE,
    )
    return [path for path in candidates if not path.exists()]


def compose_command(root_dir: Path, *args: str) -> list[str]:
    """`docker compose` for this stack, the one way every caller builds it.

    Once a generation has been published, that is the stack: its copy of
    the base file, its override and its env snapshot. Before the first
    publish (a fresh checkout) the working tree's base file is all there is.
    Paths come from the checkout, never the environment: an exported
    COMPOSE_FILE from another project must not point the watchdog at a
    different stack.
    """
    override = root_dir / GENERATED_COMPOSE_FILE
    published_base = root_dir / PUBLISHED_COMPOSE_FILE
    published_env = root_dir / PUBLISHED_ENV_FILE
    if not missing_published_files(root_dir):
        return [
            "docker",
            "compose",
            # Relative paths in the copied base file must keep resolving
            # against the checkout, and the project name keeps deriving from it.
            "--project-directory",
            str(root_dir),
            "--env-file",
            str(published_env),
            "-f",
            str(published_base),
            "-f",
            str(override),
            *args,
        ]
    override_args = ["-f", str(override)] if override.exists() else []
    return ["docker", "compose", "-f", str(root_dir / "docker-compose.yml"), *override_args, *args]


def deployed_env_file(root_dir: Path) -> Path:
    """The configuration the running stack was started with.

    The published snapshot once one exists, else .env. Long-lived readers (the
    watchdog, the fail-safe) use this so a later .env edit cannot change
    their behavior, or crash them, before the next deliberate start.
    """
    snapshot = root_dir / PUBLISHED_ENV_FILE
    return snapshot if snapshot.exists() else root_dir / ".env"


class Runner(Protocol):
    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


def service_container_id(runner: Runner, root_dir: Path, service: str) -> str | None:
    result = runner.run(
        compose_command(root_dir, "ps", "-q", service),
        check=False,
        timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    return next((line.strip() for line in (result.stdout or "").splitlines() if line.strip()), None)


class SubprocessRunner:
    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            check=check,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=capture,
            timeout=timeout,
            env=env,
            input=input,
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
        "Try `docker ps` to confirm, then add your user to the `docker` group or use "
        "rootless Docker (docs/rootless-docker.md). After changing group membership, log "
        "out and back in, then try again.\n"
        "If you need a one-off bypass, run `sudo ./stremio`."
    )


def docker_daemon_help(runner: Runner) -> str | None:
    try:
        result = runner.run(
            ["docker", "ps", "--format", "{{.ID}}"],
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
    except (subprocess.SubprocessError, OSError):
        return None
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
    egress_probe_interval_seconds: int
    public_ip_failure_threshold: int
    vpn_recovery_budget_seconds: int
    vpn_restart_cadence_seconds: int
    vpn_lockout_file: Path
    server_countries: str | None
    server_regions: str | None
    server_cities: str | None
    server_hostnames: str | None
    server_categories: str | None
    # Where the configuration was read from; the guard reads provider and
    # server settings from the same file.
    env_file: Path | None = None
    alert_url: str | None = None
    # More auto-starts than this in an hour trips the circuit breaker; 0
    # disables the limit.
    max_auto_starts_per_hour: int = 10

    @classmethod
    def from_env(cls, root_dir: Path | None = None, *, env_file: Path | None = None) -> Config:
        # Optional root mirrors CometConfig.from_env, so callers (and tests)
        # can point at a directory other than the installed checkout.
        # `env_file` lets teardown ignore a .env that no longer parses.
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = env_file or root_dir / ".env"
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
            gluetun_healthy_timeout_seconds=int(
                os.environ.get("GLUETUN_HEALTHY_TIMEOUT_SECONDS", "60")
            ),
            watch_interval_seconds=_tunable_int(env_file, "WATCH_INTERVAL_SECONDS", 10),
            # 0 logs a summary on every tick.
            watchdog_log_interval_seconds=_tunable_int(
                env_file, "WATCHDOG_LOG_INTERVAL_SECONDS", 300, minimum=0
            ),
            public_ip_timeout_seconds=int(os.environ.get("PUBLIC_IP_TIMEOUT_SECONDS", "8")),
            home_ip_file=root_dir / ".stremio" / "home-ip",
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
            egress_probe_interval_seconds=_tunable_int(
                env_file, "EGRESS_PROBE_INTERVAL_SECONDS", 300
            ),
            public_ip_failure_threshold=_tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3),
            vpn_recovery_budget_seconds=_tunable_int(
                env_file, "VPN_RECOVERY_BUDGET_SECONDS", DEFAULT_VPN_RECOVERY_BUDGET_SECONDS
            ),
            vpn_restart_cadence_seconds=_tunable_int(
                env_file, "VPN_RESTART_CADENCE_SECONDS", DEFAULT_VPN_RESTART_CADENCE_SECONDS
            ),
            # Fixed, not overridable: every process (CLI, watchdog, fail-safe,
            # systemd) must agree on where the lockout lives.
            vpn_lockout_file=root_dir / ".stremio" / LOCKOUT_FILE_NAME,
            server_countries=env_file_value(env_file, "SERVER_COUNTRIES"),
            server_regions=env_file_value(env_file, "SERVER_REGIONS"),
            server_cities=env_file_value(env_file, "SERVER_CITIES"),
            server_hostnames=env_file_value(env_file, "SERVER_HOSTNAMES"),
            server_categories=env_file_value(env_file, "SERVER_CATEGORIES"),
            env_file=env_file,
            alert_url=_alert_url(env_file),
            max_auto_starts_per_hour=_tunable_int(
                env_file, "MAX_AUTO_STARTS_PER_HOUR", 10, minimum=0
            ),
        )


def _alert_url(env_file: Path) -> str | None:
    # STREMIO_-prefixed so publishing.render_gluetun_env never hands it to the
    # VPN container. Deferred import: alerts imports nothing from here, but
    # keeping config free of network modules keeps its import cheap.
    from stremioguard.alerts import valid_alert_url

    url = (env_file_value(env_file, "STREMIO_ALERT_URL") or "").strip()
    if not url:
        return None
    if not valid_alert_url(url):
        raise RuntimeError("Invalid STREMIO_ALERT_URL value; expected an absolute HTTP(S) URL")
    return url


def _scrape_mode(env_file: Path, key: str, default: str) -> str:
    mode = (env_file_value(env_file, key) or default).strip().lower()
    if mode == "off":
        mode = "false"
    if mode not in SCRAPE_MODES:
        raise RuntimeError(
            f"Invalid {key} value: {mode!r}; expected one of {', '.join(sorted(SCRAPE_MODES))}"
        )
    return mode


_IMAGE_DOMAIN_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"(?::[0-9]+)?"
)
_IMAGE_PATH_COMPONENT_RE = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")


def _validate_public_url(value: str | None, *, key: str) -> None:
    if not value:
        return
    try:
        parsed = urllib.parse.urlparse(value)
        hostname = parsed.hostname
    except ValueError as error:
        raise RuntimeError(
            f"Invalid {key} value (malformed URL; expected an absolute HTTP(S) URL)"
        ) from error
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(
            f"Invalid {key} value (unsupported or missing scheme; expected an absolute HTTP(S) URL)"
        )
    if not parsed.netloc or not hostname:
        raise RuntimeError(f"Invalid {key} value (missing host; expected an absolute HTTP(S) URL)")


def _validate_image_repository(value: str, *, key: str) -> str:
    # StremioGuard pins the Comet image by digest itself (`<repo>@<digest>`)
    # and resolves updates against `<repo>:latest`, so a tag or digest baked
    # into the repository override would produce invalid references.
    name_part = value.rsplit("/", 1)[-1]
    if "@" in value or ":" in name_part:
        raise RuntimeError(
            f"Invalid {key} value: {ascii(value)}; expected a repository name without a tag "
            "or digest (e.g. 'g0ldyy/comet'). StremioGuard manages the digest pin."
        )
    if not value or len(value) > 255:
        raise RuntimeError(
            f"Invalid {key} value: {ascii(value)}; expected a valid Docker repository name."
        )
    parts = value.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        domain, path_parts = parts[0], parts[1:]
        if _IMAGE_DOMAIN_RE.fullmatch(domain) is None:
            raise RuntimeError(
                f"Invalid {key} value: {ascii(value)}; expected a valid Docker repository name."
            )
    else:
        path_parts = parts
    if not path_parts or any(
        _IMAGE_PATH_COMPONENT_RE.fullmatch(part) is None for part in path_parts
    ):
        raise RuntimeError(
            f"Invalid {key} value: {ascii(value)}; expected a valid Docker repository name."
        )
    return value


def parse_bind_addresses(env_file: Path) -> list[str]:
    """STREMIO_BIND_ADDRS: the host addresses published ports bind to.

    The single parser for publishing, Comet config and the bind preflight.
    Unset means loopback only; an empty value publishes nothing.
    """
    raw = env_file_value(env_file, "STREMIO_BIND_ADDRS")
    if raw is None:
        return ["127.0.0.1"]
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
        if str(ip) not in addresses:
            addresses.append(str(ip))
    if "0.0.0.0" in addresses and len(addresses) > 1:
        raise RuntimeError("STREMIO_BIND_ADDRS cannot combine 0.0.0.0 with specific bind addresses")
    return addresses


@dataclass(frozen=True)
class CometConfig:
    root_dir: Path
    env_file: Path
    vendor_dir: Path
    lock_file: Path
    repo_dir: Path
    state_dir: Path
    runtime_env_file: Path
    data_dir: Path
    postgres_data_dir: Path
    service_name: str
    postgres_service_name: str
    container_name: str
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
    # Log files outside StremioGuard (e.g. a reverse proxy's) that the log
    # canary must also verify.
    log_canary_globs: tuple[str, ...] = ()
    scrape_torbox: str = "false"
    torbox_api_key: str | None = None
    # Searching DMM needs the ingester's local copy, so one setting drives both.
    scrape_dmm: str = "false"
    dmm_ingest_interval_seconds: int = DEFAULT_DMM_INGEST_INTERVAL_SECONDS

    def bundle_dir(self, digest: str) -> Path:
        """Where the override bundle rendered for image ``digest`` lives.

        One directory per digest: a promotion renders the next image's bundle
        beside the running one, so the active digest always points at a
        complete bundle and a failed render changes nothing.
        """
        validated = require_image_digest(digest, source="Comet bundle digest")
        return self.state_dir / "bundles" / validated.replace(":", "-")

    @property
    def stremthru_state_dir(self) -> Path:
        return self.state_dir.parent / STREMTHRU_SERVICE

    @property
    def runtime_services(self) -> list[str]:
        """Every Compose service the Comet stack runs, dependencies first.

        The one list that starting, stopping, status and the watchdog share.
        """
        services = [self.postgres_service_name, STREMTHRU_SERVICE, self.service_name]
        if self.gateway_enabled:
            services.append(COMET_GATEWAY_SERVICE)
        return services

    @classmethod
    def from_env(cls, root_dir: Path | None = None, *, env_file: Path | None = None) -> CometConfig:
        root_dir = root_dir or Path(__file__).resolve().parent.parent.parent
        env_file = env_file or root_dir / ".env"
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
            env_file, "COMET_GATEWAY_TOKEN_LENGTH", 8, minimum=8, maximum=32
        )
        log_canary_globs = tuple(
            item.strip()
            for item in (env_file_value(env_file, "COMET_LOG_CANARY_GLOBS") or "").split(",")
            if item.strip()
        )
        public_base_url = env_file_value(env_file, "COMET_PUBLIC_BASE_URL") or None
        _validate_public_url(public_base_url, key="COMET_PUBLIC_BASE_URL")
        _validate_public_url(
            gateway_public_base_url,
            key="COMET_GATEWAY_PUBLIC_BASE_URL",
        )

        bind_addresses = tuple(parse_bind_addresses(env_file))
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
        scrape_torrentio = _scrape_mode(env_file, "COMET_SCRAPE_TORRENTIO", "live")
        torrentio_url = (
            env_file_value(env_file, "COMET_TORRENTIO_URL") or "https://torrentio.strem.fun"
        ).strip()
        scrape_zilean = _scrape_mode(env_file, "COMET_SCRAPE_ZILEAN", "live")
        torbox_api_key = env_file_value(env_file, "COMET_TORBOX_API_KEY") or None
        # TorBox's search API needs an account key; searching is the default
        # once one is configured.
        scrape_torbox = _scrape_mode(
            env_file, "COMET_SCRAPE_TORBOX", "live" if torbox_api_key else "false"
        )
        if scrape_torbox != "false" and not torbox_api_key:
            raise RuntimeError("COMET_SCRAPE_TORBOX needs COMET_TORBOX_API_KEY to be set")
        scrape_dmm = _scrape_mode(env_file, "COMET_SCRAPE_DMM", "false")
        dmm_ingest_interval_seconds = env_int_value(
            env_file,
            "COMET_DMM_INGEST_INTERVAL_SECONDS",
            DEFAULT_DMM_INGEST_INTERVAL_SECONDS,
            minimum=3600,
        )
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
            state_dir=root_dir / ".stremio" / "comet",
            runtime_env_file=root_dir / ".stremio" / "comet" / ".env",
            data_dir=root_dir / ".stremio" / "comet" / "data",
            postgres_data_dir=root_dir / ".stremio" / "comet" / "postgres-data",
            service_name="comet",
            postgres_service_name="comet-postgres",
            container_name="comet",
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
            log_canary_globs=log_canary_globs,
            scrape_torbox=scrape_torbox,
            torbox_api_key=torbox_api_key,
            scrape_dmm=scrape_dmm,
            dmm_ingest_interval_seconds=dmm_ingest_interval_seconds,
        )
