"""GluetunGuard — verification core, compose interaction, and preflight checks."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import cached_property
from pathlib import Path

from loguru import logger

from stremioguard.config import (
    COMET_GATEWAY_SERVICE,
    DOCKER_QUERY_TIMEOUT_SECONDS,
    GENERATED_COMPOSE_FILE,
    MANAGED_STACK_ENV,
    PUBLIC_IP_TIMEOUT_MAX_SECONDS,
    REPEAT_WARNING_SECONDS,
    TEARDOWN_MUTATION_TIMEOUT_SECONDS,
    WATCHDOG_MUTATION_TIMEOUT_SECONDS,
    CometConfig,
    Config,
    Runner,
    SubprocessRunner,
    compose_command,
    generation_problem,
    missing_published_files,
    parse_bind_addresses,
    parse_public_ip,
    service_container_id,
)
from stremioguard.env import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    atomic_write_text,
    env_file_value,
    env_flag_enabled,
    read_regular_file,
    tighten_private_files,
)
from stremioguard.httpdeadline import (
    ConnectionTracker,
    DeadlineHTTPHandler,
    DeadlineHTTPSHandler,
)
from stremioguard.preflight import (
    require_docker,
    require_matching_daemon,
    verify_bind_addresses,
)
from stremioguard.publishing import StackPublisher
from stremioguard.resolver import nordvpn_endpoint_env

HOME_IP_STALE_AFTER_SECONDS = 30 * 24 * 3600
HOME_IP_MAX_BYTES = 256
# Ordered request headers shared by the host urllib probe and the in-gluetun
# wget probe so both send the exact same request head apart from Host.
PROBE_REQUEST_HEADERS: tuple[tuple[str, str], ...] = (
    ("User-Agent", "Wget/1.25.0"),
    ("Accept", "*/*"),
    ("Accept-Encoding", "identity"),
    ("Connection", "close"),
)
# docker-compose.yml's `docker compose up` guard; it is not a protected service.
COMPOSE_GATE_SERVICE = "use-stremio-start-instead"
GLUETUN_PULL_TIMEOUT_SECONDS = 180
GLUETUN_STATE_FORMAT = "{{.State.Health.Status}}|{{.State.StartedAt}}"
ENDPOINT_ENV_KEYS = ("OPENVPN_ENDPOINT_IP", "WIREGUARD_ENDPOINT_IP")
# What decides which VPN server gluetun connects to.
VPN_SELECTION_KEYS = (
    "VPN_SERVICE_PROVIDER",
    "VPN_TYPE",
    "SERVER_COUNTRIES",
    "SERVER_REGIONS",
    "SERVER_CITIES",
    "SERVER_HOSTNAMES",
    "SERVER_CATEGORIES",
)
# What OpenVPN/WireGuard print when the provider refuses the credentials.
# Providers also print these for reasons that are not the credentials (a
# connection limit, an overloaded server), which is why one sighting is not
# enough to lock out; see Orchestrator._note_auth_rejection.
AUTH_REJECTION_MARKERS = (
    "AUTH_FAILED",
    "Your credentials might be wrong",
    "authentication failure",
    "incorrect key size",
)
EVIDENCE_LINE_LIMIT = 300
DNS_BLOCK_RULE = "-A OUTPUT -d 127.0.0.11/32 -j REJECT --reject-with icmp-port-unreachable"


# `docker compose ps --status` values. Start and health checks want running
# containers; stop paths must also stop, or wait out, any container that
# still holds a process or will come back: paused, restarting, removing.
STREMIO_MIN_PASSWORD_LENGTH = 12
RUNNING_STATES = ("running",)
ACTIVE_STATES = ("running", "restarting", "paused", "removing")


@dataclass(frozen=True)
class GluetunState:
    """One observation of the gluetun container."""

    container_id: str | None
    health: str | None
    started_at: str | None

    @property
    def healthy(self) -> bool:
        return self.health == "healthy"

    @property
    def identity(self) -> tuple[str, str] | None:
        """Changes whenever gluetun gets a new network namespace.

        A restart keeps the container ID but changes StartedAt; a recreate
        changes both. Either way every service that joined the old namespace
        is now attached to a dead one.
        """
        if not self.container_id or not self.started_at:
            return None
        return (self.container_id, self.started_at)


def _started_at_key(value: str) -> tuple[str, int]:
    """Docker's RFC 3339 timestamp as something that orders correctly.

    The fractional part has a variable number of digits, so comparing the
    raw strings would misorder them.
    """
    seconds, _, fraction = value.rstrip("Z").partition(".")
    digits = "".join(ch for ch in fraction if ch.isdigit())
    return (seconds, int(digits.ljust(9, "0")[:9] or "0"))


class PublicIPAssessment(Enum):
    SAFE = "SAFE"
    UNSAFE_DEFINITIVE = "UNSAFE_DEFINITIVE"
    UNKNOWN = "UNKNOWN"


class LockoutActiveError(RuntimeError):
    """A lockout marker blocks normal starts until an operator recovers.

    Mapped to exit status 78 (CIRCUIT_BREAKER_EXIT_CODE) so supervisors with
    RestartPreventExitStatus=78 stop retrying instead of looping on it.
    """


LOCKOUT_REMEDIATION = {
    "auth_rejected": (
        "Update VPN credentials via `./stremio init` or attempt recovery via `./stremio restart`."
    ),
    "watchdog_unstable": (
        "The watchdog kept failing under systemd. Inspect "
        "`journalctl --user -u stremioguard-watchdog.service`, then run `./stremio restart`."
    ),
    "egress_leak": (
        "Traffic left through this host's own connection instead of the VPN on consecutive "
        "checks. Find out why gluetun's kill switch did not hold before running "
        "`./stremio restart`."
    ),
    "service_flapping": (
        "Services were stopped and auto-started too many times within an hour. Read the run "
        "log (`./stremio logs`) for the repeating cause, then run `./stremio restart`."
    ),
}
DEFAULT_LOCKOUT_REMEDIATION = (
    "Verify network connectivity/provider status, then run `./stremio restart`."
)


def lockout_marker_present(path: Path) -> bool:
    """Whether a lockout marker is present or cannot be proven absent.

    Returns True for any directory entry (regular file, symlink — dangling or
    not — or directory) and whenever status cannot be read for any reason
    other than FileNotFoundError.
    """
    if os.path.lexists(path):
        return True
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def read_lockout_marker(path: Path) -> dict[str, object] | None:
    """The marker's details, or None when it is absent or unreadable.

    Only for display: the marker's existence alone is what blocks starts, so
    a corrupt marker still locks out.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


class GluetunUnavailableError(RuntimeError):
    """Gluetun started but did not establish a verifiable safe tunnel.

    This is distinct from configuration and Compose errors: startup may hand
    this transient runtime state to the watchdog without starting protected
    services. Other preflight failures remain fatal.
    """


class GluetunGuard:
    def __init__(
        self,
        config: Config,
        runner: Runner | None = None,
        *,
        frozen: bool = False,
        teardown: bool = False,
    ) -> None:
        """``frozen`` is the watchdog's mode: run the published generation as
        it is, never render a new one, and bound every Docker call.
        ``teardown`` bounds mutation calls for fail-safe and ``stop``.
        """
        self.config = config
        self.runner = runner or SubprocessRunner()
        self.on_step: Callable[[], None] = lambda: None
        self._env_path = self.config.env_file or self.config.root_dir / ".env"
        self.frozen = frozen
        self.teardown = teardown
        if teardown:
            self.mutation_timeout: float | None = TEARDOWN_MUTATION_TIMEOUT_SECONDS
        elif frozen:
            self.mutation_timeout = WATCHDOG_MUTATION_TIMEOUT_SECONDS
        else:
            self.mutation_timeout = None
        self.last_gluetun_state: GluetunState | None = None
        self._evidence_cursor = 0.0
        self.last_observed_ip: str | None = None
        self._warned_stale_home_ip = False
        self._control_server_failed = False
        # Last SAFE live egress verification; only SAFE outcomes are cached so
        # every non-SAFE tick re-probes.
        self._verified_egress_ip: str | None = None
        self._verified_control_ip: str | None = None
        # The gluetun container (ID, start time) the last SAFE probe ran in.
        self._verified_egress_identity: tuple[str, str] | None = None
        self._last_egress_probe_time = 0.0
        self._warned_snapshot_pair: tuple[str, str] | None = None
        self._egress_warned_at: float | None = None
        self._host_ip_warned_at: float | None = None
        self._verified_dns_block_identity: tuple[str, str] | None = None
        self._dns_block_warned_at: float | None = None

    @property
    def probe_timeout_seconds(self) -> int:
        return min(self.config.public_ip_timeout_seconds, PUBLIC_IP_TIMEOUT_MAX_SECONDS)

    def log(self, message: str) -> None:
        logger.info(message)

    def warn(self, message: str) -> None:
        logger.warning(message)

    def success(self, message: str) -> None:
        logger.success(message)

    def log_lines(self, text: str) -> None:
        for line in text.splitlines() or [""]:
            logger.info(line)

    def read_vpn_lockout(self) -> dict[str, object] | None:
        return read_lockout_marker(self.config.vpn_lockout_file)

    def check_vpn_lockout(self, *, allow_recovery: bool = False) -> None:
        if not lockout_marker_present(self.config.vpn_lockout_file):
            return
        if allow_recovery:
            self.log(
                "Existing VPN lockout marker detected; proceeding under explicit recovery mode."
            )
            return

        lockout = self.read_vpn_lockout()
        reason = (
            lockout.get("reason", "unknown") if lockout else "corrupted or malformed lockout marker"
        )
        timestamp = lockout.get("timestamp", "unknown") if lockout else "unknown"
        remediation = (
            lockout.get(
                "remediation",
                "Run `./stremio init` to update credentials or "
                "`./stremio restart` to attempt recovery.",
            )
            if lockout
            else "Inspect/clear marker via `./stremio unlock` or retry with `./stremio restart`."
        )
        raise LockoutActiveError(
            f"VPN circuit breaker is active (locked out at {timestamp}, reason: {reason}).\n"
            f"{remediation}\n"
            "To clear the lockout manually without starting services, run `./stremio unlock`."
        )

    def write_vpn_lockout(
        self,
        *,
        reason: str,
        outage_duration_seconds: float = 0.0,
        evidence: str | None = None,
    ) -> None:
        try:
            container_id = self.service_container_id("gluetun") or "unknown"
        except (OSError, subprocess.SubprocessError):
            # The marker is what blocks the next start; a Docker daemon that
            # does not answer must not be able to prevent it being written.
            container_id = "unknown"
        provider = env_file_value(self._env_path, "VPN_SERVICE_PROVIDER") or "unknown"
        vpn_type = env_file_value(self._env_path, "VPN_TYPE") or "unknown"
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
            "outage_duration_seconds": round(outage_duration_seconds, 1),
            "gluetun_container_id": container_id,
            "provider": provider,
            "vpn_type": vpn_type,
            "remediation": LOCKOUT_REMEDIATION.get(reason, DEFAULT_LOCKOUT_REMEDIATION),
        }
        if evidence:
            # What was observed, not only the label it was filed under.
            payload["evidence"] = evidence[:EVIDENCE_LINE_LIMIT]
        atomic_write_text(
            self.config.vpn_lockout_file, json.dumps(payload, indent=2) + "\n", mode=0o600
        )

    def clear_vpn_lockout(self) -> None:
        if lockout_marker_present(self.config.vpn_lockout_file):
            try:
                self.config.vpn_lockout_file.unlink()
                self.log("Cleared VPN lockout marker.")
            except OSError as error:
                self.warn(
                    f"Failed to clear VPN lockout marker at {self.config.vpn_lockout_file}: {error}"
                )
                raise RuntimeError(
                    f"Failed to remove VPN lockout marker at {self.config.vpn_lockout_file}: "
                    f"{error}. Refusing to resume services while a stale lockout marker remains."
                ) from error

    def write_compose_override(self) -> None:
        publisher = StackPublisher(self.config.root_dir)
        publisher.publish()

    @cached_property
    def _comet_config(self) -> CometConfig:
        # Read once per process: the watchdog applies .env changes on restart,
        # like every other setting, instead of re-parsing it every tick.
        return CometConfig.from_env(self.config.root_dir, env_file=self._env_path)

    def deployment_profile(self) -> str:
        comet_enabled = self._comet_config.enabled
        if self.config.stremio_enabled and comet_enabled:
            return "Unified"
        elif comet_enabled:
            return "Comet-Only"
        elif self.config.stremio_enabled:
            return "Stremio-Only"
        return "Unknown"

    def enabled_runtime_services(self) -> list[str]:
        services = ["stremio"] if self.config.stremio_enabled else []
        if self._comet_config.enabled:
            services.extend(self._comet_config.runtime_services)
        return services

    def enabled_public_services(self) -> list[str]:
        services = ["stremio"] if self.config.stremio_enabled else []
        if self._comet_config.enabled:
            services.append(
                COMET_GATEWAY_SERVICE if self._comet_config.gateway_enabled else "comet"
            )
        return services

    def require_commands(self) -> None:
        require_docker(
            self.runner,
            install_missing=self.config.install_missing,
            log=self.log,
            warn=self.warn,
        )
        require_matching_daemon(
            self.runner,
            self.config.root_dir / ".stremio" / "daemon-id",
            warn=self.warn,
        )

    def compose(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Query/teardown compose call: uses the override if one exists, but
        never publishes one.

        Publishing requires a rendered Comet bundle, so doing it here made
        teardown and status depend on a state that `preflight` has not
        produced yet — a stack whose bundle is missing could not even be
        inspected or brought down. Lifecycle calls use `compose_fresh`.
        """
        call_env = {MANAGED_STACK_ENV: "1", **os.environ, **(env or {})}
        return self.runner.run(
            self._compose_command(*args),
            check=check,
            capture=capture,
            env=call_env,
            timeout=timeout if timeout is not None else self.mutation_timeout,
        )

    def compose_fresh(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Lifecycle compose call against an up-to-date generation.

        The CLI publishes a new generation from .env first. The watchdog
        (``frozen``) never does: it starts services from the generation the
        last deliberate start published, so an .env edit or a `git pull`
        cannot be deployed by a 3 AM recovery. It refuses to start anything
        when no generation exists, because the base file alone would run
        Comet unpatched from a floating tag.
        """
        if self.frozen:
            missing = missing_published_files(self.config.root_dir)
            if missing:
                override = self.config.root_dir / GENERATED_COMPOSE_FILE
                if override in missing:
                    raise RuntimeError(
                        "No published stack configuration exists; refusing to start services "
                        "from the base compose file alone. Run `./stremio start`."
                    )
                missing_names = ", ".join(str(path) for path in missing)
                raise RuntimeError(
                    f"Published stack configuration is incomplete (missing {missing_names}); "
                    "refusing to start services from the base compose file or raw .env. "
                    "Run `./stremio start`."
                )
        else:
            self.write_compose_override()
        # Stop paths never come here (they use `compose`), so a broken
        # generation can block a start but never the fail-safe.
        if not missing_published_files(self.config.root_dir):
            problem = generation_problem(self.config.root_dir)
            if problem:
                raise RuntimeError(
                    f"The published stack configuration is not one complete generation "
                    f"({problem}); refusing to start services from it. "
                    "Run `./stremio start` to publish it again."
                )
        return self.compose(*args, check=check, capture=capture, env=env)

    def _compose_command(self, *args: str) -> list[str]:
        return compose_command(self.config.root_dir, *args)

    def service_container_id(self, service: str) -> str | None:
        return service_container_id(self.runner, self.config.root_dir, service)

    def gluetun_state(self) -> GluetunState:
        """Gluetun's container ID, health and start time in one inspect."""
        container_id = self.service_container_id("gluetun")
        if not container_id:
            state = GluetunState(None, None, None)
        else:
            result = self.runner.run(
                ["docker", "inspect", "--format", GLUETUN_STATE_FORMAT, container_id],
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                state = GluetunState(container_id, None, None)
            else:
                health, _, started_at = (result.stdout or "").strip().partition("|")
                state = GluetunState(container_id, health or None, started_at or None)
        self.last_gluetun_state = state
        return state

    def gluetun_healthy(self) -> bool:
        return self.gluetun_state().healthy

    def stale_namespace_services(
        self, services: list[str], gluetun: GluetunState
    ) -> list[str] | None:
        """Running services attached to a network namespace gluetun no longer has.

        A service joins gluetun's namespace when it starts. If gluetun has
        since restarted or been recreated, the service keeps the old, dead
        namespace: its loopback healthcheck still passes, but nothing reaches
        it and it reaches nothing. It must be restarted to rejoin.

        Ground truth, not bookkeeping: a service is stale when it names a
        different gluetun container or started before gluetun did. None when
        Docker cannot answer.
        """
        if gluetun.identity is None:
            return None
        gluetun_id, gluetun_started = gluetun.identity
        container_ids: dict[str, str] = {}
        for service in services:
            container_id = self.service_container_id(service)
            if container_id:
                container_ids[container_id] = service
        if not container_ids:
            return []
        result = self.runner.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}|{{.HostConfig.NetworkMode}}",
                *container_ids,
            ],
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            return None
        stale: list[str] = []
        seen: set[str] = set()
        for line in (result.stdout or "").splitlines():
            fields = line.strip().split("|")
            if len(fields) != 4:
                return None
            container_id, running, started_at, network_mode = fields
            service = container_ids.get(container_id)
            if service is None:
                # An answer about a container that was not asked about: the
                # two queries disagree, so nothing has been verified.
                return None
            seen.add(container_id)
            if running != "true":
                continue
            if (
                network_mode.startswith("container:")
                and (network_mode.removeprefix("container:") != gluetun_id)
                or _started_at_key(started_at) < _started_at_key(gluetun_started)
            ):
                stale.append(service)
        if seen != set(container_ids):
            return None
        return stale

    def gluetun_recent_logs(self, lines: int = 20, since_epoch: float | None = None) -> str:
        container_id = self.service_container_id("gluetun")
        if not container_id:
            return ""
        cmd = ["docker", "logs"]
        if since_epoch is not None:
            cmd.extend(["--since", str(int(since_epoch))])
        else:
            cmd.extend(["--tail", str(lines)])
        cmd.append(container_id)
        result = self.runner.run(cmd, check=False, timeout=DOCKER_QUERY_TIMEOUT_SECONDS)
        parts = [p for p in (result.stdout or "", result.stderr or "") if p.strip()]
        return "\n".join(parts).strip()

    def gluetun_auth_evidence(
        self, lines: int = 50, since_epoch: float | None = None
    ) -> str | None:
        """The most recent log line showing the provider refused the credentials."""
        recent = self.gluetun_recent_logs(lines=lines, since_epoch=since_epoch)
        for line in reversed(recent.splitlines()):
            if any(marker in line for marker in AUTH_REJECTION_MARKERS):
                return line.strip()[:EVIDENCE_LINE_LIMIT]
        return None

    def gluetun_auth_failed(self, lines: int = 50, since_epoch: float | None = None) -> bool:
        return self.gluetun_auth_evidence(lines=lines, since_epoch=since_epoch) is not None

    def capture_gluetun_evidence(self, context: str, lines: int = 60) -> None:
        """Copy gluetun's recent log into the run log before it is destroyed.

        Recreating the container deletes its log, which is the only record
        of why the tunnel failed. Each call records what was logged since
        the previous call, so repeated restarts do not repeat the same lines.
        """
        since = self._evidence_cursor or None
        self._evidence_cursor = time.time()
        try:
            recent = self.gluetun_recent_logs(lines=lines, since_epoch=since)
        except (OSError, subprocess.SubprocessError):
            recent = ""
        if not recent:
            self.log(f"No new gluetun log lines to record ({context}).")
            return
        self.log(f"Gluetun log before {context}:")
        self.log_lines(recent)

    def wait_for_gluetun_healthy(self) -> None:
        deadline = time.monotonic() + self.config.gluetun_healthy_timeout_seconds
        while time.monotonic() < deadline:
            if self.gluetun_healthy():
                self.log("Gluetun is healthy.")
                return
            time.sleep(2)

        recent = self.gluetun_recent_logs(lines=20)
        if recent:
            self.warn("Last gluetun log lines:")
            self.log_lines(recent)

        if self.gluetun_auth_failed():
            raise GluetunUnavailableError(
                "Gluetun VPN credentials were rejected (AUTH_FAILED). "
                "Re-run `./stremio init` to update your VPN credentials."
            )

        raise GluetunUnavailableError(
            f"Gluetun did not become healthy within "
            f"{self.config.gluetun_healthy_timeout_seconds}s. "
            "Check the log lines above or run `docker logs gluetun` for details."
        )

    @staticmethod
    def _fetch_ip_url(
        opener: urllib.request.OpenerDirector,
        url: str,
        timeout: float,
        *,
        tracker: ConnectionTracker | None = None,
    ) -> str | None:
        """Fetch up to 128 bytes from ``url`` under a strict wall-clock deadline."""
        timeout_seconds = max(0.0, timeout)
        active_tracker = tracker or ConnectionTracker(time.monotonic() + timeout_seconds)
        result: list[str | None] = [None]
        done = threading.Event()
        request = urllib.request.Request(url, headers=dict(PROBE_REQUEST_HEADERS))

        def _worker() -> None:
            try:
                with opener.open(request, timeout=timeout_seconds) as response:
                    raw = response.read(128)
                if not active_tracker.cancelled:
                    if isinstance(raw, bytes):
                        result[0] = raw.decode("utf-8", errors="replace")
                    elif isinstance(raw, str):
                        result[0] = raw
            except (
                OSError,
                urllib.error.URLError,
                TimeoutError,
                http.client.HTTPException,
                ValueError,
            ):
                pass
            finally:
                active_tracker.close_all()
                done.set()

        thread = threading.Thread(target=_worker, name="stremioguard-ip-probe", daemon=True)
        thread.start()
        if not done.wait(timeout=timeout_seconds):
            active_tracker.cancel()
            thread.join(timeout=0.5)
            return None
        thread.join(timeout=0.1)
        return result[0]

    def public_ip(self, *, version: int | None = None) -> str | None:
        """This host's direct public IP, optionally restricted to one IP family.

        Proxy environment variables are ignored: the answer must describe the
        host's own route, never a proxy's. A result of the wrong family is
        skipped rather than returned, because comparing an IPv6 host address
        with an IPv4 tunnel egress could never match and would pass silently.
        """
        timeout = float(self.probe_timeout_seconds)
        for url in self.config.ip_check_urls:
            tracker = ConnectionTracker(time.monotonic() + max(0.0, timeout))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                DeadlineHTTPHandler(tracker),
                DeadlineHTTPSHandler(tracker),
            )
            self.on_step()
            body = self._fetch_ip_url(opener, url, timeout, tracker=tracker)
            if body is None:
                continue
            ip = parse_public_ip(body)
            if ip and (version is None or ipaddress.ip_address(ip).version == version):
                return ip
        return None

    def public_ip_via_gluetun(self) -> str | None:
        try:
            container_id = self.service_container_id("gluetun")
        except (subprocess.SubprocessError, OSError):
            return None
        if not container_id:
            return None
        t = self.probe_timeout_seconds
        for url in self.config.ip_check_urls:
            try:
                result = self.runner.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "timeout",
                        "-s",
                        "KILL",
                        str(t),
                        "wget",
                        "--tries=1",
                        f"--timeout={t}",
                        *(f"--header={name}: {value}" for name, value in PROBE_REQUEST_HEADERS),
                        "-qO-",
                        url,
                    ],
                    check=False,
                    timeout=t + 2,
                )
            except (subprocess.SubprocessError, OSError):
                continue
            if result.returncode == 0:
                ip = parse_public_ip(result.stdout or "")
                if ip:
                    return ip
        return None

    def public_ip_via_control_server(self) -> str | None:
        if self._control_server_failed:
            return None

        try:
            container_id = self.service_container_id("gluetun")
        except (subprocess.SubprocessError, OSError):
            return None
        if not container_id:
            return None

        # No -q: quiet mode suppresses the HTTP status line on stderr, which is
        # the only way to distinguish an auth/route failure (permanent) from a
        # transient one. The response body still arrives alone on stdout.
        t = self.probe_timeout_seconds
        try:
            result = self.runner.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "timeout",
                    "-s",
                    "KILL",
                    str(t),
                    "wget",
                    "--tries=1",
                    f"--timeout={t}",
                    "-O-",
                    "http://127.0.0.1:18080/v1/publicip/ip",
                ],
                check=False,
                timeout=t + 2,
            )
        except (subprocess.SubprocessError, OSError):
            return None

        if result.returncode != 0:
            output = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
            # GNU wget exits 6 on auth failure; busybox wget always exits 1 but
            # prints the status line, so match the text as well.
            if result.returncode == 6 or "401" in output or "404" in output:
                self.warn(
                    "Gluetun control server rejected the public-IP route (auth is "
                    "required on gluetun v3.40+). StremioGuard mounts "
                    ".stremio/gluetun-auth.toml to allow it; run `./stremio restart` "
                    "so gluetun picks it up. Using external IP probes for this run."
                )
                self._control_server_failed = True
            return None

        body = (result.stdout or "").strip()
        if not body:
            return None

        try:
            data = json.loads(body)
            if isinstance(data, dict) and "public_ip" in data:
                return parse_public_ip(str(data["public_ip"]))
        except json.JSONDecodeError:
            pass

        return None

    def namespace_dns_block_active(self) -> bool | None:
        """Whether gluetun's OUTPUT chain starts with the Docker DNS block."""
        try:
            container_id = self.service_container_id("gluetun")
        except Exception:
            return None
        if not container_id:
            return None
        try:
            result = self.runner.run(
                ["docker", "exec", container_id, "iptables", "-S", "OUTPUT"],
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if result.returncode != 0:
            return None
        for raw_line in (result.stdout or "").splitlines():
            line = raw_line.strip()
            if line.startswith("-A OUTPUT"):
                return line == DNS_BLOCK_RULE
        return False

    def public_ip_assessment(
        self, *, log_observation: bool = False, force_probe: bool = False
    ) -> PublicIPAssessment:
        """Verify that traffic leaves through the tunnel, not this host's own route.

        The authority is a live probe from inside gluetun compared with this
        host's live direct IP (or the recorded home baseline when the host
        probe fails). Gluetun's control-server IP is a snapshot taken once per
        gluetun start and goes stale after an in-tunnel reconnect, so it is
        only a cheap change trigger and a diagnostic, never proof of anything.

        A SAFE verification is trusted for `egress_probe_interval_seconds`, and
        only for the gluetun container it was probed in: a gluetun that was
        restarted or recreated since (even with the same control-server IP) is
        a new tunnel and is probed again before anything trusts it.
        """
        control_ip = self.public_ip_via_control_server()
        now = time.monotonic()
        identity = self.last_gluetun_state.identity if self.last_gluetun_state is not None else None
        due = (
            force_probe
            or self._verified_egress_ip is None
            or identity is None
            or identity != self._verified_egress_identity
            or control_ip != self._verified_control_ip
            or now - self._last_egress_probe_time >= self.config.egress_probe_interval_seconds
        )
        if due or identity is None or identity != self._verified_dns_block_identity:
            block_active = self.namespace_dns_block_active()
            if block_active is not True:
                self._verified_dns_block_identity = None
                self._verified_egress_ip = None
                if (
                    self._dns_block_warned_at is None
                    or now - self._dns_block_warned_at >= REPEAT_WARNING_SECONDS
                ):
                    self._dns_block_warned_at = now
                    if block_active is False:
                        self.warn(
                            "Gluetun's OUTPUT chain does not start with the Docker DNS block "
                            f"({DNS_BLOCK_RULE}). Ensure docker-compose.yml mounts "
                            "gluetun-post-rules-v1 at /iptables/post-rules.txt and restart gluetun."
                        )
                    else:
                        self.warn(
                            "Could not verify Docker DNS block in gluetun's OUTPUT chain; "
                            "holding protected services stopped."
                        )
                return PublicIPAssessment.UNKNOWN
            self._verified_dns_block_identity = identity
            self._dns_block_warned_at = None

        if not due:
            return PublicIPAssessment.SAFE

        self._verified_egress_ip = None
        egress_raw = self.public_ip_via_gluetun()
        egress_ip = parse_public_ip(egress_raw) if egress_raw else None
        if not egress_ip:
            if (
                self._egress_warned_at is None
                or now - self._egress_warned_at >= REPEAT_WARNING_SECONDS
            ):
                self._egress_warned_at = now
                self.warn("Could not determine the tunnel egress IP via gluetun.")
            return PublicIPAssessment.UNKNOWN
        self._egress_warned_at = None

        if log_observation:
            self.log(f"Observed public IP: {egress_ip}")
        elif self.last_observed_ip and self.last_observed_ip != egress_ip:
            self.log(f"Public IP changed from {self.last_observed_ip} to {egress_ip}.")
        self.last_observed_ip = egress_ip

        egress_version = ipaddress.ip_address(egress_ip).version
        raw_home_bytes = read_regular_file(self.config.home_ip_file, max_bytes=HOME_IP_MAX_BYTES)
        raw_home: str | None = None
        if raw_home_bytes is not None:
            self._warn_if_home_ip_stale()
            # A malformed or non-public baseline counts as missing, so it cannot
            # stand in for a failed host probe.
            raw_home = parse_public_ip(raw_home_bytes.decode("utf-8", errors="replace"))
        home_ip = (
            raw_home
            if raw_home is not None and ipaddress.ip_address(raw_home).version == egress_version
            else None
        )

        host_raw = self.public_ip(version=egress_version)
        host_ip = parse_public_ip(host_raw) if host_raw else None
        if host_ip is not None and ipaddress.ip_address(host_ip).version != egress_version:
            host_ip = None
        if host_ip == egress_ip:
            self.warn(
                f"Tunnel egress IP {egress_ip} equals this host's direct public IP; "
                "traffic is not leaving through the VPN."
            )
            return PublicIPAssessment.UNSAFE_DEFINITIVE
        if host_ip is None and home_ip is None:
            if (
                self._host_ip_warned_at is None
                or now - self._host_ip_warned_at >= REPEAT_WARNING_SECONDS
            ):
                self._host_ip_warned_at = now
                if raw_home is not None:
                    self.warn(
                        f"Could not determine this host's direct IPv{egress_version} public IP "
                        f"and the recorded home-IP baseline ({raw_home}) is a different address "
                        "family, so the tunnel egress cannot be proven to differ from it."
                    )
                else:
                    self.warn(
                        "Could not determine this host's direct public IP and no valid home-IP "
                        "baseline is recorded, so the tunnel egress cannot be proven to differ "
                        "from it. Run `./stremio record-home-ip` while gluetun is stopped."
                    )
            return PublicIPAssessment.UNKNOWN
        self._host_ip_warned_at = None

        expected_vpn_ip = (
            parse_public_ip(self.config.expected_vpn_ip) or self.config.expected_vpn_ip
            if self.config.expected_vpn_ip
            else None
        )
        if expected_vpn_ip and egress_ip != expected_vpn_ip:
            self.warn(f"Public IP does not match EXPECTED_VPN_IP={self.config.expected_vpn_ip}.")
            return PublicIPAssessment.UNSAFE_DEFINITIVE

        if home_ip and egress_ip == home_ip:
            self.warn(f"Public IP matches saved home IP baseline ({home_ip}); possible leak.")
            return PublicIPAssessment.UNSAFE_DEFINITIVE

        if control_ip and control_ip != egress_ip:
            pair = (control_ip, egress_ip)
            if pair != self._warned_snapshot_pair:
                self._warned_snapshot_pair = pair
                self.warn(
                    f"Gluetun control server reports {control_ip} but the live tunnel egress "
                    f"is {egress_ip}. Gluetun only fetches its public IP once per start, so "
                    "this is expected after an in-tunnel reconnect; the live egress is used."
                )

        self._verified_egress_ip = egress_ip
        self._verified_control_ip = control_ip
        self._verified_egress_identity = identity
        self._last_egress_probe_time = now
        return PublicIPAssessment.SAFE

    def public_ip_safe(self, *, log_observation: bool = False) -> bool:
        return self.public_ip_assessment(log_observation=log_observation) == PublicIPAssessment.SAFE

    def home_ip_age_seconds(self) -> float | None:
        try:
            st = os.lstat(self.config.home_ip_file)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        return max(0.0, time.time() - st.st_mtime)

    def _warn_if_home_ip_stale(self) -> None:
        if self._warned_stale_home_ip:
            return
        age = self.home_ip_age_seconds()
        if age is not None and age > HOME_IP_STALE_AFTER_SECONDS:
            self.warn(
                f"home-IP baseline is {int(age // 86400)} days old; residential IPs rotate, "
                "so a stale baseline weakens leak detection. Re-run "
                "`./stremio record-home-ip` while gluetun is stopped to refresh it."
            )
            self._warned_stale_home_ip = True

    def check_stremio_auth(self) -> None:
        """Refuse an unauthenticated Stremio server unless the owner opted in.

        The image's nginx puts basic auth on every server route except raw
        stream URLs, but only when it is given credentials; without them the
        settings, proxy, subtitle and torrent-creation routes are open to
        anyone who can reach the port, and they make requests from inside the
        VPN namespace. Security hardening: require credentials by default.
        """
        env = self._env_path
        if not env_flag_enabled("STREMIO_ENABLED", True, env_path=env):
            return
        if env_flag_enabled("STREMIO_ALLOW_NO_AUTH", False, env_path=env):
            self.warn(
                "STREMIO_ALLOW_NO_AUTH=1: the Stremio server accepts unauthenticated requests "
                "on every route. Set STREMIO_USERNAME and STREMIO_PASSWORD to require auth."
            )
            return
        container_port = env_file_value(env, "STREMIO_CONTAINER_PORT") or str(
            DEFAULT_STREMIO_CONTAINER_PORT
        )
        if container_port.strip() != str(DEFAULT_STREMIO_CONTAINER_PORT):
            raise RuntimeError(
                f"STREMIO_CONTAINER_PORT={container_port.strip()} publishes a port without "
                f"auth; only {DEFAULT_STREMIO_CONTAINER_PORT} (the image's nginx) enforces "
                "STREMIO_USERNAME and STREMIO_PASSWORD. Remove the setting, or set "
                "STREMIO_ALLOW_NO_AUTH=1 to accept an open server."
            )
        username = env_file_value(env, "STREMIO_USERNAME") or ""
        password = env_file_value(env, "STREMIO_PASSWORD") or ""
        if not username or len(password) < STREMIO_MIN_PASSWORD_LENGTH:
            raise RuntimeError(
                "The Stremio server needs credentials: set STREMIO_USERNAME and a "
                f"STREMIO_PASSWORD of at least {STREMIO_MIN_PASSWORD_LENGTH} characters in .env "
                "(every server route except raw stream URLs then requires them), set "
                "STREMIO_ENABLED=0, or set STREMIO_ALLOW_NO_AUTH=1 to accept an open server."
            )

    def check_bind_addresses(self) -> None:
        if os.environ.get("SKIP_BIND_PREFLIGHT") == "1":
            self.log("SKIP_BIND_PREFLIGHT=1 is set; skipping bind address validation.")
            return
        verify_bind_addresses(
            self.runner, parse_bind_addresses(self._env_path), log=self.log, warn=self.warn
        )

    def refresh_gluetun_image(self) -> None:
        """Best-effort `compose pull gluetun` so the pinned image is present.

        docker-compose.yml pins gluetun by digest, so this fetches exactly
        that image when it is missing (after a Dependabot bump was pulled)
        and is a no-op otherwise. A registry hiccup, hung pull, or offline
        host must never block a start, so every failure only warns and
        gluetun boots from the image already on the host.
        """
        self.log("Making sure the pinned gluetun image is present.")
        try:
            if not (self.config.root_dir / GENERATED_COMPOSE_FILE).exists():
                self.write_compose_override()
            result = self.runner.run(
                self._compose_command("pull", "gluetun"),
                check=False,
                timeout=GLUETUN_PULL_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                suffix = f": {detail[-1]}" if detail else "."
                self.warn(f"gluetun image pull failed; starting with the existing image{suffix}")
        except subprocess.TimeoutExpired:
            self.warn(
                f"gluetun image pull timed out after {GLUETUN_PULL_TIMEOUT_SECONDS}s; "
                "starting with the existing image."
            )
        except Exception:
            logger.opt(exception=True).debug("gluetun image pull failed unexpectedly.")
            self.warn("gluetun image pull failed; starting with the existing image.")

    def running_gluetun_endpoint_env(self) -> dict[str, str]:
        """The VPN endpoint the running gluetun container was created with.

        The NordVPN endpoint is re-resolved by load, so it differs between
        any two calls an hour apart. Handing Compose the value the running
        container already has keeps `./stremio start` from recreating a
        healthy tunnel, and dropping live streams, over a new recommendation.
        Empty when gluetun is not running.
        """
        state = self.gluetun_state()
        if not state.container_id or state.health is None:
            return {}
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{json .Config.Env}}", state.container_id],
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            return {}
        try:
            entries = json.loads((result.stdout or "").strip() or "[]")
        except json.JSONDecodeError:
            return {}
        running: dict[str, str] = {}
        for entry in entries if isinstance(entries, list) else []:
            key, separator, value = str(entry).partition("=")
            if separator:
                running[key] = value
        # Only while the container still matches what is configured. After a
        # provider or location change gluetun is about to be recreated, and
        # its old server would pin the new filters to the wrong place.
        for key in VPN_SELECTION_KEYS:
            configured = os.environ.get(key)
            if configured is None:
                configured = env_file_value(self._env_path, key) or ""
            if running.get(key, "") != configured:
                return {}
        return {key: running[key] for key in ENDPOINT_ENV_KEYS if running.get(key)}

    def preflight(
        self,
        *,
        allow_recovery: bool = False,
        defer_vpn_recovery: bool = False,
        keep_running_gluetun: bool = False,
    ) -> bool:
        """Prepare Gluetun and verify a safe tunnel.

        ``keep_running_gluetun`` is `./stremio start`'s mode: a gluetun that
        is already running keeps its VPN endpoint, so it is recreated only
        when its configuration really changed.

        If ``defer_vpn_recovery`` is enabled, an unavailable tunnel returns
        ``False`` after Gluetun has been launched. The caller must immediately
        launch the watchdog and must not start protected services. Configuration
        and Compose failures still raise normally.
        """
        self.require_commands()
        if not self._env_path.exists():
            raise RuntimeError(
                f".env not found at {self._env_path}. Run `./stremio init` for guided "
                "first-time setup, or copy .env.example to .env and populate the "
                "chosen VPN credentials manually (see docs/setup.md)."
            )
        self.check_vpn_lockout(allow_recovery=allow_recovery)
        self.check_bind_addresses()
        self.check_stremio_auth()
        private_dirs = [self.config.vpn_lockout_file.parent]
        if self.config.log_file is not None:
            private_dirs.append(self.config.log_file.parent)
        for directory in private_dirs:
            tightened = tighten_private_files(directory)
            if tightened:
                self.log(
                    f"Made {len(tightened)} older file(s) in {directory.name}/ owner-only: "
                    f"{', '.join(tightened)}."
                )

        comet_config = CometConfig.from_env(self.config.root_dir, env_file=self._env_path)
        if comet_config.enabled:
            from stremioguard.comet import CometManager

            comet_manager = CometManager(comet_config, self.runner)
            comet_manager.prepare_runtime()

        self.log("Ensuring the gluetun service is running.")
        # Publish first: the pull below and the `up` after it must act on the
        # same generation, or a newly pinned gluetun image would be fetched by
        # `up` itself, without the pull's timeout and offline tolerance.
        self.write_compose_override()
        self.refresh_gluetun_image()
        # Lifecycle path: gluetun must come up against a freshly rendered
        # override so bind/mount changes apply BEFORE the VPN is verified,
        # not via a surprise dependency-recreate during the services `up`.
        endpoint_env = self.running_gluetun_endpoint_env() if keep_running_gluetun else {}
        self.compose_fresh("up", "-d", "gluetun", capture=False, env=endpoint_env or None)
        try:
            self.wait_for_gluetun_healthy()
        except GluetunUnavailableError:
            if not defer_vpn_recovery:
                raise
            self.warn(
                "Gluetun is unavailable at startup; stopping protected services and "
                "handing bounded recovery to the watchdog."
            )
            return False
        if not self.public_ip_safe(log_observation=True):
            if defer_vpn_recovery:
                self.warn(
                    "Gluetun is healthy but its public IP cannot be verified at startup; "
                    "stopping protected services for fail-closed watchdog monitoring."
                )
                return False
            raise RuntimeError("Public IP check failed via gluetun; refusing to start services.")
        self.clear_vpn_lockout()

        return True

    def ensure_data_dir(self) -> None:
        data_dir = self.config.root_dir / "stremio-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.log(f"Using Stremio data directory: {data_dir}")

    def compose_instance_exists(self) -> bool:
        # Deliberately does not publish an override: this runs before
        # `preflight` has rendered the Comet bundle, and publishing without
        # one raises. Asking "does an instance exist" must stay a question.
        for service in self.enabled_runtime_services():
            result = self.runner.run(
                self._compose_command("ps", "-a", "-q", service),
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
            if bool((result.stdout or "").strip()):
                return True
        return False

    def running_services(
        self, services: list[str], *, states: tuple[str, ...] = RUNNING_STATES
    ) -> set[str] | None:
        """Which of ``services`` Docker reports in one of ``states``, in one query.

        None when Docker cannot answer, or answers with anything other than
        the requested service names, one per line (a warning on stdout, a
        changed output format): an answer this parser did not fully
        understand is never "none of them". Callers decide whether None
        counts as running (stop paths) or not (start paths).
        """
        if not services:
            return set()
        status_args = [arg for state in states for arg in ("--status", state)]
        try:
            result = self.runner.run(
                self._compose_command("ps", *status_args, "--services", *services),
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if result.returncode != 0:
            return None
        reported: set[str] = set()
        for raw_line in (result.stdout or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line not in services:
                return None
            reported.add(line)
        return reported

    def container_running(self, services: list[str] | None = None) -> bool | None:
        """Whether all ``services`` are running, or ``None`` if Docker did not answer."""
        if services is None:
            services = self.enabled_runtime_services()
        running = self.running_services(services)
        if running is None:
            return None
        return running >= set(services)

    def start_services(
        self, services: list[str], *, build: bool = False, check: bool = True
    ) -> bool:
        """Start protected services against the gluetun that is already running.

        `--no-deps` keeps this from touching gluetun: Compose otherwise
        recreates a dependency whose interpolated config differs from its
        container, so a stale endpoint IP in this process's environment would
        replace the tunnel that was just verified with an unverified one.
        Every enabled runtime service is listed explicitly, so no dependency
        between them is skipped.
        """
        # The watchdog never rebuilds: a build reads the working tree, and
        # nothing from the working tree is deployed outside a deliberate
        # start. Compose still builds an image that does not exist at all.
        build_args = ("--build",) if build and not self.frozen else ()
        result = self.compose_fresh(
            "up", "-d", "--no-deps", *build_args, *services, check=check, capture=False
        )
        if result.returncode != 0:
            self.warn(
                f"Starting {', '.join(services)} failed (exit {result.returncode}); Compose's "
                "own message is in the console or `journalctl --user -u "
                "stremioguard-watchdog.service`."
            )
            return False
        return True

    def services_confirmed_stopped(self, services: list[str]) -> bool:
        """Whether Docker positively reports none of ``services`` active.

        Active is running, restarting, paused or removing: a paused container
        still holds its process and a restarting one comes back. A failed or
        unreadable query is not proof of a stopped container.
        """
        return self.running_services(services, states=ACTIVE_STATES) == set()

    def protected_services(self) -> list[str]:
        """Every service in the Compose project except gluetun and the gate.

        Read from Compose, not .env: stopping must keep working when a .env
        edit no longer parses, and stopping a disabled service is harmless.
        """
        result = self.runner.run(
            self._compose_command("config", "--services"),
            check=True,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
        return [
            service
            for service in (result.stdout or "").split()
            if service not in {"gluetun", COMPOSE_GATE_SERVICE}
        ]

    def _docker_stop_service(self, service: str) -> None:
        try:
            container_id = self.service_container_id(service)
        except (subprocess.SubprocessError, OSError) as error:
            self.warn(f"Could not resolve container ID for {service}: {error}")
            return
        if not container_id:
            return
        try:
            self.runner.run(
                ["docker", "stop", "-t", "5", container_id],
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError) as error:
            self.warn(f"Direct `docker stop` failed for {service} ({container_id[:12]}): {error}")

    def stop_active_services(self, services: list[str] | None = None) -> bool:
        """Stop ``services`` (default: all protected) and return whether that was verified."""
        if services is None:
            try:
                services = self.protected_services()
            except subprocess.SubprocessError as error:
                self.warn(
                    f"Could not read protected services from Compose ({error}); "
                    "falling back to configured runtime services."
                )
                try:
                    services = self.enabled_runtime_services()
                except (RuntimeError, ValueError):
                    services = [
                        "stremio",
                        "comet-gateway",
                        "comet",
                        "stremthru",
                        "comet-postgres",
                    ]
        running = self.running_services(services, states=ACTIVE_STATES)
        if running == set():
            return True
        # Unknown state: stop everything named rather than guess.
        running_services = [s for s in services if running is None or s in running]
        self.log(f"Stopping active services: {', '.join(running_services)}.")
        compose_ok = False
        try:
            result = self.compose("stop", *running_services, check=False)
            compose_ok = result.returncode == 0
        except subprocess.SubprocessError as error:
            self.warn(f"`docker compose stop` failed ({error}); falling back to `docker stop`.")
        if compose_ok and self.services_confirmed_stopped(running_services):
            self.success("Active services are stopped.")
            return True
        still_running = self.running_services(running_services, states=ACTIVE_STATES)
        fallback_targets = (
            running_services
            if still_running is None
            else [s for s in running_services if s in still_running]
        )
        for service in fallback_targets:
            self._docker_stop_service(service)
        if self.services_confirmed_stopped(running_services):
            self.success("Active services are stopped.")
            return True
        self.warn(f"Failed to confirm shutdown of services: {', '.join(running_services)}.")
        return False

    def stop_gluetun(self) -> None:
        self.log("Stopping gluetun VPN container.")
        compose_ok = False
        try:
            result = self.compose("stop", "gluetun", check=False)
            compose_ok = result.returncode == 0
        except (subprocess.SubprocessError, OSError) as error:
            self.warn(
                f"`docker compose stop gluetun` failed ({error}); falling back to `docker stop`."
            )
        if self.container_running(["gluetun"]) is not False or not compose_ok:
            self._docker_stop_service("gluetun")
            if self.container_running(["gluetun"]) is not False:
                self.warn(
                    "FATAL: Gluetun VPN container could not be stopped. "
                    "Container may still be running in the background."
                )
                return
        self.success("Gluetun VPN container is stopped.")

    def _recreate_gluetun(self, env_override: dict[str, str]) -> bool:
        """Recreate gluetun and report whether Compose accepted the command.

        `--no-deps`: recovery must not depend on the gate service, whose
        image may not be on the host (a pulled Dependabot bump) at the very
        moment the network is unreliable. A failure is logged with Compose's
        own message; the caller's recovery budget handles the rest.
        """
        result = self.compose(
            "up", "-d", "--no-deps", "--force-recreate", "gluetun", check=False, env=env_override
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            self.warn(
                f"Recreating gluetun failed (exit {result.returncode})"
                + (f": {detail[-1][:EVIDENCE_LINE_LIMIT]}" if detail else ".")
            )
            return False
        return True

    def restart_gluetun(self) -> bool:
        """Restart gluetun; return whether the restart command succeeded.

        Success here is only "Docker accepted it": whether the tunnel came
        back is what the next health check observes.
        """
        self.log("Restarting gluetun service (best-effort candidate reselection).")
        self.capture_gluetun_evidence("restart")
        self.on_step()
        env_override = nordvpn_endpoint_env(
            self._env_path,
            self.config.root_dir / ".stremio" / "nordvpn-endpoint-cache.json",
            force_refresh=True,
        )
        if env_override:
            return self._recreate_gluetun(env_override)
        result = self.compose("restart", "gluetun", check=False)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            self.warn(
                f"Restarting gluetun failed (exit {result.returncode})"
                + (f": {detail[-1][:EVIDENCE_LINE_LIMIT]}" if detail else ".")
            )
            return False
        return True

    def restart_gluetun_relaxed(self) -> bool:
        self.log("Restarting gluetun service with relaxed broad country pool.")
        self.capture_gluetun_evidence("relaxed restart")
        env_override = {
            "SERVER_REGIONS": "",
            "SERVER_CITIES": "",
            "SERVER_HOSTNAMES": "",
            "SERVER_CATEGORIES": "",
            "OPENVPN_ENDPOINT_IP": "",
            "WIREGUARD_ENDPOINT_IP": "",
        }
        return self._recreate_gluetun(env_override)
