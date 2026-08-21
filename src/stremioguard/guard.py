"""GluetunGuard — verification core, compose interaction, and preflight checks."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from enum import Enum

from loguru import logger

from stremioguard.comet_gateway import CometGatewayConfig
from stremioguard.config import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    DEFAULT_STREMIO_HOST_PORT,
    MANAGED_STACK_ENV,
    CometConfig,
    Config,
    Runner,
    SubprocessRunner,
    parse_public_ip,
)
from stremioguard.env import atomic_write_text, env_file_value, env_int_value
from stremioguard.preflight import (
    require_docker,
    require_matching_daemon,
    verify_bind_addresses,
)
from stremioguard.publishing import StackPublisher

HOME_IP_STALE_AFTER_SECONDS = 30 * 24 * 3600
GLUETUN_PULL_TIMEOUT_SECONDS = 180


class PublicIPAssessment(Enum):
    SAFE = "SAFE"
    UNSAFE_DEFINITIVE = "UNSAFE_DEFINITIVE"
    UNKNOWN = "UNKNOWN"


class GluetunUnavailableError(RuntimeError):
    """Gluetun started but did not establish a verifiable safe tunnel.

    This is distinct from configuration and Compose errors: startup may hand
    this transient runtime state to the watchdog without starting protected
    services. Other preflight failures remain fatal.
    """


class GluetunGuard:
    def __init__(self, config: Config, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()
        self._env_path = self.config.root_dir / ".env"
        self.last_observed_ip: str | None = None
        self._warned_stale_home_ip = False
        self._control_server_failed = False
        self._last_crosscheck_time = 0.0

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
        if not self.config.vpn_lockout_file.exists():
            return None
        try:
            data = json.loads(self.config.vpn_lockout_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def check_vpn_lockout(self, *, allow_recovery: bool = False) -> None:
        if not self.config.vpn_lockout_file.exists():
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
        raise RuntimeError(
            f"VPN circuit breaker is active (locked out at {timestamp}, reason: {reason}).\n"
            f"{remediation}\n"
            "To clear the lockout manually without starting services, run `./stremio unlock`."
        )

    def write_vpn_lockout(self, *, reason: str, outage_duration_seconds: float) -> None:
        container_id = self.service_container_id("gluetun") or "unknown"
        provider = env_file_value(self._env_path, "VPN_SERVICE_PROVIDER") or "unknown"
        vpn_type = env_file_value(self._env_path, "VPN_TYPE") or "unknown"
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
            "outage_duration_seconds": round(outage_duration_seconds, 1),
            "gluetun_container_id": container_id,
            "provider": provider,
            "vpn_type": vpn_type,
            "remediation": (
                "Update VPN credentials via `./stremio init` or "
                "attempt recovery via `./stremio restart`."
                if reason == "auth_rejected"
                else "Verify network connectivity/provider status, then run `./stremio restart`."
            ),
        }
        atomic_write_text(
            self.config.vpn_lockout_file, json.dumps(payload, indent=2) + "\n", mode=0o600
        )

    def clear_vpn_lockout(self) -> None:
        if self.config.vpn_lockout_file.exists():
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

    def stremio_host_port(self) -> int:
        return env_int_value(
            self._env_path, "STREMIO_HOST_PORT", DEFAULT_STREMIO_HOST_PORT, minimum=1, maximum=65535
        )

    def stremio_container_port(self) -> int:
        return env_int_value(
            self._env_path,
            "STREMIO_CONTAINER_PORT",
            DEFAULT_STREMIO_CONTAINER_PORT,
            minimum=1,
            maximum=65535,
        )

    def write_compose_override(self) -> None:
        publisher = StackPublisher(self.config.root_dir, self.config.compose_override_file)
        publisher.publish()

    def deployment_profile(self) -> str:
        comet_config = CometConfig.from_env(self.config.root_dir)
        if self.config.stremio_enabled and comet_config.enabled:
            return "Unified"
        elif comet_config.enabled:
            return "Comet-Only"
        elif self.config.stremio_enabled:
            return "Stremio-Only"
        return "Unknown"

    def enabled_runtime_services(self) -> list[str]:
        services = []
        if self.config.stremio_enabled:
            services.append("stremio")
        comet_config = CometConfig.from_env(self.config.root_dir)
        if comet_config.enabled:
            services.extend(["comet", "comet-postgres"])
            gateway_config = CometGatewayConfig.from_env(self.config.root_dir)
            if gateway_config.enabled:
                services.append("comet-gateway")
        return services

    def enabled_public_services(self) -> list[str]:
        services = []
        if self.config.stremio_enabled:
            services.append("stremio")
        comet_config = CometConfig.from_env(self.config.root_dir)
        if comet_config.enabled:
            gateway_config = CometGatewayConfig.from_env(self.config.root_dir)
            if gateway_config.enabled:
                services.append("comet-gateway")
            else:
                services.append("comet")
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
            self.config.compose_override_file.parent / "daemon-id",
            warn=self.warn,
        )

    def compose(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        env: dict[str, str] | None = None,
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
            self._compose_command(*args), check=check, capture=capture, env=call_env
        )

    def compose_fresh(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.write_compose_override()
        call_env = {MANAGED_STACK_ENV: "1", **os.environ, **(env or {})}
        return self.runner.run(
            self._compose_command(*args), check=check, capture=capture, env=call_env
        )

    def _compose_command(self, *args: str) -> list[str]:
        override = self.config.compose_override_file
        override_args = ["-f", str(override)] if override.exists() else []
        return [
            "docker",
            "compose",
            "-f",
            str(self.config.compose_file),
            *override_args,
            *args,
        ]

    def service_container_id(self, service: str) -> str | None:
        result = self.runner.run(self._compose_command("ps", "-q", service), check=False)
        if result.returncode != 0:
            return None
        return next(
            (line.strip() for line in (result.stdout or "").splitlines() if line.strip()), None
        )

    def gluetun_healthy(self) -> bool:
        container_id = self.service_container_id("gluetun")
        if not container_id:
            return False
        result = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
            check=False,
        )
        return result.returncode == 0 and (result.stdout or "").strip() == "healthy"

    def gluetun_recent_logs(self, lines: int = 20, since_epoch: float | None = None) -> str:
        container_id = self.service_container_id("gluetun")
        if not container_id:
            return ""
        cmd = ["docker", "logs", "--tail", str(lines)]
        if since_epoch is not None:
            cmd.extend(["--since", str(int(since_epoch))])
        cmd.append(container_id)
        result = self.runner.run(
            cmd,
            check=False,
        )
        parts = [p for p in (result.stdout or "", result.stderr or "") if p.strip()]
        return "\n".join(parts).strip()

    def gluetun_auth_failed(self, lines: int = 50, since_epoch: float | None = None) -> bool:
        recent = self.gluetun_recent_logs(lines=lines, since_epoch=since_epoch)
        if not recent:
            return False
        auth_markers = (
            "AUTH_FAILED",
            "Your credentials might be wrong",
            "authentication failure",
            "AUTH: Received control message: AUTH_FAILED",
            "incorrect key size",
        )
        return any(m in recent for m in auth_markers)

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
                    self.service_container_id("gluetun") or "",
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

    def public_ip_via_control_server(self) -> str | None:
        if self._control_server_failed:
            return None

        container_id = self.service_container_id("gluetun")
        if not container_id:
            return None

        # No -q: quiet mode suppresses the HTTP status line on stderr, which is
        # the only way to distinguish an auth/route failure (permanent) from a
        # transient one. The response body still arrives alone on stdout.
        result = self.runner.run(
            [
                "docker",
                "exec",
                container_id,
                "wget",
                "-O-",
                "--timeout",
                str(self.config.public_ip_timeout_seconds),
                "http://127.0.0.1:18080/v1/publicip/ip",
            ],
            check=False,
            timeout=self.config.public_ip_timeout_seconds + 2,
        )

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

    def public_ip_assessment(self, *, log_observation: bool = False) -> PublicIPAssessment:
        control_ip = self.public_ip_via_control_server()
        resolved_ip = control_ip

        if not control_ip:
            resolved_ip = self.public_ip_via_gluetun()
            if not resolved_ip:
                self.warn("Could not determine public IP via gluetun or control server.")
                return PublicIPAssessment.UNKNOWN
        else:
            now = time.monotonic()
            if now - self._last_crosscheck_time >= self.config.ip_crosscheck_interval_seconds:
                self._last_crosscheck_time = now
                external_ip = self.public_ip_via_gluetun()
                if external_ip and external_ip != control_ip:
                    self.warn(
                        f"IP mismatch detected during cross-check: control server IP={control_ip}, "
                        f"external probe IP={external_ip}. Threat vector possible, marking unsafe."
                    )
                    return PublicIPAssessment.UNSAFE_DEFINITIVE

        if log_observation:
            self.log(f"Observed public IP: {resolved_ip}")
        elif self.last_observed_ip and self.last_observed_ip != resolved_ip:
            self.log(f"Public IP changed from {self.last_observed_ip} to {resolved_ip}.")
        self.last_observed_ip = resolved_ip

        if self.config.expected_vpn_ip and resolved_ip != self.config.expected_vpn_ip:
            self.warn(f"Public IP does not match EXPECTED_VPN_IP={self.config.expected_vpn_ip}.")
            return PublicIPAssessment.UNSAFE_DEFINITIVE

        if self.config.home_ip_file.exists():
            self._warn_if_home_ip_stale()
            home_ip = self.config.home_ip_file.read_text(encoding="utf-8").strip()
            if home_ip and resolved_ip == home_ip:
                self.warn(f"Public IP matches saved home IP baseline ({home_ip}); possible leak.")
                return PublicIPAssessment.UNSAFE_DEFINITIVE

        return PublicIPAssessment.SAFE

    def public_ip_safe(self, *, log_observation: bool = False) -> bool:
        return self.public_ip_assessment(log_observation=log_observation) == PublicIPAssessment.SAFE

    def home_ip_age_seconds(self) -> float | None:
        if not self.config.home_ip_file.exists():
            return None
        return max(0.0, time.time() - self.config.home_ip_file.stat().st_mtime)

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

    def check_bind_addresses(self) -> None:
        if os.environ.get("SKIP_BIND_PREFLIGHT") == "1":
            self.log("SKIP_BIND_PREFLIGHT=1 is set; skipping bind address validation.")
            return
        verify_bind_addresses(self.runner, self.bind_addresses(), log=self.log, warn=self.warn)

    def refresh_gluetun_image(self) -> None:
        """Best-effort `compose pull gluetun` so every start/restart tracks
        the pinned release channel (`qmcgaw/gluetun:v3` in the compose file).

        The health wait and IP check right after `up` validate whatever was
        pulled, and a broken image fails closed. A registry hiccup, hung
        pull, or offline host must never block a start, so every failure
        only warns and gluetun boots from the existing local image.
        """
        self.log("Checking the gluetun release channel for a newer image.")
        try:
            if not self.config.compose_override_file.exists():
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

    def preflight(self, *, allow_recovery: bool = False, defer_vpn_recovery: bool = False) -> bool:
        """Prepare Gluetun and verify a safe tunnel.

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
                "chosen VPN credentials manually (see README.md → First-time setup)."
            )
        self.check_vpn_lockout(allow_recovery=allow_recovery)
        self.check_bind_addresses()

        comet_config = CometConfig.from_env(self.config.root_dir)
        if comet_config.enabled:
            from stremioguard.comet import CometManager

            comet_manager = CometManager(comet_config, self.runner)
            comet_manager.prepare_runtime()

        self.log("Ensuring the gluetun service is running.")
        self.refresh_gluetun_image()
        # Lifecycle path: gluetun must come up against a freshly rendered
        # override so bind/mount changes apply BEFORE the VPN is verified,
        # not via a surprise dependency-recreate during the services `up`.
        self.compose_fresh("up", "-d", "gluetun", capture=False)
        try:
            self.wait_for_gluetun_healthy()
        except GluetunUnavailableError:
            if not defer_vpn_recovery:
                raise
            self.warn(
                "Gluetun is unavailable at startup. Protected services remain stopped; "
                "the watchdog will own the bounded recovery window."
            )
            return False
        if not self.public_ip_safe(log_observation=True):
            if defer_vpn_recovery:
                self.warn(
                    "Gluetun is healthy but its public IP cannot be verified at startup. "
                    "Protected services remain stopped; the watchdog will continue "
                    "fail-closed monitoring."
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
            result = self.runner.run(self._compose_command("ps", "-a", "-q", service), check=False)
            if bool((result.stdout or "").strip()):
                return True
        return False

    def container_running(self, services: list[str] | None = None) -> bool:
        if services is None:
            services = self.enabled_runtime_services()
        for service in services:
            container_id = self.service_container_id(service)
            if not container_id:
                return False
            result = self.runner.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
                check=False,
            )
            if result.returncode != 0 or (result.stdout or "").strip().lower() != "true":
                return False
        return True

    def stop_active_services(self, services: list[str] | None = None) -> None:
        if services is None:
            services = self.enabled_runtime_services()
        running_services = [s for s in services if self.container_running([s])]
        if not running_services:
            return
        self.log(f"Stopping active services: {', '.join(running_services)}.")
        result = self.compose("stop", *running_services, check=False)
        still_running = [s for s in running_services if self.container_running([s])]
        if still_running or result.returncode != 0:
            target = ", ".join(still_running or running_services)
            self.warn(f"Failed to confirm shutdown of services: {target}.")
        else:
            self.success("Active services are stopped.")

    def stop_gluetun(self) -> None:
        self.log("Stopping gluetun VPN container.")
        result = self.compose("stop", "gluetun", check=False)
        if self.container_running(["gluetun"]) or result.returncode != 0:
            container_id = self.service_container_id("gluetun")
            if container_id:
                self.runner.run(["docker", "stop", "-t", "5", container_id], check=False)
            if self.container_running(["gluetun"]):
                self.warn(
                    "FATAL: Gluetun VPN container could not be stopped. "
                    "Container may still be running in the background."
                )
                return
        self.success("Gluetun VPN container is stopped.")

    def restart_gluetun(self) -> None:
        self.log("Restarting gluetun service (best-effort candidate reselection).")
        env_override: dict[str, str] = {}
        if self._env_path.exists():
            from stremioguard.env import env_file_value
            from stremioguard.resolver import resolve_nordvpn_endpoint

            provider = env_file_value(self._env_path, "VPN_SERVICE_PROVIDER")
            explicit_hostname = env_file_value(self._env_path, "SERVER_HOSTNAMES")
            if provider == "nordvpn" and not explicit_hostname:
                country = env_file_value(self._env_path, "SERVER_COUNTRIES")
                city = env_file_value(self._env_path, "SERVER_CITIES")
                cache_path = self.config.root_dir / ".stremio" / "nordvpn-endpoint-cache.json"
                endpoint = resolve_nordvpn_endpoint(
                    country=country, city=city, cache_path=cache_path, force_refresh=True
                )
                if endpoint:
                    _, ip = endpoint
                    env_override["OPENVPN_ENDPOINT_IP"] = ip
                    env_override["WIREGUARD_ENDPOINT_IP"] = ip

        if env_override:
            self.compose("up", "-d", "--force-recreate", "gluetun", check=False, env=env_override)
        else:
            self.compose("restart", "gluetun", check=False)

    def restart_gluetun_relaxed(self) -> None:
        self.log("Restarting gluetun service with relaxed broad country pool.")
        env_override = {
            "SERVER_REGIONS": "",
            "SERVER_CITIES": "",
            "SERVER_HOSTNAMES": "",
            "SERVER_CATEGORIES": "",
            "OPENVPN_ENDPOINT_IP": "",
            "WIREGUARD_ENDPOINT_IP": "",
        }
        self.compose("up", "-d", "--force-recreate", "gluetun", check=False, env=env_override)
