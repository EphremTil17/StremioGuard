from __future__ import annotations

import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from loguru import logger

from stremioguard.comet.lock import CometLock
from stremioguard.comet.probe import PlaybackProbeResult, probe_playback_url
from stremioguard.comet_gateway import (
    COMET_GATEWAY_CONTAINER_PORT,
    CometGatewayConfig,
    CometGatewayManager,
)
from stremioguard.config import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    DEFAULT_STREMIO_HOST_PORT,
    GENERATED_COMPOSE_FILE,
    CometConfig,
    Runner,
    SubprocessRunner,
)
from stremioguard.env import env_file_value, env_flag_enabled
from stremioguard.overrides import write_override_bundle
from stremioguard.preflight import require_docker, verify_bind_addresses
from stremioguard.publishing import render_stack_compose_override


class CometManager:
    def __init__(self, config: CometConfig, runner: Runner | None = None) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()

    def log(self, message: str) -> None:
        logger.info(message)

    def warn(self, message: str) -> None:
        logger.warning(message)

    def success(self, message: str) -> None:
        logger.success(message)

    def load_lock(self) -> CometLock:
        return CometLock.load(self.config.lock_file)

    def repo_exists(self) -> bool:
        return (self.config.repo_dir / ".git").exists()

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.runner.run(["git", *args], check=check)

    def clone_if_missing(self) -> None:
        if self.repo_exists():
            return
        lock = self.load_lock()
        self.config.vendor_dir.mkdir(parents=True, exist_ok=True)
        self.log(f"Cloning Comet into {self.config.repo_dir}.")
        self._git("clone", lock.upstream_url, str(self.config.repo_dir))

    def fetch_and_checkout_pinned(self) -> None:
        lock = self.load_lock()
        self.clone_if_missing()

        dirty = self._git("-C", str(self.config.repo_dir), "status", "--porcelain", check=False)
        if (dirty.stdout or "").strip():
            self.warn(
                f"Comet checkout at {self.config.repo_dir} has local changes. "
                "Leaving them in place, but switching commits may fail."
            )

        self.log("Fetching latest upstream refs for Comet.")
        self._git("-C", str(self.config.repo_dir), "fetch", "origin")
        self.log(f"Checking out pinned Comet commit {lock.pinned_commit}.")
        self._git("-C", str(self.config.repo_dir), "checkout", "--detach", lock.pinned_commit)

    def current_commit(self) -> str | None:
        if not self.repo_exists():
            return None
        result = self._git("-C", str(self.config.repo_dir), "rev-parse", "HEAD", check=False)
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def stremio_host_port(self) -> int:
        raw = env_file_value(self.config.env_file, "STREMIO_HOST_PORT")
        if raw in {None, ""}:
            return DEFAULT_STREMIO_HOST_PORT
        assert raw is not None
        return int(raw)

    def stremio_container_port(self) -> int:
        raw = env_file_value(self.config.env_file, "STREMIO_CONTAINER_PORT")
        if raw in {None, ""}:
            return DEFAULT_STREMIO_CONTAINER_PORT
        assert raw is not None
        return int(raw)

    def root_compose_file(self) -> Path:
        return self.config.root_dir / "docker-compose.yml"

    def root_override_file(self) -> Path:
        return self.config.root_dir / GENERATED_COMPOSE_FILE

    def gateway_config(self) -> CometGatewayConfig:
        return CometGatewayConfig.from_env(self.config.root_dir)

    def gateway_manager(self) -> CometGatewayManager:
        return CometGatewayManager(self.gateway_config(), self.runner)

    def gateway_addon_base_url(self) -> str | None:
        gateway_config = self.gateway_config()
        if not gateway_config.enabled:
            return None
        gateway_manager = self.gateway_manager()
        default_token = gateway_manager.default_token()
        if not default_token:
            return None
        if not gateway_config.public_base_url:
            return f"/comet/{default_token}"
        return gateway_manager.addon_base_url(default_token)

    def write_stack_override_file(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.postgres_data_dir.mkdir(parents=True, exist_ok=True)
        gateway_config = self.gateway_config()
        gateway_manager = CometGatewayManager(gateway_config, self.runner)
        if gateway_config.enabled:
            gateway_manager.prepare_runtime()
        write_override_bundle(
            repo_dir=self.config.repo_dir,
            state_dir=self.config.state_dir,
            result_format_style=self.config.result_format_style,
            patch_episode_pack_results=self.config.patch_episode_pack_results,
            gateway_addon_base_url=self.gateway_addon_base_url(),
        )
        stremio_enabled = env_flag_enabled("STREMIO_ENABLED", True, env_path=self.config.env_file)
        content = render_stack_compose_override(
            bind_addresses=list(self.config.bind_addresses),
            stremio_host_port=self.stremio_host_port(),
            stremio_container_port=self.stremio_container_port(),
            stremio_enabled=stremio_enabled,
            comet_config=self.config,
            comet_gateway_config=gateway_config if gateway_config.enabled else None,
        )
        root_override = self.root_override_file()
        root_override.parent.mkdir(parents=True, exist_ok=True)
        root_override.write_text(content, encoding="utf-8")

    def render_runtime_env(self) -> str:
        existing = self.config.runtime_env_file if self.config.runtime_env_file.exists() else None
        admin_password = (
            env_file_value(existing, "ADMIN_DASHBOARD_PASSWORD") if existing else None
        ) or secrets.token_urlsafe(18)
        configure_password = (
            (env_file_value(existing, "CONFIGURE_PAGE_PASSWORD") if existing else None)
            or self.config.configure_page_password
            or secrets.token_urlsafe(18)
        )
        proxy_password = (
            env_file_value(existing, "PROXY_DEBRID_STREAM_PASSWORD") if existing else None
        ) or secrets.token_urlsafe(18)
        gateway_config = self.gateway_config()
        public_base_url = "" if gateway_config.enabled else self.config.public_base_url or ""
        api_key = self.config.default_debrid_apikey or ""
        return "\n".join(
            [
                "# Generated by ./stremio comet install; do not edit by hand.",
                "DATABASE_TYPE=postgresql",
                "DATABASE_URL=comet:comet@127.0.0.1:5432/comet",
                f"PUBLIC_BASE_URL={public_base_url}",
                f"ADMIN_DASHBOARD_PASSWORD={admin_password}",
                f"CONFIGURE_PAGE_PASSWORD={configure_password}",
                f"PROXY_DEBRID_STREAM={'True' if self.config.proxy_debrid_stream else 'False'}",
                f"PROXY_DEBRID_STREAM_PASSWORD={proxy_password}",
                f"PROXY_DEBRID_STREAM_MAX_CONNECTIONS={self.config.proxy_max_connections}",
                f"SCRAPE_TORRENTIO={self.config.scrape_torrentio}",
                f"TORRENTIO_URL={self.config.torrentio_url}",
                f"SCRAPE_ZILEAN={self.config.scrape_zilean}",
                f"ZILEAN_URL={self.config.zilean_url}",
                f"PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE={self.config.default_debrid_service}",
                f"PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY={api_key}",
                "",
            ]
        )

    def write_runtime_env(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.runtime_env_file.write_text(self.render_runtime_env(), encoding="utf-8")

    def require_commands(self) -> None:
        require_docker(
            self.runner,
            install_missing=False,
            log=self.log,
            warn=self.warn,
        )

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
        self, *args: str, check: bool = True, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.write_stack_override_file()
        return self.runner.run(self._compose_command(*args), check=check, capture=capture)

    def install(self) -> None:
        self.prepare_runtime()

    def prepare_runtime(self) -> None:
        self.fetch_and_checkout_pinned()
        self.write_runtime_env()
        self.write_stack_override_file()

    def check_bind_addresses(self) -> None:
        verify_bind_addresses(
            self.runner,
            list(self.config.bind_addresses),
            log=self.log,
            warn=self.warn,
        )

    def start(self) -> None:
        self.require_commands()
        self.prepare_runtime()
        self.check_bind_addresses()
        self.log("Starting Comet stack.")
        services = [self.config.postgres_service_name, self.config.service_name]
        gateway_config = self.gateway_config()
        if gateway_config.enabled:
            services.append(gateway_config.service_name)
        self.compose("up", "-d", *services, capture=False)

    def stop(self) -> None:
        self.require_commands()
        self.log("Stopping Comet stack.")
        services = []
        gateway_config = self.gateway_config()
        if gateway_config.enabled:
            services.append(gateway_config.service_name)
        services.extend([self.config.service_name, self.config.postgres_service_name])
        self.compose(
            "stop",
            *services,
            check=False,
            capture=False,
        )

    def status(self) -> None:
        current = self.current_commit()
        lock = self.load_lock()
        self.log(f"Vendored repo: {self.config.repo_dir}")
        self.log(f"Pinned commit: {lock.pinned_commit}")
        self.log(f"Current commit: {current or 'missing'}")
        if current and current != lock.pinned_commit:
            self.warn("Comet checkout is not on the pinned commit.")
        self.require_commands()
        gateway_config = self.gateway_config()
        services = [self.config.service_name, self.config.postgres_service_name]
        if gateway_config.enabled:
            services.append(gateway_config.service_name)
        result = self.compose(
            "ps",
            *services,
            check=False,
        )
        self.log((result.stdout or "").rstrip() or "No Comet compose output available.")
        network_mode = self.network_mode()
        self.log(
            "Network mode: "
            f"{network_mode or 'unknown'} (expected to share gluetun namespace when enabled)"
        )
        health = self.healthcheck()
        self.log(
            f"HTTP health: {'ok' if health else 'unreachable'} "
            "(checked from inside the Comet container)"
        )

    def healthcheck(self) -> bool:
        if not self.container_health_status():
            return False
        url = "http://127.0.0.1:8000/health"
        result = self.runner.run(
            [
                "docker",
                "exec",
                self.config.container_name,
                "wget",
                "-qO-",
                url,
            ],
            check=False,
            timeout=5,
        )
        if result.returncode != 0:
            return False
        body = (result.stdout or "").replace(" ", "")
        return '{"status":"ok"}' in body

    def container_health_status(self) -> str | None:
        result = self.runner.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                self.config.container_name,
            ],
            check=False,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def public_ip(self, container_name: str) -> str | None:
        for url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
            result = self.runner.run(
                ["docker", "exec", container_name, "wget", "-qO-", url],
                check=False,
                timeout=10,
            )
            if result.returncode == 0:
                return (result.stdout or "").strip() or None
        return None

    def gluetun_container_id(self) -> str | None:
        result = self.runner.run(
            ["docker", "inspect", "-f", "{{.Id}}", "gluetun"],
            check=False,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def network_mode(self) -> str | None:
        result = self.runner.run(
            ["docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", self.config.container_name],
            check=False,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or "").strip() or None

    def host_healthcheck(self) -> bool:
        url = f"{self.base_url_for_checks()}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read(128).decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, TimeoutError):
            return False
        return response.status == 200 and '"status":"ok"' in body.replace(" ", "")

    def base_url_for_checks(self) -> str:
        if self.gateway_config().enabled:
            return f"http://127.0.0.1:{self.config.host_port}"
        address = self.config.bind_addresses[0] if self.config.bind_addresses else "127.0.0.1"
        host = "127.0.0.1" if address == "0.0.0.0" else address
        return f"http://{host}:{self.config.host_port}"

    def doctor(self) -> None:
        lock = self.load_lock()
        if not self.repo_exists():
            raise RuntimeError("Comet repo is not installed. Run `./stremio comet install` first.")
        current = self.current_commit()
        if current != lock.pinned_commit:
            raise RuntimeError(
                "Vendored Comet checkout is at "
                f"{current or 'unknown'}, expected {lock.pinned_commit}."
            )
        self.require_commands()
        if not self.healthcheck():
            raise RuntimeError(
                "Comet health endpoint is not healthy from inside the container "
                f"({self.config.container_name} -> 127.0.0.1:8000/health)."
            )
        if not self.host_healthcheck():
            self.warn(
                "Host-side /health probe did not respond at "
                f"{self.base_url_for_checks()}/health. This can happen on WSL or "
                "multi-interface hosts even when container health is fine."
            )
        gateway_config = self.gateway_config()
        comet_is_gateway_gated = gateway_config.enabled
        port_output = self.compose("ps", "gluetun", check=False).stdout or ""
        if comet_is_gateway_gated:
            for address in self.config.bind_addresses:
                raw_comet_publish = f"{address}:{self.config.host_port}->8000/tcp"
                if address != "127.0.0.1" and raw_comet_publish in port_output:
                    raise RuntimeError(
                        "Comet gateway is enabled but Comet's raw host port is still "
                        f"published on {address}."
                    )
                expected_gateway = (
                    f"{address}:{gateway_config.host_port}->{COMET_GATEWAY_CONTAINER_PORT}/tcp"
                )
                if expected_gateway not in port_output:
                    raise RuntimeError(
                        "Comet gateway port publishing does not include expected mapping "
                        f"{expected_gateway!r}."
                    )
            if f"127.0.0.1:{self.config.host_port}->8000/tcp" not in port_output:
                raise RuntimeError(
                    "Comet gateway is enabled but raw Comet is not available on loopback "
                    "for local operator diagnostics."
                )
        else:
            for address in self.config.bind_addresses:
                expected = f"{address}:{self.config.host_port}->8000/tcp"
                if address == "0.0.0.0":
                    expected = f"0.0.0.0:{self.config.host_port}->8000/tcp"
                if expected not in port_output:
                    raise RuntimeError(
                        f"Comet port publishing does not include expected mapping {expected!r}."
                    )
        runtime_env = self.config.runtime_env_file
        proxy_setting = (env_file_value(runtime_env, "PROXY_DEBRID_STREAM") or "").strip().lower()
        if proxy_setting not in {"true", "1", "yes", "on"}:
            raise RuntimeError("Comet runtime env does not enable PROXY_DEBRID_STREAM.")
        if not env_file_value(runtime_env, "CONFIGURE_PAGE_PASSWORD"):
            raise RuntimeError("Comet runtime env is missing CONFIGURE_PAGE_PASSWORD.")
        if "0.0.0.0:" in port_output and "0.0.0.0" not in self.config.bind_addresses:
            raise RuntimeError("Comet appears to be exposed on all interfaces unexpectedly.")
        gluetun_id = self.gluetun_container_id()
        network_mode = self.network_mode()
        if not gluetun_id or network_mode != f"container:{gluetun_id}":
            raise RuntimeError(
                "Comet is not sharing gluetun's network namespace "
                f"(observed network mode: {network_mode or 'unknown'})."
            )
        gluetun_ip = self.public_ip("gluetun")
        comet_ip = self.public_ip(self.config.container_name)
        if not gluetun_ip or not comet_ip:
            raise RuntimeError("Could not compare Comet and gluetun public egress IPs.")
        if gluetun_ip != comet_ip:
            raise RuntimeError(
                f"Comet public IP {comet_ip} does not match gluetun public IP {gluetun_ip}."
            )
        self.success("Comet doctor checks passed.")

    def probe_playback(self, url: str, *, expect_proxy: bool = True) -> PlaybackProbeResult:
        result = probe_playback_url(url)
        if expect_proxy and result.classification != "proxied":
            raise RuntimeError(
                f"Expected proxied playback but observed {result.classification}"
                + (f" -> {result.location}" if result.location else "")
            )
        if not expect_proxy and result.classification != "redirected":
            raise RuntimeError(f"Expected redirected playback but observed {result.classification}")
        return result
