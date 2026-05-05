"""Comet repo management, compose lifecycle, and playback validation."""

from __future__ import annotations

import json
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import typer
from loguru import logger

from stremioguard.comet_overrides import (
    render_formatter_override as render_formatter_override_file,
)
from stremioguard.comet_overrides import (
    render_stream_override as render_stream_override_file,
)
from stremioguard.comet_overrides import (
    render_torrentio_override as render_torrentio_override_file,
)
from stremioguard.comet_overrides import (
    write_override_bundle,
)
from stremioguard.config import (
    DEFAULT_STREMIO_CONTAINER_PORT,
    DEFAULT_STREMIO_HOST_PORT,
    GENERATED_COMPOSE_FILE,
    CometConfig,
    Runner,
    SubprocessRunner,
)
from stremioguard.env import env_file_value, fail, write_env_setting
from stremioguard.preflight import require_docker, verify_bind_addresses
from stremioguard.publishing import render_stack_compose_override

SUPPORTED_DEBRID_PROVIDERS = (
    "realdebrid",
    "torbox",
    "alldebrid",
    "premiumize",
    "debridlink",
    "easydebrid",
    "offcloud",
    "pikpak",
)


@dataclass(frozen=True)
class CometLock:
    upstream_url: str
    pinned_commit: str
    default_branch: str

    @classmethod
    def load(cls, path: Path) -> CometLock:
        if not path.exists():
            raise RuntimeError(f"Comet lock file missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            upstream_url=data["upstream_url"],
            pinned_commit=data["pinned_commit"],
            default_branch=data["default_branch"],
        )


@dataclass(frozen=True)
class PlaybackProbeResult:
    status_code: int
    classification: str
    location: str | None
    content_type: str | None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


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

    def formatter_override_file(self) -> Path:
        return self.config.state_dir / "formatting.py"

    def stream_override_file(self) -> Path:
        return self.config.state_dir / "stream.py"

    def torrentio_override_file(self) -> Path:
        return self.config.state_dir / "torrentio.py"

    def render_formatter_override(self) -> str | None:
        return render_formatter_override_file(self.config.repo_dir, self.config.result_format_style)

    def write_formatter_override_file(self) -> Path | None:
        rendered = self.render_formatter_override()
        target = self.formatter_override_file()
        if rendered is None:
            if target.exists():
                target.unlink()
            return None
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        return target

    def render_stream_override(self) -> str:
        return render_stream_override_file(self.config.repo_dir)

    def render_torrentio_override(self) -> str:
        return render_torrentio_override_file(self.config.repo_dir)

    def write_stream_override_file(self) -> Path:
        rendered = self.render_stream_override()
        target = self.stream_override_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        return target

    def write_torrentio_override_file(self) -> Path:
        rendered = self.render_torrentio_override()
        target = self.torrentio_override_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        return target

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

    def write_stack_override_file(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.postgres_data_dir.mkdir(parents=True, exist_ok=True)
        write_override_bundle(
            repo_dir=self.config.repo_dir,
            state_dir=self.config.state_dir,
            result_format_style=self.config.result_format_style,
            patch_episode_pack_results=self.config.patch_episode_pack_results,
        )
        content = render_stack_compose_override(
            bind_addresses=list(self.config.bind_addresses),
            stremio_host_port=self.stremio_host_port(),
            stremio_container_port=self.stremio_container_port(),
            comet_config=self.config,
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
        public_base_url = self.config.public_base_url or ""
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
        self.compose(
            "up",
            "-d",
            self.config.postgres_service_name,
            self.config.service_name,
            capture=False,
        )

    def stop(self) -> None:
        self.require_commands()
        self.log("Stopping Comet stack.")
        self.compose(
            "stop",
            self.config.service_name,
            self.config.postgres_service_name,
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
        result = self.compose(
            "ps",
            self.config.service_name,
            self.config.postgres_service_name,
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
        port_output = self.compose("ps", "gluetun", check=False).stdout or ""
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


def probe_playback_url(url: str) -> PlaybackProbeResult:
    request = urllib.request.Request(
        url,
        headers={"Range": "bytes=0-0", "User-Agent": "stremioguard/1"},
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=10) as response:
            headers = dict(response.headers.items())
            classification = classify_playback_response(
                status_code=response.status,
                headers=headers,
                request_url=url,
            )
            return PlaybackProbeResult(
                status_code=response.status,
                classification=classification,
                location=headers.get("Location"),
                content_type=headers.get("Content-Type"),
            )
    except urllib.error.HTTPError as error:
        headers = dict(error.headers.items())
        classification = classify_playback_response(
            status_code=error.code,
            headers=headers,
            request_url=url,
        )
        return PlaybackProbeResult(
            status_code=error.code,
            classification=classification,
            location=headers.get("Location"),
            content_type=headers.get("Content-Type"),
        )


def classify_playback_response(
    *,
    status_code: int,
    headers: dict[str, str],
    request_url: str,
) -> str:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    location = normalized_headers.get("location")
    if location:
        request_host = urllib.parse.urlparse(request_url).netloc
        location_host = urllib.parse.urlparse(location).netloc
        if location_host and location_host != request_host:
            return "redirected"
        return "same-origin-redirect"
    if status_code in {200, 206}:
        if normalized_headers.get("accept-ranges") or normalized_headers.get("content-range"):
            return "proxied"
        content_type = normalized_headers.get("content-type", "")
        if content_type.startswith("video/") or content_type.startswith("application/octet-stream"):
            return "proxied"
    return "unexpected"


def prompt_comet_setup(config: CometConfig) -> None:
    if not config.env_file.exists():
        fail(f"{config.env_file} is missing. Run `./stremio init` first.")

    logger.info("Comet server-owned proxy setup:")
    host_port = typer.prompt("Comet host port", default=str(config.host_port)).strip()
    try:
        parsed_port = int(host_port)
    except ValueError:
        fail(f"COMET_HOST_PORT must be a TCP port number; got {host_port!r}.")
    if parsed_port < 1 or parsed_port > 65535:
        fail(f"COMET_HOST_PORT must be between 1 and 65535; got {parsed_port!r}.")
    write_env_setting(config.env_file, "COMET_ENABLED", "1")
    write_env_setting(config.env_file, "COMET_HOST_PORT", str(parsed_port))
    write_env_setting(config.env_file, "COMET_SCRAPE_TORRENTIO", config.scrape_torrentio)
    write_env_setting(config.env_file, "COMET_TORRENTIO_URL", config.torrentio_url)
    write_env_setting(config.env_file, "COMET_SCRAPE_ZILEAN", config.scrape_zilean)
    write_env_setting(config.env_file, "COMET_ZILEAN_URL", config.zilean_url)
    write_env_setting(config.env_file, "COMET_RESULT_FORMAT_STYLE", config.result_format_style)
    typer.echo("")
    typer.echo(
        "Optional compatibility patch: preserve more episode results from season packs "
        "when Comet consumes Torrentio/Zilean-style scraper results."
    )
    patch_episode_pack_results = typer.confirm(
        "Apply the Comet episode-pack result preservation patch?",
        default=config.patch_episode_pack_results,
    )
    write_env_setting(
        config.env_file,
        "COMET_PATCH_EPISODE_PACK_RESULTS",
        "1" if patch_episode_pack_results else "0",
    )

    typer.echo("")
    typer.echo(
        "Comet will inherit Stremio's bind addresses so both services publish on the "
        "same host interfaces."
    )

    typer.echo("")
    typer.echo("Protect the Comet configure page so other users cannot change settings.")
    configure_password = typer.prompt(
        "Configure page password",
        hide_input=True,
        confirmation_prompt=True,
        default=config.configure_page_password or secrets.token_urlsafe(12),
        show_default=False,
    ).strip()
    if not configure_password:
        fail("A configure page password is required for shared-domain Comet access.")
    write_env_setting(config.env_file, "COMET_CONFIGURE_PAGE_PASSWORD", configure_password)

    proxy_enabled = typer.confirm("Enable Comet debrid stream proxying?", default=True)
    write_env_setting(config.env_file, "COMET_PROXY_DEBRID_STREAM", "1" if proxy_enabled else "0")
    max_connections = typer.prompt(
        "Per-IP proxy max connections (-1 for unlimited)",
        default=str(config.proxy_max_connections),
    ).strip()
    try:
        parsed_max_connections = int(max_connections)
    except ValueError:
        fail(f"COMET_PROXY_MAX_CONNECTIONS must be an integer; got {max_connections!r}.")
    if parsed_max_connections < -1 or parsed_max_connections == 0:
        fail(
            "COMET_PROXY_MAX_CONNECTIONS must be -1 for unlimited or a positive integer; "
            f"got {parsed_max_connections!r}."
        )
    write_env_setting(
        config.env_file,
        "COMET_PROXY_MAX_CONNECTIONS",
        str(parsed_max_connections),
    )
    typer.echo("")
    typer.echo(
        "Optional: configure one server-owned fallback debrid account. Leave this disabled "
        "if you plan to do all debrid setup in Comet's configure page before distributing "
        "the finished addon or Stremio account."
    )
    use_server_defaults = typer.confirm(
        "Set server-owned fallback debrid credentials now?",
        default=False,
    )
    if use_server_defaults:
        default_service = _prompt_debrid_provider(config.default_debrid_service)
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_SERVICE", default_service)
        api_key = typer.prompt("Default debrid API key", hide_input=True).strip()
        if not api_key:
            fail("A debrid API key is required when server-owned fallback credentials are enabled.")
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_APIKEY", api_key)
    else:
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_SERVICE", "realdebrid")
        write_env_setting(config.env_file, "COMET_DEFAULT_DEBRID_APIKEY", "")


def _prompt_debrid_provider(default: str) -> str:
    normalized_default = default if default in SUPPORTED_DEBRID_PROVIDERS else "realdebrid"
    default_choice = str(SUPPORTED_DEBRID_PROVIDERS.index(normalized_default) + 1)
    typer.echo("Choose the fallback debrid provider:")
    for index, provider in enumerate(SUPPORTED_DEBRID_PROVIDERS, start=1):
        typer.echo(f"  {index}) {provider}")
    choice = typer.prompt("Provider", default=default_choice).strip().lower()
    if choice.isdigit():
        selected_index = int(choice) - 1
        if 0 <= selected_index < len(SUPPORTED_DEBRID_PROVIDERS):
            return SUPPORTED_DEBRID_PROVIDERS[selected_index]
    if choice in SUPPORTED_DEBRID_PROVIDERS:
        return choice
    fail(f"Unsupported debrid provider choice: {choice!r}.")
