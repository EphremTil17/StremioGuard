"""Shared test fixtures for the StremioGuard test suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from stremioguard.comet_gateway import CometGatewayConfig
from stremioguard.config import CometConfig, Config

# Deployment paths that modules bind at import time (`from ...context import
# ROOT_DIR`), so patching the defining module alone would not reach them.
_SANDBOXED_PATHS = {
    "ROOT_DIR": lambda root: root,
    "ENV_FILE": lambda root: root / ".env",
    "STATE_DIR": lambda root: root / ".stremio",
    "LOG_DIR": lambda root: root / "logs",
    "UV_CACHE": lambda root: root / ".uv-cache",
    "PID_FILE": lambda root: root / ".stremio" / "watchdog.pid",
    "LOCK_FILE": lambda root: root / ".stremio" / "watchdog.lock",
}


@pytest.fixture(autouse=True)
def sandbox_deployment_paths(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point every module-level deployment path at a throwaway root.

    The test suite must never touch the real deployment: on a hardened
    install `.env` and `.stremio/` are root-owned, so reaching them raises
    PermissionError, and on a permissive one a test could mutate live
    credentials or state. Rebinding the constants in every already-imported
    stremioguard module keeps that structural rather than something each new
    test has to remember.
    """
    root = tmp_path_factory.mktemp("deployment")
    (root / ".stremio").mkdir()
    for module in list(sys.modules.values()):
        if not getattr(module, "__name__", "").startswith("stremioguard"):
            continue
        for attribute, build in _SANDBOXED_PATHS.items():
            if isinstance(getattr(module, attribute, None), Path):
                monkeypatch.setattr(module, attribute, build(root))
    return root


class FakeRunner:
    def __init__(
        self,
        responses: dict[
            tuple[str, ...],
            list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
        ],
    ) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []
        self.envs: list[dict[str, str] | None] = []

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        self.envs.append(env)
        key = tuple(args)
        response = self.responses.get(key)
        if isinstance(response, list):
            result = response.pop(0)
        elif response is not None:
            result = response
        else:
            if len(args) >= 3 and args[-3:] == ["ps", "-q", args[-1]]:
                result = subprocess.CompletedProcess(args, 0, f"{args[-1]}\n", "")
            elif len(args) >= 4 and args[:4] == ["docker", "inspect", "-f", "{{.State.Running}}"]:
                result = subprocess.CompletedProcess(args, 0, "true\n", "")
            else:
                result = subprocess.CompletedProcess(args, 0, "", "")

        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, args, result.stdout, result.stderr
            )
        return result


def completed(
    args: list[str],
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


def make_config(tmp_path: Path, **overrides: object) -> Config:
    state_dir = tmp_path / ".stremio"
    state_dir.mkdir(parents=True, exist_ok=True)
    # A configured deployment has already published its override, and compose
    # commands only pass `-f` for a file that exists (a missing one is a hard
    # docker error). Create it so command assertions match a real stack.
    (state_dir / "docker-compose.bindings.yml").touch()
    values: dict[str, object] = {
        "root_dir": tmp_path,
        "compose_file": tmp_path / "docker-compose.yml",
        "compose_override_file": tmp_path / ".stremio" / "docker-compose.bindings.yml",
        "service_name": "stremio",
        "container_name": "stremio-server",
        "gluetun_container_name": "gluetun",
        "gluetun_healthy_timeout_seconds": 1,
        "watch_interval_seconds": 1,
        "watchdog_log_interval_seconds": 300,
        "public_ip_timeout_seconds": 1,
        "home_ip_file": state_dir / "home-ip",
        "expected_vpn_ip": None,
        "ip_check_urls": ("https://example.test/ip",),
        "install_missing": False,
        "run_id": "test-run",
        "log_file": None,
        "log_session": True,
        "stremio_enabled": True,
        "ip_crosscheck_interval_seconds": 300,
        "public_ip_failure_threshold": 3,
        "vpn_recovery_budget_seconds": 300,
        "vpn_restart_cadence_seconds": 45,
        "vpn_lockout_file": state_dir / "vpn-lockout",
        "server_countries": None,
        "server_regions": None,
        "server_cities": None,
        "server_hostnames": None,
        "server_categories": None,
    }
    values.update(overrides)
    return Config(**values)  # type: ignore[arg-type]


def compose_args_prefix(tmp_path: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(tmp_path / "docker-compose.yml"),
        "-f",
        str(tmp_path / ".stremio" / "docker-compose.bindings.yml"),
    ]


def make_comet_config(tmp_path: Path, **overrides: object) -> CometConfig:
    state_dir = tmp_path / ".stremio" / "comet"
    state_dir.mkdir(parents=True, exist_ok=True)
    values: dict[str, object] = {
        "root_dir": tmp_path,
        "env_file": tmp_path / ".env",
        "vendor_dir": tmp_path / "vendor",
        "lock_file": tmp_path / "vendor" / "comet.lock.json",
        "repo_dir": tmp_path / "vendor" / "comet",
        "compose_source_file": tmp_path / "vendor" / "comet" / "deployment" / "docker-compose.yml",
        "state_dir": state_dir,
        "runtime_env_file": state_dir / ".env",
        "data_dir": state_dir / "data",
        "postgres_data_dir": state_dir / "postgres-data",
        "service_name": "comet",
        "postgres_service_name": "comet-postgres",
        "container_name": "comet",
        "postgres_container_name": "comet-postgres",
        "host_port": 18000,
        "bind_addresses": ("127.0.0.1",),
        "public_base_url": None,
        "proxy_debrid_stream": True,
        "proxy_max_connections": -1,
        "healthcheck_interval_seconds": 300,
        "configure_page_password": "cfg-password",
        "scrape_torrentio": "live",
        "torrentio_url": "https://torrentio.strem.fun",
        "scrape_zilean": "live",
        "zilean_url": "https://zileanfortheweebs.midnightignite.me",
        "result_format_style": "plain",
        "patch_episode_pack_results": True,
        "default_debrid_service": "realdebrid",
        "default_debrid_apikey": "rd-key",
        "enabled": True,
    }
    values.update(overrides)
    return CometConfig(**values)  # type: ignore[arg-type]


def make_comet_gateway_config(tmp_path: Path, **overrides: object) -> CometGatewayConfig:
    state_dir = tmp_path / ".stremio" / "comet-gateway"
    state_dir.mkdir(parents=True, exist_ok=True)
    values: dict[str, object] = {
        "root_dir": tmp_path,
        "env_file": tmp_path / ".env",
        "state_dir": state_dir,
        "tokens_file": state_dir / "tokens.json",
        "nginx_conf_file": state_dir / "nginx.conf",
        "tokens_map_file": state_dir / "tokens.map",
        "service_name": "comet-gateway",
        "container_name": "comet-gateway",
        "host_port": 18001,
        "bind_addresses": ("127.0.0.1",),
        "public_base_url": "https://comet.example.com",
        "token_length": 8,
        "enabled": True,
    }
    values.update(overrides)
    return CometGatewayConfig(**values)  # type: ignore[arg-type]


def write_minimal_bundle_manifest(comet_config: CometConfig) -> None:
    """Satisfy StackPublisher's fail-closed manifest check in orchestration tests."""
    import json

    comet_config.state_dir.mkdir(parents=True, exist_ok=True)
    (comet_config.state_dir / "bundle-manifest.json").write_text(
        json.dumps(
            {
                "outputs": {
                    "stream.py": "/app/comet/api/endpoints/stream.py",
                    "media_search.py": "/app/comet/services/media_search.py",
                    "config.py": "/app/comet/api/endpoints/config.py",
                    "index.html": "/app/comet/templates/index.html",
                }
            }
        ),
        encoding="utf-8",
    )
