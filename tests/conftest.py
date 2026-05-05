"""Shared test fixtures for the StremioGuard test suite."""

from __future__ import annotations

import subprocess
from pathlib import Path

from stremioguard.config import CometConfig, Config


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

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        key = tuple(args)
        response = self.responses.get(key)
        if isinstance(response, list):
            result = response.pop(0)
        elif response is not None:
            result = response
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
