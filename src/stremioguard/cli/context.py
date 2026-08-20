from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from stremioguard.comet import CometManager
from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager
from stremioguard.config import MANAGED_STACK_ENV, CometConfig

# Path resolution: src/stremioguard/cli/context.py
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
LOG_DIR = ROOT_DIR / "logs"
STATE_DIR = ROOT_DIR / ".stremio"
PID_FILE = STATE_DIR / "watchdog.pid"


def toolchain_cache_dir() -> Path:
    """Where `uv` should keep its cache for this invocation.

    The `./stremio` wrapper exports UV_CACHE_DIR, pointing a non-owner (sudo,
    a service account) at their own state directory so they never write into
    the repo owner's tree. Child processes re-derive the path in Python, so
    they have to honour the same variable — reading only ROOT_DIR here is
    what previously left a root-owned .uv-cache in the checkout.
    """
    override = os.environ.get("UV_CACHE_DIR")
    return Path(override) if override else ROOT_DIR / ".uv-cache"


UV_CACHE = toolchain_cache_dir()
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE = ROOT_DIR / ".env.example"


@dataclass(frozen=True)
class RunContext:
    run_id: str
    log_file: Path

    @classmethod
    def create(cls) -> RunContext:
        run_id = os.environ.get("STREMIO_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = Path(os.environ.get("STREMIO_LOG_FILE", LOG_DIR / f"stremio-{run_id}.log"))
        return cls(run_id=run_id, log_file=log_file)

    def env(self, *, background: bool = False, file_logging: bool = True) -> dict[str, str]:
        env = os.environ.copy()
        env[MANAGED_STACK_ENV] = "1"
        env.setdefault("INSTALL_MISSING_DEPS", "1")
        env["STREMIO_RUN_ID"] = self.run_id
        if file_logging:
            env["STREMIO_LOG_FILE"] = str(self.log_file)
            env["STREMIO_LOG_SESSION"] = "1"
        else:
            env.pop("STREMIO_LOG_FILE", None)
            env["STREMIO_LOG_SESSION"] = "0"
        if background:
            env["STREMIO_BACKGROUND"] = "1"

        if ENV_FILE.exists():
            from stremioguard.env import env_file_value
            from stremioguard.resolver import resolve_nordvpn_endpoint

            provider = env_file_value(ENV_FILE, "VPN_SERVICE_PROVIDER")
            explicit_hostname = env_file_value(ENV_FILE, "SERVER_HOSTNAMES")
            if provider == "nordvpn" and not explicit_hostname:
                country = env_file_value(ENV_FILE, "SERVER_COUNTRIES")
                city = env_file_value(ENV_FILE, "SERVER_CITIES")
                cache_path = STATE_DIR / "nordvpn-endpoint-cache.json"
                endpoint = resolve_nordvpn_endpoint(
                    country=country, city=city, cache_path=cache_path
                )
                if endpoint:
                    _, ip = endpoint
                    env.setdefault("OPENVPN_ENDPOINT_IP", ip)
                    env.setdefault("WIREGUARD_ENDPOINT_IP", ip)

        return env


def _comet_manager() -> CometManager:
    return CometManager(CometConfig.from_env(ROOT_DIR))


def _comet_enabled() -> bool:
    return CometConfig.from_env(ROOT_DIR).enabled


def _comet_gateway_manager() -> CometGatewayManager:
    return CometGatewayManager(CometGatewayConfig.from_env(ROOT_DIR))
