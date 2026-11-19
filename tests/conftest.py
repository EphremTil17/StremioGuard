"""Shared test fixtures for the StremioGuard test suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from stremioguard.comet_gateway import CometGatewayConfig
from stremioguard.config import CometConfig, Config

# Well-known public anycast DNS resolver addresses for tests (D3).
PUBLIC_IPV4_HOST = "1.1.1.1"
PUBLIC_IPV4_EGRESS = "8.8.8.8"
PUBLIC_IPV4_ALT = "9.9.9.9"
PUBLIC_IPV4_SNAPSHOT = "8.8.4.4"
PUBLIC_IPV4_STATION = "1.0.0.1"
PUBLIC_IPV6_HOST = "2606:4700:4700::1111"
PUBLIC_IPV6_EGRESS = "2001:4860:4860::8888"

# Deployment paths that modules bind at import time (`from ...context import
# ROOT_DIR`), so patching the defining module alone would not reach them.
_SANDBOXED_PATHS = {
    "ROOT_DIR": lambda root: root,
    "ENV_FILE": lambda root: root / ".env",
    "STATE_DIR": lambda root: root / ".stremio",
    "LOG_DIR": lambda root: root / "logs",
    "UV_CACHE": lambda root: root / ".uv-cache",
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


@pytest.fixture(autouse=True)
def isolate_user_systemd(sandbox_deployment_paths: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep tests away from the real user service manager and unit directory.

    A test that forgets to stub systemctl fails loudly instead of rewriting or
    stopping the live watchdog unit.
    """
    from stremioguard.cli import supervisor

    def refuse(*args: str) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"unstubbed systemctl --user {' '.join(args)}")

    units = sandbox_deployment_paths / "systemd-user"
    monkeypatch.setattr(supervisor, "_systemctl", refuse)
    monkeypatch.setattr(supervisor, "unit_dir", lambda: units)
    return units


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
        self.timeouts: list[float | None] = []
        self.inputs: list[str | None] = []

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
        self.calls.append(args)
        self.envs.append(env)
        self.timeouts.append(timeout)
        self.inputs.append(input)
        key = tuple(args)
        response = self.responses.get(key)
        if isinstance(response, list):
            result = response.pop(0)
        elif response is not None:
            result = response
        else:
            result = subprocess.CompletedProcess(
                args, 1, "", f"unstubbed command: {' '.join(args)}"
            )

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
        "egress_probe_interval_seconds": 300,
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


# `ps --status` flags of the stop paths (see guard.ACTIVE_STATES).
ACTIVE_STATUS_ARGS = (
    "--status",
    "running",
    "--status",
    "restarting",
    "--status",
    "paused",
    "--status",
    "removing",
)


def seal_generation(root: Path) -> None:
    """Write the generation manifest for files a test created by hand (what publish does last)."""
    from stremioguard.config import PUBLISHED_GENERATION_FILE, render_generation_manifest

    (root / PUBLISHED_GENERATION_FILE).write_text(
        render_generation_manifest(root), encoding="utf-8"
    )


def compose_args_prefix(tmp_path: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(tmp_path / "docker-compose.yml"),
        "-f",
        str(tmp_path / ".stremio" / "docker-compose.bindings.yml"),
    ]


def compose_stack_responses(
    tmp_path: Path,
    *,
    containers: tuple[str, ...] = ("gluetun",),
    running: tuple[str, ...] = (),
    running_query_services: tuple[str, ...] | None = None,
    compose_services: tuple[str, ...] | None = None,
) -> dict[
    tuple[str, ...],
    list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
]:
    """Build explicit Docker/Compose stubs so tests opt in to fake running state."""
    from stremioguard.config import compose_command

    responses: dict[
        tuple[str, ...],
        list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
    ] = {}
    prefixes: tuple[list[str], ...] = (
        compose_command(tmp_path),
        compose_args_prefix(tmp_path),
    )
    for prefix in prefixes:
        for service in containers:
            ps_cmd = [*prefix, "ps", "-q", service]
            responses[tuple(ps_cmd)] = completed(ps_cmd, f"{service}\n")
        if compose_services is not None:
            cfg_cmd = [*prefix, "config", "--services"]
            responses[tuple(cfg_cmd)] = completed(cfg_cmd, "\n".join(compose_services) + "\n")
        query_targets = running_query_services if running_query_services is not None else running
        if query_targets:
            for status_args in (("--status", "running"), ACTIVE_STATUS_ARGS):
                status_cmd = [*prefix, "ps", *status_args, "--services", *query_targets]
                responses[tuple(status_cmd)] = completed(
                    status_cmd, "\n".join(s for s in query_targets if s in running) + "\n"
                )
    for service in containers:
        if service in running:
            responses[("docker", "inspect", "-f", "{{.State.Running}}", service)] = completed(
                ["docker", "inspect", "-f", "{{.State.Running}}", service], "true\n"
            )
    return responses


def make_comet_config(tmp_path: Path, **overrides: object) -> CometConfig:
    state_dir = tmp_path / ".stremio" / "comet"
    state_dir.mkdir(parents=True, exist_ok=True)
    values: dict[str, object] = {
        "root_dir": tmp_path,
        "env_file": tmp_path / ".env",
        "vendor_dir": tmp_path / "vendor",
        "lock_file": tmp_path / "vendor" / "comet.lock.json",
        "repo_dir": tmp_path / "vendor" / "comet",
        "state_dir": state_dir,
        "runtime_env_file": state_dir / ".env",
        "data_dir": state_dir / "data",
        "postgres_data_dir": state_dir / "postgres-data",
        "service_name": "comet",
        "postgres_service_name": "comet-postgres",
        "container_name": "comet",
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
        # Most gateway tests cover the full route set; tests of the default
        # (configure page not served) pass public_configure=False.
        "public_configure": True,
    }
    values.update(overrides)
    return CometGatewayConfig(**values)  # type: ignore[arg-type]


TEST_COMET_DIGEST = "sha256:" + "a" * 64


def record_test_digest(state_dir: Path) -> None:
    """A bootstrapped deployment: the publisher refuses to render without one."""
    from stremioguard.comet.state import STATE_FILE_NAME, CometState

    state_dir.mkdir(parents=True, exist_ok=True)
    CometState(active_digest=TEST_COMET_DIGEST).save(state_dir / STATE_FILE_NAME)


MINIMAL_BUNDLE_OUTPUTS = {
    "app.py": "/app/comet/api/app.py",
    "stremioguard_response_guard.py": "/app/comet/stremioguard_response_guard.py",
    "logger.py": "/app/comet/core/logger.py",
    "stream.py": "/app/comet/api/endpoints/stream.py",
    "media_search.py": "/app/comet/services/media_search.py",
    "config.py": "/app/comet/api/endpoints/config.py",
    "index.html": "/app/comet/templates/index.html",
    "stremioguard_stream_guard.py": "/app/comet/stremioguard_stream_guard.py",
    "playback.py": "/app/comet/api/endpoints/playback.py",
    "config_validation.py": "/app/comet/core/config_validation.py",
    "admin.py": "/app/comet/api/endpoints/admin.py",
}


def write_bundle(
    comet_config: CometConfig,
    digest: str = TEST_COMET_DIGEST,
    *,
    outputs: dict[str, str] | None = None,
    manifest_digest: str | None = None,
    create_files: bool = True,
    extra: dict[str, object] | None = None,
) -> Path:
    """Write a per-digest override bundle: its manifest and the listed files.

    ``manifest_digest`` overrides the recorded ``active_digest`` (to build a
    bundle that claims another image); ``create_files=False`` leaves the
    listed outputs absent on disk.
    """
    import json

    bundle_dir = comet_config.bundle_dir(digest)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    outputs = dict(MINIMAL_BUNDLE_OUTPUTS if outputs is None else outputs)
    if create_files:
        for name in outputs:
            (bundle_dir / name).write_text(f"# patched {name}\n", encoding="utf-8")
    manifest: dict[str, object] = {
        "active_digest": digest if manifest_digest is None else manifest_digest,
        "outputs": outputs,
        **(extra or {}),
    }
    (bundle_dir / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def write_minimal_bundle_manifest(comet_config: CometConfig) -> Path:
    """Satisfy StackPublisher's fail-closed manifest and digest-pin checks.

    Records TEST_COMET_DIGEST as active and writes a complete bundle for it
    in ``comet_config.bundle_dir(TEST_COMET_DIGEST)``.
    """
    record_test_digest(comet_config.state_dir)
    return write_bundle(comet_config)


# Current upstream shape of comet/api/app.py's request logger (the parts the
# api_app override touches).
COMET_API_APP_SOURCE = """\
from loguru import logger

Request = object  # upstream: from fastapi import Request

STREMIO_API_PREFIX = "/s/secret-token"


CORSMiddleware = object  # upstream: from fastapi.middleware.cors import CORSMiddleware


class FastAPI:
    def __init__(self, *args, **kwargs):
        self.user_middleware = []

    def add_middleware(self, cls, **kwargs):
        self.user_middleware.insert(0, (cls, kwargs))


def _metrics_route(request: Request) -> str:
    route = getattr(request.scope.get("route"), "path", "unmatched")
    if STREMIO_API_PREFIX and route.startswith(STREMIO_API_PREFIX):
        return route.replace(STREMIO_API_PREFIX, "/s/{token}", 1)
    return route


async def dispatch(request, method, status_code, process_time):
    logger.log(
        "API",
        f"{method} {request.url.path} - {status_code} - {process_time:.2f}s",
    )


app = FastAPI(title="Comet")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
"""


# Upstream's two scraper log lines, built in pieces (each is one long line upstream).
_TIMEOUT_LINE = (
    'f"Timeout while getting torrents for {media_id} with {scraper_name} '
    '({censor_url(scraper_url)})"'
)
_EXCEPTION_LINE = (
    'f"Exception while getting torrents for {media_id} with {scraper_name} '
    "({censor_url(scraper_url)}), you are most likely being "
    'ratelimited{api_password_missing}: {error}"'
)


# The upstream shape of the masking sites the logger override patches.
COMET_LOGGER_SOURCE = """\
import sys

from comet.utils.parsing import associate_urls_credentials


def handlers():
    return [
            {
                "sink": sys.stderr,
            }
    ]


def add_capture(logger, loguru_handler):
    logger.add(
    loguru_handler.write,
    )


def log_scraper_error(scraper_name, scraper_url, media_id, error):
    if "timeout" in str(error):
        return @@TIMEOUT_LINE@@
    return @@EXCEPTION_LINE@@


def censor(text: str):
    if not text:
        return ""
    half = len(text) // 2
    return text[:half] + "*" * (len(text) - half)


def censor_url(url: str):
    if not url:
        return url
    if "://" in url:
        try:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                auth, host = rest.split("@", 1)
                if ":" in auth:
                    user, password = auth.split(":", 1)
                    return f"{scheme}://{user}:{censor(password)}@{host}"
        except Exception:
            pass
    return url


def preview(token_value):
    return f"{token_value[:6]}...{token_value[-4:]}"
""".replace("@@TIMEOUT_LINE@@", _TIMEOUT_LINE).replace("@@EXCEPTION_LINE@@", _EXCEPTION_LINE)

# Manifest outputs every bundle must carry, whatever the deployment shape.
REQUIRED_PATCH_OUTPUTS = {
    "app.py": "/app/comet/api/app.py",
    "stremioguard_response_guard.py": "/app/comet/stremioguard_response_guard.py",
    "logger.py": "/app/comet/core/logger.py",
    "stream.py": "/app/comet/api/endpoints/stream.py",
    "stremioguard_stream_guard.py": "/app/comet/stremioguard_stream_guard.py",
    "playback.py": "/app/comet/api/endpoints/playback.py",
    "config_validation.py": "/app/comet/core/config_validation.py",
    "admin.py": "/app/comet/api/endpoints/admin.py",
}


def write_comet_api_app(repo_root: Path, source: str = COMET_API_APP_SOURCE) -> None:
    app_file = repo_root / "comet" / "api" / "app.py"
    app_file.parent.mkdir(parents=True, exist_ok=True)
    app_file.write_text(source, encoding="utf-8")


def write_comet_logger(repo_root: Path, source: str = COMET_LOGGER_SOURCE) -> None:
    logger_file = repo_root / "comet" / "core" / "logger.py"
    logger_file.parent.mkdir(parents=True, exist_ok=True)
    logger_file.write_text(source, encoding="utf-8")


# The upstream shape of comet/api/endpoints/playback.py where the playback override patches.
COMET_PLAYBACK_SOURCE = """\
import mediaflow_proxy.utils.http_utils
from fastapi import Request


async def playback(request: Request, download_url: str, torrent_name: str, ip: str):
    return await custom_handle_stream_request(
            request.method,
            download_url,
            mediaflow_proxy.utils.http_utils.get_proxy_headers(request),
            media_id=torrent_name,
            ip=ip,
    )
"""


def write_comet_playback(repo_root: Path, source: str = COMET_PLAYBACK_SOURCE) -> None:
    target = repo_root / "comet" / "api" / "endpoints" / "playback.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")


# The upstream shape of comet/core/config_validation.py where the config limits patch.
COMET_CONFIG_VALIDATION_SOURCE = """\
import base64
from functools import lru_cache

import orjson

from comet.core.models import ConfigModel


@lru_cache(maxsize=4096)
def _parse_and_validate_config(b64config: str):
    try:
        config = orjson.loads(base64.b64decode(b64config).decode())

        validated_config = ConfigModel(**config)
        return validated_config.model_dump()
    except Exception:
        return None


def config_check(b64config: str | None, strict_b64config: bool = False):
    if not b64config:
        return None

    validated_config = _parse_and_validate_config(b64config)
    return validated_config
"""


def write_comet_config_validation(
    repo_root: Path, source: str = COMET_CONFIG_VALIDATION_SOURCE
) -> None:
    target = repo_root / "comet" / "core" / "config_validation.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")


# The upstream shape of comet/api/endpoints/admin.py where the admin cookie patch applies.
COMET_ADMIN_SOURCE = """\
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter()
ADMIN_SESSION_COOKIE = "admin_session"
ADMIN_SESSION_TTL = 86400


def create_admin_session():
    return "tok"


@router.post("/admin/login")
async def admin_login(
    request: Request,
):
    response = RedirectResponse("/admin/dashboard", status_code=303)
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=create_admin_session(),
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=ADMIN_SESSION_TTL,
    )
    return response
"""


def write_comet_admin(repo_root: Path, source: str = COMET_ADMIN_SOURCE) -> None:
    target = repo_root / "comet" / "api" / "endpoints" / "admin.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")


def write_required_comet_sources(repo_root: Path) -> None:
    """Upstream files every required override patches."""
    write_comet_api_app(repo_root)
    write_comet_logger(repo_root)
    write_comet_playback(repo_root)
    write_comet_config_validation(repo_root)
    write_comet_admin(repo_root)
