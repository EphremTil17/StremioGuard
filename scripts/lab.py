"""Reusable gateway and Comet patch test lab.

Standalone developer script (`uv run python scripts/lab.py <command>`).
Creates throwaway containers labeled ``stremioguard.lab=1`` and temporary
directories only, never reads ``.env`` or live secret files, never touches
existing ``stremioguard-*`` containers, and removes everything it created on
exit or interrupt.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from stremioguard.comet_gateway import (
    GATEWAY_CONFIG_DIR,
    CometGatewayConfig,
    CometGatewayManager,
)
from stremioguard.config import COMET_GATEWAY_CONTAINER_PORT, COMET_GATEWAY_HEALTH_PORT
from stremioguard.overrides.bundle import SPECS, Requirement, write_override_bundle

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_LABEL = "stremioguard.lab=1"
READINESS_CASE_ID = "lab-readiness"
DEFAULT_NAME_PREFIX = "sglab-"
NAME_PREFIX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")

ECHO_SERVER_SCRIPT = """\
import http.server
import json


class EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _handle(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length > 0:
            self.rfile.read(length)
        record = {
            "method": self.command,
            "path": self.path,
            "case": self.headers.get("X-Lab-Case"),
            "headers": {
                "Host": self.headers.get("Host"),
                "X-Forwarded-Prefix": self.headers.get("X-Forwarded-Prefix"),
                "X-Forwarded-Proto": self.headers.get("X-Forwarded-Proto"),
                "X-Forwarded-Host": self.headers.get("X-Forwarded-Host"),
                "X-Forwarded-For": self.headers.get("X-Forwarded-For"),
                "CF-Connecting-IP": self.headers.get("CF-Connecting-IP"),
            },
        }
        print(json.dumps(record), flush=True)
        body = (json.dumps(record) + "\\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


server = http.server.ThreadingHTTPServer(("127.0.0.1", 8000), EchoHandler)
server.serve_forever()
"""

SENDER_SCRIPT = """\
import socket
import sys

port = int(sys.argv[1])
timeout = float(sys.argv[2])
raw_req = sys.stdin.buffer.read()
try:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(raw_req)
        while True:
            data = sock.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
except OSError as exc:
    sys.stderr.write(f"CONNECT_ERROR:{type(exc).__name__}:{exc}\\n")
    sys.exit(2)
"""


class LabError(RuntimeError):
    """Operational error surfaced as a single clean line without a traceback."""


class LabConnectionError(LabError):
    """Socket connection failure inside the lab namespace."""


@dataclass(frozen=True)
class GatewayContainerSpec:
    image: str
    cap_drop: tuple[str, ...]
    cap_add: tuple[str, ...]
    security_opt: tuple[str, ...]
    read_only: bool
    tmpfs: tuple[str, ...]


@dataclass(frozen=True)
class GatewayCase:
    name: str
    method: str
    raw_target: str
    http_version: str | None = "HTTP/1.1"
    headers: tuple[tuple[str, str], ...] = ()
    send_host: bool = True
    host_header: str | None = None
    target_port: int = COMET_GATEWAY_CONTAINER_PORT
    expected_status: int | tuple[int, ...] = 200
    expect_proxied: bool = False
    expected_upstream_path: str | None = None
    expected_forwarded_prefix: str | None = None
    expected_host: str | None = None
    expected_forwarded_host: str | None = None
    forbidden_upstream_headers: tuple[str, ...] = ()
    expected_location: str | None = None
    rate_limit_bucket: str | None = None
    upstream_marker: str | None = None


@dataclass(frozen=True)
class HttpResponse:
    status: int | None
    headers: dict[str, str]
    body: bytes
    is_http09: bool = False


@dataclass(frozen=True)
class CaseResult:
    passed: bool
    name: str
    expected: str
    observed: str


def _single_line(text: str) -> str:
    return " ".join(text.strip().split())


def format_case_line(result: CaseResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    return f"{status}  {result.name}  expected={result.expected}  observed={result.observed}"


def validate_name_prefix(prefix: str) -> str:
    """Validate --name-prefix before any Docker command runs."""
    if not NAME_PREFIX_PATTERN.fullmatch(prefix):
        raise LabError(f"Invalid --name-prefix {prefix!r}; expected ^[a-z0-9][a-z0-9-]{{0,30}}$.")
    return prefix


def load_gateway_service_spec(
    compose_path: Path,
    *,
    name_prefix: str = DEFAULT_NAME_PREFIX,
) -> GatewayContainerSpec:
    """Read comet-gateway's image and hardening settings from `docker compose config`."""
    if not compose_path.exists():
        raise LabError(f"Compose file not found at {compose_path}")
    proc = _run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-p",
            f"{name_prefix}config",
            "-f",
            str(compose_path),
            "config",
            "--format",
            "json",
            "--no-env-resolution",
            "--no-interpolate",
        ],
        timeout=30.0,
    )
    try:
        data = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabError(f"Failed to parse docker compose config JSON: {exc}") from exc
    services = data.get("services") if isinstance(data, dict) else None
    gateway = services.get("comet-gateway") if isinstance(services, dict) else None
    if not isinstance(gateway, dict):
        raise LabError(f"Service 'comet-gateway' not found in {compose_path}")
    image = gateway.get("image")
    if not isinstance(image, str) or not image:
        raise LabError(f"Service 'comet-gateway' in {compose_path} has no image")

    def _str_tuple(key: str) -> tuple[str, ...]:
        raw = gateway.get(key) or []
        if not isinstance(raw, list):
            return ()
        return tuple(str(item) for item in raw)

    raw_tmpfs = gateway.get("tmpfs") or []
    tmpfs_targets: list[str] = []
    if isinstance(raw_tmpfs, list):
        for entry in raw_tmpfs:
            if isinstance(entry, dict) and "target" in entry:
                tmpfs_targets.append(str(entry["target"]))
            else:
                tmpfs_targets.append(str(entry).split(":", 1)[0])

    return GatewayContainerSpec(
        image=image,
        cap_drop=_str_tuple("cap_drop"),
        cap_add=_str_tuple("cap_add"),
        security_opt=_str_tuple("security_opt"),
        read_only=bool(gateway.get("read_only", False)),
        tmpfs=tuple(tmpfs_targets),
    )


def build_echo_docker_run_args(
    *,
    echo_name: str,
    echo_image: str,
    pull: bool,
) -> list[str]:
    """Build `docker run` argv for the offline namespace-owner echo container."""
    pull_flag = [] if pull else ["--pull=never"]
    return [
        "docker",
        "run",
        "-d",
        "--no-healthcheck",
        *pull_flag,
        "--label",
        LAB_LABEL,
        "--name",
        echo_name,
        "--network",
        "none",
        "-e",
        f"ECHO_SCRIPT={ECHO_SERVER_SCRIPT}",
        "--entrypoint",
        "/bin/sh",
        echo_image,
        "-c",
        "if [ -x /app/.venv/bin/python ]; then "
        'exec /app/.venv/bin/python -c "$ECHO_SCRIPT"; '
        'else exec python3 -c "$ECHO_SCRIPT"; fi',
    ]


def build_nginx_docker_run_args(
    *,
    nginx_name: str,
    echo_name: str,
    state_dir: Path,
    spec: GatewayContainerSpec,
    gateway_image: str | None,
    pull: bool,
) -> list[str]:
    """Build `docker run` argv for the hardened nginx container in echo's namespace."""
    pull_flag = [] if pull else ["--pull=never"]
    argv = [
        "docker",
        "run",
        "-d",
        *pull_flag,
        "--label",
        LAB_LABEL,
        "--name",
        nginx_name,
        "--network",
        f"container:{echo_name}",
    ]
    for cap in spec.cap_drop:
        argv.extend(["--cap-drop", cap])
    for cap in spec.cap_add:
        argv.extend(["--cap-add", cap])
    for opt in spec.security_opt:
        argv.extend(["--security-opt", opt])
    if spec.read_only:
        argv.append("--read-only")
    for target in spec.tmpfs:
        argv.extend(["--tmpfs", target])
    argv.extend(
        [
            "-v",
            f"{state_dir}:{GATEWAY_CONFIG_DIR}:ro",
            gateway_image or spec.image,
            "nginx",
            "-c",
            f"{GATEWAY_CONFIG_DIR}/nginx.conf",
            "-g",
            "daemon off;",
        ]
    )
    return argv


def resolve_echo_image(explicit_image: str | None, repo_root: Path) -> str:
    """Choose the local Comet image for the echo server per spec priority."""
    if explicit_image:
        return explicit_image
    state_file = repo_root / ".stremio" / "comet" / "state.json"
    if not state_file.exists():
        raise LabError(
            "No --echo-image specified and no .stremio/comet/state.json found; "
            "pass --echo-image <ref>."
        )
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabError(
            f"Could not read active_digest from {state_file}: {exc}; pass --echo-image <ref>."
        ) from exc
    digest = data.get("active_digest") if isinstance(data, dict) else None
    if not isinstance(digest, str) or not digest.strip():
        raise LabError(f"No active_digest in {state_file}; pass --echo-image <ref>.")
    digest = digest.strip()
    if "@" in digest or "/" in digest:
        return digest
    return f"g0ldyy/comet@{digest}"


def parse_http_response(raw: bytes, *, http09: bool = False) -> HttpResponse:
    """Parse raw HTTP/1.x or HTTP/0.9 response bytes."""
    if http09 and not raw.startswith(b"HTTP/"):
        return HttpResponse(status=None, headers={}, body=raw, is_http09=True)
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    if separator not in raw:
        raise ValueError(f"Malformed HTTP response (missing header terminator): {raw[:120]!r}")
    head, body = raw.split(separator, 1)
    lines = head.decode("iso-8859-1").splitlines()
    if not lines or not lines[0].startswith("HTTP/"):
        raise ValueError(f"Malformed HTTP status line: {lines[:1]!r}")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError(f"Invalid HTTP status code in {lines[0]!r}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    return HttpResponse(status=int(parts[1]), headers=headers, body=body, is_http09=False)


def parse_echo_records(log_text: str) -> list[dict[str, object]]:
    """Parse JSON request records printed by the echo server container."""
    records: list[dict[str, object]] = []
    for line in log_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("case") != READINESS_CASE_ID:
            records.append(obj)
    return records


def check_access_log_secrets(log_text: str, secrets_to_hide: Mapping[str, str]) -> list[CaseResult]:
    """Verify the nginx access log recorded requests and leaked none of the secrets."""
    lines = [line for line in log_text.splitlines() if line.strip()]
    results = [
        CaseResult(
            passed=len(lines) > 0,
            name="access_log_nonempty",
            expected=">=1 log lines",
            observed=f"{len(lines)} lines",
        )
    ]
    for label, secret_value in secrets_to_hide.items():
        count = log_text.count(secret_value)
        results.append(
            CaseResult(
                passed=count == 0,
                name=f"access_log_leak_{label}",
                expected=f"0 occurrences of {label}",
                observed=f"{count} occurrences",
            )
        )
    return results


def build_gateway_cases(
    token: str,
    cfg_blob: str,
    host_header: str,
    *,
    api_token: str = "LabApi_Token-1",
) -> list[GatewayCase]:
    """Build the gateway request matrix matching the addon-only routes and health listener."""
    prefix = f"/comet/{token}"
    api = f"/s/{api_token}"
    return [
        # Allowed token shapes (0011 D1), proxied with raw path & query unchanged
        GatewayCase(
            name="valid_manifest_no_cfg",
            method="GET",
            raw_target=f"{prefix}{api}/manifest.json",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/manifest.json",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="valid_manifest_with_cfg",
            method="GET",
            raw_target=f"{prefix}{api}/{cfg_blob}/manifest.json",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/{cfg_blob}/manifest.json",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="valid_stream_query_preserved",
            method="GET",
            raw_target=f"{prefix}{api}/stream/movie/tt1234567.json?foo=bar&baz=1%202",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/stream/movie/tt1234567.json?foo=bar&baz=1%202",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="valid_playback_encoded_space",
            method="GET",
            raw_target=f"{prefix}{api}/{cfg_blob}/playback/host/0/Movie%20Title/1/2",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/{cfg_blob}/playback/host/0/Movie%20Title/1/2",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="valid_token_configure",
            method="GET",
            raw_target=f"{prefix}/configure",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path="/configure",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="valid_token_configure_login",
            method="POST",
            raw_target=f"{prefix}/configure/login",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path="/configure/login",
            expected_forwarded_prefix=prefix,
        ),
        # Public routes: no X-Forwarded-Prefix
        GatewayCase(
            name="public_configure",
            method="GET",
            raw_target="/configure",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path="/configure",
            forbidden_upstream_headers=("X-Forwarded-Prefix",),
            rate_limit_bucket="admin",
        ),
        GatewayCase(
            name="public_health",
            method="GET",
            raw_target="/health",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path="/health",
            forbidden_upstream_headers=("X-Forwarded-Prefix",),
            rate_limit_bucket="admin",
        ),
        # Host with port preserved as Host + X-Forwarded-Host; client-IP headers stripped
        GatewayCase(
            name="host_port_and_stripped_ip_headers",
            method="GET",
            raw_target=f"{prefix}{api}/manifest.json",
            host_header="gw.example.test:8443",
            headers=(
                ("X-Forwarded-For", "198.51.100.77"),
                ("CF-Connecting-IP", "198.51.100.88"),
            ),
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/manifest.json",
            expected_forwarded_prefix=prefix,
            expected_host="gw.example.test:8443",
            expected_forwarded_host="gw.example.test:8443",
            forbidden_upstream_headers=("X-Forwarded-For", "CF-Connecting-IP"),
        ),
        # Base token URL redirects relative 302 to /comet/<token>/configure
        GatewayCase(
            name="token_base_redirect",
            method="GET",
            raw_target=prefix,
            expected_status=302,
            expect_proxied=False,
            expected_location=f"{prefix}/configure",
        ),
        GatewayCase(
            name="token_slash_redirect",
            method="GET",
            raw_target=f"{prefix}/",
            expected_status=302,
            expect_proxied=False,
            expected_location=f"{prefix}/configure",
        ),
        # HTTP/1.0 without Host answers 400 and never proxies
        GatewayCase(
            name="http10_no_host",
            method="GET",
            raw_target=f"{prefix}{api}/manifest.json",
            http_version="HTTP/1.0",
            send_host=False,
            expected_status=400,
            expect_proxied=False,
        ),
        # Denied with 403 under valid token and never proxied
        GatewayCase(
            name="token_admin",
            method="GET",
            raw_target=f"{prefix}/admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_kodi",
            method="GET",
            raw_target=f"{prefix}/kodi/get_manifest/123",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_torznab",
            method="GET",
            raw_target=f"{prefix}{api}/torznab/api",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_debrid_sync",
            method="GET",
            raw_target=f"{prefix}{api}/{cfg_blob}/debrid-sync/0",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_cometnet",
            method="GET",
            raw_target=f"{prefix}/cometnet/status",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_administrator",
            method="GET",
            raw_target=f"{prefix}/administrator",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_kodiak",
            method="GET",
            raw_target=f"{prefix}/kodiak",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_encoded_slash",
            method="GET",
            raw_target=f"{prefix}{api}/{cfg_blob}/playback/host/0/Movie%2FTitle/1/2",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_encoded_dot",
            method="GET",
            raw_target=f"{prefix}{api}/manifest%2Ejson",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_dotdot_admin",
            method="GET",
            raw_target=f"{prefix}/x/../admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_pct_admin",
            method="GET",
            raw_target=f"{prefix}/%61dmin/",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_double_slash_admin",
            method="GET",
            raw_target=f"{prefix}//admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_upper_admin",
            method="GET",
            raw_target=f"{prefix}/ADMIN",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_configure_dotdot_admin",
            method="GET",
            raw_target=f"{prefix}/configure/../admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="token_pct_kodi",
            method="GET",
            raw_target=f"{prefix}/%6bodi/get_manifest/123",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        # Denied top-level & public-port health paths
        GatewayCase(
            name="top_admin",
            method="GET",
            raw_target="/admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_pct_admin",
            method="GET",
            raw_target="/%61dmin/",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_double_slash_admin",
            method="GET",
            raw_target="//admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_upper_admin",
            method="GET",
            raw_target="/ADMIN",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_dotdot_admin",
            method="GET",
            raw_target="/x/../admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_configure_dotdot_admin",
            method="GET",
            raw_target="/configure/../admin",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_kodi",
            method="GET",
            raw_target="/kodi/x",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="top_pct_kodi",
            method="GET",
            raw_target="/%6bodi/x",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        GatewayCase(
            name="public_sg_alive_denied",
            method="GET",
            raw_target="/__sg_alive",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="fail",
        ),
        # Invalid & case-variant tokens (403 through auth limiter)
        GatewayCase(
            name="invalid_token_manifest",
            method="GET",
            raw_target=f"/comet/INVALIDTOKEN99{api}/manifest.json",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="auth",
        ),
        GatewayCase(
            name="invalid_token_root",
            method="GET",
            raw_target="/comet/INVALIDTOKEN99",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="auth",
        ),
        GatewayCase(
            name="token_case_variant",
            method="GET",
            raw_target=f"/comet/{token.swapcase()}{api}/manifest.json",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="auth",
        ),
        # Access-log masking probes
        GatewayCase(
            name="log_probe_configure_dotdot_comet",
            method="GET",
            raw_target=f"/configure/../comet/{token}{api}/{cfg_blob}/manifest.json",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="auth",
        ),
        GatewayCase(
            name="log_probe_configure_dotdot_pct2f",
            method="GET",
            raw_target=f"/configure/..%2Fcomet%2F{token}",
            expected_status=403,
            expect_proxied=False,
            rate_limit_bucket="auth",
        ),
        GatewayCase(
            name="log_probe_full_url",
            method="GET",
            raw_target=f"http://example.test{prefix}{api}/{cfg_blob}/manifest.json",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"{api}/{cfg_blob}/manifest.json",
            expected_forwarded_prefix=prefix,
        ),
        GatewayCase(
            name="log_probe_http09",
            method="GET",
            raw_target=f"{prefix}{api}/{cfg_blob}/manifest.json",
            http_version=None,
            expected_status=400,
            expect_proxied=False,
        ),
        GatewayCase(
            name="log_probe_configure_query",
            method="GET",
            raw_target=f"/configure?next={prefix}&cfg={cfg_blob}",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path=f"/configure?next={prefix}&cfg={cfg_blob}",
            forbidden_upstream_headers=("X-Forwarded-Prefix",),
            rate_limit_bucket="admin",
        ),
        # Dedicated loopback health listener (D4), executed at the end
        GatewayCase(
            name="health_alive_204",
            method="GET",
            raw_target="/__sg_alive",
            target_port=COMET_GATEWAY_HEALTH_PORT,
            host_header=f"127.0.0.1:{COMET_GATEWAY_HEALTH_PORT}",
            expected_status=204,
            expect_proxied=False,
        ),
        GatewayCase(
            name="health_root_404",
            method="GET",
            raw_target="/",
            target_port=COMET_GATEWAY_HEALTH_PORT,
            host_header=f"127.0.0.1:{COMET_GATEWAY_HEALTH_PORT}",
            expected_status=404,
            expect_proxied=False,
        ),
    ]


def evaluate_gateway_case(
    case: GatewayCase,
    response: HttpResponse | str,
    echo_records: Sequence[dict[str, object]],
) -> CaseResult:
    """Evaluate one gateway request against its HTTP response (or error) and upstream log."""
    matching_records = [
        rec
        for rec in echo_records
        if (
            rec.get("case") == case.name
            or (case.upstream_marker is not None and rec.get("path") == case.upstream_marker)
        )
    ]

    if isinstance(response, str):
        exp = (
            f"status={case.expected_status}"
            if isinstance(case.expected_status, int)
            else f"status={','.join(str(s) for s in case.expected_status)}"
        )
        return CaseResult(passed=False, name=case.name, expected=exp, observed=response)

    expected_parts: list[str] = []
    observed_parts: list[str] = []
    failures: list[str] = []

    if response.is_http09:
        observed_parts.append("status=http09")
        if case.expected_status == 200:
            expected_parts.append("http09_body")
        elif case.expected_status == 400:
            expected_parts.append("http09_400")
            if b"400 Bad Request" not in response.body:
                failures.append("http09_expected_400")
        else:
            expected_parts.append(f"status={case.expected_status}")
            failures.append("unexpected_http09")
    else:
        exp_statuses = (
            (case.expected_status,)
            if isinstance(case.expected_status, int)
            else case.expected_status
        )
        expected_parts.append(f"status={','.join(str(s) for s in exp_statuses)}")
        observed_parts.append(f"status={response.status}")
        if response.status not in exp_statuses:
            failures.append("status")

    if case.expect_proxied:
        expected_parts.append("proxied=1")
        observed_parts.append(f"proxied={len(matching_records)}")
        if len(matching_records) != 1:
            failures.append("upstream_count")
        else:
            rec = matching_records[0]
            headers_obj = rec.get("headers")
            rec_headers = headers_obj if isinstance(headers_obj, dict) else {}
            if case.expected_upstream_path is not None:
                expected_parts.append(f"path={case.expected_upstream_path}")
                obs_path = rec.get("path")
                observed_parts.append(f"path={obs_path}")
                if obs_path != case.expected_upstream_path:
                    failures.append("path")
            if case.expected_forwarded_prefix is not None:
                obs_prefix = rec_headers.get("X-Forwarded-Prefix")
                expected_parts.append(f"prefix={case.expected_forwarded_prefix}")
                observed_parts.append(f"prefix={obs_prefix}")
                if obs_prefix != case.expected_forwarded_prefix:
                    failures.append("prefix")
            if case.expected_host is not None:
                obs_host = rec_headers.get("Host")
                expected_parts.append(f"host={case.expected_host}")
                observed_parts.append(f"host={obs_host}")
                if obs_host != case.expected_host:
                    failures.append("host")
            if case.expected_forwarded_host is not None:
                obs_fhost = rec_headers.get("X-Forwarded-Host")
                expected_parts.append(f"xfh={case.expected_forwarded_host}")
                observed_parts.append(f"xfh={obs_fhost}")
                if obs_fhost != case.expected_forwarded_host:
                    failures.append("xfh")
            for forbidden_hdr in case.forbidden_upstream_headers:
                obs_val = rec_headers.get(forbidden_hdr)
                if obs_val is not None:
                    failures.append(f"leaked_{forbidden_hdr}")
                    observed_parts.append(f"{forbidden_hdr}={obs_val!r}")
    else:
        expected_parts.append("upstream=0")
        observed_parts.append(f"upstream={len(matching_records)}")
        if matching_records:
            failures.append("upstream_called")

    if case.expected_location is not None:
        obs_location = response.headers.get("location")
        expected_parts.append(f"location={case.expected_location}")
        observed_parts.append(f"location={obs_location}")
        if obs_location != case.expected_location:
            failures.append("location")

    return CaseResult(
        passed=not failures,
        name=case.name,
        expected=" ".join(expected_parts),
        observed=" ".join(observed_parts),
    )


def _run(
    args: list[str],
    *,
    timeout: float = 30.0,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            args,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LabError(f"Command not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LabError(f"Command timed out after {timeout}s: {' '.join(args)}") from exc
    if check and proc.returncode != 0:
        detail = _single_line((proc.stderr or proc.stdout).decode("utf-8", errors="replace"))
        raise LabError(f"Command failed ({proc.returncode}): {' '.join(args)} — {detail}")
    return proc


def check_docker_reachable() -> None:
    try:
        proc = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10.0, check=False)
    except LabError as exc:
        raise LabError(f"Docker daemon is unreachable: {exc}") from exc
    if proc.returncode != 0:
        detail = _single_line((proc.stderr or proc.stdout).decode("utf-8", errors="replace"))
        raise LabError(f"Docker daemon is unreachable: {detail or 'unknown error'}")


def ensure_local_image(image_ref: str, *, pull: bool) -> str:
    if pull:
        _run(["docker", "pull", "-q", image_ref], timeout=300.0)
    proc = _run(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        timeout=15.0,
        check=False,
    )
    if proc.returncode != 0:
        raise LabError(f"Image {image_ref!r} is not available locally (pass --pull to fetch it).")
    return proc.stdout.decode("utf-8", errors="replace").strip()


@contextmanager
def lab_resources(*, name_prefix: str = DEFAULT_NAME_PREFIX) -> Iterator[tuple[Path, list[str]]]:
    """Manage a lab temp directory and created Docker containers with SIGINT-safe cleanup."""
    tmpdir = Path(tempfile.mkdtemp(prefix=name_prefix))
    containers: list[str] = []
    old_sigint = signal.getsignal(signal.SIGINT)
    old_sigterm = signal.getsignal(signal.SIGTERM)

    def _raise_interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _raise_interrupt)
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        yield tmpdir, containers
    finally:
        # Shield cleanup from a second Ctrl-C so every container and temp dir is removed.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            for name in reversed(containers):
                with suppress(OSError, subprocess.TimeoutExpired):
                    subprocess.run(
                        ["docker", "rm", "-f", name],
                        capture_output=True,
                        timeout=20.0,
                        check=False,
                    )
            shutil.rmtree(tmpdir, ignore_errors=True)
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)


def _render_gateway_configs(state_dir: Path, *, ref: str | None) -> str:
    """Write nginx.conf and tokens.map into ``state_dir`` and return a mixed-case token."""
    state_dir.mkdir(parents=True, exist_ok=True)
    if ref is None:
        cfg = CometGatewayConfig(
            root_dir=state_dir.parent,
            env_file=state_dir.parent / ".env",
            state_dir=state_dir,
            tokens_file=state_dir / "tokens.json",
            nginx_conf_file=state_dir / "nginx.conf",
            tokens_map_file=state_dir / "tokens.map",
            service_name="comet-gateway",
            container_name="comet-gateway",
            host_port=18001,
            bind_addresses=("127.0.0.1",),
            public_base_url=None,
            token_length=8,
            enabled=True,
        )
        manager = CometGatewayManager(cfg)
        while True:
            token_id, token = manager.add_token("lab-test", make_default=True)
            if token.swapcase() != token:
                return token
            manager.revoke_token(token_id)

    # Render using the code at `<ref>` without touching the working tree.
    _run(["git", "-C", str(REPO_ROOT), "rev-parse", "--verify", f"{ref}^{{commit}}"], timeout=10.0)
    archive = _run(
        ["git", "-C", str(REPO_ROOT), "archive", "--format=tar", ref, "src"],
        timeout=30.0,
    )
    ref_root = state_dir.parent / "ref-src"
    ref_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
        tar.extractall(ref_root, filter="data")
    src_path = ref_root / "src"
    helper = (
        "import json, sys; "
        "sys.path.insert(0, sys.argv[1]); "
        "from pathlib import Path; "
        "from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager; "
        "sd = Path(sys.argv[2]); "
        "cfg = CometGatewayConfig("
        "root_dir=sd.parent, env_file=sd.parent / '.env', state_dir=sd, "
        "tokens_file=sd / 'tokens.json', nginx_conf_file=sd / 'nginx.conf', "
        "tokens_map_file=sd / 'tokens.map', service_name='comet-gateway', "
        "container_name='comet-gateway', host_port=18001, bind_addresses=('127.0.0.1',), "
        "public_base_url=None, token_length=8, enabled=True); "
        "mgr = CometGatewayManager(cfg); "
        "\nwhile True:\n"
        "    tid, tok = mgr.add_token('lab-test', make_default=True)\n"
        "    if tok.swapcase() != tok:\n"
        "        break\n"
        "    mgr.revoke_token(tid)\n"
        "print(json.dumps({'token': tok}))"
    )
    proc = _run([sys.executable, "-c", helper, str(src_path), str(state_dir)], timeout=30.0)
    payload = json.loads(proc.stdout.decode("utf-8").strip().splitlines()[-1])
    return str(payload["token"])


def _build_raw_http_request(case: GatewayCase, *, default_host: str) -> tuple[bytes, bool]:
    if case.http_version is None:
        return f"{case.method} {case.raw_target}\r\n".encode("ascii"), True
    effective_host = case.host_header if case.host_header is not None else default_host
    lines = [f"{case.method} {case.raw_target} {case.http_version}"]
    if case.send_host:
        lines.append(f"Host: {effective_host}")
    lines.append(f"X-Lab-Case: {case.name}")
    lines.append("Connection: close")
    for key, value in case.headers:
        lines.append(f"{key}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii"), False


def _send_raw_http_in_namespace(
    echo_name: str,
    case: GatewayCase,
    *,
    default_host: str,
    timeout: float = 5.0,
) -> HttpResponse:
    raw_req, http09 = _build_raw_http_request(case, default_host=default_host)
    proc = _run(
        [
            "docker",
            "exec",
            "-i",
            echo_name,
            "/bin/sh",
            "-c",
            "if [ -x /app/.venv/bin/python ]; then "
            'exec /app/.venv/bin/python -c "$1" "$2" "$3"; '
            'else exec python3 -c "$1" "$2" "$3"; fi',
            "_",
            SENDER_SCRIPT,
            str(case.target_port),
            str(timeout),
        ],
        input_bytes=raw_req,
        timeout=timeout + 10.0,
        check=False,
    )
    if proc.returncode != 0:
        detail = _single_line((proc.stderr or proc.stdout).decode("utf-8", errors="replace"))
        raise LabConnectionError(detail or f"exec exited {proc.returncode}")
    return parse_http_response(proc.stdout, http09=http09)


def _wait_for_ready(
    echo_name: str,
    nginx_name: str,
    *,
    default_host: str,
    timeout: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout
    readiness_case = GatewayCase(
        name=READINESS_CASE_ID,
        method="GET",
        raw_target="/health",
        headers=(),
    )
    while time.monotonic() < deadline:
        for cname in (echo_name, nginx_name):
            insp = _run(
                ["docker", "inspect", "--format", "{{.State.Running}}", cname],
                timeout=5.0,
                check=False,
            )
            if insp.returncode == 0 and insp.stdout.decode().strip().lower() == "false":
                logs = _run(["docker", "logs", cname], timeout=5.0, check=False)
                detail = _single_line((logs.stdout + logs.stderr).decode("utf-8", errors="replace"))
                raise LabError(f"Container {cname} exited unexpectedly: {detail}")
        try:
            resp = _send_raw_http_in_namespace(
                echo_name,
                readiness_case,
                default_host=default_host,
                timeout=1.5,
            )
            if resp.status == 200:
                return
        except (LabError, OSError, ValueError):
            pass
        time.sleep(0.15)
    raise LabError(f"Gateway/echo containers did not become ready within {timeout}s")


def _docker_logs_stdout_lines(container_name: str) -> list[str]:
    proc = _run(["docker", "logs", container_name], timeout=15.0)
    return [line for line in proc.stdout.decode("utf-8", errors="replace").splitlines() if line]


def run_gateway_lab(args: argparse.Namespace) -> int:
    name_prefix = validate_name_prefix(args.name_prefix)
    check_docker_reachable()
    spec = load_gateway_service_spec(REPO_ROOT / "docker-compose.yml", name_prefix=name_prefix)
    gateway_image = args.gateway_image or spec.image
    echo_image = resolve_echo_image(args.echo_image, REPO_ROOT)
    pull = bool(args.pull)
    ensure_local_image(gateway_image, pull=pull)
    ensure_local_image(echo_image, pull=pull)

    with lab_resources(name_prefix=name_prefix) as (tmpdir, containers):
        state_dir = tmpdir / "gateway-state"
        logger.disable("stremioguard")
        try:
            token = _render_gateway_configs(state_dir, ref=args.ref)
        finally:
            logger.enable("stremioguard")

        suffix = secrets.token_hex(4)
        echo_name = f"{name_prefix}{suffix}-echo"
        nginx_name = f"{name_prefix}{suffix}-nginx"

        containers.append(echo_name)
        _run(
            build_echo_docker_run_args(
                echo_name=echo_name,
                echo_image=echo_image,
                pull=pull,
            ),
            timeout=30.0,
        )

        containers.append(nginx_name)
        _run(
            build_nginx_docker_run_args(
                nginx_name=nginx_name,
                echo_name=echo_name,
                state_dir=state_dir,
                spec=spec,
                gateway_image=args.gateway_image,
                pull=pull,
            ),
            timeout=30.0,
        )

        default_host = f"127.0.0.1:{COMET_GATEWAY_CONTAINER_PORT}"
        _wait_for_ready(echo_name, nginx_name, default_host=default_host)

        cfg_blob = "SGVsbG9MYWJUZXN0Q29uZmln"
        api_token = "LabApi_Token-1"
        cases = build_gateway_cases(token, cfg_blob, default_host, api_token=api_token)
        responses: list[tuple[GatewayCase, HttpResponse | str]] = []
        last_bucket_ts: dict[str, float] = {}
        access_lines_before_health: int | None = None
        access_lines_after_alive: int | None = None

        for case in cases:
            if case.name == "health_alive_204":
                time.sleep(0.1)
                access_lines_before_health = len(_docker_logs_stdout_lines(nginx_name))
            if case.rate_limit_bucket is not None:
                prev = last_bucket_ts.get(case.rate_limit_bucket)
                if prev is not None:
                    elapsed = time.monotonic() - prev
                    if elapsed < 0.25:
                        time.sleep(0.25 - elapsed)
                last_bucket_ts[case.rate_limit_bucket] = time.monotonic()
            try:
                resp: HttpResponse | str = _send_raw_http_in_namespace(
                    echo_name,
                    case,
                    default_host=default_host,
                )
            except (LabConnectionError, ValueError) as exc:
                resp = f"error:{_single_line(str(exc))}"
            responses.append((case, resp))
            if case.name == "health_alive_204":
                time.sleep(0.1)
                access_lines_after_alive = len(_docker_logs_stdout_lines(nginx_name))

        # Allow nginx/echo stdout flush to settle before reading docker logs.
        time.sleep(0.1)
        echo_logs_proc = _run(["docker", "logs", echo_name], timeout=15.0)
        nginx_logs_proc = _run(["docker", "logs", nginx_name], timeout=15.0)
        echo_records = parse_echo_records(echo_logs_proc.stdout.decode("utf-8", errors="replace"))
        nginx_logs = (nginx_logs_proc.stdout + nginx_logs_proc.stderr).decode(
            "utf-8", errors="replace"
        )

    results: list[CaseResult] = [
        evaluate_gateway_case(case, resp, echo_records) for case, resp in responses
    ]

    alive_resp = next(
        (resp for case, resp in responses if case.name == "health_alive_204"),
        None,
    )
    if (
        isinstance(alive_resp, HttpResponse)
        and alive_resp.status == 204
        and access_lines_before_health is not None
        and access_lines_after_alive is not None
    ):
        delta = access_lines_after_alive - access_lines_before_health
        results.append(
            CaseResult(
                passed=delta == 0,
                name="health_alive_no_access_log",
                expected="0 new access_log lines",
                observed=f"{delta} new lines",
            )
        )
    else:
        results.append(
            CaseResult(
                passed=False,
                name="health_alive_no_access_log",
                expected="204 with 0 new access_log lines",
                observed=(
                    alive_resp
                    if isinstance(alive_resp, str)
                    else f"status={alive_resp.status if alive_resp else None}"
                ),
            )
        )

    expected_proxied_total = sum(1 for case in cases if case.expect_proxied)
    results.append(
        CaseResult(
            passed=len(echo_records) == expected_proxied_total,
            name="upstream_total_call_count",
            expected=f"{expected_proxied_total} proxied calls",
            observed=f"{len(echo_records)} proxied calls",
        )
    )
    results.extend(
        check_access_log_secrets(
            nginx_logs,
            {"token": token, "api_token": api_token, "cfg_blob": cfg_blob},
        )
    )

    for result in results:
        print(format_case_line(result))

    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count
    print(f"Summary: {passed_count} passed, {failed_count} failed ({len(results)} total)")
    return 0 if failed_count == 0 else 1


def _image_digest_or_id(image_ref: str) -> str:
    proc = _run(
        ["docker", "image", "inspect", image_ref, "--format", "{{json .RepoDigests}}"],
        timeout=10.0,
        check=False,
    )
    if proc.returncode == 0:
        try:
            digests = json.loads(proc.stdout.decode("utf-8", errors="replace").strip() or "[]")
            if (
                isinstance(digests, list)
                and digests
                and isinstance(digests[0], str)
                and "@" in digests[0]
            ):
                return digests[0].split("@", 1)[1]
        except json.JSONDecodeError:
            pass
    id_proc = _run(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"],
        timeout=10.0,
    )
    return id_proc.stdout.decode("utf-8", errors="replace").strip()


def evaluate_render_manifest(
    manifest: dict[str, object],
    *,
    gateway_enabled: bool = True,
) -> list[CaseResult]:
    """Build per-patch PASS/FAIL results from a rendered bundle manifest."""
    applied_raw = manifest.get("applied", [])
    applied = set(applied_raw) if isinstance(applied_raw, list) else set()
    skipped_raw = manifest.get("skipped", [])
    skipped_reasons: dict[str, str] = {}
    if isinstance(skipped_raw, list):
        for entry in skipped_raw:
            if isinstance(entry, dict) and "name" in entry:
                skipped_reasons[str(entry["name"])] = str(entry.get("reason", "unknown"))
    outputs_raw = manifest.get("outputs", {})
    outputs = outputs_raw if isinstance(outputs_raw, dict) else {}

    results: list[CaseResult] = []
    for spec in SPECS:
        is_required = spec.requirement == Requirement.REQUIRED or (
            gateway_enabled and spec.requirement == Requirement.REQUIRED_WHEN_GATEWAY
        )
        if spec.name in applied:
            results.append(
                CaseResult(
                    passed=True,
                    name=f"patch:{spec.name}",
                    expected="applied" if is_required else "applied_or_optional",
                    observed=f"applied -> {outputs.get(spec.output_name, spec.container_path)}",
                )
            )
        else:
            reason = skipped_reasons.get(spec.name, "not applied")
            results.append(
                CaseResult(
                    passed=not is_required,
                    name=f"patch:{spec.name}",
                    expected="applied" if is_required else "optional",
                    observed=f"skipped: {reason}",
                )
            )
    return results


def run_render_lab(args: argparse.Namespace) -> int:
    name_prefix = validate_name_prefix(args.name_prefix)
    check_docker_reachable()
    image_ref: str = args.image
    pull = bool(args.pull)
    ensure_local_image(image_ref, pull=pull)
    image_digest = _image_digest_or_id(image_ref)

    with lab_resources(name_prefix=name_prefix) as (tmpdir, containers):
        source_root = tmpdir / "image-root"
        source_root.mkdir(parents=True, exist_ok=True)
        bundle_dir = tmpdir / "bundle"
        extract_name = f"{name_prefix}{secrets.token_hex(4)}-extract"
        pull_flag = [] if pull else ["--pull=never"]

        containers.append(extract_name)
        _run(
            [
                "docker",
                "create",
                *pull_flag,
                "--label",
                LAB_LABEL,
                "--name",
                extract_name,
                image_ref,
            ],
            timeout=30.0,
        )
        cp_proc = _run(
            ["docker", "cp", f"{extract_name}:/app/comet", str(source_root)],
            timeout=60.0,
            check=False,
        )
        if cp_proc.returncode != 0 or not (source_root / "comet").is_dir():
            result = CaseResult(
                passed=False,
                name="extract_comet_source",
                expected="/app/comet directory present",
                observed=f"missing /app/comet in {image_ref}",
            )
            print(format_case_line(result))
            print("Summary: 0 passed, 1 failed (1 total)")
            return 1

        results: list[CaseResult] = [
            CaseResult(
                passed=True,
                name="extract_comet_source",
                expected="/app/comet directory present",
                observed=f"extracted from {image_ref}",
            )
        ]

        render_error: str | None = None
        logger.disable("stremioguard")
        try:
            write_override_bundle(
                repo_dir=source_root,
                state_dir=bundle_dir,
                result_format_style="plain",
                patch_episode_pack_results=True,
                gateway_addon_base_url="/comet/lab-test",
                gateway_enabled=True,
                image_digest=image_digest,
            )
        except Exception as exc:
            render_error = _single_line(str(exc))
        finally:
            logger.enable("stremioguard")

        manifest_path = bundle_dir / "bundle-manifest.json"
        manifest: dict[str, object] = {}
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            results.extend(evaluate_render_manifest(manifest, gateway_enabled=True))

        compiled_files = sorted(bundle_dir.glob("*.py")) if bundle_dir.exists() else []
        compile_failures: list[str] = []
        for py_file in compiled_files:
            try:
                compile(py_file.read_text(encoding="utf-8"), str(py_file), "exec")
            except SyntaxError as exc:
                compile_failures.append(f"{py_file.name}:{exc.lineno}")

        results.append(
            CaseResult(
                passed=bool(compiled_files) and not compile_failures,
                name="compile_bundle_python",
                expected="all generated .py compile",
                observed=(
                    f"{len(compiled_files)} files compiled"
                    if not compile_failures
                    else f"syntax errors: {', '.join(compile_failures)}"
                ),
            )
        )
        results.append(
            CaseResult(
                passed=render_error is None,
                name="bundle_render",
                expected="bundle rendered cleanly",
                observed="ok" if render_error is None else render_error,
            )
        )

    for result in results:
        print(format_case_line(result))

    applied_list = manifest.get("applied", [])
    skipped_list = manifest.get("skipped", [])
    applied_names = (
        ", ".join(str(x) for x in applied_list) if isinstance(applied_list, list) else ""
    )
    skipped_names = (
        ", ".join(
            f"{e.get('name')} ({e.get('reason')})" for e in skipped_list if isinstance(e, dict)
        )
        if isinstance(skipped_list, list) and skipped_list
        else "none"
    )
    print(
        f"Applied ({len(applied_list) if isinstance(applied_list, list) else 0}): {applied_names}"
    )
    print(
        f"Skipped ({len(skipped_list) if isinstance(skipped_list, list) else 0}): {skipped_names}"
    )

    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count
    print(f"Summary: {passed_count} passed, {failed_count} failed ({len(results)} total)")
    return 0 if failed_count == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/lab.py",
        description="Reusable gateway and Comet override patch test lab.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gw = sub.add_parser("gateway", help="Run nginx gateway matrix against a real container.")
    gw.add_argument(
        "--echo-image",
        help="Local Comet image ref for the echo upstream (defaults to state.json active_digest).",
    )
    gw.add_argument(
        "--gateway-image",
        help="Override nginx gateway image (defaults to docker-compose.yml comet-gateway).",
    )
    gw.add_argument(
        "--ref",
        help="Git commit/ref to render gateway configs from without modifying the working tree.",
    )
    gw.add_argument(
        "--name-prefix",
        default=DEFAULT_NAME_PREFIX,
        help="Container and temp prefix (default: sglab-, ^[a-z0-9][a-z0-9-]{0,30}$).",
    )
    gw.add_argument(
        "--pull",
        action="store_true",
        help="Pull images if needed (by default only local images are used).",
    )

    rd = sub.add_parser("render", help="Extract /app/comet from an image and render overrides.")
    rd.add_argument("--image", required=True, help="Comet image reference to inspect and render.")
    rd.add_argument(
        "--name-prefix",
        default=DEFAULT_NAME_PREFIX,
        help="Container and temp prefix (default: sglab-, ^[a-z0-9][a-z0-9-]{0,30}$).",
    )
    rd.add_argument(
        "--pull",
        action="store_true",
        help="Pull the image before rendering (by default only local images are used).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "gateway":
            return run_gateway_lab(args)
        if args.command == "render":
            return run_render_lab(args)
        parser.error(f"Unknown command: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("Interrupted; cleaned up lab containers and temp directories.", file=sys.stderr)
        return 130
    except LabError as exc:
        print(f"Error: {_single_line(str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
