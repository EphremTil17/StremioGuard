"""In-container smoke probe run inside candidate Comet images.

Imported on the host for unit tests and executed inside the candidate image as
`python -c <source> <module> ...`. Imports only the Python standard library at
import time; Comet and Starlette modules are imported dynamically at runtime.
"""

from __future__ import annotations

import asyncio
import base64
import builtins
import dis
import importlib
import json
import sys
import types
from pathlib import Path
from typing import Any

REPORT_PREFIX = "STREMIOGUARD-SMOKE-REPORT "
_PROBE_STREAM_PATH = "/__stremioguard_probe__/stream/movie/tt0000000.json"


def _walk_code_objects(root: types.CodeType) -> list[types.CodeType]:
    codes: list[types.CodeType] = []
    stack: list[types.CodeType] = [root]
    while stack:
        current = stack.pop()
        codes.append(current)
        for const in current.co_consts:
            if isinstance(const, types.CodeType):
                stack.append(const)
    return codes


def _instruction_line(instr: dis.Instruction, code: types.CodeType) -> int:
    line_number = getattr(instr, "line_number", None)
    if isinstance(line_number, int):
        return line_number
    positions = getattr(instr, "positions", None)
    lineno = getattr(positions, "lineno", None) if positions is not None else None
    if isinstance(lineno, int):
        return lineno
    return code.co_firstlineno


def scan_module_undefined_names(module: types.ModuleType) -> list[str]:
    """Return undefined-name findings across every code object of ``module``."""
    file_path = getattr(module, "__file__", None)
    if not isinstance(file_path, str) or not file_path.endswith(".py"):
        return []
    path = Path(file_path)
    if not path.is_file():
        return []

    source = path.read_text(encoding="utf-8")
    top_code = compile(source, file_path, "exec")
    all_codes = _walk_code_objects(top_code)

    global_writes: set[str] = set()
    for code in all_codes:
        for instr in dis.get_instructions(code):
            if instr.opname in ("STORE_GLOBAL", "DELETE_GLOBAL") and isinstance(instr.argval, str):
                global_writes.add(instr.argval)

    allowed = set(vars(module).keys()) | set(dir(builtins)) | global_writes
    findings: list[str] = []

    for code in all_codes:
        instructions = list(dis.get_instructions(code))
        local_stores = {
            instr.argval
            for instr in instructions
            if instr.opname == "STORE_NAME" and isinstance(instr.argval, str)
        }
        code_name = getattr(code, "co_qualname", code.co_name)
        for instr in instructions:
            name = instr.argval
            if not isinstance(name, str):
                continue
            if instr.opname == "LOAD_GLOBAL":
                if name not in allowed:
                    lineno = _instruction_line(instr, code)
                    findings.append(
                        f"undefined name {name!r} at {file_path}:{lineno} in {code_name}"
                    )
            elif instr.opname == "LOAD_NAME":
                if name.startswith("__") and name.endswith("__"):
                    continue
                if name in local_stores:
                    continue
                if name not in allowed:
                    lineno = _instruction_line(instr, code)
                    findings.append(
                        f"undefined name {name!r} at {file_path}:{lineno} in {code_name}"
                    )

    return findings


async def _drive_asgi(
    app: Any, path: str, *, query_string: str = ""
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query_string.encode("ascii"),
        "root_path": "",
        "headers": [(b"host", b"127.0.0.1:8000")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    request_sent = False
    done = asyncio.Event()
    status = 0
    headers: list[tuple[bytes, bytes]] = []
    body_chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await done.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status, headers
        msg_type = message.get("type")
        if msg_type == "http.response.start":
            status = int(message["status"])
            headers = list(message.get("headers") or ())
        elif msg_type == "http.response.body":
            chunk = message.get("body", b"")
            if chunk:
                body_chunks.append(chunk)
            if not message.get("more_body", False):
                done.set()

    try:
        await app(scope, receive, send)
    finally:
        done.set()

    return status, headers, b"".join(body_chunks)


def verify_response_guard() -> list[str]:
    """Verify outermost guard middleware, P2P stream stripping, and torznab 404."""
    findings: list[str] = []
    app_mod = importlib.import_module("comet.api.app")
    guard_mod = importlib.import_module("comet.stremioguard_response_guard")
    models_mod = importlib.import_module("comet.core.models")
    routing_mod = importlib.import_module("starlette.routing")
    responses_mod = importlib.import_module("starlette.responses")

    app = app_mod.app
    guard_cls = guard_mod.StremioGuardResponseGuard

    user_middleware = getattr(app, "user_middleware", None)
    if not user_middleware or user_middleware[0].cls is not guard_cls:
        actual = user_middleware[0].cls if user_middleware else None
        findings.append(f"outermost-middleware check failed: expected {guard_cls}, got {actual}")
        return findings

    async def _probe_stream(_request: Any) -> Any:
        return responses_mod.JSONResponse(
            {
                "streams": [
                    {
                        "name": "p2p-only",
                        "infoHash": "0123456789abcdef0123456789abcdef01234567",
                    },
                    {
                        "name": "hybrid-https",
                        "url": "https://comet.example.test/playback/1",
                        "infoHash": "0123456789abcdef0123456789abcdef01234567",
                        "fileIdx": 0,
                        "sources": ["tracker:udp://example.test:80"],
                    },
                    {
                        "name": "magnet-url",
                        "url": " MAGNET:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
                    },
                    {
                        "name": "magnet-ext",
                        "externalUrl": (
                            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
                        ),
                    },
                    {
                        "name": "plain-https",
                        "url": "https://comet.example.test/playback/2",
                    },
                ]
            }
        )

    probe_route = routing_mod.Route(_PROBE_STREAM_PATH, _probe_stream, methods=["GET"])
    app.router.routes.insert(0, probe_route)
    try:
        stream_status, _stream_headers, stream_body = asyncio.run(
            _drive_asgi(app, _PROBE_STREAM_PATH)
        )
    finally:
        if probe_route in app.router.routes:
            app.router.routes.remove(probe_route)

    expected_streams = [
        {"name": "hybrid-https", "url": "https://comet.example.test/playback/1"},
        {"name": "plain-https", "url": "https://comet.example.test/playback/2"},
    ]
    if stream_status != 200:
        findings.append(f"stream probe failed: expected status 200, got {stream_status}")
    else:
        try:
            payload = json.loads(stream_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append(f"stream probe failed: invalid JSON ({error})")
        else:
            actual_streams = payload.get("streams") if isinstance(payload, dict) else None
            if actual_streams != expected_streams:
                findings.append(
                    f"stream probe failed: expected {expected_streams!r}, got {actual_streams!r}"
                )

    prefix = getattr(models_mod, "STREMIO_API_PREFIX", "") or ""
    torznab_path = f"{prefix}/torznab/api"
    tz_status, _tz_headers, tz_body = asyncio.run(
        _drive_asgi(app, torznab_path, query_string="t=caps")
    )
    tz_text = tz_body.decode("utf-8", errors="replace").lower()
    if tz_status != 404 or "caps" in tz_text or "magnet" in tz_text:
        findings.append(
            f"torznab probe failed: path={torznab_path!r} status={tz_status} body={tz_text[:200]!r}"
        )

    return findings


def verify_stream_guard() -> list[str]:
    """The playback endpoint is patched and the stream proxy hardening is installed."""
    findings: list[str] = []
    playback = importlib.import_module("comet.api.endpoints.playback")
    guard = importlib.import_module("comet.stremioguard_stream_guard")
    if getattr(playback, "_sg_safe_proxy_headers", None) is not guard.safe_proxy_headers:
        findings.append("playback does not build proxy headers through the stream guard")
    if getattr(playback, "_sg_admission_key", None) is not guard.admission_key:
        findings.append("playback does not count stream slots through the stream guard")
    if not guard.installed():
        findings.append("stream guard is not installed in the proxy library")
    return findings


def verify_config_limits() -> list[str]:
    """Oversized configs and configs with too many debrid services are refused."""
    findings: list[str] = []
    validation = importlib.import_module("comet.core.config_validation")
    limit = getattr(validation, "_SG_MAX_B64CONFIG_LENGTH", None)
    max_services = getattr(validation, "_SG_MAX_DEBRID_SERVICES", None)
    if not isinstance(limit, int) or not isinstance(max_services, int):
        return ["config validation carries no StremioGuard limits"]

    def encoded(services: int) -> str:
        entries = [{"service": "realdebrid", "apiKey": "probe"}] * services
        return base64.b64encode(json.dumps({"debridServices": entries}).encode()).decode()

    if validation.config_check(encoded(1), strict_b64config=True) is None:
        findings.append("config limits refused a config with one debrid service")
    if validation.config_check(encoded(max_services + 1), strict_b64config=True) is not None:
        findings.append("config limits accepted more debrid services than the cap")
    if validation.config_check("A" * (limit + 4), strict_b64config=True) is not None:
        findings.append("config limits accepted a config over the length cap")
    return findings


def run_probe(module_names: list[str]) -> dict[str, Any]:
    findings: list[str] = []
    imported: list[types.ModuleType] = []

    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
        except Exception as error:
            findings.append(f"import {module_name} failed: {type(error).__name__}: {error}")
        else:
            imported.append(module)

    for module in imported:
        try:
            findings.extend(scan_module_undefined_names(module))
        except Exception as error:
            findings.append(
                f"undefined-name scan {module.__name__} failed: {type(error).__name__}: {error}"
            )

    if not findings:
        try:
            findings.extend(verify_response_guard())
        except Exception as error:
            findings.append(f"guard probe failed: {type(error).__name__}: {error}")
    if not findings:
        try:
            findings.extend(verify_stream_guard())
        except Exception as error:
            findings.append(f"stream guard probe failed: {type(error).__name__}: {error}")
    if not findings:
        try:
            findings.extend(verify_config_limits())
        except Exception as error:
            findings.append(f"config limits probe failed: {type(error).__name__}: {error}")

    return {"ok": not findings, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    module_names = list(sys.argv[1:] if argv is None else argv)
    try:
        report = run_probe(module_names)
    except Exception as error:
        report = {"ok": False, "findings": [f"probe failed: {type(error).__name__}: {error}"]}
    print(f"{REPORT_PREFIX}{json.dumps(report)}", flush=True)
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
