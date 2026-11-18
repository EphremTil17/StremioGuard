"""Real-nginx + real-Comet-router integration tests for the Comet gateway.

Opt-in (`STREMIOGUARD_DOCKER_TESTS=1`): runs throwaway containers with the pinned
nginx image in front of a route oracle wrapping Comet's real FastAPI router
(`--network none`), using configs rendered by `CometGatewayManager`.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import textwrap
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest

from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="requires Docker with pinned nginx and Comet images; set STREMIOGUARD_DOCKER_TESTS=1",
)

CONTAINER_PREFIX = os.environ.get("STREMIOGUARD_DOCKER_TEST_PREFIX", "sgfix11-")
NGINX_IMAGE = "nginx@sha256:fed7e14be83cbd2661a75cdc5b872d936cf155d46c327084d30b8df19ae88d72"
DEFAULT_COMET_IMAGE = (
    "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
)
COMET_IMAGE = os.environ.get("STREMIOGUARD_GATEWAY_TEST_COMET_IMAGE") or DEFAULT_COMET_IMAGE

TEST_API_TOKEN = "TestApi_Token-123"
TOKEN_A = "GwTok3nA"
TOKEN_A_ID = "toka01"
TOKEN_B = "Gw_Tok-3nB"
TOKEN_B_ID = "tokb02"
# Standard base64 containing both `+` and `=` (and no `/`):
TEST_CONFIG_BLOB = base64.b64encode(b'{"tag":"~~~>"}').decode("ascii")
assert "+" in TEST_CONFIG_BLOB and "=" in TEST_CONFIG_BLOB and "/" not in TEST_CONFIG_BLOB

COMET_IP_PROXY_HEADERS = (
    "cf-connecting-ip",
    "true-client-ip",
    "x-real-ip",
    "x-client-ip",
    "do-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "x-forwarded-for",
    "x-forwarded",
    "forwarded-for",
    "forwarded",
    "x-appengine-user-ip",
    "cf-pseudo-ipv4",
    "X-AIOStreams-User-IP",
)

ORACLE_SOURCE = textwrap.dedent(
    """\
    import asyncio
    import json

    from comet.api.app import app as comet_app

    RECORDS = []


    async def _send_json(send, status, payload):
        body = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


    async def app(scope, receive, send):
        if scope["type"] == "websocket":
            RECORDS.append(
                {
                    "type": "websocket",
                    "path": scope.get("path"),
                    "raw_path": scope.get("raw_path", b"").decode("latin1"),
                }
            )
            await send({"type": "websocket.close", "code": 1000})
            return
        if scope["type"] != "http":
            return

        path = scope.get("path", "")
        raw_headers = [
            (k.decode("latin1"), v.decode("latin1")) for k, v in scope.get("headers", [])
        ]
        header_names = {k.lower() for k, _ in raw_headers}
        if "x-forwarded-host" not in header_names:
            if path == "/__oracle/health":
                await _send_json(send, 200, {"ok": True})
                return
            if path == "/__oracle/openapi":
                schema = comet_app.openapi()
                await _send_json(send, 200, {"paths": schema.get("paths", {})})
                return
            if path == "/__oracle/records":
                await _send_json(send, 200, {"records": RECORDS})
                return
            if path == "/__oracle/clear" and scope.get("method") == "POST":
                RECORDS.clear()
                await _send_json(send, 200, {"cleared": True})
                return

        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                body_chunks.append(message.get("body", b""))
                more_body = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                more_body = False
        body_bytes = b"".join(body_chunks)

        sent_first = False
        captured_status = None
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return {"type": "http.disconnect"}

        async def capture_send(message):
            nonlocal sent_first, captured_status
            if message["type"] == "http.response.start":
                sent_first = True
                captured_status = message["status"]
            await send(message)

        try:
            await asyncio.wait_for(comet_app(scope, replay_receive, capture_send), timeout=3.0)
        except asyncio.TimeoutError:
            if not sent_first:
                captured_status = 504
                await _send_json(send, 504, {"oracle": "timeout"})
        except Exception as exc:
            if not sent_first:
                captured_status = 500
                await _send_json(send, 500, {"oracle": repr(exc)})

        route = scope.get("route")
        RECORDS.append(
            {
                "type": "http",
                "method": scope.get("method"),
                "raw_path": scope.get("raw_path", b"").decode("latin1"),
                "path": scope.get("path"),
                "query_string": scope.get("query_string", b"").decode("latin1"),
                "headers": raw_headers,
                "body": body_bytes.decode("latin1"),
                "route": getattr(route, "path", None),
                "status": captured_status,
            }
        )
    """
)


@dataclass
class GatewayHarness:
    oracle_container: str
    nginx_container: str
    root_dir: Path

    def exec_nginx(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "exec", "-i", self.nginx_container, "sh", "-s"],
            input=script,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )

    def clear_records(self) -> None:
        res = self.exec_nginx("curl -sS -X POST http://127.0.0.1:8000/__oracle/clear >/dev/null")
        assert res.returncode == 0, res.stderr

    def fetch_records(self) -> list[dict[str, object]]:
        res = self.exec_nginx("curl -sS http://127.0.0.1:8000/__oracle/records")
        assert res.returncode == 0, res.stderr
        return json.loads(res.stdout)["records"]

    def fetch_openapi_paths(self) -> dict[str, dict[str, object]]:
        res = self.exec_nginx("curl -sS http://127.0.0.1:8000/__oracle/openapi")
        assert res.returncode == 0, res.stderr
        return json.loads(res.stdout)["paths"]

    def curl_batch(self, specs: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
        """Execute a batch of curl requests in one `docker exec` call.

        Each spec supports:
          - method (str, default "GET")
          - target (str, path or full target; sent via --request-target)
          - host (str, default "127.0.0.1:8090")
          - headers (Sequence[str], optional)
          - body (str, optional)
          - http10 (bool, default False)
        """
        lines = ["set -u"]
        for idx, spec in enumerate(specs):
            method = str(spec.get("method", "GET"))
            target = str(spec["target"])
            host = spec.get("host", "127.0.0.1:8090")
            raw_headers = spec.get("headers")
            headers = list(raw_headers) if isinstance(raw_headers, (list, tuple)) else []
            body = spec.get("body")
            http10 = bool(spec.get("http10", False))

            hdr_file = f"/tmp/hdr_{idx}"
            cmd_parts = [
                "curl",
                "-sS",
                "--path-as-is",
                "-o",
                "/dev/null",
                "-D",
                hdr_file,
                "-w",
                "'%{http_code}'",
            ]
            if method == "HEAD":
                cmd_parts.append("--head")
            else:
                cmd_parts.extend(["-X", _sh_quote(method)])
            cmd_parts.extend(["--request-target", _sh_quote(target)])
            if http10:
                cmd_parts.append("--http1.0")
            if host is None:
                cmd_parts.extend(["-H", "'Host:'"])
            else:
                cmd_parts.extend(["-H", _sh_quote(f"Host: {host}")])
            for hdr in headers:
                cmd_parts.extend(["-H", _sh_quote(str(hdr))])
            if body is not None:
                cmd_parts.extend(["--data-raw", _sh_quote(str(body))])
            cmd_parts.append("http://127.0.0.1:8090/")
            lines.append(
                f"code=$({' '.join(cmd_parts)})\n"
                f"loc=$(tr -d '\\r' < {hdr_file} | "
                "awk 'tolower($1)==\"location:\" {print $2; exit}')\n"
                f'printf \'%s\\t%s\\n\' "$code" "$loc"\n'
                f"rm -f {hdr_file}"
            )
        res = self.exec_nginx("\n".join(lines))
        assert res.returncode == 0, f"curl batch failed: {res.stderr}\n{res.stdout}"
        results: list[dict[str, object]] = []
        for row in res.stdout.splitlines():
            code_str, _, loc = row.partition("\t")
            results.append({"status": int(code_str), "location": loc})
        assert len(results) == len(specs), (res.stdout, res.stderr)
        return results

    def nginx_logs(self) -> tuple[str, str]:
        res = subprocess.run(
            ["docker", "logs", self.nginx_container],
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
        )
        return res.stdout, res.stderr


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


@pytest.fixture(scope="module")
def gateway_harness(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GatewayHarness]:
    """The gateway with the configure page public (COMET_GATEWAY_PUBLIC_CONFIGURE=1)."""
    with _running_harness(
        tmp_path_factory.mktemp("sgfix11-int"), "COMET_GATEWAY_PUBLIC_CONFIGURE=1\n"
    ) as harness:
        yield harness


@pytest.fixture(scope="module")
def default_gateway_harness(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GatewayHarness]:
    """The gateway as installed by default: no configure page."""
    with _running_harness(tmp_path_factory.mktemp("sgfix11-default"), "") as harness:
        yield harness


@contextmanager
def _running_harness(tmp_root: Path, extra_env: str) -> Iterator[GatewayHarness]:
    (tmp_root / ".env").write_text(
        "COMET_ENABLED=1\n"
        "COMET_GATEWAY_ENABLED=1\n"
        "COMET_GATEWAY_PUBLIC_BASE_URL=https://comet.example.com\n" + extra_env,
        encoding="utf-8",
    )
    config = CometGatewayConfig.from_env(tmp_root)
    manager = CometGatewayManager(config)
    manager.save_state(
        {
            "default": TOKEN_A_ID,
            "tokens": {
                TOKEN_A_ID: {
                    "label": "Token A",
                    "token": TOKEN_A,
                    "created": "2026-11-16T00:00:00+00:00",
                },
                TOKEN_B_ID: {
                    "label": "Token B",
                    "token": TOKEN_B,
                    "created": "2026-11-16T00:00:01+00:00",
                },
            },
        }
    )
    manager.write_nginx_configs()

    oracle_file = tmp_root / "sg_oracle.py"
    oracle_file.write_text(ORACLE_SOURCE, encoding="utf-8")
    oracle_file.chmod(0o644)

    suffix = uuid.uuid4().hex[:8]
    oracle_name = f"{CONTAINER_PREFIX}oracle-{suffix}"
    nginx_name = f"{CONTAINER_PREFIX}nginx-{suffix}"

    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--no-healthcheck",
                "--name",
                oracle_name,
                "--network",
                "none",
                "--entrypoint",
                "python",
                "-e",
                "CONFIGURE_PAGE_PASSWORD=test-password",
                "-e",
                f"PUBLIC_API_TOKEN={TEST_API_TOKEN}",
                "-e",
                "PYTHONPATH=/opt:/app",
                "-v",
                f"{oracle_file}:/opt/sg_oracle.py:ro",
                COMET_IMAGE,
                "-m",
                "uvicorn",
                "sg_oracle:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
                "--lifespan",
                "off",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                nginx_name,
                "--network",
                f"container:{oracle_name}",
                "-v",
                f"{config.state_dir}:/etc/nginx/stremioguard:ro",
                NGINX_IMAGE,
                "nginx",
                "-c",
                "/etc/nginx/stremioguard/nginx.conf",
                "-g",
                "daemon off;",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        # Wait for both uvicorn oracle and nginx to listen.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            probe = subprocess.run(
                [
                    "docker",
                    "exec",
                    nginx_name,
                    "sh",
                    "-c",
                    "curl -s -o /dev/null http://127.0.0.1:8000/__oracle/health && "
                    "curl -s -o /dev/null http://127.0.0.1:8090/health",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.25)
        else:
            o_logs = subprocess.run(["docker", "logs", oracle_name], capture_output=True, text=True)
            n_logs = subprocess.run(["docker", "logs", nginx_name], capture_output=True, text=True)
            raise RuntimeError(
                f"Harness failed to become ready.\nOracle:\n{o_logs.stdout}\n{o_logs.stderr}\n"
                f"Nginx:\n{n_logs.stdout}\n{n_logs.stderr}"
            )

        yield GatewayHarness(oracle_name, nginx_name, tmp_root)
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", nginx_name], capture_output=True, check=False)
        subprocess.run(["docker", "rm", "-f", "-v", oracle_name], capture_output=True, check=False)


def _header_values(record: dict[str, object], name: str) -> list[str]:
    target = name.lower()
    return [v for k, v in record["headers"] if k.lower() == target]  # type: ignore[misc]


def test_ac1_allowed_routes_preserve_raw_path_query_range_body_and_prefix(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-1 (INV-1, INV-7): allowed addon routes reach Comet with exact raw path and headers."""
    gateway_harness.clear_records()
    api = TEST_API_TOKEN
    cfg = TEST_CONFIG_BLOB
    play_target = (
        f"/comet/{TOKEN_A}/s/{api}/{cfg}/playback/deadbeef/0/1/1/2?torrent_name=a%20b%2Bc%3Dd%26e"
    )
    specs = [
        {"target": f"/comet/{TOKEN_A}/s/{api}/manifest.json"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/{cfg}/manifest.json"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/stream/movie/tt0111161.json"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/{cfg}/stream/series/tt0903747%3A1%3A2.json"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/{cfg}/stream/series/tt0903747:1:2.json"},
        {"target": play_target, "headers": ["Range: bytes=100-"]},
        {"method": "HEAD", "target": play_target},
        {"target": f"/comet/{TOKEN_A}/configure"},
        {"target": f"/comet/{TOKEN_A}/{cfg}/configure"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/configure"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/{cfg}/configure"},
        {
            "method": "POST",
            "target": f"/comet/{TOKEN_A}/configure/login",
            "headers": ["Content-Type: application/x-www-form-urlencoded"],
            "body": "password=test-password",
        },
    ]
    responses = gateway_harness.curl_batch(specs)
    records = gateway_harness.fetch_records()
    assert len(records) == len(specs)

    expected_routes = [
        "/manifest.json",
        "/{b64config}/manifest.json",
        "/stream/{media_type}/{media_id}.json",
        "/{b64config}/stream/{media_type}/{media_id}.json",
        "/{b64config}/stream/{media_type}/{media_id}.json",
        "/{b64config}/playback/{hash}/{service_index}/{index}/{season}/{episode}",
        "/{b64config}/playback/{hash}/{service_index}/{index}/{season}/{episode}",
        "/configure",
        "/{b64config}/configure",
        "/configure",
        "/{b64config}/configure",
        "/configure/login",
    ]

    for spec, resp, rec, exp_route in zip(specs, responses, records, expected_routes, strict=True):
        assert resp["status"] != 403 and resp["status"] != 503, (spec, resp)
        assert rec["route"] == exp_route, (spec, rec)
        raw_after_tok, _, raw_query = (
            str(spec["target"]).removeprefix(f"/comet/{TOKEN_A}").partition("?")
        )
        assert rec["raw_path"] == raw_after_tok
        assert rec["query_string"] == raw_query
        assert _header_values(rec, "x-forwarded-prefix") == [f"/comet/{TOKEN_A}"]

    assert _header_values(records[5], "range") == ["bytes=100-"]
    assert records[11]["body"] == "password=test-password"


def test_ac2_every_comet_openapi_route_and_extra_probes(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-2 (INV-1): only the 10 allowed routes from Comet's live OpenAPI schema reach Comet."""
    paths = gateway_harness.fetch_openapi_paths()
    api = TEST_API_TOKEN
    cfg = TEST_CONFIG_BLOB
    gateway_harness.clear_records()

    sample_values = {
        "b64config": cfg,
        "media_type": "movie",
        "media_id": "tt0111161",
        "hash": "deadbeef",
        "service_index": "0",
        "index": "1",
        "season": "1",
        "episode": "2",
        "code": "123456",
        "pool_id": "pool1",
        "invite_code": "inv1",
        "member_key": "mem1",
    }

    def fill_path(template: str) -> str:
        out = template
        for key, val in sample_values.items():
            out = out.replace(f"{{{key}}}", val)
        return out

    # Probe every route in app.openapi()["paths"] (deduplicating (method, target)),
    # plus /cometnet/ws, /metrics, /docs, /openapi.json, /, unprefixed forms, and swapped order.
    probes: list[dict[str, object]] = []
    seen_probes: set[tuple[str, str]] = set()

    def add_probe(method: str, target: str, headers: list[str] | None = None) -> None:
        key = (method.upper(), target)
        if key in seen_probes:
            return
        seen_probes.add(key)
        entry: dict[str, object] = {"method": key[0], "target": target}
        if headers:
            entry["headers"] = headers
        probes.append(entry)

    for route_path, methods in sorted(paths.items()):
        filled = fill_path(route_path)
        for method in sorted(methods):
            upper_m = method.upper()
            if filled.startswith(f"/s/{api}"):
                add_probe(upper_m, f"/comet/{TOKEN_A}{filled}")
                unprefixed = filled.removeprefix(f"/s/{api}") or "/"
                add_probe(upper_m, f"/comet/{TOKEN_A}{unprefixed}")
            else:
                add_probe(upper_m, f"/comet/{TOKEN_A}{filled}")

    sample_prefixed = any(p.startswith(f"/s/{api}/") for p in paths)
    if not sample_prefixed:
        for route_path, methods in sorted(paths.items()):
            filled = fill_path(route_path)
            if route_path.startswith(("/admin", "/kodi", "/cometnet")) or route_path in {
                "/",
                "/health",
                "/configure",
                "/{b64config}/configure",
                "/configure/login",
            }:
                continue
            for method in sorted(methods):
                add_probe(method.upper(), f"/comet/{TOKEN_A}/s/{api}{filled}")

    add_probe(
        "GET",
        f"/comet/{TOKEN_A}/cometnet/ws",
        [
            "Connection: Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version: 13",
        ],
    )
    add_probe("GET", f"/comet/{TOKEN_A}/metrics")
    add_probe("GET", f"/comet/{TOKEN_A}/docs")
    add_probe("GET", f"/comet/{TOKEN_A}/openapi.json")
    add_probe("GET", f"/comet/{TOKEN_A}/")
    add_probe("GET", f"/comet/{TOKEN_A}/{cfg}/s/{api}/manifest.json")

    allowed_raw_paths = {
        "/configure",
        f"/{cfg}/configure",
        "/configure/login",
        f"/s/{api}/configure",
        f"/s/{api}/{cfg}/configure",
        f"/s/{api}/manifest.json",
        f"/s/{api}/{cfg}/manifest.json",
        f"/s/{api}/stream/movie/tt0111161.json",
        f"/s/{api}/{cfg}/stream/movie/tt0111161.json",
        f"/s/{api}/{cfg}/playback/deadbeef/0/1/1/2",
    }

    expected_allowed_keys: set[tuple[str, str]] = set()
    time.sleep(0.8)
    responses = gateway_harness.curl_batch(probes)
    records = gateway_harness.fetch_records()

    for probe, resp in zip(probes, responses, strict=True):
        raw_after = str(probe["target"]).removeprefix(f"/comet/{TOKEN_A}")
        print(f"AC2 {probe['method']} {raw_after} -> {resp['status']}")
        if raw_after == "/":
            assert resp["status"] == 302
        elif raw_after in allowed_raw_paths:
            assert resp["status"] not in {403, 503}, (probe, resp)
            expected_allowed_keys.add((str(probe["method"]), raw_after))
        else:
            assert resp["status"] in {403, 503}, (probe, resp)

    assert len(expected_allowed_keys) == 10
    assert len(records) == 10
    reached_routes = {(str(rec["method"]), str(rec["raw_path"])) for rec in records}
    assert all(rec["type"] == "http" for rec in records)
    assert reached_routes == expected_allowed_keys


def test_ac3_spelling_and_traversal_variants_denied_and_absolute_form_works(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-3 (INV-1, INV-2): spelling/traversal variants are denied and never reach Comet."""
    gateway_harness.clear_records()
    api = TEST_API_TOKEN
    cfg = TEST_CONFIG_BLOB

    denied_targets = [
        f"/comet/{TOKEN_A}//",
        f"/comet/{TOKEN_A}//s/{api}/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}//manifest.json",
        f"/comet/{TOKEN_A}/configure//",
        f"/comet/{TOKEN_A}/./configure",
        f"/comet/{TOKEN_A}/s/{api}/./manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/x/../manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/manifest.json/..",
        f"/comet/{TOKEN_A}/s/{api}/%2e/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/%2E/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/%2e%2e/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/x%2Fmanifest.json",
        f"/comet/{TOKEN_A}/s/{api}/x%2fmanifest.json",
        f"/comet/{TOKEN_A}/s/{api}/x%5C/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/x\\/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/manifest.json;p=1",
        f"/comet/{TOKEN_A}/s/{api}/x;p=1/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/MANIFEST.JSON",
        f"/comet/{TOKEN_A}/S/{api}/manifest.json",
        f"/comet/{TOKEN_A}/s/{api}/Stream/movie/tt0111161.json",
        f"/comet/{TOKEN_A}/s/{api}/{cfg}/PLAYBACK/a/0/1/1/2",
        f"/comet/{TOKEN_A}/s/{api}/manifest%2Ejson",
        f"/comet/{TOKEN_A}/s/{api}/m%61nifest.json",
        f"/comet/{TOKEN_A}/s/{api}/manifest.json/",
        f"/comet/{TOKEN_A}/s/{api}/stream/movie/tt0111161.json/",
        f"/comet/{TOKEN_A}/s/{api}/{cfg}/playback/a/0/1/1/2/",
        f"/comet/{TOKEN_A}/configure/",
        f"/comet/{TOKEN_A}/configure/login/",
        f"/comet/{TOKEN_A}/s/{api}/manifest.json#frag",
        f"/comet/{TOKEN_A}/s/{api}/{cfg}/playback/a/0/1/1",
        f"/comet/{TOKEN_A}/s/{api}/{cfg}/playback/a/0/1/1/2/3",
        f"/comet/{TOKEN_A}/s/{api}/manifest.json/../torznab/api",
        f"/comet/{TOKEN_A}/s/{api}/%2e%2e/torznab/api",
        f"/comet/{TOKEN_A}/s/{api}/x%2F..%2F..%2Ftorznab/api",
        f"/comet/{TOKEN_A}/../{TOKEN_A}/s/{api}/torznab/api",
        f"/x/../comet/{TOKEN_A}/s/{api}/manifest.json",
        f"/COMET/{TOKEN_A}/s/{api}/manifest.json",
        f"http://evil.example:9/comet/{TOKEN_A}/s/{api}/torznab/api",
    ]
    time.sleep(0.8)
    responses = gateway_harness.curl_batch([{"target": t} for t in denied_targets])
    for target, resp in zip(denied_targets, responses, strict=True):
        assert resp["status"] in {400, 403, 503}, (target, resp)
    assert gateway_harness.fetch_records() == []

    # Absolute-form target for an allowed path reaches Comet.
    abs_ok = gateway_harness.curl_batch(
        [{"target": f"http://evil.example:9/comet/{TOKEN_A}/s/{api}/manifest.json"}]
    )
    assert abs_ok[0]["status"] not in {400, 403, 503}
    records = gateway_harness.fetch_records()
    assert len(records) == 1
    assert records[0]["raw_path"] == f"/s/{api}/manifest.json"


def test_ac4_exact_case_sensitive_token_matching_and_tid_logging(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-4 (INV-3): tokens match only byte-for-byte; variants hit gateway_auth and log tid=-."""
    api = TEST_API_TOKEN
    time.sleep(2.2)  # Refill gateway_auth burst=10.
    gateway_harness.clear_records()

    for token, expected_id in ((TOKEN_A, TOKEN_A_ID), (TOKEN_B, TOKEN_B_ID)):
        marker = f"ac4-{expected_id}"
        flipped = (token[0].lower() if token[0].isupper() else token[0].upper()) + token[1:]
        pct = f"%{ord(token[-1]):02X}"
        pct_tok = token[:-1] + pct
        variants = [
            token.upper(),
            token.lower(),
            flipped,
            token + "x",
            "x" + token,
            pct_tok,
        ]

        specs = [{"target": f"/comet/{token}/s/{api}/manifest.json?m={marker}"}]
        specs.extend({"target": f"/comet/{v}/s/{api}/manifest.json"} for v in variants)
        specs.append({"target": f"/comet/totally_invalid_tok/s/{api}/manifest.json"})

        resps = gateway_harness.curl_batch(specs)
        assert resps[0]["status"] not in {403, 503}
        for bad_resp in resps[1:]:
            assert bad_resp["status"] in {403, 503}
        # At least one plain 403 for invalid-token denial.
        assert any(r["status"] == 403 for r in resps[1:])
        time.sleep(2.2)

    records = gateway_harness.fetch_records()
    assert len(records) == 2

    stdout, _ = gateway_harness.nginx_logs()
    assert f"tid={TOKEN_A_ID}" in stdout
    assert f"tid={TOKEN_B_ID}" in stdout
    assert "tid=-" in stdout


def test_ac5_host_port_preserved_and_base_url_302_relative(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-5 (INV-4, D4): Host/X-Forwarded-Host keep port and case; base URL gives relative 302."""
    api = TEST_API_TOKEN
    hosts = [
        "192.0.2.10:18001",
        "[2001:db8::1]:18001",
        "comet.example.com",
        "Comet.Example.COM:8443",
    ]
    time.sleep(0.5)
    gateway_harness.clear_records()
    specs: list[dict[str, object]] = []
    for host in hosts:
        for path in (f"/comet/{TOKEN_A}/s/{api}/manifest.json", "/configure", "/"):
            specs.append(
                {
                    "target": path,
                    "host": host,
                    "headers": ["X-Forwarded-Host: evil.example"],
                }
            )
    resps = gateway_harness.curl_batch(specs)
    for resp in resps:
        assert resp["status"] not in {400, 403, 503}, resp

    records = gateway_harness.fetch_records()
    assert len(records) == len(specs)
    for spec, rec in zip(specs, records, strict=True):
        assert _header_values(rec, "host") == [spec["host"]]
        assert _header_values(rec, "x-forwarded-host") == [spec["host"]]

    # Base URLs: valid -> 302 Location: /comet/<tok>/configure; invalid -> 403.
    gateway_harness.clear_records()
    base_resps = gateway_harness.curl_batch(
        [
            {"target": f"/comet/{TOKEN_A}", "host": "192.0.2.10:18001"},
            {"target": f"/comet/{TOKEN_A}/?x=1", "host": "192.0.2.10:18001"},
            {"target": "/comet/InvalidTok9", "host": "192.0.2.10:18001"},
            {"target": "/comet/InvalidTok9/?x=1", "host": "192.0.2.10:18001"},
        ]
    )
    assert base_resps[0] == {"status": 302, "location": f"/comet/{TOKEN_A}/configure"}
    assert base_resps[1] == {"status": 302, "location": f"/comet/{TOKEN_A}/configure"}
    assert base_resps[2]["status"] in {403, 503}
    assert base_resps[3]["status"] in {403, 503}
    assert gateway_harness.fetch_records() == []


def test_ac6_invalid_or_missing_host_returns_400_never_proxied(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-6 (INV-4): bad Host values and HTTP/1.0 without Host return 400 and never proxy."""
    gateway_harness.clear_records()
    api = TEST_API_TOKEN
    bad_hosts = ["x.com'y", "x(y)", "x,y", "x.com;y", "x%2fy", "x.com:"]
    specs: list[dict[str, object]] = []
    for bad_host in bad_hosts:
        for path in (f"/comet/{TOKEN_A}/s/{api}/manifest.json", "/configure", "/"):
            specs.append({"target": path, "host": bad_host})
    for path in (f"/comet/{TOKEN_A}/s/{api}/manifest.json", "/configure", "/"):
        specs.append({"target": path, "host": None, "http10": True})

    resps = gateway_harness.curl_batch(specs)
    for spec, resp in zip(specs, resps, strict=True):
        assert resp["status"] == 400, (spec, resp)
    assert gateway_harness.fetch_records() == []


def test_ac7_clears_ip_proxy_headers_and_client_forwarded_headers(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-7 (INV-5): 14 IP headers and client X-Forwarded-Prefix/Host are stripped everywhere."""
    time.sleep(0.5)
    gateway_harness.clear_records()
    api = TEST_API_TOKEN
    spoof_headers = [f"{hdr}: 203.0.113.9" for hdr in COMET_IP_PROXY_HEADERS]
    spoof_headers.extend(
        [
            "X-Forwarded-Prefix: //evil.example",
            "X-Forwarded-Host: evil.example",
            "X-StremioGuard-Client: spoofed-client",
        ]
    )
    specs = [
        {"target": f"/comet/{TOKEN_A}/s/{api}/manifest.json", "headers": spoof_headers},
        {"target": "/configure", "headers": spoof_headers},
        {
            "method": "POST",
            "target": "/configure/login",
            "headers": [*spoof_headers, "Content-Type: application/x-www-form-urlencoded"],
            "body": "password=test-password",
        },
        {"target": "/", "headers": spoof_headers},
    ]
    resps = gateway_harness.curl_batch(specs)
    for resp in resps:
        assert resp["status"] not in {400, 403, 503}, resp

    records = gateway_harness.fetch_records()
    assert len(records) == 4
    for idx, rec in enumerate(records):
        for ip_hdr in COMET_IP_PROXY_HEADERS:
            assert _header_values(rec, ip_hdr) == [], (idx, ip_hdr, rec["headers"])
        assert _header_values(rec, "x-forwarded-host") == ["127.0.0.1:8090"]
        if idx == 0:
            assert _header_values(rec, "x-forwarded-prefix") == [f"/comet/{TOKEN_A}"]
            # Comet counts stream slots under the token's ID, never a client's value.
            assert _header_values(rec, "x-stremioguard-client") == [TOKEN_A_ID]
        else:
            assert _header_values(rec, "x-forwarded-prefix") == []
            assert _header_values(rec, "x-stremioguard-client") == []


def test_ac8_rate_limit_storms_throttle_denials_never_valid_playback(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-8 (INV-6): forbidden, /nope, and invalid-token storms hit 503; 50 playbacks never do."""
    api = TEST_API_TOKEN
    cfg = TEST_CONFIG_BLOB
    time.sleep(2.5)  # Refill gateway_auth and gateway_fail buckets.
    gateway_harness.clear_records()

    # Single docker exec with curl -K - over keep-alive so all 140 requests fire rapidly.
    forbidden_url = f"http://127.0.0.1:8090/comet/{TOKEN_A}/s/{api}/torznab/api"
    nope_url = "http://127.0.0.1:8090/nope"
    invalid_url = f"http://127.0.0.1:8090/comet/WrongTok99/s/{api}/manifest.json"
    playback_url = f"http://127.0.0.1:8090/comet/{TOKEN_A}/s/{api}/{cfg}/playback/deadbeef/0/1/1/2"

    # Run all 4 storms sequentially in ONE docker exec script using curl -K - for keep-alive speed.
    script_lines = ["set -e"]
    for label, url, count, hdr in (
        ("forbid", forbidden_url, 30, None),
        ("nope", nope_url, 30, None),
        ("invalid", invalid_url, 30, None),
        ("play", playback_url, 50, "Range: bytes=0-99"),
    ):
        cfg_entries = []
        for _ in range(count):
            cfg_entries.append(f'url = "{url}"')
            cfg_entries.append('output = "/dev/null"')
            cfg_entries.append('write-out = "%{http_code}\\n"')
        cfg_block = "\n".join(cfg_entries)
        hdr_opt = f'-H "{hdr}" ' if hdr else ""
        script_lines.append(
            f"echo '==={label}==='\ncurl -sS {hdr_opt}-K - <<'CURLCFG'\n{cfg_block}\nCURLCFG"
        )
    res = gateway_harness.exec_nginx("\n".join(script_lines))
    assert res.returncode == 0, res.stderr

    sections: dict[str, list[int]] = {}
    current = ""
    for line in res.stdout.splitlines():
        if line.startswith("===") and line.endswith("==="):
            current = line.strip("=")
            sections[current] = []
        elif line.strip():
            sections[current].append(int(line.strip()))

    assert len(sections["forbid"]) == 30
    assert 403 in sections["forbid"] and 503 in sections["forbid"]
    assert all(c in {403, 503} for c in sections["forbid"])

    assert len(sections["nope"]) == 30
    assert 503 in sections["nope"]
    assert all(c in {403, 503} for c in sections["nope"])

    assert len(sections["invalid"]) == 30
    assert 403 in sections["invalid"] and 503 in sections["invalid"]
    assert all(c in {403, 503} for c in sections["invalid"])

    assert len(sections["play"]) == 50
    assert all(c not in {403, 503} for c in sections["play"])

    records = gateway_harness.fetch_records()
    assert len(records) == 50
    assert all(
        rec["raw_path"] == f"/s/{api}/{cfg}/playback/deadbeef/0/1/1/2"
        and _header_values(rec, "range") == ["bytes=0-99"]
        for rec in records
    )


def test_ac10_public_top_level_routes_and_blocked_paths(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-10 (INV-7, D8): public routes reach Comet; admin/kodi/s/<api>/cometnet do not."""
    api = TEST_API_TOKEN
    time.sleep(0.8)
    gateway_harness.clear_records()

    public_specs = [
        {"method": "GET", "target": "/configure"},
        {
            "method": "POST",
            "target": "/configure/login",
            "headers": ["Content-Type: application/x-www-form-urlencoded"],
            "body": "password=test-password",
        },
        {"method": "GET", "target": "/health"},
        {"method": "GET", "target": "/"},
        {"method": "GET", "target": "/static/x"},
    ]
    pub_resps = gateway_harness.curl_batch(public_specs)
    for spec, resp in zip(public_specs, pub_resps, strict=True):
        assert resp["status"] not in {403, 503}, (spec, resp)
    pub_records = gateway_harness.fetch_records()
    assert len(pub_records) == 5

    gateway_harness.clear_records()
    blocked_targets = [
        "/admin",
        "/kodi/get_manifest/1",
        f"/s/{api}/manifest.json",
        f"/s/{api}/torznab/api",
        "/cometnet/health",
        f"/configure/../s/{api}/torznab/api",
        "/configure/%2e%2e/admin",
        "/health/..%2F..%2Fadmin",
    ]
    blocked_resps = gateway_harness.curl_batch([{"target": t} for t in blocked_targets])
    for target, resp in zip(blocked_targets, blocked_resps, strict=True):
        assert resp["status"] in {400, 403, 503}, (target, resp)
    assert gateway_harness.fetch_records() == []


def test_ac9_nginx_logs_never_leak_tokens_api_token_or_config_blob(
    gateway_harness: GatewayHarness,
) -> None:
    """AC-9 (INV-7, A3): access and error logs mask every /comet/ line and leak no secrets."""
    stdout, stderr = gateway_harness.nginx_logs()
    secrets = (TOKEN_A, TOKEN_B, TEST_API_TOKEN, TEST_CONFIG_BLOB)
    for secret in secrets:
        assert secret not in stdout, secret
        assert secret not in stderr, secret

    access_lines = [line for line in stdout.splitlines() if "HTTP/" in line]
    assert access_lines
    comet_lines = [line for line in access_lines if "/comet/" in line]
    assert comet_lines
    for line in comet_lines:
        assert re.search(r'"\S+\s+\S*/comet/\*\*\*\s+HTTP/\S+"', line), line

    # Ensure 302, 403, 400 and 503 responses all appeared and stayed masked.
    statuses_seen = set()
    for line in comet_lines:
        match = re.search(r'"\s+(\d{3})\s+', line)
        if match:
            statuses_seen.add(int(match.group(1)))
    assert {302, 403, 400, 503}.issubset(statuses_seen), statuses_seen

    # Error log (`crit`) must have no request lines (no `request: "` entries).
    assert 'request: "' not in stderr


def test_ac11_every_response_hides_the_version_and_carries_security_headers(
    gateway_harness: GatewayHarness,
) -> None:
    """Every class of response: no nginx version anywhere, one copy of each header."""
    api = TEST_API_TOKEN
    cases = [
        ("proxied addon route", f"/comet/{TOKEN_A}/s/{api}/manifest.json", "127.0.0.1:8090", 8090),
        ("public page", "/configure", "127.0.0.1:8090", 8090),
        ("token redirect", f"/comet/{TOKEN_A}/", "127.0.0.1:8090", 8090),
        ("invalid token", "/comet/NotAT0ken/s/x/manifest.json", "127.0.0.1:8090", 8090),
        ("forbidden route", f"/comet/{TOKEN_A}/admin", "127.0.0.1:8090", 8090),
        ("unknown path", "/admin", "127.0.0.1:8090", 8090),
        ("invalid host", "/configure", "bad host!", 8090),
        ("liveness", "/__sg_alive", "127.0.0.1:8099", 8099),
        ("liveness 404", "/nope", "127.0.0.1:8099", 8099),
    ]
    time.sleep(1.0)
    seen: dict[str, int] = {}
    for name, target, host, port in cases:
        res = gateway_harness.exec_nginx(
            f"curl -sS -i --path-as-is -H {_sh_quote('Host: ' + host)} "
            f"http://127.0.0.1:{port}{target}"
        )
        assert res.returncode == 0, (name, res.stderr)
        head, _, body = res.stdout.replace("\r\n", "\n").partition("\n\n")
        status = int(head.split()[1])
        seen[name] = status
        headers = [line.split(":", 1) for line in head.splitlines()[1:] if ":" in line]
        values: dict[str, list[str]] = {}
        for key, value in headers:
            values.setdefault(key.strip().lower(), []).append(value.strip())
        assert values.get("server") == ["nginx"], (name, values.get("server"))
        assert "nginx/" not in body, name
        assert values.get("x-content-type-options") == ["nosniff"], name
        assert values.get("x-frame-options") == ["DENY"], name
        assert values.get("referrer-policy") == ["same-origin"], name
        time.sleep(0.4)
    # The cases really did cover every response class.
    assert seen["proxied addon route"] == 200
    assert seen["token redirect"] == 302
    assert {seen["invalid token"], seen["forbidden route"], seen["unknown path"]} == {403}
    assert seen["invalid host"] == 400
    assert seen["liveness"] == 204 and seen["liveness 404"] == 404


def test_ac12_login_attempts_share_a_strict_bucket_that_nothing_else_draws_from(
    gateway_harness: GatewayHarness,
) -> None:
    """POSTs to configure/login (public or under a token) are capped; nothing else is."""
    time.sleep(12.0)  # let earlier tests' login POST drain from the 6-a-minute bucket
    gateway_harness.clear_records()
    login = {
        "method": "POST",
        "target": "/configure/login",
        "headers": ["Content-Type: application/x-www-form-urlencoded"],
        "body": "password=wrong",
    }
    token_login = {**login, "target": f"/comet/{TOKEN_A}/configure/login"}
    # Other spellings of the same path, which Comet routes to the same login.
    respelled = [
        {**login, "target": "/configure/%6cogin"},
        {**login, "target": "//configure//login"},
    ]
    batch = [login] * 6 + respelled + [token_login] * 2
    statuses = [r["status"] for r in gateway_harness.curl_batch(batch)]
    assert all(status != 503 for status in statuses[:5]), statuses
    assert statuses[6:8] == [503, 503], f"a respelled login path shares the bucket: {statuses}"
    assert statuses[-1] == 503, "the token-route login shares the same bucket"
    login_records = gateway_harness.fetch_records()
    assert len(login_records) <= 6, "throttled attempts must never reach Comet"

    # GETs and addon traffic draw nothing from the login bucket, even right now.
    others = gateway_harness.curl_batch(
        [{"target": "/configure"}]
        + [{"target": f"/comet/{TOKEN_A}/s/{TEST_API_TOKEN}/manifest.json"}] * 15
    )
    assert [r["status"] for r in others] == [200] * 16, others


def _headers_of(
    harness: GatewayHarness, target: str, host: str = "127.0.0.1:8090"
) -> tuple[int, dict[str, list[str]]]:
    res = harness.exec_nginx(
        f"curl -sS -i --path-as-is -H {_sh_quote('Host: ' + host)} http://127.0.0.1:8090{target}"
    )
    assert res.returncode == 0, res.stderr
    head = res.stdout.replace("\r\n", "\n").partition("\n\n")[0]
    values: dict[str, list[str]] = {}
    for line in head.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            values.setdefault(key.strip().lower(), []).append(value.strip())
    return int(head.split()[1]), values


def test_ac13_by_default_no_configure_page_but_addon_routes_and_health_work(
    default_gateway_harness: GatewayHarness,
) -> None:
    """Without COMET_GATEWAY_PUBLIC_CONFIGURE the configure page never reaches Comet."""
    harness = default_gateway_harness
    api = TEST_API_TOKEN
    time.sleep(1.0)
    harness.clear_records()
    login = {
        "method": "POST",
        "headers": ["Content-Type: application/x-www-form-urlencoded"],
        "body": "password=test-password",
    }
    refused = [
        {"target": "/configure"},
        {"target": "/configure/"},
        {**login, "target": "/configure/login"},
        {"target": "/static/x.js"},
        {"target": "/"},
        {"target": f"/comet/{TOKEN_A}/configure"},
        {"target": f"/comet/{TOKEN_A}/s/{api}/configure"},
        {**login, "target": f"/comet/{TOKEN_A}/configure/login"},
        {"target": f"/comet/{TOKEN_A}"},
        {"target": f"/comet/{TOKEN_A}/"},
    ]
    statuses = []
    for spec in refused:  # paced so the denial limiter answers 403, not 503
        statuses.append(harness.curl_batch([spec])[0]["status"])
        time.sleep(0.3)
    assert statuses == [403] * len(refused), statuses
    assert harness.fetch_records() == [], "a configure request reached Comet"

    allowed = harness.curl_batch(
        [
            {"target": f"/comet/{TOKEN_A}/s/{api}/manifest.json"},
            {"target": f"/comet/{TOKEN_A}/s/{api}/stream/movie/tt1.json"},
            {"target": "/health"},
        ]
    )
    assert [r["status"] for r in allowed] == [200, 200, 200], allowed
    assert len(harness.fetch_records()) == 3


@pytest.mark.parametrize("harness_name", ["default_gateway_harness", "gateway_harness"])
def test_ac14_request_bodies_over_64k_are_refused_before_comet(
    harness_name: str, request: pytest.FixtureRequest
) -> None:
    """Sized and chunked bodies, and a login form split into many fields."""
    harness: GatewayHarness = request.getfixturevalue(harness_name)
    manifest = f"/comet/{TOKEN_A}/s/{TEST_API_TOKEN}/manifest.json"
    time.sleep(1.0)
    harness.clear_records()
    script = f"""
set -u
head -c 61440 /dev/zero | tr '\\0' a > /tmp/b60k
head -c 71680 /dev/zero | tr '\\0' a > /tmp/b70k
head -c 1048576 /dev/zero | tr '\\0' a > /tmp/b1m
i=0; : > /tmp/fields; while [ $i -lt 200 ]; do
  printf 'f%d=' $i >> /tmp/fields; head -c 1024 /dev/zero | tr '\\0' a >> /tmp/fields
  printf '&' >> /tmp/fields; i=$((i+1)); done
post() {{ curl -sS -o /dev/null -w '%{{http_code}}\\n' -H 'Host: 127.0.0.1:8090' "$@"; }}
post --data-binary @/tmp/b60k http://127.0.0.1:8090{manifest}
post --data-binary @/tmp/b70k http://127.0.0.1:8090{manifest}
post -H 'Transfer-Encoding: chunked' --data-binary @/tmp/b1m http://127.0.0.1:8090{manifest}
post -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/fields \\
  http://127.0.0.1:8090/configure/login
post -H 'Content-Type: application/json' --data-binary @/tmp/b1m http://127.0.0.1:8090/
rm -f /tmp/b60k /tmp/b70k /tmp/b1m /tmp/fields
"""
    res = harness.exec_nginx(script)
    assert res.returncode == 0, res.stderr
    statuses = [int(line) for line in res.stdout.split()]
    # Under the cap passes through to Comet's routing (405: the manifest is
    # GET-only); everything over it is 413 from the gateway.
    assert statuses == [405, 413, 413, 413, 413], statuses
    records = harness.fetch_records()
    assert len(records) == 1, "only the body under the cap may reach Comet"


@pytest.mark.parametrize(
    ("harness_name", "csp"),
    [
        (
            "default_gateway_harness",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
        (
            "gateway_harness",
            "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
        ),
    ],
)
def test_ac15_every_response_carries_one_content_and_permissions_policy(
    harness_name: str, csp: str, request: pytest.FixtureRequest
) -> None:
    harness: GatewayHarness = request.getfixturevalue(harness_name)
    targets = [
        (f"/comet/{TOKEN_A}/s/{TEST_API_TOKEN}/manifest.json", "127.0.0.1:8090", 200),
        ("/health", "127.0.0.1:8090", 200),
        ("/comet/NotAT0ken/s/x/manifest.json", "127.0.0.1:8090", 403),
        ("/admin", "127.0.0.1:8090", 403),
        ("/health", "bad host!", 400),
    ]
    if harness_name == "gateway_harness":
        targets.append(("/configure", "127.0.0.1:8090", 200))
    time.sleep(1.0)
    for target, host, expected in targets:
        status, values = _headers_of(harness, target, host)
        assert status == expected, (target, status)
        assert values.get("content-security-policy") == [csp], (target, values)
        assert values.get("permissions-policy") == [
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()"
        ], target
        time.sleep(0.4)
