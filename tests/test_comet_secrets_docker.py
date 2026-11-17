"""Real Comet image: no configured secret reaches its logs, and no credentialed CORS.

Runs Comet's own code from the pinned image, offline (`--network none`, read-only
root), once with upstream's files as a positive control (which must leak and
allow credentials) and once with StremioGuard's patched files.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from stremioguard.comet.manager import extract_image_source
from stremioguard.config import SubprocessRunner
from stremioguard.overrides.bundle import SPECS, RenderContext

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="set STREMIOGUARD_DOCKER_TESTS=1 to run Docker integration tests",
)

CONTAINER_PREFIX = os.environ.get("STREMIOGUARD_TEST_PREFIX", "sgfix-secrets-")
COMET_IMAGES = (
    "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea",
    "g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe",
)

CONTEXT = RenderContext(result_format_style="default", patch_episode_pack_results=False)

# Canary values for every kind of credential Comet is given.
CANARIES = {
    "TORBOX_API_KEY": "sgcanaryTORBOXkey0123456789",
    "ADMIN_DASHBOARD_PASSWORD": "sgcanaryADMINpw01",
    "CONFIGURE_PAGE_PASSWORD": "sgcanary/CONF+pw=1&x",
    "PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY": "sgcanaryDEBRIDkey01",
    "DEBRIDIO_PROVIDER_KEY": "sgcanaryDEBRIDIOkey1",
    "DEBRIDIO_API_KEY": "sgcanaryDEBRIDIOapi1",
    "PUBLIC_API_TOKEN": "sgcanaryAPItoken0001",
}
DB_PASSWORD = "sgcanaryDBpw0001"
CONFIG_BLOB = "eyJhcGlLZXkiOiJTRUNSRVQifQ"

LOG_PROBE = f"""
import os, sys, time, urllib.parse
from comet.core.logger import logger, log_capture, log_scraper_error
from comet.core.models import settings

class HTTPFailure(Exception):
    status = 404
    def __str__(self):
        return "404, message='Not Found', url='https://addon.debridio.com/{CONFIG_BLOB}/s/m.json'"

log_scraper_error("TorBox", settings.TORBOX_API_KEY, "tt1", ConnectionError(
    "boom " + os.environ["TORBOX_API_KEY"]))
log_scraper_error(
    "Debridio", f"{{settings.DEBRIDIO_PROVIDER}}|{{settings.DEBRIDIO_PROVIDER_KEY}}", "tt2",
    HTTPFailure())
log_scraper_error("Torrentio", "https://u:pw12345678@torrentio.example/opt=rd=abc/m.json", "tt3",
    TimeoutError("timed out"))
quoted = urllib.parse.quote(os.environ["CONFIGURE_PAGE_PASSWORD"], safe="")
logger.info(f"plain {{settings.ADMIN_DASHBOARD_PASSWORD}} quoted {{quoted}}")
try:
    secret_local = settings.PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY
    raise RuntimeError(f"failed with {{secret_local}}")
except RuntimeError:
    logger.exception("exception path")
logger.info(f"token {{settings.PUBLIC_API_TOKEN}} db {{settings.DATABASE_URL}}")
logger.info("LINE-CHECK scraping https://torrentio.strem.fun works")
logger.complete()
time.sleep(0.5)
print("CAPTURE:" + "||".join(e["message"] for e in log_capture.get_logs()), file=sys.stderr)
"""

CORS_PROBE = """
from fastapi.testclient import TestClient
from comet.api.app import app
from comet.core.models import settings
client = TestClient(app, raise_server_exceptions=False)
prefix = settings.STREMIO_API_PREFIX
for origin in ("https://evil.example", "null"):
    for cookie in (False, True):
        headers = {"Origin": origin}
        if cookie:
            headers["Cookie"] = "session=abc"
        for path in (prefix + "/manifest.json", "/configure", "/admin"):
            r = client.get(path, headers=headers, follow_redirects=False)
            print("ROW", path == prefix + "/manifest.json", r.status_code,
                  r.headers.get("access-control-allow-origin"),
                  r.headers.get("access-control-allow-credentials"))
        r = client.options(prefix + "/manifest.json", headers={
            **headers, "Access-Control-Request-Method": "GET"})
        print("ROW", True, r.status_code, r.headers.get("access-control-allow-origin"),
              r.headers.get("access-control-allow-credentials"))
"""


@pytest.fixture(scope="module", params=COMET_IMAGES, ids=lambda ref: ref[-8:])
def sources(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[str, Path, Path]]:
    """(image, upstream comet/ tree, patched comet/ tree)."""
    image = str(request.param)
    root = tmp_path_factory.mktemp("comet-src")
    with extract_image_source(SubprocessRunner(), image) as extracted:
        upstream = root / "upstream" / "comet"
        shutil.copytree(extracted / "comet", upstream)
    patched = root / "patched" / "comet"
    shutil.copytree(upstream, patched)
    for spec in SPECS:
        if spec.name in {"logger", "api_app", "response_guard", "stream_guard", "playback"}:
            target = patched / spec.container_path.removeprefix("/app/comet/")
            rendered = spec.render(upstream.parent, CONTEXT)
            assert rendered is not None
            target.write_text(rendered, encoding="utf-8")
    # Upstream's app.py imports nothing of ours; give both trees the guard module
    # so only the patched files differ.
    shutil.copy(patched / "stremioguard_response_guard.py", upstream)
    shutil.copy(patched / "stremioguard_stream_guard.py", upstream)
    yield image, upstream, patched


def _run(image: str, comet_dir: Path, probe: str) -> str:
    env = [
        arg
        for name, value in {
            **CANARIES,
            "DEBRIDIO_PROVIDER": "torbox",
            "DATABASE_TYPE": "sqlite",
            "DATABASE_URL": f"postgresql://comet:{DB_PASSWORD}@127.0.0.1:5432/comet",
            "PUBLIC_API_TOKEN_FILE": "/tmp/token.txt",
            "DATA_DIR": "/tmp",
        }.items()
        for arg in ("-e", f"{name}={value}")
    ]
    name = f"{CONTAINER_PREFIX}{uuid.uuid4().hex[:8]}"
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "-v",
            f"{comet_dir}:/sg/comet:ro",
            *env,
            "-e",
            "PROBE",
            "--entrypoint",
            "sh",
            image,
            "-c",
            "cd /sg && P=python; test -x /app/.venv/bin/python && P=/app/.venv/bin/python; "
            'PYTHONPATH=/sg:/app exec "$P" -c "$PROBE"',
        ],
        env={**os.environ, "PROBE": probe},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    # `-e PROBE` hands the probe to the container; `-c "$PROBE"` runs it there.
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout + result.stderr


def _leaks(output: str) -> list[str]:
    forms = [DB_PASSWORD, CONFIG_BLOB, "pw12345678", "opt=rd=abc"]
    for value in CANARIES.values():
        forms.append(value)
        forms.append(urllib.parse.quote(value, safe=""))
    return sorted({form for form in forms if form in output})


def test_upstream_leaks_and_patched_comet_logs_no_secret(sources: tuple[str, Path, Path]) -> None:
    image, upstream, patched = sources
    upstream_out = _run(image, upstream, LOG_PROBE)
    assert CANARIES["TORBOX_API_KEY"] in upstream_out, "positive control: upstream must leak"
    patched_out = _run(image, patched, LOG_PROBE)
    assert _leaks(patched_out) == []
    # The capture behind /admin/api/logs went through the same scrubber.
    capture = patched_out.split("CAPTURE:", 1)[1]
    assert "with TorBox, you are most likely being ratelimited: ConnectionError" in capture
    assert "Torrentio (https://torrentio.example)" in patched_out
    # Ordinary text is untouched.
    assert "LINE-CHECK scraping https://torrentio.strem.fun works" in patched_out


def test_patched_comet_never_allows_credentialed_cross_origin_reads(
    sources: tuple[str, Path, Path],
) -> None:
    image, upstream, patched = sources

    def rows(comet_dir: Path) -> list[list[str]]:
        output = _run(image, comet_dir, CORS_PROBE)
        return [line.split()[1:] for line in output.splitlines() if line.startswith("ROW ")]

    upstream_rows = rows(upstream)
    assert upstream_rows and all(row[3] == "true" for row in upstream_rows), "positive control"
    patched_rows = rows(patched)
    assert len(patched_rows) == len(upstream_rows) == 16
    for is_addon, status, allow_origin, allow_credentials in patched_rows:
        assert allow_credentials == "None"
        assert allow_origin == "*"
        if is_addon == "True":
            assert status == "200"  # addon clients keep uncredentialed access


STDLIB_LOG_PROBE = """
import logging, os, time
import comet.core.logger as comet_logger
key = os.environ["TORBOX_API_KEY"]
logging.getLogger("mediaflow_proxy.handlers").error(
    "Upstream service error: url='https://cdn.example/dl/%s/v.mkv?token=%s'", key, key)
try:
    raise RuntimeError("failed for " + key)
except RuntimeError:
    logging.getLogger("aiohttp.client").exception("library traceback")
comet_logger.logger.complete()
time.sleep(0.5)
"""


def test_library_logging_goes_through_the_scrubber(sources: tuple[str, Path, Path]) -> None:
    image, upstream, patched = sources
    upstream_out = _run(image, upstream, STDLIB_LOG_PROBE)
    assert CANARIES["TORBOX_API_KEY"] in upstream_out, "positive control: upstream must leak"
    patched_out = _run(image, patched, STDLIB_LOG_PROBE)
    assert _leaks(patched_out) == []
    assert "mediaflow_proxy.handlers: Upstream service error: url='https://cdn.example'" in (
        patched_out
    )
    assert "aiohttp.client: library traceback" in patched_out


STREAM_PROBE = r"""
import asyncio, json, threading, http.server
from starlette.requests import Request
import mediaflow_proxy.handlers as handlers
import mediaflow_proxy.utils.http_utils as http_utils
import comet.api.endpoints.playback  # installs the guard when patched

class Internal(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/hop":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/internal" % internal_port)
            self.end_headers()
            return
        body = b'{"internal": "namespace-only data"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

internal = http.server.HTTPServer(("127.0.0.1", 0), Internal)
internal_port = internal.server_address[1]
hop = http.server.HTTPServer(("127.0.0.2", 0), Internal)
for server in (internal, hop):
    threading.Thread(target=server.serve_forever, daemon=True).start()

scope = {
    "type": "http", "method": "GET", "path": "/playback/x",
    "query_string": b"h_authorization=Bearer+SMUGGLED&r_set-cookie=admin%3Dpwn"
    b"&x_headers=content-type",
    "headers": [(b"range", b"bytes=0-")],
}
request = Request(scope)
playback_headers = (
    comet.api.endpoints.playback._sg_safe_proxy_headers(request)
    if hasattr(comet.api.endpoints.playback, "_sg_safe_proxy_headers")
    else http_utils.get_proxy_headers(request)
)
print("HEADERS", json.dumps({
    "request": playback_headers.request, "response": playback_headers.response,
    "remove": playback_headers.remove, "propagate": playback_headers.propagate}))

patched = hasattr(comet.api.endpoints.playback, "_sg_safe_proxy_headers")
if patched:
    import comet.stremioguard_stream_guard as guard
    print("PUBLIC", json.dumps({a: guard.is_public_address(a) for a in [
        "8.8.8.8", "127.0.0.1", "10.1.2.3", "172.18.0.2", "192.168.1.5", "169.254.169.254",
        "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1",
        "2002:7f00:1::", "224.0.0.1", "2606:4700:4700::1111", "not-an-ip"]}))
else:
    print("PUBLIC {}")

async def fetch(url):
    response = await handlers.handle_stream_request("GET", url, playback_headers)
    body = b""
    if hasattr(response, "body_iterator"):
        async for chunk in response.body_iterator:
            body += chunk if isinstance(chunk, bytes) else chunk.encode()
        if response.background:
            await response.background()
    else:
        body = response.body
    return response.status_code, body.decode(errors="replace")

internal_url = "http://127.0.0.1:%d/internal" % internal_port
print("DIRECT", json.dumps(asyncio.run(fetch(internal_url))))
print("NAMED", json.dumps(asyncio.run(fetch("http://localhost:%d/internal" % internal_port))))
# A first hop the guard is told to trust, redirecting into the namespace:
if patched:
    guard.is_public_address = lambda address: address == "127.0.0.2"
print("REDIRECT", json.dumps(asyncio.run(fetch("http://127.0.0.2:%d/hop" % hop.server_address[1]))))
"""


def _stream_results(image: str, comet_dir: Path) -> dict[str, Any]:
    import json

    out = _run(image, comet_dir, STREAM_PROBE)
    rows = {}
    for line in out.splitlines():
        tag, _, payload = line.partition(" ")
        if tag in {"HEADERS", "PUBLIC", "DIRECT", "NAMED", "REDIRECT"}:
            rows[tag] = json.loads(payload)
    assert set(rows) == {"HEADERS", "PUBLIC", "DIRECT", "NAMED", "REDIRECT"}, out[-3000:]
    return rows


def test_stream_proxy_hardening(sources: tuple[str, Path, Path]) -> None:
    image, upstream, patched = sources
    # The guard module exists in both trees; only the patched playback imports
    # it (the probe imports it only when patched), so the upstream run is the
    # unhardened library.
    before = _stream_results(image, upstream)
    assert before["HEADERS"]["response"] == {"set-cookie": "admin=pwn"}, "positive control"
    assert before["HEADERS"]["request"]["authorization"] == "Bearer SMUGGLED"
    assert "namespace-only data" in before["DIRECT"][1], "positive control"
    assert "namespace-only data" in before["REDIRECT"][1], "positive control: redirect followed"

    after = _stream_results(image, patched)
    headers = after["HEADERS"]
    assert headers["request"] == {
        "range": "bytes=0-",
        "user-agent": headers["request"]["user-agent"],
    }
    assert headers["response"] == {} and headers["remove"] == [] and headers["propagate"] == {}
    public = after["PUBLIC"]
    assert public.pop("8.8.8.8") is True and public.pop("2606:4700:4700::1111") is True
    assert not any(public.values()), public
    for tag in ("DIRECT", "NAMED", "REDIRECT"):
        status, body = after[tag]
        assert status >= 400, (tag, status, body)
        assert "namespace-only data" not in body, tag
        assert "127.0.0.1" not in body and "localhost" not in body, (tag, body)
