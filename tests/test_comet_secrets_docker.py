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
        if spec.name in {"logger", "api_app", "response_guard"}:
            target = patched / spec.container_path.removeprefix("/app/comet/")
            rendered = spec.render(upstream.parent, CONTEXT)
            assert rendered is not None
            target.write_text(rendered, encoding="utf-8")
    # Upstream's app.py imports nothing of ours; give both trees the guard module
    # so only the patched files differ.
    shutil.copy(patched / "stremioguard_response_guard.py", upstream)
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
