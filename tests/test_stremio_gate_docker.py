"""The Stremio image's raw stream gate, against the real image (security hardening).

Builds the image from docker/stremio/Dockerfile and runs it with no network.
A raw stream URL must need basic auth unless its torrent already exists, and
an unauthenticated request must never start a torrent.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="requires Docker and the pinned Stremio base image; set STREMIOGUARD_DOCKER_TESTS=1",
)

REPO = Path(__file__).resolve().parents[1]
IMAGE = f"stremioguard-stremio:gate-test-{uuid.uuid4().hex[:8]}"
CREDENTIALS = "tester:gate-test-password"

PROBE = r"""
const http = require("http");
const [user, password] = process.env.PROBE_CREDENTIALS.split(":");
function get(port, path, auth, timeout = 3000) {
  return new Promise(resolve => {
    const headers = auth ? { Authorization: "Basic " + Buffer.from(auth).toString("base64") } : {};
    const req = http.get({ host: "127.0.0.1", port, path, headers }, res => {
      let body = ""; res.on("data", d => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.setTimeout(timeout, () => { req.destroy(); resolve({ status: "pending", body: "" }); });
    req.on("error", e => resolve({ status: "error", body: e.code }));
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hash = c => c.repeat(40);
const engines = async () => {
  const stats = JSON.parse((await get(11470, "/stats.json")).body || "{}");
  return Object.keys(stats).map(k => k[0]).sort().join("");
};
(async () => {
  for (let i = 0; i < 90; i++) {
    if ((await get(11470, "/heartbeat", null, 1000)).status === 200) break;
    await sleep(1000);
  }
  for (let i = 0; i < 30; i++) {
    if (typeof (await get(8080, "/manifest.json", null, 1000)).status === "number") break;
    await sleep(500);
  }
  const good = `${user}:${password}`, out = {};
  out.raw = (await get(8080, `/${hash("a")}/0`)).status;
  out.raw_largest_file = (await get(8080, `/${hash("a")}/-1`)).status;
  out.raw_wrong_password = (await get(8080, `/${hash("a")}/0`, `${user}:not-the-password`)).status;
  out.settings = (await get(8080, "/settings")).status;
  out.check_route_from_outside = (await get(8080, "/_stremioguard/engine-exists")).status;
  out.engines_after_refusals = await engines();
  await get(8080, `/${hash("b")}/create`, good);
  out.raw_started_torrent = (await get(8080, `/${hash("b")}/0`)).status;
  out.raw_with_password = (await get(8080, `/${hash("c")}/0`, good)).status;
  out.engines_end = await engines();
  console.log("PROBE " + JSON.stringify(out));
})();
"""


@pytest.fixture(scope="module")
def image() -> Iterator[str]:
    subprocess.run(
        ["docker", "build", "-q", "-f", "docker/stremio/Dockerfile", "-t", IMAGE, "."],
        cwd=REPO,
        check=True,
        capture_output=True,
        timeout=900,
    )
    yield IMAGE
    subprocess.run(["docker", "rmi", "-f", IMAGE], capture_output=True, check=False)


def _probe(image: str, *env: str) -> dict[str, object]:
    args = [arg for item in env for arg in ("-e", item)]
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-e",
            "STREMIO_SKIP_HW_PROBE=1",
            "-e",
            "CASTING_DISABLED=1",
            "-e",
            f"PROBE_CREDENTIALS={CREDENTIALS}",
            "-e",
            "PROBE",
            *args,
            "--entrypoint",
            "sh",
            image,
            "-c",
            './stremio-web-service-run.sh >/tmp/run.log 2>&1 & node -e "$PROBE"',
        ],
        env={**os.environ, "PROBE": PROBE},
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    for line in result.stdout.splitlines():
        if line.startswith("PROBE "):
            return json.loads(line.removeprefix("PROBE "))
    raise AssertionError(result.stdout[-2000:] + result.stderr[-2000:])


def test_raw_streams_need_auth_or_a_started_torrent(image: str) -> None:
    user, password = CREDENTIALS.split(":")
    out = _probe(image, f"USERNAME={user}", f"PASSWORD={password}")
    assert out == {
        "raw": 401,
        "raw_largest_file": 401,
        "raw_wrong_password": 401,
        "settings": 401,
        "check_route_from_outside": 404,
        # No refused request started a torrent.
        "engines_after_refusals": "",
        # Passed to the server, which waits for metadata it cannot fetch offline.
        "raw_started_torrent": "pending",
        "raw_with_password": "pending",
        "engines_end": "bc",
    }


@pytest.mark.parametrize(
    "env",
    [
        (),
        (
            f"USERNAME={CREDENTIALS.split(':')[0]}",
            f"PASSWORD={CREDENTIALS.split(':')[1]}",
            "STREMIO_OPEN_RAW_STREAMS=1",
        ),
    ],
    ids=["no-auth-configured", "opted-out"],
)
def test_without_auth_or_opted_out_raw_streams_behave_as_upstream(
    image: str, env: tuple[str, ...]
) -> None:
    out = _probe(image, *env)
    assert out["raw"] == "pending" and out["engines_after_refusals"] == "a"
    assert out["check_route_from_outside"] == 404
