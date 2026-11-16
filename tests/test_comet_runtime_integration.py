"""Opt-in Docker integration tests for handoff 0013 (AC-17, AC-19)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from stremioguard.comet.manager import CometManager
from stremioguard.comet.state import CometState
from stremioguard.config import (
    GENERATED_COMPOSE_FILE,
    PUBLISHED_COMPOSE_FILE,
    PUBLISHED_ENV_FILE,
    SubprocessRunner,
    compose_command,
)

from .conftest import make_comet_config

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="set STREMIOGUARD_DOCKER_TESTS=1 to run Docker integration tests",
)

TEST_PREFIX = os.environ.get("STREMIOGUARD_TEST_PREFIX", "sgfix13-")

COMET_LIVE_DIGEST = "sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
COMET_LIVE_IMAGE = f"g0ldyy/comet@{COMET_LIVE_DIGEST}"
BUSYBOX_DIGEST = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
BUSYBOX_IMAGE = f"busybox@{BUSYBOX_DIGEST}"


@pytest.fixture()
def docker_cleanup():
    containers: list[str] = []
    compose_roots: list[Path] = []
    tags: list[str] = []
    try:
        yield containers, compose_roots, tags
    finally:
        for root in reversed(compose_roots):
            subprocess.run(
                compose_command(root, "down", "-v"),
                check=False,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["docker", "compose", "-p", root.name, "down", "-v"],
                check=False,
                capture_output=True,
                text=True,
            )
        for name in reversed(containers):
            subprocess.run(["docker", "rm", "-f", "-v", name], check=False, capture_output=True)
        for tag in reversed(tags):
            subprocess.run(["docker", "rmi", tag], check=False, capture_output=True)


def test_ac17a_real_image_digest_picks_configured_repository(
    tmp_path: Path, docker_cleanup: tuple[list[str], list[Path], list[str]]
) -> None:
    """AC-17 (a): _image_digest selects the configured repository's entry on real Docker."""
    _, _, tags = docker_cleanup
    runner = SubprocessRunner()

    cfg_busybox = make_comet_config(tmp_path / "bb", image="busybox")
    mgr_busybox = CometManager(cfg_busybox, runner)
    assert mgr_busybox._image_digest(BUSYBOX_IMAGE) == BUSYBOX_DIGEST

    extra_tag = f"{TEST_PREFIX}aaa/bb:t"
    tags.append(extra_tag)
    subprocess.run(["docker", "tag", BUSYBOX_IMAGE, extra_tag], check=True, capture_output=True)

    # Even with two RepoDigests entries present, each COMET_IMAGE selects its own repo
    assert mgr_busybox._image_digest(BUSYBOX_IMAGE) == BUSYBOX_DIGEST

    cfg_tagged = make_comet_config(tmp_path / "tagged", image=f"{TEST_PREFIX}aaa/bb")
    mgr_tagged = CometManager(cfg_tagged, runner)
    assert mgr_tagged._image_digest(BUSYBOX_IMAGE) == BUSYBOX_DIGEST
    assert mgr_tagged._image_digest(extra_tag) == BUSYBOX_DIGEST


def test_ac17b_real_compose_bundle_convergence_and_recreate(
    tmp_path: Path, docker_cleanup: tuple[list[str], list[Path], list[str]]
) -> None:
    """AC-17 (b): ensure_running_bundle recreates Comet only after a bundle directory swap."""
    containers, compose_roots, _ = docker_cleanup
    root = tmp_path / f"{TEST_PREFIX}compose-{secrets.token_hex(4)}"
    root.mkdir(parents=True)
    compose_roots.append(root)

    container_name = f"{TEST_PREFIX}comet-{secrets.token_hex(4)}"
    containers.append(container_name)

    (root / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8")
    (root / PUBLISHED_ENV_FILE).parent.mkdir(parents=True, exist_ok=True)
    (root / PUBLISHED_ENV_FILE).write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8"
    )

    cfg = make_comet_config(root, gateway_enabled=False, container_name=container_name)
    CometState(active_digest=COMET_LIVE_DIGEST).save(cfg.state_dir / "state.json")

    bundle_dir = cfg.bundle_dir(COMET_LIVE_DIGEST)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    stream_v1 = b"# bundle v1\n"
    (bundle_dir / "stream.py").write_bytes(stream_v1)
    manifest = {
        "active_digest": COMET_LIVE_DIGEST,
        "outputs": {"stream.py": "/app/comet/api/endpoints/stream.py"},
    }
    (bundle_dir / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    base_compose = (
        "services:\n"
        "  comet:\n"
        f"    image: {COMET_LIVE_IMAGE}\n"
        f"    container_name: {container_name}\n"
        "    network_mode: none\n"
        '    entrypoint: ["/usr/bin/sleep", "300"]\n'
    )
    (root / "docker-compose.yml").write_text(base_compose, encoding="utf-8")
    (root / PUBLISHED_COMPOSE_FILE).write_text(base_compose, encoding="utf-8")
    override_compose = (
        "services:\n"
        "  comet:\n"
        f"    image: {COMET_LIVE_IMAGE}\n"
        "    volumes:\n"
        f"      - {bundle_dir / 'stream.py'}:/app/comet/api/endpoints/stream.py:ro\n"
    )
    (root / GENERATED_COMPOSE_FILE).write_text(override_compose, encoding="utf-8")

    subprocess.run(
        compose_command(root, "up", "-d"),
        check=True,
        capture_output=True,
        text=True,
    )

    runner = SubprocessRunner()
    manager = CometManager(cfg, runner)

    t0 = time.monotonic()
    manager.verify_running_image(require_running=True)
    id_before = manager._running_container_id("comet")
    assert id_before
    manager.ensure_running_bundle()
    t_noop = time.monotonic() - t0
    assert manager._running_container_id("comet") == id_before

    # Re-render bundle directory by rename, matching _render_bundle
    staging = bundle_dir.with_name(f".staging-{secrets.token_hex(4)}")
    staging.mkdir()
    stream_v2 = b"# bundle v2 updated\n"
    (staging / "stream.py").write_bytes(stream_v2)
    (staging / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    retired = bundle_dir.with_name(f".retired-{bundle_dir.name}-{secrets.token_hex(4)}")
    os.rename(bundle_dir, retired)
    os.rename(staging, bundle_dir)
    shutil.rmtree(retired)

    t1 = time.monotonic()
    manager.ensure_running_bundle()
    manager.verify_running_image(require_running=True)
    t_recreate = time.monotonic() - t1

    id_after = manager._running_container_id("comet")
    assert id_after and id_after != id_before

    in_container = subprocess.run(
        ["docker", "exec", id_after, "/usr/bin/sha256sum", "/app/comet/api/endpoints/stream.py"],
        check=True,
        capture_output=True,
        text=True,
    )
    observed_hash = in_container.stdout.split(" ", 1)[0].strip()
    assert observed_hash == hashlib.sha256(stream_v2).hexdigest()
    print(f"[AC-17b] noop_check={t_noop:.2f}s recreate_and_verify={t_recreate:.2f}s")


def test_ac19_starlette_routes_in_live_comet_image(
    docker_cleanup: tuple[list[str], list[Path], list[str]],
) -> None:
    """AC-19: bare Response (no content-type), PlainTextResponse and JSONResponse are filtered."""
    containers, _, _ = docker_cleanup
    name = f"{TEST_PREFIX}ac19-{secrets.token_hex(4)}"
    containers.append(name)
    guard_file = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "stremioguard"
        / "overrides"
        / "response_guard.py"
    )
    script = """
import asyncio, importlib.util, json
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

spec = importlib.util.spec_from_file_location("rg", "/tmp/response_guard.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

payload = {
    "streams": [
        {"name": "p2p", "infoHash": "0123456789abcdef0123456789abcdef01234567"},
        {"name": "http", "url": "https://comet.example/1"},
    ]
}
raw_bytes = json.dumps(payload).encode("utf-8")

async def bare(request):
    return Response(content=raw_bytes)

async def plain(request):
    return PlainTextResponse(raw_bytes.decode("utf-8"))

async def json_ep(request):
    return JSONResponse(payload)

app = Starlette(routes=[
    Route("/bare", bare),
    Route("/plain", plain),
    Route("/json", json_ep),
])
guarded = mod.StremioGuardResponseGuard(app)

async def call(asgi_app, path):
    status = 0
    headers = []
    chunks = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(msg):
        nonlocal status, headers
        if msg["type"] == "http.response.start":
            status = msg["status"]
            headers = [(k.decode(), v.decode()) for k, v in msg.get("headers", ())]
        elif msg["type"] == "http.response.body":
            chunks.append(msg.get("body", b""))
    await asgi_app(
        {"type": "http", "asgi": {"version": "3.0"}, "method": "GET", "path": path, "headers": []},
        receive,
        send,
    )
    return status, headers, b"".join(chunks).decode("utf-8")

async def main():
    bare_status, bare_hdrs, _ = await call(app, "/bare")
    assert bare_status == 200
    assert not any(k.lower() == "content-type" for k, _ in bare_hdrs), bare_hdrs
    results = {}
    for route in ("/bare", "/plain", "/json"):
        st, hdrs, body = await call(guarded, route)
        results[route] = {"status": st, "headers": hdrs, "body": json.loads(body)}
    print(json.dumps({"bare_unwrapped_headers": bare_hdrs, "guarded": results}))

asyncio.run(main())
"""
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--entrypoint",
            "/app/.venv/bin/python",
            "-v",
            f"{guard_file}:/tmp/response_guard.py:ro",
            COMET_LIVE_IMAGE,
            "-c",
            script,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    out = json.loads(proc.stdout.strip())
    assert not any(k.lower() == "content-type" for k, _ in out["bare_unwrapped_headers"])
    for route in ("/bare", "/plain", "/json"):
        entry = out["guarded"][route]
        assert entry["status"] == 200
        assert entry["body"] == {"streams": [{"name": "http", "url": "https://comet.example/1"}]}
