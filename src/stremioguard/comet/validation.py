"""Validation stages that run the CANDIDATE IMAGE itself, beyond the
render+compile stage in `comet/manager.py` (plan Phase 6).

- Import smoke (mandatory): every applied override is bind-mounted read-only
  at its container path and imported inside the image's own `uv`-managed
  venv, with `--network none`. Comet's settings model (`AppSettings`)
  defaults every field, so no environment stub is required for a clean
  import — verified empirically against `g0ldyy/comet:latest`.
- Ephemeral boot (`--deep`, opt-in): actually starts a throwaway candidate
  container on an isolated bridge network (no published ports, sqlite
  defaults — no postgres needed), polls `/health`, fetches `/manifest.json`,
  then tears down. This is the paranoid pre-promotion check, never part of
  the default validation path.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import time
from pathlib import Path, PurePosixPath

from stremioguard.config import Runner

IMPORT_SMOKE_TIMEOUT_SECONDS = 60
# Comet's single gunicorn worker runs its anime-mapping refresh synchronously
# at startup and won't answer ANY request, including /health, until it's
# done — observed taking ~110s against the real image. The default here
# gives real margin above that rather than a number that just looked safe.
EPHEMERAL_BOOT_TIMEOUT_SECONDS = 180
EPHEMERAL_BOOT_POLL_INTERVAL_SECONDS = 2


def container_path_to_module(container_path: str) -> str | None:
    """`/app/comet/api/endpoints/stream.py` -> `comet.api.endpoints.stream`.
    Returns None for non-Python outputs (e.g. the configure-page template)."""
    if not container_path.endswith(".py"):
        return None
    relative = container_path.removeprefix("/app/").removesuffix(".py")
    return relative.replace("/", ".")


def _override_mount_args(outputs: dict[str, str], bundle_dir: Path) -> list[str]:
    args: list[str] = []
    for output_name, container_path in outputs.items():
        if not container_path.endswith(".py"):
            continue
        args += ["-v", f"{bundle_dir / output_name}:{container_path}:ro"]
    return args


def image_python_command(runner: Runner, image_ref: str) -> list[str]:
    """How to invoke THIS image's own Python, read from its entrypoint.

    Not hardcoded, for the same reason the deep boot check runs the image's
    own entrypoint: upstream changes it. Images through 2026-06 declare
    `uv run python -m comet.main` and need `uv run python`, because the bare
    `python` there is the system one without Comet's dependencies; the
    2026-07 image dropped uv, put its venv first on PATH, and declares
    `python -m comet.main`. Taking the entrypoint prefix up to and including
    the interpreter adapts to both. Falls back to plain `python`.
    """
    result = runner.run(
        ["docker", "image", "inspect", image_ref, "--format", "{{json .Config.Entrypoint}}"],
        check=False,
    )
    if result.returncode == 0:
        try:
            entrypoint = json.loads((result.stdout or "").strip() or "null")
        except json.JSONDecodeError:
            entrypoint = None
        if isinstance(entrypoint, list):
            for index, part in enumerate(entrypoint):
                if isinstance(part, str) and PurePosixPath(part).name.startswith("python"):
                    return [str(item) for item in entrypoint[: index + 1]]
    return ["python"]


def import_smoke_test(
    runner: Runner, image_ref: str, outputs: dict[str, str], bundle_dir: Path
) -> dict[str, object]:
    """Import every applied override's module inside `image_ref`'s own venv,
    each bind-mounted read-only over its container path. `--network none`:
    this is a static import check, not a live boot.

    Returns {"status": "passed"|"failed", "stage": "import", "detail": str}.
    """
    modules = sorted(
        module for module in (container_path_to_module(path) for path in outputs.values()) if module
    )
    if not modules:
        return {"status": "passed", "stage": "import", "detail": ""}

    python_command = image_python_command(runner, image_ref)
    args = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-w",
        "/app",
        "--entrypoint",
        python_command[0],
        *_override_mount_args(outputs, bundle_dir),
        image_ref,
        *python_command[1:],
        "-c",
        "; ".join(f"import {module}" for module in modules),
    ]
    try:
        result = runner.run(args, check=False, timeout=IMPORT_SMOKE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "stage": "import",
            "detail": f"import smoke test timed out after {IMPORT_SMOKE_TIMEOUT_SECONDS}s",
        }
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown import error").strip()
        return {"status": "failed", "stage": "import", "detail": detail}
    return {"status": "passed", "stage": "import", "detail": ""}


def ephemeral_boot_check(
    runner: Runner,
    image_ref: str,
    outputs: dict[str, str],
    bundle_dir: Path,
    *,
    timeout_seconds: int = EPHEMERAL_BOOT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = EPHEMERAL_BOOT_POLL_INTERVAL_SECONDS,
) -> dict[str, object]:
    """Start a throwaway candidate container on an isolated bridge network
    (no published ports, scratch sqlite config — no postgres required), poll
    `/health`, fetch `/manifest.json`, then tear down both the container and
    the network. Opt-in (`--deep`): a real boot is slow and makes an
    outbound network call (anime-mapping refresh), so this never runs as
    part of the default validation path.

    Returns {"status": "passed"|"failed", "stage": "deep", "detail": str}.
    """
    network_name = f"stremioguard-comet-deep-{secrets.token_hex(4)}"
    container_id: str | None = None
    try:
        created = runner.run(["docker", "network", "create", network_name], check=False)
        if created.returncode != 0:
            detail = (created.stderr or created.stdout or "unknown docker error").strip()
            return {
                "status": "failed",
                "stage": "deep",
                "detail": f"network create failed: {detail}",
            }

        # No --entrypoint override: the whole point of the deep check is to
        # boot the exact artifact compose will run. Re-implementing the
        # image's entrypoint by hand here would silently drift the moment
        # upstream changes it.
        run_args = [
            "docker",
            "run",
            "-d",
            "--network",
            network_name,
            *_override_mount_args(outputs, bundle_dir),
            image_ref,
        ]
        started = runner.run(run_args, check=False)
        if started.returncode != 0:
            detail = (started.stderr or started.stdout or "unknown docker error").strip()
            return {
                "status": "failed",
                "stage": "deep",
                "detail": f"container start failed: {detail}",
            }
        container_id = (started.stdout or "").strip()
        if not container_id:
            return {
                "status": "failed",
                "stage": "deep",
                "detail": "docker run produced no container ID",
            }

        deadline = time.monotonic() + timeout_seconds
        healthy = False
        while time.monotonic() < deadline:
            try:
                health = runner.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "wget",
                        "-qO-",
                        "http://127.0.0.1:8000/health",
                    ],
                    check=False,
                    timeout=5,
                )
            except subprocess.TimeoutExpired:
                time.sleep(poll_interval_seconds)
                continue
            if health.returncode == 0 and '"status":"ok"' in (health.stdout or "").replace(" ", ""):
                healthy = True
                break
            time.sleep(poll_interval_seconds)

        if not healthy:
            logs = runner.run(["docker", "logs", "--tail", "60", container_id], check=False)
            tail = f"{logs.stdout or ''}{logs.stderr or ''}".strip()
            return {
                "status": "failed",
                "stage": "deep",
                "detail": f"/health never became reachable within {timeout_seconds}s.\n{tail}",
            }

        try:
            manifest = runner.run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "wget",
                    "-qO-",
                    "http://127.0.0.1:8000/manifest.json",
                ],
                check=False,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "failed",
                "stage": "deep",
                "detail": "manifest.json request timed out after a healthy boot.",
            }
        if manifest.returncode != 0 or not (manifest.stdout or "").strip():
            return {
                "status": "failed",
                "stage": "deep",
                "detail": "manifest.json was not reachable after a healthy boot.",
            }
        return {"status": "passed", "stage": "deep", "detail": ""}
    finally:
        # Captured: these teardown commands echo the container ID / network
        # name, which is noise interactively and corrupts machine-readable
        # stdout (the Phase 7 validator prints its JSON report there).
        if container_id:
            runner.run(["docker", "rm", "-f", container_id], check=False)
        runner.run(["docker", "network", "rm", network_name], check=False)
