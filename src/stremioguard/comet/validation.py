"""Validation stages that run the CANDIDATE IMAGE itself, beyond the
render+compile stage in `comet/manager.py` (plan Phase 6).

- Import smoke (mandatory): every applied override is bind-mounted read-only
  at its container path and imported inside the image's own `uv`-managed
  venv, with `--network none`. Comet's settings model (`AppSettings`)
  defaults every field, so no environment stub is required for a clean
  import — verified empirically against `g0ldyy/comet:latest`.
- Ephemeral boot (`--deep`, opt-in): actually starts a throwaway candidate
  container with `--network none` (no network access, sqlite defaults — no
  postgres needed), polls `/health`, fetches `/manifest.json`, then tears down.
  This is the paranoid pre-promotion check, never part of the default
  validation path.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path, PurePosixPath

from stremioguard.comet.smoke_probe import REPORT_PREFIX
from stremioguard.config import Runner

IMPORT_SMOKE_TIMEOUT_SECONDS = 60
_REQUIRED_GUARD_CONTAINER_PATHS = (
    "/app/comet/api/app.py",
    "/app/comet/stremioguard_response_guard.py",
    "/app/comet/api/endpoints/playback.py",
    "/app/comet/stremioguard_stream_guard.py",
    "/app/comet/core/config_validation.py",
    "/app/comet/api/endpoints/admin.py",
)
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


def _stderr_tail(result: subprocess.CompletedProcess[str], *, limit: int = 2000) -> str:
    text = (result.stderr or result.stdout or "").strip()
    if len(text) > limit:
        return text[-limit:]
    return text


def import_smoke_test(
    runner: Runner, image_ref: str, outputs: dict[str, str], bundle_dir: Path
) -> dict[str, object]:
    """Import every applied override's module inside `image_ref`'s own venv,
    scan all code objects for undefined names, and probe the response guard
    against the real ASGI app (`--network none`).

    Returns {"status": "passed"|"failed", "stage": "import", "detail": str}.
    """
    present_paths = set(outputs.values())
    missing_guard = [path for path in _REQUIRED_GUARD_CONTAINER_PATHS if path not in present_paths]
    if missing_guard:
        return {
            "status": "failed",
            "stage": "import",
            "detail": (
                "import smoke test requires guard outputs missing from bundle: "
                + ", ".join(missing_guard)
            ),
        }

    modules = sorted(
        module for module in (container_path_to_module(path) for path in outputs.values()) if module
    )
    if not modules:
        return {
            "status": "failed",
            "stage": "import",
            "detail": "import smoke test found no Python modules to validate",
        }

    probe_source = Path(__file__).with_name("smoke_probe.py").read_text(encoding="utf-8")
    python_command = image_python_command(runner, image_ref)
    args = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--tmpfs",
        "/tmp:size=64m,noexec,nosuid,nodev",
        "-w",
        "/app",
        "--entrypoint",
        python_command[0],
        *_override_mount_args(outputs, bundle_dir),
        image_ref,
        *python_command[1:],
        "-c",
        probe_source,
        *modules,
    ]
    try:
        result = runner.run(args, check=False, timeout=IMPORT_SMOKE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {
            "status": "failed",
            "stage": "import",
            "detail": f"import smoke test timed out after {IMPORT_SMOKE_TIMEOUT_SECONDS}s",
        }

    stdout_lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    last_line = stdout_lines[-1] if stdout_lines else ""
    if not last_line.startswith(REPORT_PREFIX):
        tail = _stderr_tail(result)
        detail = tail or f"smoke probe exited {result.returncode} without emitting a report"
        if tail and result.returncode != 0:
            detail = f"smoke probe exited {result.returncode} without a report:\n{tail}"
        elif tail:
            detail = f"smoke probe did not emit a report:\n{tail}"
        return {"status": "failed", "stage": "import", "detail": detail}

    raw_report = last_line[len(REPORT_PREFIX) :]
    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError as error:
        return {
            "status": "failed",
            "stage": "import",
            "detail": f"malformed smoke report ({error}): {raw_report}",
        }
    if not isinstance(report, dict):
        return {
            "status": "failed",
            "stage": "import",
            "detail": f"malformed smoke report (expected JSON object): {raw_report}",
        }

    findings = report.get("findings")
    finding_lines = [str(item) for item in findings] if isinstance(findings, list) else []
    if result.returncode != 0 or report.get("ok") is not True:
        detail = "\n".join(finding_lines)
        if not detail:
            tail = _stderr_tail(result)
            detail = (
                tail or f"smoke probe failed (exit {result.returncode}, ok={report.get('ok')!r})"
            )
        return {"status": "failed", "stage": "import", "detail": detail}

    return {"status": "passed", "stage": "import", "detail": ""}


def _ephemeral_probe_script(url: str) -> str:
    return (
        "import urllib.request; "
        f"print(urllib.request.urlopen({url!r}, timeout=4).read().decode('utf-8', 'replace'))"
    )


def ephemeral_boot_check(
    runner: Runner,
    image_ref: str,
    outputs: dict[str, str],
    bundle_dir: Path,
    *,
    timeout_seconds: int = EPHEMERAL_BOOT_TIMEOUT_SECONDS,
    poll_interval_seconds: float = EPHEMERAL_BOOT_POLL_INTERVAL_SECONDS,
) -> dict[str, object]:
    """Start a throwaway candidate container with `--network none` (no network
    access, scratch sqlite config — no postgres required), poll `/health`,
    fetch `/manifest.json`, then tear down the container. Opt-in (`--deep`):
    the candidate boots with no network access and creates no Docker network.

    Returns {"status": "passed"|"failed", "stage": "deep", "detail": str}.
    """
    container_id: str | None = None
    try:
        # No --entrypoint override: the whole point of the deep check is to
        # boot the exact artifact compose will run. Re-implementing the
        # image's entrypoint by hand here would silently drift the moment
        # upstream changes it.
        run_args = [
            "docker",
            "run",
            "-d",
            "--network",
            "none",
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

        python_command = image_python_command(runner, image_ref)
        health_probe_cmd = [
            "docker",
            "exec",
            container_id,
            *python_command,
            "-c",
            _ephemeral_probe_script("http://127.0.0.1:8000/health"),
        ]
        deadline = time.monotonic() + timeout_seconds
        healthy = False
        while time.monotonic() < deadline:
            try:
                health = runner.run(health_probe_cmd, check=False, timeout=5)
            except subprocess.TimeoutExpired:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(poll_interval_seconds, remaining))
                continue
            if health.returncode == 0 and '"status":"ok"' in (health.stdout or "").replace(" ", ""):
                healthy = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(poll_interval_seconds, remaining))

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
                    *python_command,
                    "-c",
                    _ephemeral_probe_script("http://127.0.0.1:8000/manifest.json"),
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
        # Captured: this teardown command echoes the container ID, which is
        # noise interactively and corrupts machine-readable stdout (the Phase 7
        # validator prints its JSON report there).
        if container_id:
            runner.run(["docker", "rm", "-f", container_id], check=False)
