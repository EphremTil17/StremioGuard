"""Opt-in Docker integration tests for Comet patches (AC-4, AC-9, AC-12)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

import pytest

from stremioguard.comet.manager import CometManager, extract_image_source
from stremioguard.comet.validate import run_validation
from stremioguard.comet.validation import image_python_command, import_smoke_test
from stremioguard.config import Runner, SubprocessRunner
from stremioguard.overrides.bundle import SPECS, write_override_bundle

from .conftest import make_comet_config

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="set STREMIOGUARD_DOCKER_TESTS=1 to run Docker integration tests",
)

CONTAINER_PREFIX = "sgfix9-"

COMET_LIVE_IMAGE = (
    "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
)
COMET_PREV_IMAGE = (
    "g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe"
)
POSTGRES_IMAGE = "postgres@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395"


class NamedDockerRunner(Runner):
    """Wraps SubprocessRunner so every docker create/run gets a prefixed name and --network none."""

    def __init__(
        self,
        purpose: str,
        recorded_containers: list[str],
        *,
        drop_mount_container_path: str | None = None,
    ) -> None:
        self._inner = SubprocessRunner()
        self._purpose = purpose
        self._recorded = recorded_containers
        self._drop_mount = drop_mount_container_path

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        forwarded = list(args)
        if self._drop_mount and len(forwarded) >= 2 and forwarded[:2] == ["docker", "run"]:
            filtered: list[str] = []
            idx = 0
            while idx < len(forwarded):
                if (
                    forwarded[idx] == "-v"
                    and idx + 1 < len(forwarded)
                    and f":{self._drop_mount}:" in forwarded[idx + 1]
                ):
                    idx += 2
                    continue
                filtered.append(forwarded[idx])
                idx += 1
            forwarded = filtered

        if len(forwarded) >= 2 and forwarded[0] == "docker" and forwarded[1] in ("create", "run"):
            name = f"{CONTAINER_PREFIX}{self._purpose}-{secrets.token_hex(4)}"
            self._recorded.append(name)
            extra = ["--name", name]
            if "--network" not in forwarded:
                extra.extend(["--network", "none"])
            forwarded = [forwarded[0], forwarded[1], *extra, *forwarded[2:]]

        return self._inner.run(forwarded, check=check, capture=capture, timeout=timeout, env=env)


@pytest.fixture()
def docker_cleanup():
    containers: list[str] = []
    networks: list[str] = []
    try:
        yield containers, networks
    finally:
        for name in reversed(containers):
            subprocess.run(["docker", "rm", "-f", "-v", name], check=False, capture_output=True)
        for name in reversed(networks):
            subprocess.run(["docker", "network", "rm", name], check=False, capture_output=True)


def test_ac4_real_images_pass_both_shapes_and_reject_every_mutation(
    tmp_path: Path, docker_cleanup: tuple[list[str], list[str]]
) -> None:
    """AC-4: validate both local Comet images in two shapes and reject all 7 mutations."""
    containers, _ = docker_cleanup
    runner = NamedDockerRunner("ac4", containers)

    shapes = (
        {
            "name": "gateway-plain-packs",
            "gateway_enabled": True,
            "gateway_addon_base_url": "/comet/sgtest",
            "result_format_style": "plain",
            "patch_episode_pack_results": True,
        },
        {
            "name": "direct-emoji-nopacks",
            "gateway_enabled": False,
            "gateway_addon_base_url": None,
            "result_format_style": "emoji",
            "patch_episode_pack_results": False,
        },
    )

    superset_bundle: Path | None = None
    superset_outputs: dict[str, str] = {}

    for image_idx, image_ref in enumerate((COMET_LIVE_IMAGE, COMET_PREV_IMAGE)):
        with extract_image_source(runner, image_ref) as source_root:
            for shape in shapes:
                bundle_dir = tmp_path / f"img{image_idx}-{shape['name']}"
                write_override_bundle(
                    repo_dir=source_root,
                    state_dir=bundle_dir,
                    result_format_style=str(shape["result_format_style"]),
                    patch_episode_pack_results=bool(shape["patch_episode_pack_results"]),
                    gateway_addon_base_url=shape["gateway_addon_base_url"],  # type: ignore[arg-type]
                    gateway_enabled=bool(shape["gateway_enabled"]),
                    image_digest=image_ref.rsplit("@", 1)[1],
                    patch_fingerprint="ac4-test",
                )
                manifest = json.loads(
                    (bundle_dir / "bundle-manifest.json").read_text(encoding="utf-8")
                )
                outputs = dict(manifest["outputs"])
                t0 = time.monotonic()
                smoke = import_smoke_test(runner, image_ref, outputs, bundle_dir)
                elapsed = time.monotonic() - t0
                print(
                    f"[AC-4] image={image_ref[-12:]} shape={shape['name']} "
                    f"status={smoke['status']} elapsed={elapsed:.2f}s"
                )
                assert smoke["status"] == "passed", smoke["detail"]
                if image_ref == COMET_LIVE_IMAGE and shape["name"] == "gateway-plain-packs":
                    superset_bundle = bundle_dir
                    superset_outputs = outputs

    assert superset_bundle is not None

    def run_mutation(tag: str, mutator, *, custom_runner: Runner = runner) -> str:
        mut_dir = tmp_path / f"mut-{tag}"
        shutil.copytree(superset_bundle, mut_dir)
        mutator(mut_dir)
        t0 = time.monotonic()
        res = import_smoke_test(custom_runner, COMET_LIVE_IMAGE, superset_outputs, mut_dir)
        elapsed = time.monotonic() - t0
        detail = str(res["detail"]).strip()
        print(f"[AC-4({tag})] status={res['status']} elapsed={elapsed:.2f}s detail={detail[:240]}")
        assert res["status"] == "failed", f"mutation {tag} unexpectedly passed"
        return detail

    # (a) Guard install lines removed from app.py
    def mut_a(d: Path) -> None:
        app_path = d / "app.py"
        text = app_path.read_text(encoding="utf-8")
        marker = "# StremioGuard: enforce P2P stripping"
        assert marker in text
        app_path.write_text(text.split(marker, 1)[0], encoding="utf-8")

    detail_a = run_mutation("a", mut_a)
    assert "outermost-middleware" in detail_a

    # (b) Guard module replaced by a pass-through class of the same name
    def mut_b(d: Path) -> None:
        (d / "stremioguard_response_guard.py").write_text(
            "class StremioGuardResponseGuard:\n"
            "    def __init__(self, app):\n"
            "        self.app = app\n"
            "    async def __call__(self, scope, receive, send):\n"
            "        await self.app(scope, receive, send)\n",
            encoding="utf-8",
        )

    detail_b = run_mutation("b", mut_b)
    assert "stream probe" in detail_b

    # (c) Guard filters streams but does not block torznab
    def mut_c(d: Path) -> None:
        guard_path = d / "stremioguard_response_guard.py"
        text = guard_path.read_text(encoding="utf-8")
        patched = text.replace(
            "def _is_torznab_path(path: str) -> bool:\n"
            '    return any(unquote(segment).lower() == "torznab" for segment in path.split("/"))',
            "def _is_torznab_path(path: str) -> bool:\n    return False",
        )
        assert patched != text
        guard_path.write_text(patched, encoding="utf-8")

    detail_c = run_mutation("c", mut_c)
    assert "torznab probe" in detail_c

    # (d) Another middleware added after the guard
    def mut_d(d: Path) -> None:
        app_path = d / "app.py"
        app_path.write_text(
            app_path.read_text(encoding="utf-8")
            + "\nclass _ExtraAfterGuard:\n"
            + "    def __init__(self, app): self.app = app\n"
            + "    async def __call__(self, scope, receive, send):\n"
            + "        await self.app(scope, receive, send)\n"
            + "app.add_middleware(_ExtraAfterGuard)\n",
            encoding="utf-8",
        )

    detail_d = run_mutation("d", mut_d)
    assert "outermost-middleware" in detail_d

    # (e) Top-level function referencing an undefined name appended to stream.py
    def mut_e(d: Path) -> None:
        stream_path = d / "stream.py"
        stream_path.write_text(
            stream_path.read_text(encoding="utf-8")
            + "\ndef _sg_bad_probe():\n    return sg_undefined_top\n",
            encoding="utf-8",
        )

    detail_e = run_mutation("e", mut_e)
    assert "stream.py" in detail_e
    assert "sg_undefined_top" in detail_e
    assert ":" in detail_e

    # (f) Undefined name in a function nested in a method appended to app.py
    def mut_f(d: Path) -> None:
        app_path = d / "app.py"
        app_path.write_text(
            app_path.read_text(encoding="utf-8")
            + "\nclass _SgProbeNested:\n"
            + "    def method(self):\n"
            + "        def inner():\n"
            + "            return sg_undefined_nested\n"
            + "        return inner\n",
            encoding="utf-8",
        )

    detail_f = run_mutation("f", mut_f)
    assert "app.py" in detail_f
    assert "sg_undefined_nested" in detail_f
    assert ":" in detail_f

    # (g) Guard module not mounted
    drop_guard_runner = NamedDockerRunner(
        "ac4-nomount",
        containers,
        drop_mount_container_path="/app/comet/stremioguard_response_guard.py",
    )
    detail_g = run_mutation("g", lambda _d: None, custom_runner=drop_guard_runner)
    assert "No module named" in detail_g or "ModuleNotFoundError" in detail_g


def test_ac9_end_to_end_postgres_and_comet_31a41fa(
    tmp_path: Path, docker_cleanup: tuple[list[str], list[str]]
) -> None:
    """AC-9: compose config resolution, live Postgres, live patched Comet, logs, and routes."""
    containers, _ = docker_cleanup
    runner = NamedDockerRunner("ac9", containers)

    password = "SGF9FAKE-Qz7@w:x/9%Lm#?k$Tq"
    encoded_password = urllib.parse.quote(password, safe="")
    cfg = make_comet_config(
        tmp_path,
        configure_page_password="SGF9FAKE-ConfigurePass",
        default_debrid_apikey="",
        scrape_torrentio="false",
        scrape_zilean="false",
    )
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    manager = CometManager(cfg, runner)
    manager._write_postgres_env(password)
    cfg.runtime_env_file.write_text(manager.render_runtime_env(), encoding="utf-8")

    # Resolve environment through docker compose config (mirrors docker-compose.yml).
    temp_compose = tmp_path / "docker-compose.ac9.yml"
    temp_compose.write_text(
        f"""\
services:
  comet:
    image: {COMET_LIVE_IMAGE}
    environment:
      DATABASE_TYPE: postgresql
    env_file:
      - {cfg.runtime_env_file}
""",
        encoding="utf-8",
    )
    cfg_proc = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            f"{CONTAINER_PREFIX}cfg",
            "-f",
            str(temp_compose),
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    resolved_env: dict[str, str] = json.loads(cfg_proc.stdout)["services"]["comet"]["environment"]
    assert resolved_env["DATABASE_TYPE"] == "postgresql"
    assert resolved_env["DISABLE_TORRENT_STREAMS"] == "True"
    assert resolved_env["DATABASE_URL"].startswith("postgresql://comet:")

    # Render real 31a41fa gateway-shape bundle.
    bundle_dir = tmp_path / "bundle"
    with extract_image_source(runner, COMET_LIVE_IMAGE) as source_root:
        write_override_bundle(
            repo_dir=source_root,
            state_dir=bundle_dir,
            result_format_style="plain",
            patch_episode_pack_results=True,
            gateway_addon_base_url="/comet/SGF9FAKE-tok",
            gateway_enabled=True,
            image_digest=COMET_LIVE_IMAGE.rsplit("@", 1)[1],
            patch_fingerprint="ac9-test",
        )
    manifest = json.loads((bundle_dir / "bundle-manifest.json").read_text(encoding="utf-8"))
    outputs: dict[str, str] = dict(manifest["outputs"])

    # Start throwaway Postgres on --network none.
    pg_name = f"{CONTAINER_PREFIX}pg-{secrets.token_hex(4)}"
    containers.append(pg_name)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            pg_name,
            "--network",
            "none",
            "-e",
            "POSTGRES_USER=comet",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            "POSTGRES_DB=comet",
            POSTGRES_IMAGE,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    pg_ready = False
    for _ in range(30):
        ready = subprocess.run(
            ["docker", "exec", pg_name, "pg_isready", "-U", "comet", "-d", "comet"],
            check=False,
            capture_output=True,
            text=True,
        )
        if ready.returncode == 0:
            pg_ready = True
            break
        time.sleep(1)
    assert pg_ready, "Postgres did not become ready"

    # Start throwaway Comet sharing Postgres's network namespace.
    comet_name = f"{CONTAINER_PREFIX}comet-{secrets.token_hex(4)}"
    containers.append(comet_name)
    comet_cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        comet_name,
        "--network",
        f"container:{pg_name}",
        "-v",
        f"{cfg.data_dir}:/app/data",
    ]
    for output_name, container_path in outputs.items():
        comet_cmd.extend(["-v", f"{bundle_dir / output_name}:{container_path}:ro"])
    for key, value in resolved_env.items():
        comet_cmd.extend(["-e", f"{key}={value}"])
    comet_cmd.append(COMET_LIVE_IMAGE)
    subprocess.run(comet_cmd, check=True, capture_output=True, text=True)

    python_cmd = image_python_command(SubprocessRunner(), COMET_LIVE_IMAGE)
    healthy = False
    for _ in range(60):
        probe = subprocess.run(
            [
                "docker",
                "exec",
                comet_name,
                *python_cmd,
                "-c",
                (
                    "import urllib.request; "
                    "print(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
                    ".read().decode())"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0 and '"ok"' in probe.stdout:
            healthy = True
            break
        time.sleep(1)
    logs_proc = subprocess.run(
        ["docker", "logs", comet_name], check=True, capture_output=True, text=True
    )
    comet_logs = f"{logs_proc.stdout}{logs_proc.stderr}"
    assert healthy, f"Comet never became healthy. Logs:\n{comet_logs}"

    # Verify Postgres holds Comet's tables.
    tables_proc = subprocess.run(
        [
            "docker",
            "exec",
            pg_name,
            "psql",
            "-U",
            "comet",
            "-d",
            "comet",
            "-tAc",
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    table_count = int(tables_proc.stdout.strip())
    assert table_count > 0

    # Verify Comet logs contain masked DB URL, disabled torrents, and zero password fragments.
    assert "Database (postgresql): postgresql://comet:********@127.0.0.1:5432/comet" in comet_logs
    assert "Disable Torrent Streams: True" in comet_logs
    assert password not in comet_logs
    assert encoded_password not in comet_logs
    for secret_form in (password, encoded_password):
        suffix = secret_form.removeprefix("SGF9FAKE-")
        for idx in range(len(suffix) - 5):
            fragment = suffix[idx : idx + 6]
            assert fragment not in comet_logs, f"found password fragment {fragment!r} in logs"

    # Read public API token and probe HTTP endpoints from inside the container.
    token = (cfg.data_dir / "public_api_token.txt").read_text(encoding="utf-8").strip()
    assert token

    def http_get(path: str) -> tuple[int, str]:
        script = (
            "import sys, urllib.error, urllib.request\n"
            "try:\n"
            "    r = urllib.request.urlopen(sys.argv[1], timeout=5)\n"
            "    status, body = r.status, r.read().decode('utf-8', 'replace')\n"
            "except urllib.error.HTTPError as e:\n"
            "    status, body = e.code, e.read().decode('utf-8', 'replace')\n"
            "print(status)\n"
            "print(body)\n"
        )
        res = subprocess.run(
            [
                "docker",
                "exec",
                comet_name,
                *python_cmd,
                "-c",
                script,
                f"http://127.0.0.1:8000{path}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        status_line, _, body = res.stdout.partition("\n")
        return int(status_line.strip()), body

    s1, b1 = http_get(f"/s/{token}/torznab/api?t=caps")
    s2, b2 = http_get(f"/s/{token}/torznab/api?t=movie&imdbid=0133093")
    s3, b3 = http_get(f"/s/{token}/stream/movie/tt0133093.json")
    s4, _ = http_get("/configure")

    print(
        f"[AC-9] tables={table_count} torznab_caps={s1} torznab_movie={s2} "
        f"stream={s3} configure={s4}"
    )
    assert s1 == 404 and "caps" not in b1.lower() and "magnet" not in b1.lower()
    assert s2 == 404 and "magnet" not in b2.lower()
    assert s3 == 200 and "infoHash" not in b3 and "streams" in json.loads(b3)
    assert s4 == 200


def test_ac12_ci_validator_passes_real_image_with_no_lint_stage(
    docker_cleanup: tuple[list[str], list[str]],
) -> None:
    """AC-12: run_validation() passes against 31a41fa with all specs applied and no lint stage."""
    containers, _ = docker_cleanup
    runner = NamedDockerRunner("ac12", containers)
    report = run_validation(runner, COMET_LIVE_IMAGE)
    print(f"[AC-12] report={json.dumps(report)}")

    assert report["status"] == "passed", report["detail"]
    assert report["stage"] == "import"
    assert report["skipped"] == []
    assert set(report["applied"]) == {spec.name for spec in SPECS}  # type: ignore[arg-type]

    validate_src = (
        Path(__file__).resolve().parent.parent / "src" / "stremioguard" / "comet" / "validate.py"
    ).read_text(encoding="utf-8")
    assert '"lint"' not in validate_src
    assert "_undefined_names" not in validate_src
