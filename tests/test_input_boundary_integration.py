"""Opt-in Docker/Compose integration tests for env and image input boundaries."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from stremioguard import env
from stremioguard.comet.manager import extract_image_source
from stremioguard.config import SubprocessRunner
from stremioguard.overrides import write_override_bundle
from stremioguard.overrides.bundle import required_output_names
from stremioguard.publishing import (
    GENERATED_ENV_HEADER,
    render_gluetun_env,
    render_stack_compose_override,
)
from tests.conftest import make_comet_config
from tests.test_env import AWKWARD_VALUES

RESOURCE_PREFIX = os.environ.get("STREMIOGUARD_TEST_PREFIX", "sgfix10-")

BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
COMET_IMAGE_LIVE = (
    "g0ldyy/comet@sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
)
COMET_IMAGE_PREV = (
    "g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe"
)

ALL_D1_CHARS = tuple(sorted(env.FORBIDDEN_ENV_CHARS, key=ord))
CORPUS = [
    *AWKWARD_VALUES,
    "é",
    "🔒",
    "\t",
    "\u00a0",
    "$HOME",
    "${PATH}",
    "a #b",
    "#x",
    "\\",
    "x" * 300,
]

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs a live Docker daemon and local images; set STREMIOGUARD_DOCKER_TESTS=1",
)


class _RecordingRunner(SubprocessRunner):
    """SubprocessRunner wrapper recording temporary container IDs from `docker create`."""

    def __init__(self) -> None:
        self.created_ids: list[str] = []

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = super().run(
            args, check=check, capture=capture, timeout=timeout, env=env, input=input
        )
        if args[:2] == ["docker", "create"] and result.returncode == 0:
            cid = (result.stdout or "").strip()
            if cid:
                self.created_ids.append(cid)
        return result


# --- AC-4: Real Compose parser ----------------------------------------------


def test_ac4_real_compose_delivers_exact_corpus_and_refuses_forbidden_chars(tmp_path: Path) -> None:
    """AC-4 / INV-1: Compose env_file and --env-file interpolation deliver exact corpus bytes."""
    env_path = tmp_path / ".env"
    env_path.write_text("", encoding="utf-8")
    written = {f"SG_K_{idx}": value for idx, value in enumerate(CORPUS)}
    env.write_env_settings(env_path, written)

    raw_env_text = env_path.read_bytes().decode("utf-8")
    gluetun_env_path = tmp_path / "gluetun.env"
    gluetun_env_path.write_text(render_gluetun_env(raw_env_text), encoding="utf-8")

    snapshot_path = tmp_path / "env.snapshot"
    snapshot_path.write_text(
        env.render_dotenv(
            env.parse_dotenv(raw_env_text, source=str(env_path)), header=GENERATED_ENV_HEADER
        ),
        encoding="utf-8",
    )

    interp_lines = "\n".join(f'      {key}: "${{{key}}}"' for key in written)
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        "services:\n"
        "  leaf-envfile:\n"
        f"    image: {BUSYBOX_IMAGE}\n"
        "    network_mode: none\n"
        "    env_file:\n"
        f"      - {gluetun_env_path}\n"
        "  leaf-interp:\n"
        f"    image: {BUSYBOX_IMAGE}\n"
        "    network_mode: none\n"
        "    environment:\n"
        f"{interp_lines}\n",
        encoding="utf-8",
    )

    project = f"{RESOURCE_PREFIX}env-{uuid.uuid4().hex[:8]}"
    base_cmd = [
        "docker",
        "compose",
        "-p",
        project,
        "--project-directory",
        str(tmp_path),
        "--env-file",
        str(snapshot_path),
        "-f",
        str(compose_path),
    ]
    try:
        subprocess.run(
            [*base_cmd, "create", "leaf-envfile", "leaf-interp"],
            check=True,
            capture_output=True,
            text=True,
        )
        for svc in ("leaf-envfile", "leaf-interp"):
            cid = subprocess.check_output([*base_cmd, "ps", "-aq", svc], text=True).strip()
            assert cid, f"no container created for {svc}"
            raw_json = subprocess.check_output(
                ["docker", "inspect", "--format", "{{json .Config.Env}}", cid],
                text=True,
            )
            env_list = json.loads(raw_json)
            parsed = dict(entry.split("=", 1) for entry in env_list)
            assert set(parsed.keys()) == set(written.keys()) | {"PATH"}
            for key, expected in written.items():
                assert parsed[key] == expected, f"{svc} mismatch for {key}"
    finally:
        subprocess.run(
            [*base_cmd, "down", "-v", "--remove-orphans"], check=False, capture_output=True
        )

    # Every D1 character is refused on write and on hand-written render.
    for char in ALL_D1_CHARS:
        with pytest.raises(ValueError):
            env.write_env_settings(env_path, {"SG_K_0": f"SGC{char}X"})

        raw_bad = tmp_path / "bad.env"
        if char == "\n":
            raw_bad.write_text('SG_K_0="SGC\\nX"\n', encoding="utf-8")
        else:
            raw_bad.write_bytes(f"SG_K_0=SGC{char}X\n".encode())
        raw_bad_text = raw_bad.read_bytes().decode("utf-8")
        with pytest.raises(RuntimeError):
            render_gluetun_env(raw_bad_text)
        with pytest.raises(RuntimeError):
            env.parse_dotenv(raw_bad_text, source=str(raw_bad))


# --- AC-11: Real docker cp on hostile and real Comet images -----------------


def _build_hostile_image(kind: str, shell_cmd: str) -> tuple[str, str]:
    uid = uuid.uuid4().hex[:8]
    ctr_name = f"{RESOURCE_PREFIX}build-{kind}-{uid}"
    image_tag = f"{RESOURCE_PREFIX}hostile-{kind}:{uid}"
    subprocess.run(
        [
            "docker",
            "run",
            "--network",
            "none",
            "--name",
            ctr_name,
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            shell_cmd,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        subprocess.run(
            ["docker", "commit", ctr_name, image_tag], check=True, capture_output=True, text=True
        )
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", ctr_name], check=False, capture_output=True)
    return image_tag, ctr_name


def test_ac11_real_docker_cp_refuses_hostile_images_and_cleans_up(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """AC-11 / INV-7: real docker cp hostile trees are refused before yield and leave no residue."""
    canary_file = tmp_path / "host_canary.txt"
    canary_file.write_text("SGCANARY_REAL_DOCKER_CP\n", encoding="utf-8")
    canary_dir = tmp_path / "host_canary_dir"
    (canary_dir / "api").mkdir(parents=True)
    (canary_dir / "api" / "app.py").write_text("SGCANARY_DIR_APP\n", encoding="utf-8")

    hostile_specs = [
        (
            "abs-link",
            f"mkdir -p /app/comet/api/endpoints && "
            f"ln -s '{canary_file}' /app/comet/api/endpoints/stream.py",
        ),
        (
            "comet-root-link",
            f"mkdir -p /app && ln -s '{canary_dir}' /app/comet",
        ),
        (
            "fifo",
            "mkdir -p /app/comet/api && mkfifo /app/comet/api/app.py",
        ),
        (
            "rel-escape",
            "mkdir -p /app/comet/api/endpoints && "
            "ln -s ../../../../etc/passwd /app/comet/api/endpoints/stream.py",
        ),
    ]

    tmp_base = Path(tempfile.gettempdir())
    built_images: list[str] = []
    try:
        for kind, cmd in hostile_specs:
            image_tag, _ = _build_hostile_image(kind, cmd)
            built_images.append(image_tag)

            before_dirs = {p.name for p in tmp_base.glob("stremioguard-comet-*")}
            runner = _RecordingRunner()
            entered = False
            t0 = time.monotonic()
            with (
                pytest.raises(RuntimeError) as exc_info,
                extract_image_source(runner, image_tag),
            ):
                entered = True
            elapsed = time.monotonic() - t0

            assert entered is False
            assert elapsed < 10.0, f"{kind} took {elapsed:.2f}s"
            assert "SGCANARY" not in str(exc_info.value)
            assert "SGCANARY" not in caplog.text
            assert len(runner.created_ids) == 1
            remaining_ps = subprocess.check_output(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    f"id={runner.created_ids[0]}",
                    "--format",
                    "{{.ID}}",
                ],
                text=True,
            ).strip()
            assert remaining_ps == ""
            after_dirs = {p.name for p in tmp_base.glob("stremioguard-comet-*")}
            assert after_dirs <= before_dirs
    finally:
        for image_tag in built_images:
            subprocess.run(["docker", "rmi", "-f", image_tag], check=False, capture_output=True)


@pytest.mark.parametrize("image_ref", [COMET_IMAGE_LIVE, COMET_IMAGE_PREV])
def test_ac11_real_comet_images_pass_tree_check_and_render_bundle(
    tmp_path: Path, image_ref: str
) -> None:
    """AC-11 regression: pinned Comet images pass verification and render gateway patches."""
    runner = _RecordingRunner()
    out_dir = tmp_path / "bundle"
    out_dir.mkdir()
    t0 = time.monotonic()
    with extract_image_source(runner, image_ref) as source_root:
        extract_elapsed = time.monotonic() - t0
        write_override_bundle(
            repo_dir=source_root,
            state_dir=out_dir,
            result_format_style="plain",
            patch_episode_pack_results=True,
            gateway_addon_base_url="https://comet.example.com/comet/tok123",
            gateway_enabled=True,
            image_digest=image_ref.split("@", 1)[1],
            patch_fingerprint="ac11-test",
            active_digest=image_ref.split("@", 1)[1],
        )
    print(f"\nextract_image_source({image_ref}) took {extract_elapsed:.2f}s")

    assert len(runner.created_ids) == 1
    remaining_ps = subprocess.check_output(
        ["docker", "ps", "-a", "--filter", f"id={runner.created_ids[0]}", "--format", "{{.ID}}"],
        text=True,
    ).strip()
    assert remaining_ps == ""

    manifest = json.loads((out_dir / "bundle-manifest.json").read_text(encoding="utf-8"))
    for req_name in required_output_names(gateway_enabled=True):
        assert req_name in manifest["outputs"]
        assert (out_dir / req_name).is_file()


# --- AC-13: Real Compose config for accepted COMET_IMAGE values -------------


def test_ac13_real_compose_resolves_all_accepted_comet_images(tmp_path: Path) -> None:
    """AC-13 / INV-9: render_stack_compose_override + docker compose config resolve exact refs."""
    accepted = [
        "g0ldyy/comet",
        "ghcr.io/g0ldyy/comet",
        "localhost/comet",
        "localhost:5000/comet",
        "registry.local:5000/mirror/comet",
        "Registry.Example.com/team/comet",
        "my_org/comet__x",
        "a/b--c",
        "a/" + "b" * 253,
    ]
    digest = "sha256:" + "a" * 64
    base_cfg = make_comet_config(tmp_path)
    base_cfg.runtime_env_file.parent.mkdir(parents=True, exist_ok=True)
    base_cfg.runtime_env_file.write_text("", encoding="utf-8")
    base_compose = tmp_path / "docker-compose.yml"
    base_compose.write_text(
        "services:\n"
        "  gluetun:\n"
        f"    image: {BUSYBOX_IMAGE}\n"
        "  comet:\n"
        f"    image: {BUSYBOX_IMAGE}\n",
        encoding="utf-8",
    )
    override_path = tmp_path / "override.yml"
    project = f"{RESOURCE_PREFIX}img-{uuid.uuid4().hex[:8]}"

    for name in accepted:
        expected_ref = f"{name}@{digest}"
        comet_cfg = make_comet_config(tmp_path, image=expected_ref)
        override_text = render_stack_compose_override(
            bind_addresses=["127.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=True,
            comet_config=comet_cfg,
            comet_gateway_config=None,
            gluetun_auth_config_file=None,
            comet_bundle_dir=None,
        )
        override_path.write_text(override_text, encoding="utf-8")
        raw_json = subprocess.check_output(
            [
                "docker",
                "compose",
                "-p",
                project,
                "-f",
                str(base_compose),
                "-f",
                str(override_path),
                "config",
                "--format",
                "json",
            ],
            text=True,
        )
        resolved = json.loads(raw_json)
        assert resolved["services"]["comet"]["image"] == expected_ref
