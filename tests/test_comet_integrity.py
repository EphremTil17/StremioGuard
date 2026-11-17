"""Adversarial and regression tests for handoff 0013 (AC-1 through AC-16)."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import typer
from loguru import logger
from typer.testing import CliRunner

from stremioguard import config as config_mod
from stremioguard.cli import APP as cli_app
from stremioguard.cli import supervisor as supervisor_mod
from stremioguard.cli.commands import general as general_cmd_mod
from stremioguard.comet import manager as manager_mod
from stremioguard.comet.lock import CometLock
from stremioguard.comet.manager import CometManager
from stremioguard.comet.state import CandidateDigest, CometState
from stremioguard.config import (
    GENERATED_COMPOSE_FILE,
    GLUETUN_ENV_FILE,
    PUBLISHED_COMPOSE_FILE,
    PUBLISHED_ENV_FILE,
    compose_command,
)
from stremioguard.digests import is_image_digest, require_image_digest
from stremioguard.env import env_file_value, write_env_setting
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import Orchestrator, PublicIPAssessment
from stremioguard.stacklock import required_stack_lock, stack_lock_path

from .conftest import (
    FakeRunner,
    completed,
    compose_stack_responses,
    make_comet_config,
    make_comet_gateway_config,
    make_config,
    seal_generation,
    write_bundle,
)
from .test_comet import _write_lock, _write_upstream_patch_sources

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64

BAD_DIGESTS: tuple[object, ...] = (
    "sha256:" + "A" * 64,
    "sha256:" + "a" * 63,
    "sha256:" + "a" * 65,
    "sha512:" + "a" * 128,
    SHA_A + "\n",
    " " + SHA_A,
    SHA_A + " ",
    "../../x",
    "-x",
    "",
    None,
    12345,
)


@contextmanager
def _stub_extract(source_root: Path):
    yield source_root


def _wait_for_file(path: Path, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"Timed out waiting for {path}")
        time.sleep(0.02)


# ---------------------------------------------------------------------------
# AC-1 & AC-2: Digest grammar and bundle_dir choke point
# ---------------------------------------------------------------------------


def test_ac1_digest_grammar_accepts_only_canonical_sha256() -> None:
    """AC-1: only sha256:<64 lowercase hex> passes; trailing newline is refused."""
    assert is_image_digest(SHA_A) is True
    assert require_image_digest(SHA_A, source="AC-1 source") == SHA_A

    for bad in BAD_DIGESTS:
        assert is_image_digest(bad) is False, f"unexpectedly accepted {bad!r}"
        with pytest.raises(RuntimeError, match="AC-1 source"):
            require_image_digest(bad, source="AC-1 source")


def test_ac2_bundle_dir_refuses_malformed_digests_without_creating_paths(
    tmp_path: Path,
) -> None:
    """AC-2: CometConfig.bundle_dir rejects every AC-1 bad value and creates nothing."""
    cfg = make_comet_config(tmp_path)
    state_before = sorted(p.name for p in cfg.state_dir.iterdir())
    for bad in BAD_DIGESTS:
        with pytest.raises(RuntimeError):
            cfg.bundle_dir(bad)  # type: ignore[arg-type]
    assert sorted(p.name for p in cfg.state_dir.iterdir()) == state_before
    assert not (cfg.state_dir / "bundles").exists()

    valid = cfg.bundle_dir(SHA_A)
    assert valid == cfg.state_dir / "bundles" / f"sha256-{'a' * 64}"


# ---------------------------------------------------------------------------
# AC-3: _image_digest own-repository selection and normalization
# ---------------------------------------------------------------------------


def test_ac3_image_digest_repository_selection_normalization_and_failures(
    tmp_path: Path,
) -> None:
    """AC-3: _image_digest matches normalized repo, fails closed on bad/conflicting entries."""

    def inspect_repo_cmd(image_ref: str) -> tuple[str, ...]:
        return ("docker", "image", "inspect", image_ref, "--format", "{{json .RepoDigests}}")

    def inspect_id_cmd(image_ref: str) -> tuple[str, ...]:
        return ("docker", "image", "inspect", image_ref, "--format", "{{.Id}}")

    # (a) Selects configured repo over earlier foreign repo entry
    cfg = make_comet_config(tmp_path, image="g0ldyy/comet")
    runner = FakeRunner(
        {
            inspect_repo_cmd("g0ldyy/comet"): completed(
                list(inspect_repo_cmd("g0ldyy/comet")),
                json.dumps([f"aaa/other@{SHA_A}", f"g0ldyy/comet@{SHA_B}"]),
            )
        }
    )
    assert CometManager(cfg, runner)._image_digest() == SHA_B

    # (b) Docker Hub normalization for docker.io/g0ldyy/comet and docker.io/library/busybox
    for configured, repo_digest_repo in (
        ("docker.io/g0ldyy/comet", "g0ldyy/comet"),
        ("docker.io/library/busybox", "busybox"),
    ):
        cfg_b = make_comet_config(tmp_path, image=configured)
        runner_b = FakeRunner(
            {
                inspect_repo_cmd(configured): completed(
                    list(inspect_repo_cmd(configured)),
                    json.dumps([f"{repo_digest_repo}@{SHA_B}"]),
                )
            }
        )
        assert CometManager(cfg_b, runner_b)._image_digest() == SHA_B

    # (c) Selected entry with malformed or uppercase digest fails with no {{.Id}} fallback
    for bad_entry in ("g0ldyy/comet@../../evil", f"g0ldyy/comet@sha256:{'A' * 64}"):
        runner_c = FakeRunner(
            {
                inspect_repo_cmd("g0ldyy/comet"): completed(
                    list(inspect_repo_cmd("g0ldyy/comet")), json.dumps([bad_entry])
                ),
                inspect_id_cmd("g0ldyy/comet"): completed(
                    list(inspect_id_cmd("g0ldyy/comet")), SHA_A
                ),
            }
        )
        with pytest.raises(RuntimeError):
            CometManager(cfg, runner_c)._image_digest()
        assert list(inspect_id_cmd("g0ldyy/comet")) not in runner_c.calls

    # (d) Two matching entries that disagree fail with no {{.Id}} fallback
    runner_d = FakeRunner(
        {
            inspect_repo_cmd("g0ldyy/comet"): completed(
                list(inspect_repo_cmd("g0ldyy/comet")),
                json.dumps([f"g0ldyy/comet@{SHA_A}", f"g0ldyy/comet@{SHA_B}"]),
            ),
            inspect_id_cmd("g0ldyy/comet"): completed(list(inspect_id_cmd("g0ldyy/comet")), SHA_A),
        }
    )
    with pytest.raises(RuntimeError):
        CometManager(cfg, runner_d)._image_digest()
    assert list(inspect_id_cmd("g0ldyy/comet")) not in runner_d.calls

    # (e) Empty or foreign-only RepoDigests falls back to {{.Id}} and validates it
    for repo_out in ("[]", json.dumps([f"aaa/other@{SHA_A}"])):
        runner_e_ok = FakeRunner(
            {
                inspect_repo_cmd("g0ldyy/comet"): completed(
                    list(inspect_repo_cmd("g0ldyy/comet")), repo_out
                ),
                inspect_id_cmd("g0ldyy/comet"): completed(
                    list(inspect_id_cmd("g0ldyy/comet")), f"{SHA_C}\n"
                ),
            }
        )
        assert CometManager(cfg, runner_e_ok)._image_digest() == SHA_C

        for bad_id in ("../x", ""):
            runner_e_bad = FakeRunner(
                {
                    inspect_repo_cmd("g0ldyy/comet"): completed(
                        list(inspect_repo_cmd("g0ldyy/comet")), repo_out
                    ),
                    inspect_id_cmd("g0ldyy/comet"): completed(
                        list(inspect_id_cmd("g0ldyy/comet")), bad_id
                    ),
                }
            )
            with pytest.raises(RuntimeError):
                CometManager(cfg, runner_e_bad)._image_digest()

    # (f) Non-JSON RepoDigests falls back to {{.Id}}
    runner_f = FakeRunner(
        {
            inspect_repo_cmd("g0ldyy/comet"): completed(
                list(inspect_repo_cmd("g0ldyy/comet")), "not-json{"
            ),
            inspect_id_cmd("g0ldyy/comet"): completed(list(inspect_id_cmd("g0ldyy/comet")), SHA_B),
        }
    )
    assert CometManager(cfg, runner_f)._image_digest() == SHA_B


# ---------------------------------------------------------------------------
# AC-4: Digest validation in _remote_digest, CometLock, CometState, prepare_runtime
# ---------------------------------------------------------------------------


def test_ac4_digest_sources_and_prepare_runtime_refuse_malformed(tmp_path: Path) -> None:
    """AC-4: _remote_digest, CometLock.load, CometState.load, prepare_runtime refuse bad input."""
    cfg = make_comet_config(tmp_path)
    cmd = (
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        "g0ldyy/comet:latest",
        "--format",
        "{{json .Manifest.Digest}}",
    )

    # (a) _remote_digest
    for bad_stdout in ("sha256:zz\n", '"../x"\n', ""):
        manager = CometManager(cfg, FakeRunner({cmd: completed(list(cmd), bad_stdout)}))
        with mock.patch.object(manager, "warn") as warn_mock:
            assert manager._remote_digest() is None
        warn_mock.assert_called_once()
        assert "../x" not in warn_mock.call_args.args[0]
        assert "sha256:zz" not in warn_mock.call_args.args[0]

    manager_ok = CometManager(cfg, FakeRunner({cmd: completed(list(cmd), f'"{SHA_A}"\n')}))
    with mock.patch.object(manager_ok, "warn") as warn_mock:
        assert manager_ok._remote_digest() == SHA_A
    warn_mock.assert_not_called()

    # (b) CometLock.load
    lock_path = cfg.lock_file
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    for bad_lock in (
        "{not json",
        "[]",
        json.dumps({"image": "g0ldyy/comet", "tested_digest": "../x"}),
    ):
        lock_path.write_text(bad_lock, encoding="utf-8")
        with pytest.raises(RuntimeError):
            CometLock.load(lock_path)

    lock_path.write_text(json.dumps({"image": "g0ldyy/comet", "tested_digest": SHA_A}))
    loaded_lock = CometLock.load(lock_path)
    assert loaded_lock.image == "g0ldyy/comet"
    assert loaded_lock.tested_digest == SHA_A

    # (c) & (d) CometState.load and prepare_runtime with sentinel files
    bad_states: list[tuple[str, str]] = [
        (json.dumps({"active_digest": "../../x"}), "active_digest"),
        (json.dumps({"previous_digest": "sha256:" + "A" * 64}), "previous_digest"),
        (json.dumps({"candidate": []}), "candidate"),
        (json.dumps({"candidate": {"checked_at": "t"}}), "candidate.digest"),
        (json.dumps({"candidate": {"digest": "bad"}}), "candidate.digest"),
        (json.dumps({"last_remote_check": 42}), "last_remote_check"),
        ("[]", "state.json"),
    ]

    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=True)
    gw_cfg = make_comet_gateway_config(tmp_path, enabled=True)
    sentinels = {
        cfg.runtime_env_file: b"# SENTINEL runtime env\n",
        cfg.state_dir / "postgres.env": b"# SENTINEL postgres env\n",
        tmp_path / PUBLISHED_ENV_FILE: b"# SENTINEL snapshot\n",
        tmp_path / GENERATED_COMPOSE_FILE: b"# SENTINEL override\n",
        gw_cfg.nginx_conf_file: b"# SENTINEL nginx\n",
    }
    for path, content in sentinels.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    state_path = cfg.state_dir / "state.json"
    for payload_text, expected_field in bad_states:
        state_path.write_text(payload_text, encoding="utf-8")
        with pytest.raises(RuntimeError) as exc_info:
            CometState.load(state_path)
        assert str(state_path) in str(exc_info.value)
        assert expected_field in str(exc_info.value)

        with pytest.raises(RuntimeError):
            CometManager(cfg, FakeRunner({})).prepare_runtime()
        for path, expected_bytes in sentinels.items():
            assert path.read_bytes() == expected_bytes, f"sentinel changed at {path}"

    # Regression: valid state round-trips
    valid_state = CometState(
        active_digest=SHA_A,
        previous_digest=SHA_B,
        candidate=CandidateDigest(digest=SHA_C, checked_at="2026-11-16T00:00:00+00:00"),
        last_remote_check="2026-11-16T00:00:00+00:00",
    )
    valid_state.save(state_path)
    assert CometState.load(state_path) == valid_state


# ---------------------------------------------------------------------------
# AC-5: Compatibility cache shape resilience & source_commit retirement
# ---------------------------------------------------------------------------


def test_ac5_corrupt_compatibility_cache_is_miss_and_legacy_hits_without_source_commit(
    tmp_path: Path,
) -> None:
    """AC-5: non-object cache triggers re-validation; legacy source_commit cache still hits."""
    cfg = make_comet_config(tmp_path, patch_episode_pack_results=False)
    _write_upstream_patch_sources(cfg)
    (cfg.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()
    image_ref = f"{cfg.image}@{SHA_A}"
    inspect_cmd = ("docker", "image", "inspect", image_ref)
    inspect_repo_cmd = (*inspect_cmd, "--format", "{{json .RepoDigests}}")
    runner = FakeRunner(
        {
            inspect_cmd: completed(list(inspect_cmd)),
            inspect_repo_cmd: completed(list(inspect_repo_cmd), json.dumps([image_ref])),
        }
    )
    manager = CometManager(cfg, runner)
    manager.save_state(CometState(active_digest=SHA_A))
    cache_file = cfg.state_dir / "compatibility.json"

    for non_object in ("[]", '"x"', "1", "null"):
        cache_file.write_text(non_object, encoding="utf-8")
        assert manager._compatibility_cache_valid(SHA_A, "fp") is False

        extract_calls = 0

        @contextmanager
        def counting_extract(r, ref):
            nonlocal extract_calls
            extract_calls += 1
            yield cfg.repo_dir

        with (
            mock.patch.object(manager_mod, "extract_image_source", side_effect=counting_extract),
            mock.patch.object(
                manager_mod,
                "import_smoke_test",
                return_value={"status": "passed", "stage": "import", "detail": ""},
            ),
        ):
            manager.validate_compatibility()
        assert extract_calls == 1
        written = json.loads(cache_file.read_text(encoding="utf-8"))
        assert "source_commit" not in written

    # Base-format cache (carrying source_commit) stays a hit with no extraction
    written["source_commit"] = "581455f24206dc40a27f28f054077f1be9203466"
    cache_file.write_text(json.dumps(written), encoding="utf-8")
    with mock.patch.object(
        manager_mod, "extract_image_source", side_effect=AssertionError("should hit cache")
    ):
        manager.validate_compatibility()


# ---------------------------------------------------------------------------
# AC-6: Stack lock wiring across separate processes and nested preflight
# ---------------------------------------------------------------------------


def test_ac6_stack_lock_refuses_concurrent_process_and_allows_nested_preflight(
    tmp_path: Path,
) -> None:
    """AC-6: child process stack.lock blocks all 7 Comet mutations; nested preflight succeeds."""
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\nSTREMIO_ENABLED=0\n", encoding="utf-8"
    )
    cfg = make_comet_config(tmp_path, gateway_enabled=False, patch_episode_pack_results=False)
    CometState(
        active_digest=SHA_A,
        previous_digest=SHA_B,
        candidate=CandidateDigest(digest=SHA_C, checked_at="2026-11-16T00:00:00+00:00"),
    ).save(cfg.state_dir / "state.json")
    bundle_dir = write_bundle(cfg, SHA_A)

    state_file = cfg.state_dir / "state.json"
    cfg.runtime_env_file.write_bytes(b"# SENTINEL comet env\n")
    (tmp_path / PUBLISHED_ENV_FILE).write_bytes(b"# SENTINEL env snapshot\n")
    (tmp_path / GENERATED_COMPOSE_FILE).write_bytes(b"# SENTINEL override\n")
    sentinel_files = {
        state_file: state_file.read_bytes(),
        cfg.runtime_env_file: cfg.runtime_env_file.read_bytes(),
        tmp_path / PUBLISHED_ENV_FILE: (tmp_path / PUBLISHED_ENV_FILE).read_bytes(),
        tmp_path / GENERATED_COMPOSE_FILE: (tmp_path / GENERATED_COMPOSE_FILE).read_bytes(),
    }
    bundles_listing = sorted(p.name for p in (cfg.state_dir / "bundles").iterdir())

    lock_file = stack_lock_path(tmp_path)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    ready_flag = tmp_path / "lock-held"
    release_flag = tmp_path / "lock-release"
    holder_script = (
        "import fcntl, os, sys, time; from pathlib import Path\n"
        "lock = Path(sys.argv[1]); ready = Path(sys.argv[2]); rel = Path(sys.argv[3])\n"
        "fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\n"
        "ready.write_text('1')\n"
        "while not rel.exists(): time.sleep(0.02)\n"
        "os.close(fd)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", holder_script, str(lock_file), str(ready_flag), str(release_flag)]
    )
    try:
        _wait_for_file(ready_flag)
        runner = FakeRunner({})
        manager = CometManager(cfg, runner)

        with (
            mock.patch.object(manager_mod, "STACK_LOCK_WAIT_SECONDS", 0.5),
            mock.patch.object(
                manager,
                "_validate_digest",
                return_value={"status": "passed", "detail": "", "degraded": []},
            ),
            mock.patch.object(manager, "_remote_digest", return_value=SHA_C),
            mock.patch.object(manager, "_render_bundle") as render_mock,
            mock.patch.object(manager, "validate_compatibility") as compat_mock,
            mock.patch.object(manager, "compose") as compose_mock,
        ):
            operations: list[Any] = [
                lambda: manager.prepare_runtime(),
                lambda: manager.start(),
                lambda: manager.promote_candidate(),
                lambda: manager.rollback(),
                lambda: manager.validate_candidate(SHA_C),
                lambda: manager.resolve_remote_digest(),
                lambda: manager.converge_running_stack(),
            ]
            for op in operations:
                with pytest.raises(
                    RuntimeError, match="Another StremioGuard command is changing the stack"
                ):
                    op()

            render_mock.assert_not_called()
            compat_mock.assert_not_called()
            compose_mock.assert_not_called()
            assert runner.calls == []
            for path, expected in sentinel_files.items():
                assert path.read_bytes() == expected, path
            assert sorted(p.name for p in (cfg.state_dir / "bundles").iterdir()) == bundles_listing

        release_flag.write_text("1", encoding="utf-8")
        proc.wait(timeout=5)
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    # After release, every operation proceeds
    _write_upstream_patch_sources(cfg)
    (cfg.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()
    manager2 = CometManager(cfg, FakeRunner({}))
    with (
        mock.patch.object(manager2, "require_commands"),
        mock.patch.object(manager2, "ensure_image", side_effect=lambda ref: ref.rsplit("@", 1)[1]),
        mock.patch.object(
            manager_mod,
            "extract_image_source",
            side_effect=lambda r, ref: _stub_extract(cfg.repo_dir),
        ),
        mock.patch.object(
            manager_mod,
            "import_smoke_test",
            return_value={"status": "passed", "stage": "import", "detail": ""},
        ),
        mock.patch.object(
            manager2,
            "_validate_digest",
            return_value={"status": "passed", "detail": "", "degraded": []},
        ),
        mock.patch.object(manager2, "_remote_digest", return_value=SHA_C),
        mock.patch.object(manager2, "check_bind_addresses"),
        mock.patch.object(manager2, "_up"),
        mock.patch.object(manager2, "advisory_update_check"),
        mock.patch.object(manager2, "verify_running_image"),
        mock.patch.object(manager2, "ensure_running_bundle"),
        mock.patch.object(manager2, "apply_gateway_config"),
    ):
        assert manager2.resolve_remote_digest() == SHA_C
        assert manager2.validate_candidate(SHA_C)["status"] == "passed"
        manager2.prepare_runtime()
        manager2.start()
        manager2.promote_candidate()
        manager2.rollback()
        manager2.converge_running_stack()
    assert bundle_dir.exists()

    # Nested production path: GluetunGuard.preflight() inside required_stack_lock
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    guard_cfg = make_config(tmp_path)
    guard_runner = FakeRunner(
        {
            ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
            ("docker", "ps", "--format", "{{.ID}}"): completed(["docker", "ps"], "abc\n"),
            ("docker", "image", "inspect", "qmcgaw/gluetun:v3", "--format", "{{.Id}}"): completed(
                ["docker", "image", "inspect"], SHA_A
            ),
        }
    )
    guard = GluetunGuard(guard_cfg, guard_runner)
    with (
        mock.patch.object(guard, "check_vpn_lockout"),
        mock.patch.object(guard, "check_bind_addresses"),
        mock.patch.object(guard, "refresh_gluetun_image"),
        mock.patch.object(guard, "compose_fresh"),
        mock.patch.object(guard, "wait_for_gluetun_healthy"),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(
            CometManager, "ensure_image", side_effect=lambda self, ref: ref.rsplit("@", 1)[1]
        )
        if False
        else mock.patch.object(CometManager, "ensure_image", return_value=SHA_A),
        mock.patch.object(CometManager, "_manifest_cache_valid", return_value=True),
    ):
        t0 = time.monotonic()
        with required_stack_lock(tmp_path, wait_seconds=5, purpose="outer guard"):
            assert guard.preflight() is True
        elapsed = time.monotonic() - t0
    assert elapsed < 2.0


# ---------------------------------------------------------------------------
# AC-7: Separate-process lost-update tests (state.json and .env)
# ---------------------------------------------------------------------------


def test_ac7_concurrent_state_and_env_updates_across_processes(tmp_path: Path) -> None:
    """AC-7: (a) validate_candidate vs rollback keeps Y; (b) 40 .env keys kept; (c) flock blocks."""
    # (a) Process A pauses between CometState.load and save inside validate_candidate(SHA_C);
    #     Process B runs rollback() while A is paused -> active_digest ends as Y (SHA_B).
    root_a = tmp_path / "case-a"
    root_a.mkdir()
    cfg_a = make_comet_config(root_a)
    CometState(active_digest=SHA_A, previous_digest=SHA_B).save(cfg_a.state_dir / "state.json")
    paused_flag = root_a / "paused"
    release_flag = root_a / "release"

    script_a = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from unittest import mock\n"
        "from stremioguard.comet.manager import CometManager\n"
        "from stremioguard.comet.state import CometState\n"
        "from stremioguard.config import CometConfig\n"
        "root, digest, paused, rel = (\n"
        "    Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])\n"
        ")\n"
        "cfg = CometConfig.from_env(root)\n"
        "mgr = CometManager(cfg)\n"
        "orig_load = CometState.load\n"
        "after_val = {'flag': False}\n"
        "def fake_val(*a, **k):\n"
        "    after_val['flag'] = True\n"
        "    return {'status': 'passed', 'detail': '', 'degraded': []}\n"
        "def wrapped_load(cls, path):\n"
        "    res = orig_load(path)\n"
        "    if after_val['flag'] and not paused.exists():\n"
        "        paused.write_text('1')\n"
        "        while not rel.exists():\n"
        "            time.sleep(0.02)\n"
        "    return res\n"
        "with mock.patch.object(mgr, '_validate_digest', side_effect=fake_val), "
        "mock.patch.object(CometState, 'load', classmethod(wrapped_load)):\n"
        "    mgr.validate_candidate(digest)\n"
    )
    script_b = (
        "import sys\n"
        "from pathlib import Path\n"
        "from unittest import mock\n"
        "from stremioguard.comet import manager as manager_mod\n"
        "from stremioguard.comet.manager import CometManager\n"
        "from stremioguard.config import CometConfig\n"
        "root = Path(sys.argv[1])\n"
        "mgr = CometManager(CometConfig.from_env(root))\n"
        "with mock.patch.object(manager_mod, 'STACK_LOCK_WAIT_SECONDS', 10), "
        "mock.patch.object(mgr, '_render_bundle'), "
        "mock.patch.object(mgr, 'validate_compatibility'), "
        "mock.patch.object(mgr, 'prepare_runtime'), "
        "mock.patch.object(mgr, '_up'):\n"
        "    mgr.rollback()\n"
    )

    proc_a = subprocess.Popen(
        [sys.executable, "-c", script_a, str(root_a), SHA_C, str(paused_flag), str(release_flag)]
    )
    proc_b: subprocess.Popen[bytes] | None = None
    try:
        _wait_for_file(paused_flag)
        proc_b = subprocess.Popen([sys.executable, "-c", script_b, str(root_a)])
        time.sleep(1.0)
        assert proc_b.poll() is None, "rollback should wait on A's stack lock"
        release_flag.write_text("1", encoding="utf-8")
        proc_a.wait(timeout=10)
        proc_b.wait(timeout=10)
        assert proc_a.returncode == 0
        assert proc_b.returncode == 0
    finally:
        for p in (proc_a, proc_b):
            if p is not None and p.poll() is None:
                p.kill()
                p.wait(timeout=5)

    final_state = CometState.load(cfg_a.state_dir / "state.json")
    assert final_state.active_digest == SHA_B
    assert final_state.previous_digest == SHA_A

    # (b) Two processes each call write_env_setting for 20 distinct keys
    env_b = tmp_path / "case-b" / ".env"
    env_b.parent.mkdir()
    env_b.write_text("# sentinel header\nORIGINAL=keep\n", encoding="utf-8")
    go_flag = tmp_path / "case-b" / "go"
    writer_script = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from stremioguard.env import write_env_setting\n"
        "env_p, prefix, go_p = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])\n"
        "while not go_p.exists(): time.sleep(0.01)\n"
        "for i in range(20):\n"
        "    write_env_setting(env_p, f'{prefix}_{i}', f'val-{prefix}-{i}')\n"
    )
    p1 = subprocess.Popen([sys.executable, "-c", writer_script, str(env_b), "P1", str(go_flag)])
    p2 = subprocess.Popen([sys.executable, "-c", writer_script, str(env_b), "P2", str(go_flag)])
    try:
        go_flag.write_text("1", encoding="utf-8")
        p1.wait(timeout=15)
        p2.wait(timeout=15)
        assert p1.returncode == 0
        assert p2.returncode == 0
    finally:
        for p in (p1, p2):
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)

    text_b = env_b.read_text(encoding="utf-8")
    assert "# sentinel header\nORIGINAL=keep\n" in text_b
    for prefix in ("P1", "P2"):
        for i in range(20):
            assert env_file_value(env_b, f"{prefix}_{i}") == f"val-{prefix}-{i}"

    # (c) Child holds flock on .env's parent directory; thread's write_env_setting blocks
    env_c = tmp_path / "case-c" / ".env"
    env_c.parent.mkdir()
    sentinel_c = b"# SENTINEL C\nKEY=OLD\n"
    env_c.write_bytes(sentinel_c)
    c_ready = tmp_path / "c-ready"
    c_release = tmp_path / "c-release"
    dir_lock_script = (
        "import fcntl, os, sys, time\n"
        "from pathlib import Path\n"
        "d, ready, rel = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])\n"
        "fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\n"
        "ready.write_text('1')\n"
        "while not rel.exists(): time.sleep(0.02)\n"
        "os.close(fd)\n"
    )
    proc_c = subprocess.Popen(
        [sys.executable, "-c", dir_lock_script, str(env_c.parent), str(c_ready), str(c_release)]
    )
    try:
        _wait_for_file(c_ready)
        writer_thread = threading.Thread(
            target=write_env_setting, args=(env_c, "KEY", "NEW"), daemon=True
        )
        writer_thread.start()
        time.sleep(0.5)
        assert writer_thread.is_alive()
        assert env_c.read_bytes() == sentinel_c
        c_release.write_text("1", encoding="utf-8")
        proc_c.wait(timeout=5)
        writer_thread.join(timeout=5)
        assert not writer_thread.is_alive()
        assert env_file_value(env_c, "KEY") == "NEW"
    finally:
        if proc_c.poll() is None:
            proc_c.kill()
            proc_c.wait(timeout=5)


# ---------------------------------------------------------------------------
# AC-8: Crash between the two renames (fail closed + heal) and render locking
# ---------------------------------------------------------------------------


def test_ac8_crash_between_renames_fails_closed_heals_and_locks_staging(
    tmp_path: Path,
) -> None:
    """AC-8: missing active bundle fails publish, heals on prepare_runtime, and locks staging."""
    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=False, patch_episode_pack_results=False)
    _write_upstream_patch_sources(cfg)
    (cfg.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()
    CometState(active_digest=SHA_A).save(cfg.state_dir / "state.json")

    bundles_root = cfg.state_dir / "bundles"
    bundles_root.mkdir(parents=True, exist_ok=True)
    retired_dir = bundles_root / f".retired-sha256-{'a' * 64}-deadbeef"
    retired_dir.mkdir()
    (retired_dir / "bundle-manifest.json").write_text("{}", encoding="utf-8")
    staging_orphan = bundles_root / ".staging-orphan"
    staging_orphan.mkdir()
    (staging_orphan / "partial.py").write_text("# orphan\n", encoding="utf-8")

    gen_sentinels = {
        tmp_path / PUBLISHED_ENV_FILE: b"# SENTINEL snapshot\n",
        tmp_path / GLUETUN_ENV_FILE: b"# SENTINEL gluetun\n",
        tmp_path / PUBLISHED_COMPOSE_FILE: b"# SENTINEL base\n",
        tmp_path / GENERATED_COMPOSE_FILE: b"# SENTINEL override\n",
    }
    for path, content in gen_sentinels.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    # (a) Publishing refuses with generation files byte-identical
    manager = CometManager(cfg, FakeRunner({}))
    with pytest.raises(RuntimeError, match="no override bundle exists"):
        manager.write_stack_override_file()
    for path, expected in gen_sentinels.items():
        assert path.read_bytes() == expected

    # (b) Next prepare_runtime() re-renders, publishes, and prunes orphans
    with (
        mock.patch.object(manager, "ensure_image", return_value=SHA_A),
        mock.patch.object(
            manager_mod,
            "extract_image_source",
            side_effect=lambda r, ref: _stub_extract(cfg.repo_dir),
        ),
    ):
        manager.prepare_runtime()

    entries = [p.name for p in bundles_root.iterdir()]
    assert entries == [f"sha256-{'a' * 64}"]
    assert (cfg.bundle_dir(SHA_A) / "bundle-manifest.json").is_file()
    assert b"# SENTINEL override" not in (tmp_path / GENERATED_COMPOSE_FILE).read_bytes()

    # (c) Process A paused inside write_override_bundle while Process B calls prepare_runtime()
    root_c = tmp_path / "case-c"
    root_c.mkdir()
    (root_c / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8")
    (root_c / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    cfg_c = make_comet_config(root_c, gateway_enabled=False, patch_episode_pack_results=False)
    _write_upstream_patch_sources(cfg_c)
    (cfg_c.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()
    CometState(active_digest=SHA_A).save(cfg_c.state_dir / "state.json")

    paused_c = root_c / "paused"
    release_c = root_c / "release"
    script_render_a = (
        "import sys, time\n"
        "from contextlib import contextmanager\n"
        "from pathlib import Path\n"
        "from unittest import mock\n"
        "from stremioguard.comet import manager as manager_mod\n"
        "from stremioguard.comet.manager import CometManager\n"
        "from stremioguard.config import CometConfig\n"
        "root, paused, rel = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])\n"
        "cfg = CometConfig.from_env(root)\n"
        "mgr = CometManager(cfg)\n"
        "orig_write = manager_mod.write_override_bundle\n"
        "@contextmanager\n"
        "def stub_extract(r, ref): yield cfg.repo_dir\n"
        "def wrapped_write(**kwargs):\n"
        "    paused.write_text('1')\n"
        "    while not rel.exists(): time.sleep(0.02)\n"
        "    return orig_write(**kwargs)\n"
        "with mock.patch.object(mgr, 'ensure_image', return_value=sys.argv[4]), "
        "mock.patch.object(manager_mod, 'extract_image_source', side_effect=stub_extract), "
        "mock.patch.object(manager_mod, 'write_override_bundle', side_effect=wrapped_write):\n"
        "    mgr.prepare_runtime()\n"
    )
    proc_a = subprocess.Popen(
        [sys.executable, "-c", script_render_a, str(root_c), str(paused_c), str(release_c), SHA_A]
    )
    try:
        _wait_for_file(paused_c)
        mgr_b = CometManager(cfg_c, FakeRunner({}))
        with (
            mock.patch.object(manager_mod, "STACK_LOCK_WAIT_SECONDS", 0.5),
            pytest.raises(RuntimeError, match="Another StremioGuard command is changing the stack"),
        ):
            mgr_b.prepare_runtime()
        staging_dirs = [
            p for p in (cfg_c.state_dir / "bundles").iterdir() if p.name.startswith(".staging-")
        ]
        assert len(staging_dirs) == 1
        release_c.write_text("1", encoding="utf-8")
        proc_a.wait(timeout=10)
        assert proc_a.returncode == 0
    finally:
        if proc_a.poll() is None:
            proc_a.kill()
            proc_a.wait(timeout=5)

    assert [p.name for p in (cfg_c.state_dir / "bundles").iterdir()] == [f"sha256-{'a' * 64}"]


# ---------------------------------------------------------------------------
# AC-9, AC-10, AC-11: _up() post-conditions, stale bundle, apply_gateway_config
# ---------------------------------------------------------------------------


def test_ac9_up_promote_and_doctor_post_conditions(tmp_path: Path) -> None:
    """AC-9: _up(), promote_candidate() and doctor verify running image, bundle and gateway."""
    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=True, patch_episode_pack_results=False)
    CometState(active_digest=SHA_A).save(cfg.state_dir / "state.json")
    bundle_dir = write_bundle(cfg, SHA_A, extra={"image_digest": SHA_A})
    active_ref = f"{cfg.image}@{SHA_A}"
    up_cmd = tuple([*compose_command(tmp_path), "up", "-d", "--no-deps", *cfg.runtime_services])
    ps_comet_cmd = tuple(compose_command(tmp_path, "ps", "-q", "comet"))
    inspect_container_cmd = ("docker", "inspect", "comet-id", "--format", "{{.Image}}")
    inspect_image_cmd = ("docker", "image", "inspect", active_ref, "--format", "{{.Id}}")

    # (a) Running container image differs from active image
    runner_a = FakeRunner(
        {
            up_cmd: completed(list(up_cmd)),
            ps_comet_cmd: completed(list(ps_comet_cmd), "comet-id\n"),
            inspect_container_cmd: completed(list(inspect_container_cmd), "sha256:old-img\n"),
            inspect_image_cmd: completed(list(inspect_image_cmd), "sha256:new-img\n"),
        }
    )
    mgr_a = CometManager(cfg, runner_a)
    with (
        mock.patch.object(mgr_a, "write_stack_override_file"),
        pytest.raises(RuntimeError) as exc_a,
    ):
        mgr_a._up()
    assert "sha256:old-img" in str(exc_a.value)
    assert "sha256:new-img" in str(exc_a.value)

    # (b) ps -q comet empty after up
    runner_b = FakeRunner(
        {
            up_cmd: completed(list(up_cmd)),
            ps_comet_cmd: completed(list(ps_comet_cmd), ""),
        }
    )
    mgr_b = CometManager(cfg, runner_b)
    with (
        mock.patch.object(mgr_b, "write_stack_override_file"),
        pytest.raises(RuntimeError, match="not running"),
    ):
        mgr_b._up()

    # (c) ps -q comet exits non-zero, then raises TimeoutExpired
    runner_c1 = FakeRunner(
        {
            up_cmd: completed(list(up_cmd)),
            ps_comet_cmd: completed(list(ps_comet_cmd), "", "daemon down", returncode=1),
        }
    )
    mgr_c1 = CometManager(cfg, runner_c1)
    with mock.patch.object(mgr_c1, "write_stack_override_file"), pytest.raises(RuntimeError):
        mgr_c1._up()

    def raise_timeout(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if tuple(args) == ps_comet_cmd:
            raise subprocess.TimeoutExpired(cmd=args, timeout=30)
        return completed(args)

    mgr_c2 = CometManager(cfg, FakeRunner({}))
    with (
        mock.patch.object(mgr_c2, "write_stack_override_file"),
        mock.patch.object(mgr_c2.runner, "run", side_effect=raise_timeout),
        pytest.raises(RuntimeError),
    ):
        mgr_c2._up()

    # (d) Everything matches and order is up -> image query -> bundle exec -> gateway check
    manifest = json.loads((bundle_dir / "bundle-manifest.json").read_text(encoding="utf-8"))
    import hashlib

    container_hashes = {
        cpath: hashlib.sha256((bundle_dir / oname).read_bytes()).hexdigest()
        for oname, cpath in manifest["outputs"].items()
    }
    exec_cmd = (
        "docker",
        "exec",
        "comet-id",
        "/app/.venv/bin/python",
        "-c",
        manager_mod._CONTAINER_BUNDLE_HASH_SCRIPT,
        *manifest["outputs"].values(),
    )
    events: list[str] = []

    class OrderRunner(FakeRunner):
        def run(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            t = tuple(args)
            if t == up_cmd:
                events.append("up")
            elif t == inspect_image_cmd:
                events.append("image")
            elif t == exec_cmd:
                events.append("bundle")
            return super().run(args, **kwargs)

    runner_d = OrderRunner(
        {
            up_cmd: completed(list(up_cmd)),
            ps_comet_cmd: completed(list(ps_comet_cmd), "comet-id\n"),
            inspect_container_cmd: completed(list(inspect_container_cmd), f"{SHA_A}\n"),
            inspect_image_cmd: completed(list(inspect_image_cmd), f"{SHA_A}\n"),
            exec_cmd: completed(list(exec_cmd), json.dumps(container_hashes)),
        }
    )
    mgr_d = CometManager(cfg, runner_d)
    fake_gw = mock.Mock()
    fake_gw.container_running.side_effect = lambda: events.append("gateway") or False
    with (
        mock.patch.object(mgr_d, "write_stack_override_file"),
        mock.patch.object(mgr_d, "gateway_manager", return_value=fake_gw),
    ):
        mgr_d._up()
    assert events == ["up", "image", "bundle", "gateway"]

    # promote_candidate() with (a) warns and raises
    CometState(
        active_digest=SHA_B,
        candidate=CandidateDigest(digest=SHA_A, checked_at="t"),
    ).save(cfg.state_dir / "state.json")
    runner_prom = FakeRunner(
        {
            up_cmd: completed(list(up_cmd)),
            ps_comet_cmd: completed(list(ps_comet_cmd), "comet-id\n"),
            inspect_container_cmd: completed(list(inspect_container_cmd), "sha256:old-img\n"),
            inspect_image_cmd: completed(list(inspect_image_cmd), "sha256:new-img\n"),
        }
    )
    mgr_prom = CometManager(cfg, runner_prom)
    with (
        mock.patch.object(
            mgr_prom,
            "_validate_digest",
            return_value={"status": "passed", "detail": "", "degraded": []},
        ),
        mock.patch.object(mgr_prom, "_render_bundle"),
        mock.patch.object(mgr_prom, "validate_compatibility"),
        mock.patch.object(mgr_prom, "prepare_runtime"),
        mock.patch.object(mgr_prom, "write_stack_override_file"),
        mock.patch.object(mgr_prom, "warn") as warn_prom,
        pytest.raises(RuntimeError),
    ):
        mgr_prom.promote_candidate()
    assert any("restarting the Comet stack failed" in c.args[0] for c in warn_prom.call_args_list)

    # doctor() with (a) fails through verify_running_image
    mgr_doc = CometManager(cfg, runner_a)
    with (
        mock.patch.object(mgr_doc, "require_commands"),
        pytest.raises(RuntimeError) as exc_doc,
    ):
        mgr_doc.doctor()
    assert "sha256:old-img" in str(exc_doc.value)
    assert "sha256:new-img" in str(exc_doc.value)


def test_ac10_ensure_running_bundle_recreate_and_failures(tmp_path: Path) -> None:
    """AC-10: stale bundle recreates once; matching/not-running skip; failures raise."""
    import hashlib

    (tmp_path / ".env").write_text("COMET_ENABLED=1\n", encoding="utf-8")
    (tmp_path / ".stremio").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (tmp_path / PUBLISHED_COMPOSE_FILE).write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (tmp_path / PUBLISHED_ENV_FILE).write_text("COMET_ENABLED=1\n", encoding="utf-8")
    (tmp_path / GENERATED_COMPOSE_FILE).write_text("services: {}\n", encoding="utf-8")

    cfg = make_comet_config(tmp_path)
    CometState(active_digest=SHA_A).save(cfg.state_dir / "state.json")
    bundle_dir = write_bundle(cfg, SHA_A)
    manifest = json.loads((bundle_dir / "bundle-manifest.json").read_text(encoding="utf-8"))
    outputs: dict[str, str] = dict(manifest["outputs"])
    expected_hashes = {
        cpath: hashlib.sha256((bundle_dir / oname).read_bytes()).hexdigest()
        for oname, cpath in outputs.items()
    }
    stale_hashes = dict(expected_hashes)
    first_cpath = next(iter(outputs.values()))
    stale_hashes[first_cpath] = "0" * 64

    ps_cmd = tuple(compose_command(tmp_path, "ps", "-q", "comet"))
    recreate_cmd = tuple(
        compose_command(tmp_path, "up", "-d", "--no-deps", "--force-recreate", "comet")
    )
    exec_1 = (
        "docker",
        "exec",
        "comet-1",
        "/app/.venv/bin/python",
        "-c",
        manager_mod._CONTAINER_BUNDLE_HASH_SCRIPT,
        *outputs.values(),
    )
    exec_2 = (
        "docker",
        "exec",
        "comet-2",
        "/app/.venv/bin/python",
        "-c",
        manager_mod._CONTAINER_BUNDLE_HASH_SCRIPT,
        *outputs.values(),
    )

    # (a) Differs then matches after recreate; published generation command used, no publish
    runner_a = FakeRunner(
        {
            ps_cmd: [completed(list(ps_cmd), "comet-1\n"), completed(list(ps_cmd), "comet-2\n")],
            exec_1: completed(list(exec_1), json.dumps(stale_hashes)),
            recreate_cmd: completed(list(recreate_cmd)),
            exec_2: completed(list(exec_2), json.dumps(expected_hashes)),
        }
    )
    mgr_a = CometManager(cfg, runner_a)
    with mock.patch.object(mgr_a, "write_stack_override_file") as publish_mock:
        mgr_a.ensure_running_bundle()
    publish_mock.assert_not_called()
    assert runner_a.calls.count(list(recreate_cmd)) == 1
    assert "--env-file" in runner_a.calls[2]
    assert list(exec_1) in runner_a.calls

    # (b) Still differs after recreate -> RuntimeError
    runner_b = FakeRunner(
        {
            ps_cmd: [completed(list(ps_cmd), "comet-1\n"), completed(list(ps_cmd), "comet-2\n")],
            exec_1: completed(list(exec_1), json.dumps(stale_hashes)),
            recreate_cmd: completed(list(recreate_cmd)),
            exec_2: completed(list(exec_2), json.dumps(stale_hashes)),
        }
    )
    with pytest.raises(RuntimeError):
        CometManager(cfg, runner_b).ensure_running_bundle()

    # (c) All hashes match -> no recreate
    runner_c = FakeRunner(
        {
            ps_cmd: completed(list(ps_cmd), "comet-1\n"),
            exec_1: completed(list(exec_1), json.dumps(expected_hashes)),
        }
    )
    CometManager(cfg, runner_c).ensure_running_bundle()
    assert not any("--force-recreate" in call for call in runner_c.calls)

    # (d) Exec exits non-zero -> RuntimeError
    runner_d = FakeRunner(
        {
            ps_cmd: completed(list(ps_cmd), "comet-1\n"),
            exec_1: completed(list(exec_1), "", "exec failed", returncode=1),
        }
    )
    with pytest.raises(RuntimeError):
        CometManager(cfg, runner_d).ensure_running_bundle()

    # (e) No Comet container -> returns, no recreate
    runner_e = FakeRunner({ps_cmd: completed(list(ps_cmd), "")})
    CometManager(cfg, runner_e).ensure_running_bundle()
    assert not any("--force-recreate" in call for call in runner_e.calls)

    # (f) Active manifest missing while Comet running -> RuntimeError
    (bundle_dir / "bundle-manifest.json").unlink()
    runner_f = FakeRunner({ps_cmd: completed(list(ps_cmd), "comet-1\n")})
    with pytest.raises(RuntimeError, match="missing or unreadable"):
        CometManager(cfg, runner_f).ensure_running_bundle()


def test_ac11_apply_gateway_config_branches(tmp_path: Path) -> None:
    """AC-11: apply_gateway_config covers running, stopped, unknown, disabled, and reload error."""
    import hashlib

    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=True)
    gw_cfg = make_comet_gateway_config(tmp_path, enabled=True)

    from stremioguard.comet_gateway import GATEWAY_CONFIG_DIR, CometGatewayManager

    # Running: nginx -t, both sha256sum checks, -s reload in order
    gw_ps = tuple(compose_command(tmp_path, "ps", "-q", "comet-gateway"))
    gw_running = ("docker", "inspect", "--format", "{{.State.Running}}", "gw-id")
    nginx_base = ("docker", "exec", "gw-id", "nginx", "-c", f"{GATEWAY_CONFIG_DIR}/nginx.conf")
    nginx_t = (*nginx_base, "-t")
    nginx_reload = (*nginx_base, "-s", "reload")
    sha_conf = ("docker", "exec", "gw-id", "sha256sum", f"{GATEWAY_CONFIG_DIR}/nginx.conf")
    sha_map = ("docker", "exec", "gw-id", "sha256sum", f"{GATEWAY_CONFIG_DIR}/tokens.map")

    temp_gw = CometGatewayManager(gw_cfg, FakeRunner({}))
    temp_gw.write_nginx_configs()
    conf_hash = hashlib.sha256(gw_cfg.nginx_conf_file.read_bytes()).hexdigest()
    map_hash = hashlib.sha256(gw_cfg.tokens_map_file.read_bytes()).hexdigest()

    runner_run = FakeRunner(
        {
            gw_ps: completed(list(gw_ps), "gw-id\n"),
            gw_running: completed(list(gw_running), "true\n"),
            nginx_t: completed(list(nginx_t)),
            sha_conf: completed(
                list(sha_conf), f"{conf_hash}  /etc/stremioguard-gateway/nginx.conf\n"
            ),
            sha_map: completed(
                list(sha_map), f"{map_hash}  /etc/stremioguard-gateway/tokens.map\n"
            ),
            nginx_reload: completed(list(nginx_reload)),
        }
    )
    CometManager(cfg, runner_run).apply_gateway_config()
    exec_calls = [tuple(c) for c in runner_run.calls if c[:2] == ["docker", "exec"]]
    assert exec_calls == [nginx_t, sha_conf, sha_map, nginx_reload]

    # Not running: no docker exec
    runner_stopped = FakeRunner({gw_ps: completed(list(gw_ps), "")})
    CometManager(cfg, runner_stopped).apply_gateway_config()
    assert not any(c[:2] == ["docker", "exec"] for c in runner_stopped.calls)

    # Unknown (None): RuntimeError
    runner_unknown = FakeRunner({gw_ps: completed(list(gw_ps), "", returncode=1)})
    with pytest.raises(RuntimeError):
        CometManager(cfg, runner_unknown).apply_gateway_config()

    # Comet disabled / Gateway disabled: no Docker call
    runner_disabled = FakeRunner({})
    CometManager(make_comet_config(tmp_path, enabled=False), runner_disabled).apply_gateway_config()
    assert runner_disabled.calls == []

    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8")
    CometManager(
        make_comet_config(tmp_path, gateway_enabled=False), runner_disabled
    ).apply_gateway_config()
    assert runner_disabled.calls == []

    # reload_nginx raising propagates
    runner_fail = FakeRunner(
        {
            gw_ps: completed(list(gw_ps), "gw-id\n"),
            gw_running: completed(list(gw_running), "true\n"),
            nginx_t: completed(list(nginx_t), "", "bad nginx.conf", returncode=1),
        }
    )
    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    with pytest.raises(subprocess.CalledProcessError):
        CometManager(cfg, runner_fail).apply_gateway_config()


# ---------------------------------------------------------------------------
# AC-12: CLI start/restart convergence wiring
# ---------------------------------------------------------------------------


def test_ac12_cli_start_and_restart_converge_wiring(tmp_path: Path) -> None:
    """AC-12: start/restart converge after watchdog; errors exit 1 with remediation."""
    for cmd_fn in (general_cmd_mod.start, general_cmd_mod.restart):
        calls: list[str] = []
        fake_mgr = mock.Mock()
        fake_mgr.config.enabled = True
        fake_mgr.converge_running_stack.side_effect = lambda c=calls: c.append("converge")
        with (
            mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
            mock.patch.object(general_cmd_mod, "RunContext"),
            mock.patch.object(
                supervisor_mod,
                "prepare_supervision",
                side_effect=lambda c=calls, **kw: c.append("prepare") or False,
            ),
            mock.patch.object(supervisor_mod, "stop_watchdog", return_value=True),
            mock.patch.object(supervisor_mod, "render_watchdog_env"),
            mock.patch.object(
                general_cmd_mod,
                "run_guard",
                side_effect=lambda *a, c=calls, **k: c.append("guard"),
            ),
            mock.patch.object(
                supervisor_mod,
                "start_watchdog",
                side_effect=lambda *a, c=calls, **k: c.append("watchdog"),
            ),
            mock.patch.object(general_cmd_mod, "_comet_manager", return_value=fake_mgr),
        ):
            cmd_fn()
        assert calls == ["prepare", "guard", "watchdog", "converge"]

    # run_guard exit 1 and 78: converge not called
    for code in (1, 78):
        fake_mgr = mock.Mock()
        fake_mgr.config.enabled = True
        with (
            mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
            mock.patch.object(general_cmd_mod, "RunContext"),
            mock.patch.object(supervisor_mod, "prepare_supervision", return_value=False),
            mock.patch.object(supervisor_mod, "render_watchdog_env"),
            mock.patch.object(general_cmd_mod, "run_guard", side_effect=typer.Exit(code)),
            mock.patch.object(supervisor_mod, "start_watchdog"),
            mock.patch.object(general_cmd_mod, "_comet_manager", return_value=fake_mgr),
            pytest.raises(typer.Exit),
        ):
            general_cmd_mod.start()
        fake_mgr.converge_running_stack.assert_not_called()

    # converge_running_stack raises -> exit 1 after watchdog started, naming remediation
    events: list[str] = []
    fake_mgr_fail = mock.Mock()
    fake_mgr_fail.config.enabled = True
    fake_mgr_fail.converge_running_stack.side_effect = RuntimeError("nginx reload failed")
    with (
        mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
        mock.patch.object(general_cmd_mod, "RunContext"),
        mock.patch.object(supervisor_mod, "prepare_supervision", return_value=False),
        mock.patch.object(supervisor_mod, "render_watchdog_env"),
        mock.patch.object(general_cmd_mod, "run_guard"),
        mock.patch.object(
            supervisor_mod, "start_watchdog", side_effect=lambda *a, **k: events.append("watchdog")
        ),
        mock.patch.object(general_cmd_mod, "_comet_manager", return_value=fake_mgr_fail),
        mock.patch.object(general_cmd_mod, "fail", side_effect=typer.Exit(1)) as fail_mock,
        pytest.raises(typer.Exit) as exc,
    ):
        general_cmd_mod.start()
    assert exc.value.exit_code == 1
    assert events == ["watchdog"]
    fail_msg = fail_mock.call_args.args[0]
    assert "./stremio comet gateway-reload" in fail_msg
    assert "./stremio restart" in fail_msg

    # _comet_manager() raises -> exit 1 after watchdog started
    events.clear()
    with (
        mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
        mock.patch.object(general_cmd_mod, "RunContext"),
        mock.patch.object(supervisor_mod, "prepare_supervision", return_value=False),
        mock.patch.object(supervisor_mod, "render_watchdog_env"),
        mock.patch.object(general_cmd_mod, "run_guard"),
        mock.patch.object(
            supervisor_mod, "start_watchdog", side_effect=lambda *a, **k: events.append("watchdog")
        ),
        mock.patch.object(
            general_cmd_mod, "_comet_manager", side_effect=RuntimeError("bad snapshot")
        ),
        mock.patch.object(general_cmd_mod, "fail", side_effect=typer.Exit(1)) as fail_mock,
        pytest.raises(typer.Exit) as exc,
    ):
        general_cmd_mod.start()
    assert exc.value.exit_code == 1
    assert events == ["watchdog"]
    assert "./stremio comet gateway-reload" in fail_mock.call_args.args[0]

    # Comet disabled -> converge not called
    fake_mgr_disabled = mock.Mock()
    fake_mgr_disabled.config.enabled = False
    with (
        mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
        mock.patch.object(general_cmd_mod, "RunContext"),
        mock.patch.object(supervisor_mod, "prepare_supervision", return_value=False),
        mock.patch.object(supervisor_mod, "render_watchdog_env"),
        mock.patch.object(general_cmd_mod, "run_guard"),
        mock.patch.object(supervisor_mod, "start_watchdog"),
        mock.patch.object(general_cmd_mod, "_comet_manager", return_value=fake_mgr_disabled),
    ):
        general_cmd_mod.start()
    fake_mgr_disabled.converge_running_stack.assert_not_called()


# ---------------------------------------------------------------------------
# AC-13: Configure-page password visibility and preservation
# ---------------------------------------------------------------------------


def test_ac13_configure_page_password_preservation_and_warnings(tmp_path: Path) -> None:
    """AC-13: preserves runtime password on omission/empty, warns without leaking password."""
    from stremioguard.env import parse_dotenv

    canary = "SGF13CanaryPassword-9xQ!"
    records: list[str] = []
    sink_id = logger.add(lambda msg: records.append(str(msg)), level="WARNING")
    try:
        # (a) .env sets it -> used, no warning
        root_a = tmp_path / "a"
        root_a.mkdir()
        (root_a / ".env").write_text(
            f"COMET_ENABLED=1\nCOMET_CONFIGURE_PAGE_PASSWORD={canary}\n", encoding="utf-8"
        )
        mgr_a = CometManager(config_mod.CometConfig.from_env(root_a), FakeRunner({}))
        mgr_a._write_postgres_env("pgpass")
        rendered_a = mgr_a.render_runtime_env()
        assert parse_dotenv(rendered_a)["CONFIGURE_PAGE_PASSWORD"] == canary
        assert records == []

        # (b) .env lacks it, .stremio/comet/.env has canary -> kept + warning
        root_b = tmp_path / "b"
        root_b.mkdir()
        (root_b / ".env").write_text("COMET_ENABLED=1\n", encoding="utf-8")
        cfg_b = config_mod.CometConfig.from_env(root_b)
        cfg_b.runtime_env_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_b.runtime_env_file.write_text(f"CONFIGURE_PAGE_PASSWORD='{canary}'\n", encoding="utf-8")
        mgr_b = CometManager(cfg_b, FakeRunner({}))
        mgr_b._write_postgres_env("pgpass")
        rendered_b = mgr_b.render_runtime_env()
        assert parse_dotenv(rendered_b)["CONFIGURE_PAGE_PASSWORD"] == canary
        assert len(records) == 1
        assert "COMET_CONFIGURE_PAGE_PASSWORD" in records[0]
        assert ".stremio/comet/.env" in records[0]
        assert canary not in records[0]

        # (c) .env has empty value, same runtime file -> kept + warning
        records.clear()
        root_c = tmp_path / "c"
        root_c.mkdir()
        (root_c / ".env").write_text(
            "COMET_ENABLED=1\nCOMET_CONFIGURE_PAGE_PASSWORD=\n", encoding="utf-8"
        )
        cfg_c = config_mod.CometConfig.from_env(root_c)
        cfg_c.runtime_env_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_c.runtime_env_file.write_text(f"CONFIGURE_PAGE_PASSWORD='{canary}'\n", encoding="utf-8")
        mgr_c = CometManager(cfg_c, FakeRunner({}))
        mgr_c._write_postgres_env("pgpass")
        rendered_c = mgr_c.render_runtime_env()
        assert parse_dotenv(rendered_c)["CONFIGURE_PAGE_PASSWORD"] == canary
        assert len(records) == 1
        assert "COMET_CONFIGURE_PAGE_PASSWORD" in records[0]
        assert ".stremio/comet/.env" in records[0]
        assert canary not in records[0]

        # (d) Neither has one -> generated + warning (never contains generated password)
        records.clear()
        root_d = tmp_path / "d"
        root_d.mkdir()
        (root_d / ".env").write_text("COMET_ENABLED=1\n", encoding="utf-8")
        mgr_d = CometManager(config_mod.CometConfig.from_env(root_d), FakeRunner({}))
        mgr_d._write_postgres_env("pgpass")
        rendered_d = mgr_d.render_runtime_env()

        generated = parse_dotenv(rendered_d)["CONFIGURE_PAGE_PASSWORD"]
        assert len(generated) >= 16
        assert len(records) == 1
        assert "generated" in records[0].lower()
        assert ".stremio/comet/.env" in records[0]
        assert generated not in records[0]
    finally:
        logger.remove(sink_id)


# ---------------------------------------------------------------------------
# AC-14: Incomplete generation refusal in frozen guard and watchdog tick
# ---------------------------------------------------------------------------


def test_ac14_incomplete_generation_refused_by_frozen_guard_and_tick(tmp_path: Path) -> None:
    """AC-14: frozen guard refuses when env.snapshot or compose.base.yml is missing."""
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "STREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
        encoding="utf-8",
    )
    config = make_config(tmp_path)

    # Override exists, env.snapshot and compose.base.yml missing -> raises before runner call
    runner = FakeRunner({})
    frozen_guard = GluetunGuard(config, runner, frozen=True)
    with pytest.raises(RuntimeError, match="env\\.snapshot"):
        frozen_guard.compose_fresh("up", "-d", "--no-deps", "stremio")
    assert runner.calls == []

    # Add env.snapshot, still missing compose.base.yml -> raises naming compose.base.yml
    (tmp_path / PUBLISHED_ENV_FILE).write_text("STREMIO_BIND_ADDRS='127.0.0.1'\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="compose\\.base\\.yml"):
        frozen_guard.compose_fresh("up", "-d", "--no-deps", "stremio")
    assert runner.calls == []

    # Watchdog tick with env.snapshot missing issues no compose up
    (tmp_path / PUBLISHED_ENV_FILE).unlink()
    (tmp_path / PUBLISHED_COMPOSE_FILE).write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    tick_runner = FakeRunner(
        {
            **compose_stack_responses(
                tmp_path,
                containers=("gluetun", "stremio"),
                compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
            ),
            (
                "docker",
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}",
                "gluetun",
            ): completed(["docker", "inspect"], "healthy|2026-11-16T00:00:00Z\n"),
        }
    )
    tick_guard = GluetunGuard(config, tick_runner, frozen=True)
    orch = Orchestrator(tick_guard)
    with (
        mock.patch.object(tick_guard, "gluetun_healthy", return_value=True),
        mock.patch.object(tick_guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(tick_guard, "container_running", return_value=False),
    ):
        assert orch._tick() is False
    assert not any("up" in call for call in tick_runner.calls)

    # All three present but never sealed by a publish -> still refused
    (tmp_path / PUBLISHED_ENV_FILE).write_text("STREMIO_BIND_ADDRS='127.0.0.1'\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="published-generation\\.json is missing"):
        frozen_guard.compose_fresh("up", "-d", "--no-deps", "stremio")
    assert runner.calls == []

    # Sealed as one generation -> frozen guard runs
    seal_generation(tmp_path)
    frozen_guard.compose_fresh("up", "-d", "--no-deps", "stremio", check=False)
    assert len(runner.calls) == 1

    # Non-frozen guard -> publishes, then runs
    (tmp_path / PUBLISHED_ENV_FILE).unlink()
    unfrozen_runner = FakeRunner({})
    GluetunGuard(config, unfrozen_runner, frozen=False).compose_fresh(
        "up", "-d", "--no-deps", "stremio", check=False
    )
    assert (tmp_path / PUBLISHED_ENV_FILE).exists()
    assert len(unfrozen_runner.calls) == 1


# ---------------------------------------------------------------------------
# AC-15: logs() `--` option terminator
# ---------------------------------------------------------------------------


def test_ac15_logs_passes_double_dash_before_path(tmp_path: Path) -> None:
    """AC-15: logs() passes `--` before the log file path."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "stremio-20261116.log"
    log_file.write_text("hello\n", encoding="utf-8")
    with (
        mock.patch.object(general_cmd_mod, "LOG_DIR", log_dir),
        mock.patch.object(general_cmd_mod.subprocess, "run") as run_mock,
    ):
        general_cmd_mod.logs(lines=120)
    run_mock.assert_called_once_with(["tail", "-n", "120", "-f", "--", str(log_file)], check=False)


# ---------------------------------------------------------------------------
# AC-16: Vendor retirement
# ---------------------------------------------------------------------------


def test_ac16_vendor_retirement(tmp_path: Path) -> None:
    """AC-16: vendor-sync removed, git methods gone, status shows image/revision/tested_digest."""
    # (a) Typer CLI rejects `comet vendor-sync`
    cli_result = CliRunner().invoke(cli_app, ["comet", "vendor-sync"])
    assert cli_result.exit_code != 0
    assert "No such command" in cli_result.output

    # (b) Removed methods absent from CometManager
    for removed in (
        "repo_exists",
        "_git",
        "clone_if_missing",
        "fetch_and_checkout_pinned",
        "current_commit",
    ):
        assert not hasattr(CometManager, removed), f"{removed} should be removed"

    # (c) & (d) status(), prepare_runtime(), validate_compatibility() with recording runner
    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=False, patch_episode_pack_results=False)
    _write_lock(cfg.lock_file, tested_digest=SHA_B)
    _write_upstream_patch_sources(cfg)
    (cfg.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()
    CometState(active_digest=SHA_A).save(cfg.state_dir / "state.json")

    active_ref = f"{cfg.image}@{SHA_A}"
    label_cmd = (
        "docker",
        "image",
        "inspect",
        active_ref,
        "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
    )
    inspect_img = ("docker", "image", "inspect", active_ref)
    inspect_repo = (*inspect_img, "--format", "{{json .RepoDigests}}")

    for label_response in (
        completed(list(label_cmd), "87d90b817604\n"),
        completed(list(label_cmd), "<no value>\n"),
        completed(list(label_cmd), "", "no such image", returncode=1),
    ):
        runner = FakeRunner(
            {
                **compose_stack_responses(
                    tmp_path, containers=("gluetun", "comet"), running=("comet",)
                ),
                ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                ("docker", "ps", "--format", "{{.ID}}"): completed(["docker", "ps"], "abc\n"),
                label_cmd: label_response,
                inspect_img: completed(list(inspect_img)),
                inspect_repo: completed(list(inspect_repo), json.dumps([active_ref])),
            }
        )
        mgr = CometManager(cfg, runner)
        logged: list[str] = []
        with (
            mock.patch.object(mgr, "log", side_effect=logged.append),
            mock.patch.object(mgr, "warn", side_effect=logged.append),
            mock.patch.object(
                manager_mod,
                "extract_image_source",
                side_effect=lambda r, ref: _stub_extract(cfg.repo_dir),
            ),
            mock.patch.object(
                manager_mod,
                "import_smoke_test",
                return_value={"status": "passed", "stage": "import", "detail": ""},
            ),
        ):
            mgr.prepare_runtime()
            mgr.validate_compatibility()
            logged.clear()
            mgr.status()

        joined = "\n".join(logged)
        assert active_ref in joined
        assert SHA_B in joined
        expected_rev = (
            "87d90b817604" if label_response.stdout.strip() == "87d90b817604" else "unknown"
        )
        assert expected_rev in joined
        assert "Pinned commit" not in joined
        assert "Vendored repo" not in joined
        assert not any(call[0] == "git" for call in runner.calls)

    # (e) Real vendor/comet.lock.json
    repo_root = Path(__file__).resolve().parent.parent
    real_lock = json.loads((repo_root / "vendor" / "comet.lock.json").read_text(encoding="utf-8"))
    assert set(real_lock.keys()) == {"image", "tested_digest"}
    assert real_lock["tested_digest"] == (
        "sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea"
    )

    # (f) No retired identifiers in src/ outside config.py's fields/from_env
    src_root = repo_root / "src"
    matches: list[str] = []
    for py_file in sorted(src_root.rglob("*.py")):
        for lineno, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), start=1):
            for term in (".repo_dir", "vendor_dir", "pinned_commit", "current_commit"):
                if term in line:
                    matches.append(f"{py_file.relative_to(repo_root)}:{lineno}:{line.strip()}")
    assert len(matches) == 2, matches
    assert all(m.startswith("src/stremioguard/config.py:") for m in matches), matches


# ---------------------------------------------------------------------------
# AC-21: Start path lenient callers fail closed on unknown Comet query
# ---------------------------------------------------------------------------


def test_ac21_start_path_unknown_comet_query_fails_closed(tmp_path: Path) -> None:
    """AC-21: converge_running_stack() (require_comet=False), ensure_running_bundle(),
    and _converge_comet_runtime() refuse when `compose ps -q comet` fails or raises.
    """
    (tmp_path / ".env").write_text("COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    cfg = make_comet_config(tmp_path, gateway_enabled=True)
    CometState(active_digest=SHA_A).save(cfg.state_dir / "state.json")
    write_bundle(cfg, SHA_A, extra={"image_digest": SHA_A})
    ps_cmd = compose_command(tmp_path, "ps", "-q", "comet")

    # (a) non-zero exit, (b) TimeoutExpired, (c) OSError
    faults: list[tuple[str, Any]] = [
        ("nonzero", lambda args, **kw: completed(args, "", "daemon error", returncode=1)),
        (
            "timeout",
            lambda args, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd=args, timeout=30)
            ),
        ),
        ("oserror", lambda args, **kw: (_ for _ in ()).throw(OSError("docker missing"))),
    ]

    for label, effect in faults:
        for method_name in ("converge_running_stack", "ensure_running_bundle"):
            runner = FakeRunner({})
            mgr = CometManager(cfg, runner)
            with (
                mock.patch.object(mgr.runner, "run", side_effect=effect) as run_mock,
                mock.patch.object(
                    mgr, "gateway_manager", side_effect=AssertionError("gateway should not run")
                ),
                pytest.raises(RuntimeError),
            ):
                getattr(mgr, method_name)()
            assert run_mock.call_count == 1, f"{label} {method_name}"
            assert run_mock.call_args.args[0] == ps_cmd

    # CLI _converge_comet_runtime() with ps -q comet exiting non-zero
    cli_runner = FakeRunner(
        {tuple(ps_cmd): completed(ps_cmd, "", "cannot connect to Docker daemon", returncode=1)}
    )
    cli_mgr = CometManager(cfg, cli_runner)
    with (
        mock.patch.object(general_cmd_mod, "_comet_manager", return_value=cli_mgr),
        mock.patch.object(
            cli_mgr, "gateway_manager", side_effect=AssertionError("gateway should not run")
        ),
        mock.patch.object(general_cmd_mod, "fail", side_effect=typer.Exit(1)) as fail_mock,
        pytest.raises(typer.Exit) as exc,
    ):
        general_cmd_mod._converge_comet_runtime()
    assert exc.value.exit_code == 1
    assert cli_runner.calls == [ps_cmd]
    msg = fail_mock.call_args.args[0]
    assert "./stremio comet gateway-reload" in msg
    assert "./stremio restart" in msg
