"""Tests for CometManager's digest promotion state machine (Phase 4).

Covers first-run bootstrap (plan 4.3), check_remote/validate_candidate/
promote_candidate/rollback (plan 4.4), and active_image_ref pinning (4.2).
Docker's actual image-copy step (`extract_image_source`) is stubbed to yield
a pre-populated fixture directory — FakeRunner cannot simulate `docker cp`
writing real files, so these tests patch the context manager itself rather
than trying to fake its filesystem side effects.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from stremioguard.comet import manager as manager_mod
from stremioguard.comet.manager import CometManager
from stremioguard.comet.state import CandidateDigest, CometState

from .conftest import FakeRunner, completed, make_comet_config
from .test_comet import _write_lock, _write_upstream_patch_sources

SHA_LATEST = "sha256:" + "1" * 64
SHA_FALLBACK = "sha256:" + "2" * 64
SHA_OTHER = "sha256:" + "3" * 64

PASSED = {"status": "passed", "detail": "", "degraded": []}
PASSED_DEGRADED = {
    "status": "passed",
    "detail": "",
    "degraded": [{"name": "filtering", "reason": "anchor changed"}],
}
FAILED = {"status": "failed", "detail": "required anchor missing", "degraded": []}


@contextmanager
def _stub_extract(fixture_root: Path):
    yield fixture_root


def _write_valid_sources_without_torrentio(cfg) -> None:
    """_write_upstream_patch_sources's torrentio fixture produces output that
    fails compile() (a pre-existing Phase 3 fixture gap never exercised by a
    compile check there). Removing it here makes torrentio a genuine, natural
    "file not found" OPTIONAL skip instead — a deterministic degraded case
    that doesn't depend on fixing an unrelated fixture bug."""
    _write_upstream_patch_sources(cfg)
    (cfg.repo_dir / "comet" / "scrapers" / "torrentio.py").unlink()


def _latest_pull_and_inspect(
    digest: str, *, inspect_ok: bool = True
) -> dict[
    tuple[str, ...], list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str]
]:
    pull_cmd = ("docker", "pull", "g0ldyy/comet:latest")
    inspect_latest_cmd = (
        "docker",
        "image",
        "inspect",
        "g0ldyy/comet:latest",
        "--format",
        "{{json .RepoDigests}}",
    )
    inspect_pinned_cmd = ("docker", "image", "inspect", f"g0ldyy/comet@{digest}")
    return {
        pull_cmd: completed(list(pull_cmd), ""),
        inspect_latest_cmd: completed(
            list(inspect_latest_cmd), json.dumps([f"g0ldyy/comet@{digest}"])
        ),
        inspect_pinned_cmd: completed(
            list(inspect_pinned_cmd), "", returncode=0 if inspect_ok else 1
        ),
    }


class BootstrapActiveDigestTests(unittest.TestCase):
    """Decision-logic tests: _validate_digest is mocked so these exercise only
    _bootstrap_active_digest's branching (pass / degraded-pass / fallback /
    double-failure), independent of the renderer pipeline's own correctness
    (covered by tests/test_overrides_bundle.py and live image verification)."""

    def test_full_pass_sets_active_digest_no_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            runner = FakeRunner(_latest_pull_and_inspect(SHA_LATEST))
            manager = CometManager(cfg, runner)
            with (
                mock.patch.object(manager, "_validate_digest", return_value=PASSED),
                mock.patch.object(manager, "success") as success,
                mock.patch.object(manager, "warn") as warn,
            ):
                manager._bootstrap_active_digest()

            state = manager.load_state()
            self.assertEqual(state.active_digest, SHA_LATEST)
            success.assert_called_once()
            warn.assert_not_called()

    def test_optional_failure_proceeds_non_interactively_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            runner = FakeRunner(_latest_pull_and_inspect(SHA_LATEST))
            manager = CometManager(cfg, runner)
            with (
                mock.patch.object(manager, "_validate_digest", return_value=PASSED_DEGRADED),
                mock.patch.object(manager_mod.sys.stdin, "isatty", return_value=False),
                mock.patch.object(manager, "warn") as warn,
            ):
                manager._bootstrap_active_digest()

            state = manager.load_state()
            self.assertEqual(state.active_digest, SHA_LATEST)
            self.assertTrue(any("degraded" in call.args[0] for call in warn.call_args_list))

    def test_optional_failure_interactive_decline_falls_back_to_tested_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            _write_lock(cfg.lock_file, commit="deadbeef", tested_digest=SHA_FALLBACK)
            pull_fallback = ("docker", "pull", f"g0ldyy/comet@{SHA_FALLBACK}")
            responses = _latest_pull_and_inspect(SHA_LATEST)
            responses[pull_fallback] = completed(list(pull_fallback), "")
            manager = CometManager(cfg, FakeRunner(responses))
            with (
                mock.patch.object(
                    manager, "_validate_digest", side_effect=[PASSED_DEGRADED, PASSED]
                ),
                mock.patch.object(manager_mod.sys.stdin, "isatty", return_value=True),
                mock.patch("typer.confirm", return_value=False),
                mock.patch.object(manager, "warn") as warn,
            ):
                manager._bootstrap_active_digest()
            self.assertEqual(manager.load_state().active_digest, SHA_FALLBACK)
            self.assertTrue(any("declined" in call.args[0] for call in warn.call_args_list))

    def test_required_failure_falls_back_to_tested_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            _write_lock(cfg.lock_file, commit="deadbeef", tested_digest=SHA_FALLBACK)
            pull_fallback = ("docker", "pull", f"g0ldyy/comet@{SHA_FALLBACK}")
            responses = _latest_pull_and_inspect(SHA_LATEST)
            responses[pull_fallback] = completed(list(pull_fallback), "")
            manager = CometManager(cfg, FakeRunner(responses))
            with (
                mock.patch.object(manager, "_validate_digest", side_effect=[FAILED, PASSED]),
                mock.patch.object(manager, "warn") as warn,
            ):
                manager._bootstrap_active_digest()

            state = manager.load_state()
            self.assertEqual(state.active_digest, SHA_FALLBACK)
            self.assertTrue(
                any(
                    "last maintainer-validated image" in call.args[0]
                    for call in warn.call_args_list
                )
            )

    def test_required_failure_and_fallback_failure_raises_generator_bug(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            _write_lock(cfg.lock_file, commit="deadbeef", tested_digest=SHA_FALLBACK)
            pull_fallback = ("docker", "pull", f"g0ldyy/comet@{SHA_FALLBACK}")
            responses = _latest_pull_and_inspect(SHA_LATEST)
            responses[pull_fallback] = completed(list(pull_fallback), "")
            manager = CometManager(cfg, FakeRunner(responses))
            with (
                mock.patch.object(manager, "_validate_digest", side_effect=[FAILED, FAILED]),
                self.assertRaisesRegex(RuntimeError, "bug in the StremioGuard patch"),
            ):
                manager._bootstrap_active_digest()

            # No active_digest was ever persisted from a failed bootstrap.
            self.assertIsNone(manager.load_state().active_digest)


class ValidateDigestPipelineTests(unittest.TestCase):
    """Exercises _validate_digest's real (non-mocked) extract->render->compile
    ->manifest-read wiring, with extract_image_source stubbed to a fixture dir
    (FakeRunner cannot simulate `docker cp`'s filesystem side effects)."""

    def test_empty_source_reports_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            empty_source = tmp_path / "empty-source"
            empty_source.mkdir()
            manager = CometManager(cfg, FakeRunner({}))
            with mock.patch.object(
                manager_mod,
                "extract_image_source",
                side_effect=lambda runner, image_ref: _stub_extract(empty_source),
            ):
                report = manager._validate_digest(SHA_OTHER)
            self.assertEqual(report["status"], "failed")
            self.assertIn("does not contain", str(report["detail"]))

    def test_valid_source_with_missing_optional_file_reports_passed_and_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_valid_sources_without_torrentio(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            with mock.patch.object(
                manager_mod,
                "extract_image_source",
                side_effect=lambda runner, image_ref: _stub_extract(cfg.repo_dir),
            ):
                report = manager._validate_digest(SHA_OTHER)
            self.assertEqual(report["status"], "passed")
            degraded_names = {d["name"] for d in report["degraded"]}  # type: ignore[union-attr]
            self.assertIn("torrentio", degraded_names)

    def test_import_smoke_failure_fails_the_whole_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_valid_sources_without_torrentio(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(cfg.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "failed", "stage": "import", "detail": "boom"},
                ) as smoke,
                mock.patch.object(manager_mod, "ephemeral_boot_check") as deep,
            ):
                report = manager._validate_digest(SHA_OTHER)
            self.assertEqual(report["status"], "failed")
            self.assertIn("boom", str(report["detail"]))
            smoke.assert_called_once()
            deep.assert_not_called()

    def test_deep_false_never_runs_ephemeral_boot_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_valid_sources_without_torrentio(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(cfg.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "passed", "stage": "import", "detail": ""},
                ),
                mock.patch.object(manager_mod, "ephemeral_boot_check") as deep,
            ):
                report = manager._validate_digest(SHA_OTHER, deep=False)
            self.assertEqual(report["status"], "passed")
            deep.assert_not_called()

    def test_deep_true_runs_ephemeral_boot_check_and_can_fail_the_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_valid_sources_without_torrentio(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(cfg.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "passed", "stage": "import", "detail": ""},
                ),
                mock.patch.object(
                    manager_mod,
                    "ephemeral_boot_check",
                    return_value={"status": "failed", "stage": "deep", "detail": "never healthy"},
                ) as deep,
            ):
                report = manager._validate_digest(SHA_OTHER, deep=True)
            self.assertEqual(report["status"], "failed")
            self.assertIn("never healthy", str(report["detail"]))
            deep.assert_called_once()


class ValidateCompatibilityStageTests(unittest.TestCase):
    """validate_compatibility (used by install/start) now also runs the
    mandatory import-smoke stage and records which stage a cached pass
    covers, so a compile-only-era cache entry can't satisfy today's bar."""

    def _manager_ready_to_render(self, tmp_path: Path) -> CometManager:
        cfg = make_comet_config(tmp_path)
        _write_lock(cfg.lock_file, commit="deadbeef")
        _write_valid_sources_without_torrentio(cfg)
        image_ref = f"g0ldyy/comet@{SHA_OTHER}"
        inspect_cmd = ("docker", "image", "inspect", image_ref)
        inspect_digest_cmd = (*inspect_cmd, "--format", "{{json .RepoDigests}}")
        responses: dict[
            tuple[str, ...],
            list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
        ] = {
            inspect_cmd: completed(list(inspect_cmd), ""),
            inspect_digest_cmd: completed(list(inspect_digest_cmd), json.dumps([image_ref])),
        }
        manager = CometManager(cfg, FakeRunner(responses))
        manager.save_state(CometState(active_digest=SHA_OTHER))
        return manager

    def test_writes_import_stage_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = self._manager_ready_to_render(Path(directory))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(manager.config.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "passed", "stage": "import", "detail": ""},
                ),
                mock.patch.object(manager_mod, "ephemeral_boot_check") as deep,
            ):
                manager.validate_compatibility()
            cache = json.loads(
                (manager.config.state_dir / "compatibility.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cache["stage"], "import")
            deep.assert_not_called()

    def test_deep_flag_writes_deep_stage_and_runs_ephemeral_boot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = self._manager_ready_to_render(Path(directory))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(manager.config.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "passed", "stage": "import", "detail": ""},
                ),
                mock.patch.object(
                    manager_mod,
                    "ephemeral_boot_check",
                    return_value={"status": "passed", "stage": "deep", "detail": ""},
                ) as deep,
            ):
                manager.validate_compatibility(deep=True)
            cache = json.loads(
                (manager.config.state_dir / "compatibility.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cache["stage"], "deep")
            deep.assert_called_once()

    def test_smoke_failure_raises_with_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = self._manager_ready_to_render(Path(directory))
            with (
                mock.patch.object(
                    manager_mod,
                    "extract_image_source",
                    side_effect=lambda runner, image_ref: _stub_extract(manager.config.repo_dir),
                ),
                mock.patch.object(
                    manager_mod,
                    "import_smoke_test",
                    return_value={"status": "failed", "stage": "import", "detail": "boom"},
                ),
                self.assertRaisesRegex(RuntimeError, "import-smoke stage"),
            ):
                manager.validate_compatibility()
            self.assertFalse((manager.config.state_dir / "compatibility.json").exists())


class PrepareRuntimeDigestTests(unittest.TestCase):
    def test_prepare_runtime_bootstraps_on_first_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            manager = CometManager(cfg, FakeRunner({}))
            with (
                mock.patch.object(manager, "_bootstrap_active_digest") as bootstrap,
                mock.patch.object(
                    manager,
                    "load_state",
                    side_effect=[CometState(), CometState(active_digest=SHA_LATEST)],
                ),
                mock.patch.object(manager, "ensure_image", return_value=SHA_LATEST),
                mock.patch.object(manager, "_manifest_cache_valid", return_value=True),
                mock.patch.object(manager, "write_stack_override_file"),
            ):
                manager.prepare_runtime()
            bootstrap.assert_called_once()

    def test_prepare_runtime_skips_bootstrap_when_active_digest_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with (
                mock.patch.object(manager, "_bootstrap_active_digest") as bootstrap,
                mock.patch.object(manager, "ensure_image", return_value=SHA_LATEST) as ensure_image,
                mock.patch.object(manager, "_manifest_cache_valid", return_value=True),
                mock.patch.object(manager, "write_stack_override_file"),
            ):
                manager.prepare_runtime()
            bootstrap.assert_not_called()
            ensure_image.assert_called_once_with(f"g0ldyy/comet@{SHA_LATEST}")


class ActiveImageRefTests(unittest.TestCase):
    def test_returns_floating_tag_before_state_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            self.assertEqual(manager.active_image_ref(), "g0ldyy/comet")

    def test_returns_pinned_ref_once_active_digest_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            self.assertEqual(manager.active_image_ref(), f"g0ldyy/comet@{SHA_LATEST}")


class RemoteDigestTests(unittest.TestCase):
    """_remote_digest is advisory-only: every failure mode must map to None."""

    _CMD = (
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        "g0ldyy/comet:latest",
        "--format",
        "{{json .Manifest.Digest}}",
    )

    def test_parses_quoted_json_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner({self._CMD: completed(list(self._CMD), f'"{SHA_OTHER}"\n')})
            manager = CometManager(make_comet_config(Path(directory)), runner)
            self.assertEqual(manager._remote_digest(), SHA_OTHER)

    def test_returns_none_on_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner({self._CMD: completed(list(self._CMD), "", returncode=1)})
            manager = CometManager(make_comet_config(Path(directory)), runner)
            self.assertIsNone(manager._remote_digest())

    def test_returns_none_when_registry_call_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            with mock.patch.object(
                manager.runner,
                "run",
                side_effect=subprocess.TimeoutExpired(cmd=list(self._CMD), timeout=20),
            ):
                self.assertIsNone(manager._remote_digest())


class ResolveRemoteDigestTests(unittest.TestCase):
    """resolve_remote_digest is check_remote minus the active-digest collapse:
    None means ONLY 'probe failed', so the explicit CLI check can tell
    up-to-date apart from registry-unreachable."""

    def test_returns_digest_even_when_unchanged_from_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with mock.patch.object(manager, "_remote_digest", return_value=SHA_LATEST):
                self.assertEqual(manager.resolve_remote_digest(), SHA_LATEST)
            self.assertIsNotNone(manager.load_state().last_remote_check)

    def test_returns_none_only_on_probe_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with mock.patch.object(manager, "_remote_digest", return_value=None):
                self.assertIsNone(manager.resolve_remote_digest())
            # Still records the attempt for the advisory throttle.
            self.assertIsNotNone(manager.load_state().last_remote_check)


class CheckRemoteTests(unittest.TestCase):
    def test_returns_new_digest_when_different_from_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with mock.patch.object(manager, "_remote_digest", return_value=SHA_OTHER):
                result = manager.check_remote()
            self.assertEqual(result, SHA_OTHER)
            self.assertIsNotNone(manager.load_state().last_remote_check)

    def test_returns_none_when_same_as_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with mock.patch.object(manager, "_remote_digest", return_value=SHA_LATEST):
                result = manager.check_remote()
            self.assertIsNone(result)

    def test_returns_none_when_remote_probe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            with mock.patch.object(manager, "_remote_digest", return_value=None):
                result = manager.check_remote()
            self.assertIsNone(result)
            # Still records the check attempt.
            self.assertIsNotNone(manager.load_state().last_remote_check)


class ValidateCandidateTests(unittest.TestCase):
    def test_records_candidate_with_validation_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            report = {"status": "passed", "detail": "", "degraded": []}
            with mock.patch.object(manager, "_validate_digest", return_value=report):
                result = manager.validate_candidate(SHA_OTHER)
            self.assertEqual(result, report)
            candidate = manager.load_state().candidate
            assert candidate is not None
            self.assertEqual(candidate.digest, SHA_OTHER)
            self.assertEqual(candidate.validation, report)


class PromoteCandidateTests(unittest.TestCase):
    def test_promote_requires_a_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            with self.assertRaisesRegex(RuntimeError, "No candidate digest"):
                manager.promote_candidate()

    def test_promote_refuses_when_revalidation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(
                CometState(
                    active_digest=SHA_LATEST,
                    candidate=CandidateDigest(digest=SHA_OTHER, checked_at="t"),
                )
            )
            with (
                mock.patch.object(
                    manager,
                    "_validate_digest",
                    return_value={"status": "failed", "detail": "boom", "degraded": []},
                ),
                self.assertRaisesRegex(RuntimeError, "failed re-validation"),
            ):
                manager.promote_candidate()
            # Active digest must not have moved.
            self.assertEqual(manager.load_state().active_digest, SHA_LATEST)

    def test_promote_swaps_digests_regenerates_and_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(
                CometState(
                    active_digest=SHA_LATEST,
                    candidate=CandidateDigest(digest=SHA_OTHER, checked_at="t"),
                )
            )
            with (
                mock.patch.object(
                    manager,
                    "_validate_digest",
                    return_value={"status": "passed", "detail": "", "degraded": []},
                ),
                mock.patch.object(manager, "prepare_runtime") as prepare_runtime,
                mock.patch.object(manager, "validate_compatibility") as validate_compat,
                mock.patch.object(manager, "compose_fresh") as compose_fresh,
            ):
                manager.promote_candidate()

            state = manager.load_state()
            self.assertEqual(state.active_digest, SHA_OTHER)
            self.assertEqual(state.previous_digest, SHA_LATEST)
            self.assertIsNone(state.candidate)
            prepare_runtime.assert_called_once()
            validate_compat.assert_called_once_with(force=True)
            compose_fresh.assert_called_once()
            self.assertEqual(compose_fresh.call_args.args[0], "up")


class RollbackTests(unittest.TestCase):
    def test_rollback_requires_a_previous_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with self.assertRaisesRegex(RuntimeError, "No previous digest"):
                manager.rollback()

    def test_rollback_swaps_active_and_previous(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = make_comet_config(Path(directory))
            manager = CometManager(cfg, FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_OTHER, previous_digest=SHA_LATEST))
            with (
                mock.patch.object(manager, "prepare_runtime"),
                mock.patch.object(manager, "validate_compatibility"),
                mock.patch.object(manager, "compose_fresh") as compose_fresh,
            ):
                manager.rollback()

            state = manager.load_state()
            self.assertEqual(state.active_digest, SHA_LATEST)
            self.assertEqual(state.previous_digest, SHA_OTHER)
            compose_fresh.assert_called_once()


class AdvisoryUpdateCheckTests(unittest.TestCase):
    """advisory_update_check is the throttled start-time nudge (plan 5.2):
    exception-safe, throttled to once per 24h, and silent unless a new
    digest is actually found."""

    def test_skips_before_first_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            with mock.patch.object(manager, "check_remote") as check_remote:
                manager.advisory_update_check()
            check_remote.assert_not_called()

    def test_skips_when_checked_recently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            recent = datetime.now(UTC).isoformat(timespec="seconds")
            manager.save_state(CometState(active_digest=SHA_LATEST, last_remote_check=recent))
            with mock.patch.object(manager, "check_remote") as check_remote:
                manager.advisory_update_check()
            check_remote.assert_not_called()

    def test_checks_when_last_check_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            stale = (datetime.now(UTC) - timedelta(hours=25)).isoformat(timespec="seconds")
            manager.save_state(CometState(active_digest=SHA_LATEST, last_remote_check=stale))
            with (
                mock.patch.object(manager, "check_remote", return_value=None) as check_remote,
            ):
                manager.advisory_update_check()
            check_remote.assert_called_once()

    def test_logs_one_line_when_update_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with (
                mock.patch.object(manager, "check_remote", return_value=SHA_OTHER),
                mock.patch.object(manager, "log") as log,
            ):
                manager.advisory_update_check()
            log.assert_called_once()
            self.assertIn("update", log.call_args.args[0].lower())

    def test_silent_when_no_update_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with (
                mock.patch.object(manager, "check_remote", return_value=None),
                mock.patch.object(manager, "log") as log,
            ):
                manager.advisory_update_check()
            log.assert_not_called()

    def test_never_raises_on_registry_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = CometManager(make_comet_config(Path(directory)), FakeRunner({}))
            manager.save_state(CometState(active_digest=SHA_LATEST))
            with mock.patch.object(manager, "check_remote", side_effect=RuntimeError("boom")):
                manager.advisory_update_check()  # must not raise


if __name__ == "__main__":
    unittest.main()
