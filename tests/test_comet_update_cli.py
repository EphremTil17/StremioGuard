"""Tests for `./stremio comet update` CLI commands (Phase 5.1).

Never-auto-apply is the core invariant: `check` only recommends, `apply`/
`rollback` require the explicit command and must refuse in every unsafe
state (no candidate, failed validation, stale candidate, no previous
digest, non-interactive without --yes).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

from stremioguard.cli.commands import comet_update as comet_update_mod
from stremioguard.comet.manager import CometManager
from stremioguard.comet.state import CandidateDigest, CometState

from .conftest import FakeRunner, make_comet_config

SHA_ACTIVE = "sha256:" + "1" * 64
SHA_NEW = "sha256:" + "2" * 64
SHA_PREV = "sha256:" + "0" * 64
SHA_OTHER = "sha256:" + "9" * 64


def _manager(tmp_path: Path) -> CometManager:
    return CometManager(make_comet_config(tmp_path), FakeRunner({}))


class UpdateCheckTests(unittest.TestCase):
    def test_refuses_without_active_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_check(deep=False)

    def test_registry_probe_failure_fails_loudly_not_up_to_date(self) -> None:
        # An explicit check must never report a failed probe as "up to date".
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=None),
                mock.patch.object(manager, "validate_candidate") as validate_candidate,
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_check(deep=False)
            validate_candidate.assert_not_called()

    def test_already_up_to_date_does_not_validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_ACTIVE),
                mock.patch.object(manager, "validate_candidate") as validate_candidate,
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_check(deep=False)
            validate_candidate.assert_not_called()
            logger_mock.success.assert_called_once()

    def test_new_digest_validated_and_passed_recommends_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            report = {"status": "passed", "detail": "", "degraded": [], "applied": ["stream"]}
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_NEW),
                mock.patch.object(manager, "_validate_digest", return_value=report),
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_check(deep=False)
            candidate = manager.load_state().candidate
            assert candidate is not None
            self.assertEqual(candidate.digest, SHA_NEW)
            logger_mock.success.assert_called_once()
            info_messages = [call.args[0] for call in logger_mock.info.call_args_list]
            self.assertTrue(any("apply" in msg for msg in info_messages))

    def test_new_digest_validated_with_degraded_features_warns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            report = {
                "status": "passed",
                "detail": "",
                "degraded": [{"name": "torrentio", "reason": "anchor changed"}],
                "applied": [],
            }
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_NEW),
                mock.patch.object(manager, "_validate_digest", return_value=report),
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_check(deep=False)
            warning_messages = [call.args[0] for call in logger_mock.warning.call_args_list]
            self.assertTrue(any("degraded" in msg for msg in warning_messages))
            logger_mock.success.assert_not_called()

    def test_new_digest_fails_validation_warns_and_keeps_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            report = {"status": "failed", "detail": "boom", "degraded": [], "applied": []}
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_NEW),
                mock.patch.object(manager, "_validate_digest", return_value=report),
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_check(deep=False)
            self.assertEqual(manager.load_state().active_digest, SHA_ACTIVE)
            warning_messages = [call.args[0] for call in logger_mock.warning.call_args_list]
            self.assertTrue(any("patches fail" in msg for msg in warning_messages))

    def test_feature_diff_flags_newly_degraded_and_newly_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            manager = _manager(tmp_path)
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            manifest_path = manager.config.state_dir / "bundle-manifest.json"
            manifest_path.write_text(
                '{"applied": ["torrentio"], "skipped": [{"name": "filtering", '
                '"reason": "disabled by configuration"}]}',
                encoding="utf-8",
            )
            report = {
                "status": "passed",
                "detail": "",
                "degraded": [{"name": "torrentio", "reason": "anchor changed"}],
                "applied": ["filtering"],
            }
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_NEW),
                mock.patch.object(manager, "_validate_digest", return_value=report),
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_check(deep=False)
            warning_messages = [call.args[0] for call in logger_mock.warning.call_args_list]
            info_messages = [call.args[0] for call in logger_mock.info.call_args_list]
            self.assertTrue(
                any("newly degrade" in msg and "torrentio" in msg for msg in warning_messages)
            )
            self.assertTrue(any("restores" in msg and "filtering" in msg for msg in info_messages))


class UpdateApplyTests(unittest.TestCase):
    def test_refuses_without_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_apply()

    def test_refuses_when_candidate_failed_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(
                CometState(
                    active_digest=SHA_ACTIVE,
                    candidate=CandidateDigest(
                        digest=SHA_NEW, checked_at="t", validation={"status": "failed"}
                    ),
                )
            )
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "promote_candidate") as promote_candidate,
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_apply()
            promote_candidate.assert_not_called()

    def test_refuses_when_candidate_is_stale_vs_remote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(
                CometState(
                    active_digest=SHA_ACTIVE,
                    candidate=CandidateDigest(
                        digest=SHA_NEW, checked_at="t", validation={"status": "passed"}
                    ),
                )
            )
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_OTHER),
                mock.patch.object(manager, "promote_candidate") as promote_candidate,
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_apply()
            promote_candidate.assert_not_called()
            self.assertEqual(manager.load_state().active_digest, SHA_ACTIVE)

    def test_probe_failure_does_not_block_apply(self) -> None:
        # `check_remote` returning None (probe failure vs. no-change are
        # indistinguishable) must not block applying an already-validated
        # candidate — the registry check is advisory-only.
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(
                CometState(
                    active_digest=SHA_ACTIVE,
                    candidate=CandidateDigest(
                        digest=SHA_NEW, checked_at="t", validation={"status": "passed"}
                    ),
                )
            )
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=None),
                mock.patch.object(manager, "promote_candidate") as promote_candidate,
                mock.patch.object(comet_update_mod, "logger"),
            ):
                comet_update_mod.comet_update_apply()
            promote_candidate.assert_called_once()

    def test_promotes_valid_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(
                CometState(
                    active_digest=SHA_ACTIVE,
                    candidate=CandidateDigest(
                        digest=SHA_NEW, checked_at="t", validation={"status": "passed"}
                    ),
                )
            )
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "_remote_digest", return_value=SHA_NEW),
                mock.patch.object(manager, "promote_candidate") as promote_candidate,
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_apply()
            promote_candidate.assert_called_once()
            logger_mock.success.assert_called_once()


class UpdateRollbackTests(unittest.TestCase):
    def test_refuses_without_previous_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_rollback(yes=True)

    def test_non_interactive_without_yes_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE, previous_digest=SHA_PREV))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(comet_update_mod, "is_interactive", return_value=False),
                self.assertRaises(typer.Exit),
            ):
                comet_update_mod.comet_update_rollback(yes=False)
            self.assertEqual(manager.load_state().active_digest, SHA_ACTIVE)

    def test_declining_confirmation_cancels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE, previous_digest=SHA_PREV))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(comet_update_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "confirm", return_value=False),
            ):
                comet_update_mod.comet_update_rollback(yes=False)
            self.assertEqual(manager.load_state().active_digest, SHA_ACTIVE)

    def test_yes_flag_skips_prompt_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manager = _manager(Path(directory))
            manager.save_state(CometState(active_digest=SHA_ACTIVE, previous_digest=SHA_PREV))
            with (
                mock.patch.object(comet_update_mod, "_comet_manager", return_value=manager),
                mock.patch.object(manager, "rollback") as rollback,
                mock.patch.object(comet_update_mod, "logger") as logger_mock,
            ):
                comet_update_mod.comet_update_rollback(yes=True)
            rollback.assert_called_once()
            logger_mock.success.assert_called_once()


if __name__ == "__main__":
    unittest.main()
