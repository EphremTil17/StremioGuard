"""Tests for stremioguard.comet.state — the digest promotion state machine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stremioguard.comet.state import CandidateDigest, CometState


class CometStateTests(unittest.TestCase):
    def test_load_missing_file_returns_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = CometState.load(Path(directory) / "state.json")
            self.assertIsNone(state.active_digest)
            self.assertIsNone(state.previous_digest)
            self.assertIsNone(state.candidate)
            self.assertIsNone(state.last_remote_check)

    def test_load_corrupt_json_returns_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("{not valid json", encoding="utf-8")
            state = CometState.load(path)
            self.assertIsNone(state.active_digest)

    def test_save_and_load_round_trips_without_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = CometState(
                active_digest="sha256:" + "a" * 64,
                previous_digest="sha256:" + "b" * 64,
                candidate=None,
                last_remote_check="2026-07-14T00:00:00+00:00",
            )
            state.save(path)
            loaded = CometState.load(path)
            self.assertEqual(loaded, state)

    def test_save_and_load_round_trips_with_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            candidate = CandidateDigest(
                digest="sha256:" + "c" * 64,
                checked_at="2026-07-14T00:00:00+00:00",
                validation={"status": "passed", "detail": "", "degraded": []},
            )
            state = CometState(active_digest="sha256:" + "a" * 64, candidate=candidate)
            state.save(path)
            loaded = CometState.load(path)
            self.assertEqual(loaded, state)
            self.assertEqual(loaded.candidate, candidate)

    def test_save_writes_atomically_at_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            CometState(active_digest="sha256:" + "a" * 64).save(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            # No stray temp files left behind by the atomic write.
            leftovers = [p for p in path.parent.iterdir() if p != path]
            self.assertEqual(leftovers, [])

    def test_save_produces_expected_json_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            candidate = CandidateDigest(
                digest="sha256:" + "c" * 64,
                checked_at="2026-07-14T00:00:00+00:00",
                validation={"status": "failed", "detail": "boom", "degraded": []},
            )
            CometState(
                active_digest="sha256:" + "a" * 64,
                previous_digest=None,
                candidate=candidate,
                last_remote_check="2026-07-14T00:00:00+00:00",
            ).save(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["active_digest"], "sha256:" + "a" * 64)
            self.assertIsNone(data["previous_digest"])
            self.assertEqual(data["candidate"]["digest"], "sha256:" + "c" * 64)
            self.assertEqual(data["candidate"]["validation"]["status"], "failed")

    def test_candidate_from_dict_handles_missing_and_empty(self) -> None:
        self.assertIsNone(CandidateDigest.from_dict(None))
        self.assertIsNone(CandidateDigest.from_dict({}))
        restored = CandidateDigest.from_dict({"digest": "sha256:" + "d" * 64})
        assert restored is not None
        self.assertEqual(restored.checked_at, "")
        self.assertIsNone(restored.validation)


if __name__ == "__main__":
    unittest.main()
