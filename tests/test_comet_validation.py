"""Tests for stremioguard.comet.validation — Phase 6 validation stages.

import_smoke_test and ephemeral_boot_check both shell out to real `docker`
commands; here every docker interaction is scripted through a mocked runner
(no network, no real Docker daemon), per the project's existing convention.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.comet.validation import (
    container_path_to_module,
    ephemeral_boot_check,
    import_smoke_test,
)

from .conftest import completed


class ContainerPathToModuleTests(unittest.TestCase):
    def test_converts_nested_python_path(self) -> None:
        self.assertEqual(
            container_path_to_module("/app/comet/api/endpoints/stream.py"),
            "comet.api.endpoints.stream",
        )

    def test_returns_none_for_non_python_output(self) -> None:
        self.assertIsNone(container_path_to_module("/app/comet/templates/index.html"))


class ImportSmokeTestTests(unittest.TestCase):
    def test_passes_and_mounts_every_python_output(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = completed(["docker"], "", "")
        outputs = {
            "stream.py": "/app/comet/api/endpoints/stream.py",
            "index.html": "/app/comet/templates/index.html",
        }
        result = import_smoke_test(runner, "g0ldyy/comet@sha256:abc", outputs, Path("/bundle"))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["stage"], "import")

        args = runner.run.call_args.args[0]
        self.assertEqual(args[:5], ["docker", "run", "--rm", "--network", "none"])
        self.assertIn("--entrypoint", args)
        self.assertIn("uv", args)
        # Only the .py output is bind-mounted; the template is not a module.
        self.assertIn("-v", args)
        mount_index = args.index("-v")
        self.assertEqual(
            args[mount_index + 1],
            f"{Path('/bundle') / 'stream.py'}:/app/comet/api/endpoints/stream.py:ro",
        )
        self.assertNotIn("index.html", " ".join(args))
        # The import statement only references the Python module, not the template.
        script = args[-1]
        self.assertEqual(script, "import comet.api.endpoints.stream")

    def test_no_python_outputs_passes_without_running_docker(self) -> None:
        runner = mock.Mock()
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {"index.html": "/app/comet/templates/index.html"},
            Path("."),
        )
        self.assertEqual(result["status"], "passed")
        runner.run.assert_not_called()

    def test_timeout_expired_reports_failure_instead_of_raising(self) -> None:
        # Same Runner pitfall as _remote_digest/ephemeral polls: timeout= makes
        # subprocess.run RAISE TimeoutExpired, not return a nonzero result.
        runner = mock.Mock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=60)
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {"stream.py": "/app/comet/api/endpoints/stream.py"},
            Path("/bundle"),
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("timed out", str(result["detail"]))

    def test_failure_surfaces_stderr_in_detail(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = completed(
            ["docker"], "", "ModuleNotFoundError: No module named 'fastapi'", returncode=1
        )
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {"stream.py": "/app/comet/api/endpoints/stream.py"},
            Path("/bundle"),
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("fastapi", str(result["detail"]))


def _mock_runner(*responses: object) -> mock.Mock:
    runner = mock.Mock()
    runner.run.side_effect = list(responses)
    return runner


class EphemeralBootCheckTests(unittest.TestCase):
    _OUTPUTS = {"stream.py": "/app/comet/api/endpoints/stream.py"}

    def test_full_success_path_cleans_up_container_and_network(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", ""),  # network create
            completed(["docker", "run", "-d"], "cid123\n", ""),  # container start
            completed(["docker", "exec"], '{"status":"ok"}', ""),  # health
            completed(["docker", "exec"], '{"id":"stremio.comet.fast"}', ""),  # manifest
            completed(["docker", "rm", "-f"], "", ""),  # cleanup: container
            completed(["docker", "network", "rm"], "", ""),  # cleanup: network
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result, {"status": "passed", "stage": "deep", "detail": ""})

        calls = [call.args[0] for call in runner.run.call_args_list]
        self.assertEqual(calls[0][:3], ["docker", "network", "create"])
        self.assertEqual(calls[1][:4], ["docker", "run", "-d", "--network"])
        # The deep boot must run the image's OWN entrypoint — overriding it
        # with a hand-replicated command would drift from upstream silently.
        self.assertNotIn("--entrypoint", calls[1])
        self.assertEqual(calls[1][-1], "g0ldyy/comet@sha256:abc")
        self.assertIn("cid123", calls[-2])  # container rm -f
        self.assertEqual(calls[-1][:3], ["docker", "network", "rm"])

    def test_network_create_failure_is_reported_and_still_attempts_cleanup(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", "permission denied", returncode=1),
            completed(["docker", "network", "rm"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("permission denied", str(result["detail"]))
        self.assertEqual(runner.run.call_count, 2)

    def test_container_start_failure_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", ""),
            completed(["docker", "run", "-d"], "", "no such image", returncode=1),
            completed(["docker", "network", "rm"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("no such image", str(result["detail"]))

    def test_missing_container_id_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", ""),
            completed(["docker", "run", "-d"], "", ""),
            completed(["docker", "network", "rm"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("no container ID", str(result["detail"]))

    def test_health_never_becomes_reachable_reports_failure_with_logs(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", ""),
            completed(["docker", "run", "-d"], "cid123\n", ""),
            completed(["docker", "logs"], "boot crashed\n", ""),
            completed(["docker", "rm", "-f"], "", ""),
            completed(["docker", "network", "rm"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle"), timeout_seconds=0
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("never became reachable", str(result["detail"]))
        self.assertIn("boot crashed", str(result["detail"]))

    def test_health_check_timeout_expired_is_retried_not_raised(self) -> None:
        runner = mock.Mock()
        runner.run.side_effect = [
            completed(["docker", "network", "create"], "", ""),
            completed(["docker", "run", "-d"], "cid123\n", ""),
            subprocess.TimeoutExpired(cmd=["docker", "exec"], timeout=5),
            completed(["docker", "exec"], '{"status":"ok"}', ""),
            completed(["docker", "exec"], '{"id":"stremio.comet.fast"}', ""),
            completed(["docker", "rm", "-f"], "", ""),
            completed(["docker", "network", "rm"], "", ""),
        ]
        result = ephemeral_boot_check(
            runner,
            "g0ldyy/comet@sha256:abc",
            self._OUTPUTS,
            Path("/bundle"),
            timeout_seconds=30,
            poll_interval_seconds=0,
        )
        self.assertEqual(result["status"], "passed")

    def test_manifest_unreachable_after_healthy_boot_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "network", "create"], "", ""),
            completed(["docker", "run", "-d"], "cid123\n", ""),
            completed(["docker", "exec"], '{"status":"ok"}', ""),
            completed(["docker", "exec"], "", "not found", returncode=1),
            completed(["docker", "rm", "-f"], "", ""),
            completed(["docker", "network", "rm"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("manifest.json was not reachable", str(result["detail"]))


if __name__ == "__main__":
    unittest.main()
