"""Tests for stremioguard.comet.validation — Phase 6 validation stages.

import_smoke_test and ephemeral_boot_check both shell out to real `docker`
commands; here every docker interaction is scripted through a mocked runner
(no network, no real Docker daemon), per the project's existing convention.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.comet.validation import (
    container_path_to_module,
    ephemeral_boot_check,
    image_python_command,
    import_smoke_test,
)

from .conftest import completed, make_comet_config


class ContainerPathToModuleTests(unittest.TestCase):
    def test_converts_nested_python_path(self) -> None:
        self.assertEqual(
            container_path_to_module("/app/comet/api/endpoints/stream.py"),
            "comet.api.endpoints.stream",
        )

    def test_returns_none_for_non_python_output(self) -> None:
        self.assertIsNone(container_path_to_module("/app/comet/templates/index.html"))


def _runner_with_entrypoint(
    entrypoint: str,
    *,
    smoke_stdout: str = 'STREMIOGUARD-SMOKE-REPORT {"ok": true, "findings": []}\n',
    smoke_stderr: str = "",
    smoke_returncode: int = 0,
) -> mock.Mock:
    """Runner that answers the image-inspect probe, then returns smoke output."""
    runner = mock.Mock()

    def run(args: list[str], **kwargs: object):
        if args[:3] == ["docker", "image", "inspect"]:
            return completed(args, entrypoint, "")
        return completed(args, smoke_stdout, smoke_stderr, returncode=smoke_returncode)

    runner.run.side_effect = run
    return runner


_GUARD_OUTPUTS = {
    "app.py": "/app/comet/api/app.py",
    "stremioguard_response_guard.py": "/app/comet/stremioguard_response_guard.py",
}


class ImagePythonCommandTests(unittest.TestCase):
    """The interpreter invocation is read from the image, not hardcoded:
    upstream dropped uv in 2026-07 and put its venv first on PATH."""

    def test_uses_uv_prefix_when_the_entrypoint_declares_it(self) -> None:
        runner = _runner_with_entrypoint('["uv","run","python","-m","comet.main"]')
        self.assertEqual(
            image_python_command(runner, "g0ldyy/comet@sha256:abc"), ["uv", "run", "python"]
        )

    def test_uses_bare_python_when_the_entrypoint_declares_it(self) -> None:
        runner = _runner_with_entrypoint('["python","-m","comet.main"]')
        self.assertEqual(image_python_command(runner, "g0ldyy/comet@sha256:abc"), ["python"])

    def test_falls_back_to_python_on_an_unrecognized_entrypoint(self) -> None:
        for entrypoint in ('["/bin/sh","-c","serve"]', "null", "", "not json"):
            runner = _runner_with_entrypoint(entrypoint)
            self.assertEqual(
                image_python_command(runner, "g0ldyy/comet@sha256:abc"),
                ["python"],
                msg=entrypoint,
            )


class ImportSmokeTestTests(unittest.TestCase):
    def test_passes_and_mounts_every_python_output(self) -> None:
        runner = _runner_with_entrypoint('["uv","run","python","-m","comet.main"]')
        outputs = {
            **_GUARD_OUTPUTS,
            "stream.py": "/app/comet/api/endpoints/stream.py",
            "index.html": "/app/comet/templates/index.html",
        }
        result = import_smoke_test(runner, "g0ldyy/comet@sha256:abc", outputs, Path("/bundle"))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["stage"], "import")

        args = runner.run.call_args.args[0]
        self.assertEqual(args[:5], ["docker", "run", "--rm", "--network", "none"])
        self.assertEqual(args[args.index("--entrypoint") + 1], "uv")
        # Only .py outputs are bind-mounted; the template is not a module.
        self.assertIn(
            f"{Path('/bundle') / 'stream.py'}:/app/comet/api/endpoints/stream.py:ro",
            args,
        )
        guard_mount = (
            f"{Path('/bundle') / 'stremioguard_response_guard.py'}"
            ":/app/comet/stremioguard_response_guard.py:ro"
        )
        self.assertIn(guard_mount, args)
        self.assertNotIn("index.html", " ".join(args))
        # The interpreter's remaining argv follows the image reference.
        image_index = args.index("g0ldyy/comet@sha256:abc")
        self.assertEqual(args[image_index + 1 : image_index + 4], ["run", "python", "-c"])
        # The probe source is passed via -c, followed by the sorted Python module names.
        self.assertIn("STREMIOGUARD-SMOKE-REPORT", args[image_index + 4])
        self.assertEqual(
            args[image_index + 5 :],
            [
                "comet.api.app",
                "comet.api.endpoints.stream",
                "comet.stremioguard_response_guard",
            ],
        )

    def test_uses_bare_python_on_images_without_uv(self) -> None:
        runner = _runner_with_entrypoint('["python","-m","comet.main"]')
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {**_GUARD_OUTPUTS, "stream.py": "/app/comet/api/endpoints/stream.py"},
            Path("/bundle"),
        )
        self.assertEqual(result["status"], "passed")
        args = runner.run.call_args.args[0]
        self.assertEqual(args[args.index("--entrypoint") + 1], "python")
        self.assertNotIn("uv", args)
        image_index = args.index("g0ldyy/comet@sha256:abc")
        self.assertEqual(args[image_index + 1], "-c")

    def test_no_python_outputs_passes_without_running_docker(self) -> None:
        runner = mock.Mock()
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {"index.html": "/app/comet/templates/index.html"},
            Path("."),
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("/app/comet/api/app.py", str(result["detail"]))
        runner.run.assert_not_called()

    def test_timeout_expired_reports_failure_instead_of_raising(self) -> None:
        # Same Runner pitfall as _remote_digest/ephemeral polls: timeout= makes
        # subprocess.run RAISE TimeoutExpired, not return a nonzero result.
        runner = mock.Mock()

        def run(args: list[str], **kwargs: object):
            if args[:3] == ["docker", "image", "inspect"]:
                return completed(args, '["python","-m","comet.main"]', "")
            raise subprocess.TimeoutExpired(cmd=args, timeout=60)

        runner.run.side_effect = run
        result = import_smoke_test(
            runner,
            "g0ldyy/comet@sha256:abc",
            {**_GUARD_OUTPUTS, "stream.py": "/app/comet/api/endpoints/stream.py"},
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
            {**_GUARD_OUTPUTS, "stream.py": "/app/comet/api/endpoints/stream.py"},
            Path("/bundle"),
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("fastapi", str(result["detail"]))

    def test_ac5_nonzero_exit_with_report_surfaces_findings(self) -> None:
        runner = _runner_with_entrypoint(
            '["python","-m","comet.main"]',
            smoke_stdout=(
                'STREMIOGUARD-SMOKE-REPORT {"ok": false, '
                '"findings": ["stream probe failed: bad", "torznab probe failed: 200"]}\n'
            ),
            smoke_returncode=1,
        )
        result = import_smoke_test(
            runner, "g0ldyy/comet@sha256:abc", _GUARD_OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("stream probe failed: bad", str(result["detail"]))
        self.assertIn("torznab probe failed: 200", str(result["detail"]))

    def test_ac5_zero_exit_without_report_or_malformed_or_ok_false_fails(self) -> None:
        for stdout in (
            "",
            "just some log line\n",
            "STREMIOGUARD-SMOKE-REPORT {not-json}\n",
            'STREMIOGUARD-SMOKE-REPORT {"ok": false, "findings": ["undefined name"]}\n',
        ):
            runner = _runner_with_entrypoint(
                '["python","-m","comet.main"]',
                smoke_stdout=stdout,
                smoke_stderr="stderr diagnostic tail",
                smoke_returncode=0,
            )
            result = import_smoke_test(
                runner, "g0ldyy/comet@sha256:abc", _GUARD_OUTPUTS, Path("/bundle")
            )
            self.assertEqual(result["status"], "failed", msg=stdout)

    def test_ac5_missing_guard_outputs_fail_without_running_docker(self) -> None:
        for outputs in (
            {"app.py": "/app/comet/api/app.py"},
            {"stremioguard_response_guard.py": "/app/comet/stremioguard_response_guard.py"},
        ):
            runner = mock.Mock()
            result = import_smoke_test(runner, "g0ldyy/comet@sha256:abc", outputs, Path("/bundle"))
            self.assertEqual(result["status"], "failed")
            runner.run.assert_not_called()


class UndefinedNameScanTests(unittest.TestCase):
    """AC-6: host tests of smoke_probe.scan_module_undefined_names."""

    def test_ac6_reports_real_undefined_names_and_allows_valid_patterns(self) -> None:
        import importlib
        import secrets

        from stremioguard.comet.smoke_probe import scan_module_undefined_names

        with tempfile.TemporaryDirectory() as directory:
            pkg_dir = Path(directory)
            helper_name = f"sg_helper_{secrets.token_hex(4)}"
            target_name = f"sg_target_{secrets.token_hex(4)}"

            (pkg_dir / f"{helper_name}.py").write_text("STAR_IMPORTED = 42\n", encoding="utf-8")
            target_file = pkg_dir / f"{target_name}.py"
            target_file.write_text(
                f"""\
from __future__ import annotations

from typing import TYPE_CHECKING
from {helper_name} import *

if TYPE_CHECKING:
    from typing import Any as AnnotationOnlyType

try:
    from nonexistent_optional_pkg import OptionalThing
except ImportError:
    OptionalThing = None


def init_global():
    global _assigned_elsewhere
    _assigned_elsewhere = 123


def read_allowed():
    return (
        len([1, 2]),
        _assigned_elsewhere,
        OptionalThing,
        STAR_IMPORTED,
    )


def annotated_fn(x: AnnotationOnlyType) -> AnnotationOnlyType:
    return x


class SampleClass:
    attr_a = 10
    attr_b = attr_a + 1
    annotated_attr: int = attr_b

    def method_bad(self):
        return missing_in_method


def bad_func():
    return missing_in_func


def outer_func():
    def inner_func():
        return missing_in_nested
    return inner_func


bad_lambda = lambda: missing_in_lambda


def comp_func():
    return [missing_in_comp for _ in range(1)]
""",
                encoding="utf-8",
            )

            sys.path.insert(0, str(pkg_dir))
            try:
                module = importlib.import_module(target_name)
                findings = scan_module_undefined_names(module)
            finally:
                sys.path.remove(str(pkg_dir))
                sys.modules.pop(target_name, None)
                sys.modules.pop(helper_name, None)

            joined = "\n".join(findings)
            self.assertEqual(len(findings), 5, msg=joined)
            for expected_name, expected_code in (
                ("missing_in_method", "method_bad"),
                ("missing_in_func", "bad_func"),
                ("missing_in_nested", "inner_func"),
                ("missing_in_lambda", "<lambda>"),
                ("missing_in_comp", "comp_func"),
            ):
                matching = [
                    f
                    for f in findings
                    if expected_name in f and str(target_file) in f and expected_code in f
                ]
                self.assertEqual(len(matching), 1, msg=f"missing {expected_name} in {joined}")
                # Must include a line number after `target_file:`.
                self.assertRegex(matching[0], rf"{target_file}:\d+")


def _mock_runner(*responses: object) -> mock.Mock:
    runner = mock.Mock()
    runner.run.side_effect = list(responses)
    return runner


class EphemeralBootCheckTests(unittest.TestCase):
    """AC-10 (INV-5): offline --network none ephemeral boot check and cleanup."""

    _OUTPUTS = {"stream.py": "/app/comet/api/endpoints/stream.py"}

    def test_full_success_path_uses_network_none_and_cleans_up_container(self) -> None:
        runner = _mock_runner(
            completed(["docker", "run", "-d"], "cid123\n", ""),  # container start
            completed(
                ["docker", "image", "inspect"], '["uv","run","python","-m","comet.main"]', ""
            ),
            completed(["docker", "exec"], '{"status":"ok"}', ""),  # health
            completed(["docker", "exec"], '{"id":"stremio.comet.fast"}', ""),  # manifest
            completed(["docker", "rm", "-f"], "", ""),  # cleanup: container
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result, {"status": "passed", "stage": "deep", "detail": ""})

        calls = [call.args[0] for call in runner.run.call_args_list]
        self.assertEqual(calls[0][:5], ["docker", "run", "-d", "--network", "none"])
        # The deep boot must run the image's OWN entrypoint — overriding it
        # with a hand-replicated command would drift from upstream silently.
        self.assertNotIn("--entrypoint", calls[0])
        self.assertEqual(calls[0][-1], "g0ldyy/comet@sha256:abc")
        self.assertEqual(calls[2][:6], ["docker", "exec", "cid123", "uv", "run", "python"])
        self.assertEqual(calls[2][6], "-c")
        self.assertIn("/health", calls[2][7])
        self.assertEqual(calls[3][:6], ["docker", "exec", "cid123", "uv", "run", "python"])
        self.assertEqual(calls[3][6], "-c")
        self.assertIn("/manifest.json", calls[3][7])
        self.assertEqual(calls[-1], ["docker", "rm", "-f", "cid123"])

    def test_container_start_failure_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "run", "-d"], "", "no such image", returncode=1),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("no such image", str(result["detail"]))
        self.assertEqual(runner.run.call_count, 1)

    def test_missing_container_id_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "run", "-d"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("no container ID", str(result["detail"]))
        self.assertEqual(runner.run.call_count, 1)

    def test_health_never_becomes_reachable_reports_failure_with_logs(self) -> None:
        runner = _mock_runner(
            completed(["docker", "run", "-d"], "cid123\n", ""),
            completed(["docker", "image", "inspect"], '["python","-m","comet.main"]', ""),
            completed(["docker", "logs"], "boot crashed\n", ""),
            completed(["docker", "rm", "-f"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle"), timeout_seconds=0
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("never became reachable", str(result["detail"]))
        self.assertIn("boot crashed", str(result["detail"]))
        self.assertEqual(runner.run.call_args_list[-1].args[0], ["docker", "rm", "-f", "cid123"])

    def test_health_check_timeout_expired_is_retried_not_raised(self) -> None:
        runner = mock.Mock()
        runner.run.side_effect = [
            completed(["docker", "run", "-d"], "cid123\n", ""),
            completed(["docker", "image", "inspect"], '["python","-m","comet.main"]', ""),
            subprocess.TimeoutExpired(cmd=["docker", "exec"], timeout=5),
            completed(["docker", "exec"], '{"status":"ok"}', ""),
            completed(["docker", "exec"], '{"id":"stremio.comet.fast"}', ""),
            completed(["docker", "rm", "-f"], "", ""),
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
        self.assertEqual(runner.run.call_args_list[-1].args[0], ["docker", "rm", "-f", "cid123"])

    def test_manifest_unreachable_after_healthy_boot_is_reported(self) -> None:
        runner = _mock_runner(
            completed(["docker", "run", "-d"], "cid123\n", ""),
            completed(["docker", "image", "inspect"], '["python","-m","comet.main"]', ""),
            completed(["docker", "exec"], '{"status":"ok"}', ""),
            completed(["docker", "exec"], "", "not found", returncode=1),
            completed(["docker", "rm", "-f"], "", ""),
        )
        result = ephemeral_boot_check(
            runner, "g0ldyy/comet@sha256:abc", self._OUTPUTS, Path("/bundle")
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("manifest.json was not reachable", str(result["detail"]))
        self.assertEqual(runner.run.call_args_list[-1].args[0], ["docker", "rm", "-f", "cid123"])


class ValidatorScriptTests(unittest.TestCase):
    """`python -m stremioguard.comet.validate` — the CI/canary entry point.

    Everything is exercised through `run_validation` with a scripted runner
    and a temp-dir config: these tests must never read this machine's real
    `.env` or gateway token state.
    """

    IMAGE = "g0ldyy/comet@sha256:digest"

    def _run(
        self,
        smoke_result: dict[str, object],
        manifest: dict[str, object],
        *,
        bundle_raises: Exception | None = None,
    ) -> tuple[dict[str, object], mock.Mock]:
        import stremioguard.comet.validate as validate_mod

        runner = mock.Mock()

        def runner_run(args, **kwargs):
            if "{{json .RepoDigests}}" in args:
                return completed(args, f'["{self.IMAGE}"]', "")
            return completed(args, "", "")

        runner.run.side_effect = runner_run

        def fake_write_bundle(repo_dir, state_dir, **kwargs):
            if bundle_raises is not None:
                raise bundle_raises
            state_dir.mkdir(parents=True, exist_ok=True)
            (state_dir / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            source_root = tmp_path / "source"
            (source_root / "comet").mkdir(parents=True)

            @contextlib.contextmanager
            def fake_extract(runner_arg, image_ref):
                yield source_root

            write_bundle = mock.Mock(side_effect=fake_write_bundle)
            with (
                mock.patch.object(
                    validate_mod.CometConfig,
                    "from_env",
                    return_value=make_comet_config(tmp_path),
                ),
                mock.patch.object(validate_mod, "extract_image_source", fake_extract),
                mock.patch.object(validate_mod, "write_override_bundle", write_bundle),
                mock.patch.object(validate_mod, "import_smoke_test", return_value=smoke_result),
            ):
                report = validate_mod.run_validation(runner, self.IMAGE)
        return report, write_bundle

    def test_passed_report_lists_applied_patches(self) -> None:
        report, _ = self._run(
            {"status": "passed", "stage": "import", "detail": ""},
            {"outputs": {"stream.py": "/app/x/stream.py"}, "applied": ["stream"], "skipped": []},
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["applied"], ["stream"])

    def test_renders_the_superset_bundle_not_local_config(self) -> None:
        # tested_digest must vouch for every deployment shape: the gate
        # force-enables the gateway (its specs become required) and episode
        # packs, regardless of what this machine's .env says.
        _, write_bundle = self._run(
            {"status": "passed", "stage": "import", "detail": ""},
            {"outputs": {}, "applied": [], "skipped": []},
        )
        kwargs = write_bundle.call_args.kwargs
        self.assertTrue(kwargs["gateway_enabled"])
        self.assertTrue(kwargs["patch_episode_pack_results"])
        self.assertEqual(kwargs["result_format_style"], "plain")
        self.assertIsNotNone(kwargs["gateway_addon_base_url"])

    def test_any_skipped_spec_fails_even_optional(self) -> None:
        # A skip under the superset config is upstream anchor drift; the
        # canary must not bump tested_digest past a degraded OPTIONAL patch.
        report, _ = self._run(
            {"status": "passed", "stage": "import", "detail": ""},
            {
                "outputs": {},
                "applied": ["stream"],
                "skipped": [{"name": "torrentio", "reason": "anchor not found"}],
            },
        )
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stage"], "render")
        self.assertIn("torrentio", str(report["detail"]))

    def test_smoke_failure_fails_the_report(self) -> None:
        report, _ = self._run(
            {"status": "failed", "stage": "import", "detail": "No module named 'x'"},
            {"outputs": {"stream.py": "/app/x/stream.py"}, "applied": ["stream"], "skipped": []},
        )
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stage"], "import")
        self.assertIn("No module named", str(report["detail"]))

    def test_required_render_failure_fails_the_report(self) -> None:
        report, _ = self._run(
            {"status": "passed", "stage": "import", "detail": ""},
            {},
            bundle_raises=RuntimeError("Required patch 'stream' failed to apply: drift"),
        )
        self.assertEqual(report["status"], "failed")
        self.assertIn("Required patch 'stream'", str(report["detail"]))

    def test_main_exits_nonzero_and_prints_json_report(self) -> None:
        import stremioguard.comet.validate as validate_mod

        failed_report = {"status": "failed", "stage": "import", "detail": "boom"}
        stdout = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["validate", "--image", self.IMAGE, "--json"]),
            mock.patch.object(validate_mod, "run_validation", return_value=failed_report),
            contextlib.redirect_stdout(stdout),
            self.assertRaises(SystemExit) as sysexit,
        ):
            validate_mod.main()
        self.assertEqual(sysexit.exception.code, 1)
        self.assertEqual(json.loads(stdout.getvalue()), failed_report)


if __name__ == "__main__":
    unittest.main()
