"""Tests for stremioguard.guard — GluetunGuard verification core."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stremioguard import config as config_mod
from stremioguard import guard as guard_mod
from stremioguard import preflight as preflight_mod
from stremioguard.guard import GluetunGuard, PublicIPAssessment

from .conftest import FakeRunner, completed, compose_args_prefix, make_config

GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    "{{.State.Health.Status}}",
    "gluetun",
)


class GluetunGuardTests(unittest.TestCase):
    def test_docker_permission_help_detects_socket_permission_error(self) -> None:
        help_text = config_mod.docker_permission_help(
            "permission denied while trying to connect to the docker API "
            "at unix:///var/run/docker.sock"
        )
        assert help_text is not None
        self.assertIn("permission error", help_text.lower())
        self.assertIn("docker ps", help_text)
        self.assertIn("sudo ./stremio", help_text)

    def test_docker_daemon_help_reuses_socket_permission_guidance(self) -> None:
        runner = FakeRunner(
            {
                ("docker", "ps", "--format", "{{.ID}}"): completed(
                    ["docker", "ps", "--format", "{{.ID}}"],
                    "",
                    "permission denied while trying to connect to the docker API "
                    "at unix:///var/run/docker.sock\n",
                    returncode=1,
                )
            }
        )
        help_text = config_mod.docker_daemon_help(runner)
        assert help_text is not None
        self.assertIn("`docker` group", help_text)

    def test_parse_public_ip_accepts_valid_addresses(self) -> None:
        self.assertEqual(config_mod.parse_public_ip("203.0.113.20\n"), "203.0.113.20")
        self.assertEqual(config_mod.parse_public_ip("  198.51.100.10 "), "198.51.100.10")
        self.assertEqual(config_mod.parse_public_ip("2001:db8::1"), "2001:db8::1")

    def test_parse_public_ip_rejects_garbage(self) -> None:
        self.assertIsNone(config_mod.parse_public_ip(""))
        self.assertIsNone(config_mod.parse_public_ip("not.an.ip"))
        self.assertIsNone(config_mod.parse_public_ip("999.999.999.999"))
        self.assertIsNone(config_mod.parse_public_ip("::::"))
        self.assertIsNone(config_mod.parse_public_ip("203.0.113.20 extra"))

    def test_require_commands_reports_docker_socket_permission_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed(
                        ["docker", "ps", "--format", "{{.ID}}"],
                        "",
                        "permission denied while trying to connect to the docker API "
                        "at unix:///var/run/docker.sock\n",
                        returncode=1,
                    ),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            with self.assertRaises(RuntimeError) as ctx:
                guard.require_commands()
            self.assertIn("not authorized to run it", str(ctx.exception))

    def test_gluetun_healthy_returns_true_when_inspect_shows_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "healthy\n")}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertTrue(guard.gluetun_healthy())

    def test_gluetun_healthy_returns_false_when_inspect_shows_starting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())

    def test_gluetun_healthy_returns_false_when_container_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT),
                        "",
                        "Error: No such object: gluetun\n",
                        returncode=1,
                    )
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())

    def test_gluetun_recent_logs_combines_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            docker_logs_args = ("docker", "logs", "--tail", "20", "gluetun")
            runner = FakeRunner(
                {
                    docker_logs_args: completed(
                        list(docker_logs_args), stdout="stdout line\n", stderr="stderr line\n"
                    )
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            result = guard.gluetun_recent_logs()
            self.assertIn("stdout line", result)
            self.assertIn("stderr line", result)

    def test_wait_for_gluetun_healthy_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = GluetunGuard(make_config(tmp_path, gluetun_healthy_timeout_seconds=0), runner)
            with (
                mock.patch.object(guard_mod.time, "sleep", return_value=None),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.wait_for_gluetun_healthy()
            self.assertIn("did not become healthy", str(ctx.exception))

    def test_wait_for_gluetun_healthy_detects_auth_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = GluetunGuard(make_config(tmp_path, gluetun_healthy_timeout_seconds=0), runner)
            with (
                mock.patch.object(guard_mod.time, "sleep", return_value=None),
                mock.patch.object(
                    guard,
                    "gluetun_recent_logs",
                    return_value="AUTH: Received control message: AUTH_FAILED",
                ),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.wait_for_gluetun_healthy()
            self.assertIn("credentials were rejected", str(ctx.exception))
            self.assertIn("./stremio init", str(ctx.exception))

    def test_wait_for_gluetun_healthy_surfaces_logs_on_generic_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = GluetunGuard(make_config(tmp_path, gluetun_healthy_timeout_seconds=0), runner)
            logged: list[str] = []
            with (
                mock.patch.object(guard_mod.time, "sleep", return_value=None),
                mock.patch.object(
                    guard,
                    "gluetun_recent_logs",
                    return_value="some unrecognised error line",
                ),
                mock.patch.object(guard, "log_lines", side_effect=logged.append),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.wait_for_gluetun_healthy()
            self.assertIn("did not become healthy", str(ctx.exception))
            self.assertTrue(any("unrecognised error line" in entry for entry in logged))

    def test_public_ip_via_gluetun_uses_docker_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            exec_call = (
                "docker",
                "exec",
                "gluetun",
                "wget",
                "-qO-",
                "--timeout",
                "1",
                "https://example.test/ip",
            )
            runner = FakeRunner({exec_call: completed(list(exec_call), "203.0.113.20\n")})
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertEqual(guard.public_ip_via_gluetun(), "203.0.113.20")
            self.assertIn(list(exec_call), runner.calls)

    def test_public_ip_safe_accepts_non_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = GluetunGuard(cfg, FakeRunner({}))
            with mock.patch.object(guard, "public_ip_via_gluetun", return_value="203.0.113.20"):
                self.assertTrue(guard.public_ip_safe())

    def test_public_ip_safe_rejects_saved_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = GluetunGuard(cfg, FakeRunner({}))
            with mock.patch.object(guard, "public_ip_via_gluetun", return_value="198.51.100.10"):
                self.assertFalse(guard.public_ip_safe())

    def test_public_ip_safe_warns_once_on_stale_home_ip_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            old = time.time() - (40 * 24 * 3600)
            os.utime(cfg.home_ip_file, (old, old))
            guard = GluetunGuard(cfg, FakeRunner({}))
            warnings: list[str] = []
            with (
                mock.patch.object(guard, "public_ip_via_gluetun", return_value="203.0.113.20"),
                mock.patch.object(guard, "warn", side_effect=warnings.append),
            ):
                self.assertTrue(guard.public_ip_safe())
                self.assertTrue(guard.public_ip_safe())
            stale_warnings = [w for w in warnings if "days old" in w]
            self.assertEqual(len(stale_warnings), 1)

    def test_public_ip_safe_does_not_warn_on_fresh_home_ip_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = GluetunGuard(cfg, FakeRunner({}))
            warnings: list[str] = []
            with (
                mock.patch.object(guard, "public_ip_via_gluetun", return_value="203.0.113.20"),
                mock.patch.object(guard, "warn", side_effect=warnings.append),
            ):
                self.assertTrue(guard.public_ip_safe())
            self.assertFalse(any("days old" in w for w in warnings))

    def test_compose_override_uses_bind_address_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text(
                "STREMIO_BIND_ADDRS=10.168.77.10,100.125.26.36\nSTREMIO_HOST_PORT=12470\n",
                encoding="utf-8",
            )
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            guard.write_compose_override()
            override = (tmp_path / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn('"10.168.77.10:12470:11470"', override)
            self.assertIn('"100.125.26.36:12470:11470"', override)

    def test_compose_override_supports_zero_bind_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=\n", encoding="utf-8")
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            guard.write_compose_override()
            override = (tmp_path / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn("ports: []", override)

    def test_check_bind_addresses_skips_when_env_var_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.dict(guard_mod.os.environ, {"SKIP_BIND_PREFLIGHT": "1"}),
                mock.patch.object(guard, "bind_addresses") as mock_bind,
            ):
                guard.check_bind_addresses()
                mock_bind.assert_not_called()

    def test_check_bind_addresses_skips_when_no_external_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "bind_addresses", return_value=["127.0.0.1", "0.0.0.0"]),
                mock.patch.object(guard.runner, "run") as mock_run,
            ):
                guard.check_bind_addresses()
                mock_run.assert_not_called()

    def test_check_bind_addresses_retries_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "bind_addresses", return_value=["10.0.0.5"]),
                mock.patch.object(preflight_mod.time, "sleep"),
                mock.patch.object(
                    guard.runner,
                    "run",
                    side_effect=[
                        completed(["ip", "-j", "addr", "show"], '[{"addr_info": []}]'),
                        completed(
                            ["ip", "-j", "addr", "show"],
                            '[{"addr_info": [{"local": "10.0.0.5"}]}]',
                        ),
                    ],
                ) as mock_run,
            ):
                guard.check_bind_addresses()
                self.assertEqual(mock_run.call_count, 2)

    def test_check_bind_addresses_fails_after_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "bind_addresses", return_value=["100.0.0.5"]),
                mock.patch.object(preflight_mod.time, "sleep"),
                mock.patch.object(
                    guard.runner,
                    "run",
                    return_value=completed(["ip", "-j", "addr", "show"], '[{"addr_info": []}]'),
                ),
                mock.patch.object(preflight_mod.shutil, "which", return_value="/usr/bin/tailscale"),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.check_bind_addresses()
            self.assertIn("Configured bind IP 100.0.0.5 is missing", str(ctx.exception))
            self.assertIn("check tailscaled / tailscale status", str(ctx.exception))

    def test_preflight_brings_gluetun_up_with_fresh_override(self) -> None:
        # Regression: gluetun must start against a freshly rendered override so
        # bind/mount changes apply before the VPN is verified — a stale-file
        # `compose()` here lets the later services `up` recreate gluetun AFTER
        # the IP check already passed against the old container.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "check_bind_addresses"),
                mock.patch.object(guard, "wait_for_gluetun_healthy"),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
                mock.patch.object(guard, "compose") as compose_mock,
                mock.patch.object(guard, "compose_fresh") as compose_fresh_mock,
            ):
                guard.preflight()
            compose_fresh_mock.assert_called_once_with("up", "-d", "gluetun", capture=False)
            compose_mock.assert_not_called()

    def test_preflight_defers_unavailable_gluetun_to_watchdog_without_service_promotion(
        self,
    ) -> None:
        # A start-time timeout must hand ownership to the watchdog rather than
        # abort before it starts; no protected-service promotion is permitted.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "check_bind_addresses"),
                mock.patch.object(
                    guard,
                    "wait_for_gluetun_healthy",
                    side_effect=guard_mod.GluetunUnavailableError("timed out"),
                ),
                mock.patch.object(guard, "compose_fresh") as compose_fresh_mock,
                mock.patch.object(guard, "public_ip_safe") as public_ip_safe_mock,
            ):
                self.assertFalse(guard.preflight(defer_vpn_recovery=True))

            compose_fresh_mock.assert_called_once_with("up", "-d", "gluetun", capture=False)
            public_ip_safe_mock.assert_not_called()

    def test_preflight_rejects_unverifiable_ip_without_recovery_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "check_bind_addresses"),
                mock.patch.object(guard, "wait_for_gluetun_healthy"),
                mock.patch.object(guard, "compose_fresh"),
                mock.patch.object(guard, "public_ip_safe", return_value=False),
                self.assertRaisesRegex(RuntimeError, "Public IP check failed"),
            ):
                guard.preflight()

    def _preflight_with_pull(self, runner: FakeRunner) -> GluetunGuard:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tmp_path = Path(directory.name)
        (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
        guard = GluetunGuard(make_config(tmp_path), runner)
        with (
            mock.patch.object(guard, "require_commands"),
            mock.patch.object(guard, "check_bind_addresses"),
            mock.patch.object(guard, "wait_for_gluetun_healthy"),
            mock.patch.object(guard, "public_ip_safe", return_value=True),
        ):
            guard.preflight()
        return guard

    def test_preflight_pulls_gluetun_image_before_up(self) -> None:
        # Every start/restart tracks the pinned release channel: the pull
        # must land before gluetun is brought up, never after.
        runner = FakeRunner({})
        self._preflight_with_pull(runner)
        pull_index = next(
            i for i, args in enumerate(runner.calls) if args[-2:] == ["pull", "gluetun"]
        )
        up_index = next(
            i for i, args in enumerate(runner.calls) if args[-3:] == ["up", "-d", "gluetun"]
        )
        self.assertLess(pull_index, up_index)
        self.assertEqual(runner.calls[pull_index][:2], ["docker", "compose"])

    def test_gluetun_pull_failure_never_fails_start(self) -> None:
        # A registry hiccup or offline host must not block a start; gluetun
        # boots from the existing local image instead.
        runner = FakeRunner({})
        real_run = runner.run

        def failing_pull(args: list[str], **kwargs: object):
            if args[-2:] == ["pull", "gluetun"]:
                return completed(args, "", "connection refused", returncode=1)
            return real_run(args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(runner, "run", side_effect=failing_pull):
            self._preflight_with_pull(runner)  # must not raise
        self.assertTrue(any(args[-3:] == ["up", "-d", "gluetun"] for args in runner.calls))

    def test_gluetun_pull_timeout_never_fails_start(self) -> None:
        # Runner pitfall: timeout= makes subprocess.run RAISE TimeoutExpired;
        # a hung registry must not hang or fail the start.
        runner = FakeRunner({})
        real_run = runner.run

        def hanging_pull(args: list[str], **kwargs: object):
            if args[-2:] == ["pull", "gluetun"]:
                raise subprocess.TimeoutExpired(cmd=args, timeout=180)
            return real_run(args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(runner, "run", side_effect=hanging_pull):
            self._preflight_with_pull(runner)  # must not raise
        self.assertTrue(any(args[-3:] == ["up", "-d", "gluetun"] for args in runner.calls))

    def test_public_ip_via_control_server_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cmd = [
                "docker",
                "exec",
                "gluetun-id",
                "wget",
                "-O-",
                "--timeout",
                "1",
                "http://127.0.0.1:18080/v1/publicip/ip",
            ]
            runner = FakeRunner({tuple(cmd): completed(cmd, '{"public_ip": "203.0.113.5"}')})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-id"):
                ip = guard.public_ip_via_control_server()
            self.assertEqual(ip, "203.0.113.5")
            self.assertFalse(guard._control_server_failed)

    def test_public_ip_via_control_server_401_permanent_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cmd = [
                "docker",
                "exec",
                "gluetun-id",
                "wget",
                "-O-",
                "--timeout",
                "1",
                "http://127.0.0.1:18080/v1/publicip/ip",
            ]
            # BusyBox wget shape: exit 1 with the status line on stderr.
            runner = FakeRunner(
                {
                    tuple(cmd): completed(
                        cmd,
                        stdout="",
                        stderr="wget: server returned error: HTTP/1.1 401 Unauthorized\n",
                        returncode=1,
                    )
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-id"):
                ip = guard.public_ip_via_control_server()
            self.assertIsNone(ip)
            self.assertTrue(guard._control_server_failed)

    def test_public_ip_via_control_server_gnu_wget_exit6_permanent_fallback(self) -> None:
        # GNU wget exits 6 on auth failure; detection must not depend on stderr
        # text, which -q used to suppress entirely (the original Phase 1 bug).
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cmd = [
                "docker",
                "exec",
                "gluetun-id",
                "wget",
                "-O-",
                "--timeout",
                "1",
                "http://127.0.0.1:18080/v1/publicip/ip",
            ]
            runner = FakeRunner({tuple(cmd): completed(cmd, stdout="", returncode=6)})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-id"):
                ip = guard.public_ip_via_control_server()
            self.assertIsNone(ip)
            self.assertTrue(guard._control_server_failed)

    def test_public_ip_via_control_server_transient_error_keeps_retrying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cmd = [
                "docker",
                "exec",
                "gluetun-id",
                "wget",
                "-O-",
                "--timeout",
                "1",
                "http://127.0.0.1:18080/v1/publicip/ip",
            ]
            runner = FakeRunner(
                {
                    tuple(cmd): completed(
                        cmd, stdout="", stderr="wget: can't connect to remote host\n", returncode=1
                    )
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-id"):
                ip = guard.public_ip_via_control_server()
            self.assertIsNone(ip)
            self.assertFalse(guard._control_server_failed)

    def test_public_ip_assessment_crosscheck_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(
                make_config(tmp_path, ip_crosscheck_interval_seconds=0), FakeRunner({})
            )
            with (
                mock.patch.object(
                    guard, "public_ip_via_control_server", return_value="203.0.113.5"
                ),
                mock.patch.object(guard, "public_ip_via_gluetun", return_value="198.51.100.10"),
            ):
                assessment = guard.public_ip_assessment()
            self.assertEqual(assessment, PublicIPAssessment.UNSAFE_DEFINITIVE)


if __name__ == "__main__":
    unittest.main()


class ComposeOverrideBootstrapTests(unittest.TestCase):
    """A stack whose generated override is missing must still be
    inspectable and stoppable, and must be able to bootstrap itself."""

    def _guard(self, tmp_path: Path, runner: FakeRunner) -> GluetunGuard:
        config = make_config(tmp_path)
        config.compose_override_file.unlink()  # never published yet
        return GluetunGuard(config, runner)

    def test_compose_omits_a_missing_override_file(self) -> None:
        # Passing `-f` for a nonexistent file is a hard docker error.
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner({})
            guard = self._guard(Path(directory), runner)
            guard.compose("ps", check=False)
            self.assertEqual(runner.calls[-1].count("-f"), 1)
            self.assertNotIn("docker-compose.bindings.yml", " ".join(runner.calls[-1]))
            self.assertIsNotNone(runner.envs[-1])
            assert runner.envs[-1] is not None
            self.assertEqual(runner.envs[-1].get("STREMIOGUARD_MANAGED"), "1")

    def test_instance_check_does_not_publish(self) -> None:
        # Regression: publishing here required a rendered Comet bundle, which
        # preflight has not produced yet, so `./stremio start` on a stack
        # without one failed while telling the operator to run `./stremio
        # start`.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = self._guard(tmp_path, runner)
            with mock.patch.object(guard, "write_compose_override") as publish:
                guard.compose_instance_exists()
            publish.assert_not_called()
            self.assertFalse(guard.config.compose_override_file.exists())


class DaemonIdentityTests(unittest.TestCase):
    """A host can run the rootful daemon and a rootless one side by side.
    Both see the same bind mounts, so the stack must stay pinned to the
    daemon that created it."""

    DOCKER_INFO = ["docker", "info", "--format", "{{.ID}}"]

    def _record(self, tmp_path: Path) -> Path:
        return tmp_path / ".stremio" / "daemon-id"

    def test_first_run_pins_the_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            record = self._record(tmp_path)
            runner = FakeRunner(
                {tuple(self.DOCKER_INFO): completed(self.DOCKER_INFO, "daemon-a\n")}
            )
            preflight_mod.require_matching_daemon(runner, record, warn=lambda _: None)
            self.assertEqual(record.read_text(encoding="utf-8").strip(), "daemon-a")

    def test_same_daemon_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            record = self._record(tmp_path)
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text("daemon-a\n", encoding="utf-8")
            runner = FakeRunner(
                {tuple(self.DOCKER_INFO): completed(self.DOCKER_INFO, "daemon-a\n")}
            )
            preflight_mod.require_matching_daemon(runner, record, warn=lambda _: None)

    def test_switched_daemon_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            record = self._record(tmp_path)
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text("daemon-a\n", encoding="utf-8")
            runner = FakeRunner(
                {tuple(self.DOCKER_INFO): completed(self.DOCKER_INFO, "daemon-b\n")}
            )
            with self.assertRaises(RuntimeError) as ctx:
                preflight_mod.require_matching_daemon(runner, record, warn=lambda _: None)
            message = str(ctx.exception)
            self.assertIn("daemon-a", message)
            self.assertIn("daemon-b", message)
            self.assertIn("docker context ls", message)
            # The record must survive so the operator can still reach the
            # original daemon after reading the error.
            self.assertEqual(record.read_text(encoding="utf-8").strip(), "daemon-a")

    def test_unreadable_daemon_id_warns_instead_of_blocking(self) -> None:
        # An engine that does not report an ID is not a reason to refuse to
        # run a stack that is otherwise healthy.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            record = self._record(tmp_path)
            runner = FakeRunner(
                {tuple(self.DOCKER_INFO): completed(self.DOCKER_INFO, "", "boom", 1)}
            )
            warnings: list[str] = []
            preflight_mod.require_matching_daemon(runner, record, warn=warnings.append)
            self.assertFalse(record.exists())
            self.assertEqual(len(warnings), 1)

    def test_guard_pins_daemon_during_require_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {tuple(self.DOCKER_INFO): completed(self.DOCKER_INFO, "daemon-a\n")}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard_mod, "require_docker", return_value=None):
                guard.require_commands()
            self.assertEqual(self._record(tmp_path).read_text(encoding="utf-8").strip(), "daemon-a")

    def test_gluetun_auth_failed_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-123"):
                with mock.patch.object(
                    guard,
                    "gluetun_recent_logs",
                    return_value="2026-08-20 AUTH: Received control message: AUTH_FAILED",
                ) as mock_logs:
                    self.assertTrue(guard.gluetun_auth_failed(since_epoch=1700000000.0))
                    mock_logs.assert_called_once_with(lines=50, since_epoch=1700000000.0)

                with mock.patch.object(
                    guard, "gluetun_recent_logs", return_value="normal wireguard handshake"
                ):
                    self.assertFalse(guard.gluetun_auth_failed())

    def test_read_and_write_vpn_lockout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            env_path = tmp_path / ".env"
            env_path.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=wireguard\n", encoding="utf-8"
            )
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-abc"):
                guard.write_vpn_lockout(reason="auth_rejected", outage_duration_seconds=15.4)

            lockout_file = guard.config.vpn_lockout_file
            self.assertTrue(lockout_file.exists())
            mode = stat.S_IMODE(lockout_file.stat().st_mode)
            self.assertEqual(mode, 0o600)

            data = guard.read_vpn_lockout()
            self.assertIsNotNone(data)
            assert data is not None
            self.assertEqual(data["reason"], "auth_rejected")
            self.assertEqual(data["outage_duration_seconds"], 15.4)
            self.assertEqual(data["gluetun_container_id"], "gluetun-abc")
            self.assertEqual(data["provider"], "nordvpn")
            self.assertEqual(data["vpn_type"], "wireguard")
            self.assertIn("init", str(data["remediation"]))

            guard.clear_vpn_lockout()
            self.assertFalse(lockout_file.exists())
            self.assertIsNone(guard.read_vpn_lockout())

    def test_preflight_blocks_on_lockout_and_allows_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            env_path = tmp_path / ".env"
            env_path.write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            guard.write_vpn_lockout(
                reason="recovery_budget_exhausted", outage_duration_seconds=300.0
            )

            # Blocked start
            with self.assertRaises(RuntimeError) as ctx:
                guard.preflight(allow_recovery=False)
            self.assertIn("VPN circuit breaker is active", str(ctx.exception))
            self.assertIn("recovery_budget_exhausted", str(ctx.exception))

            # Allowed recovery
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "check_bind_addresses"),
                mock.patch.object(guard, "refresh_gluetun_image"),
                mock.patch.object(guard, "compose_fresh"),
                mock.patch.object(guard, "wait_for_gluetun_healthy"),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
            ):
                guard.preflight(allow_recovery=True)
            # Lockout marker must be cleared after healthy preflight
            self.assertFalse(guard.config.vpn_lockout_file.exists())

    def test_state_aware_stop_active_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)

            # When containers are NOT running, compose stop is skipped
            with mock.patch.object(guard, "container_running", return_value=False):
                guard.stop_active_services(["stremio"])
            prefix = compose_args_prefix(tmp_path)
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)

            # When containers ARE running, compose stop is executed
            with mock.patch.object(guard, "container_running", return_value=True):
                guard.stop_active_services(["stremio"])
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)

    def test_stop_and_restart_gluetun_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            prefix = compose_args_prefix(tmp_path)

            guard.stop_gluetun()
            self.assertIn([*prefix, "stop", "gluetun"], runner.calls)

            guard.restart_gluetun()
            self.assertIn([*prefix, "restart", "gluetun"], runner.calls)

            guard.restart_gluetun_relaxed()
            self.assertIn([*prefix, "up", "-d", "--force-recreate", "gluetun"], runner.calls)

    def test_stop_gluetun_fallback_and_failure_handling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)

            # Scenario 1: Compose stop fails (e.g. nonzero return or container still running),
            # fallback docker stop succeeds
            running_states = [True, False]

            def fake_running_succeeds(*args: object, **kwargs: object) -> bool:
                return running_states.pop(0) if running_states else False

            with (
                mock.patch.object(guard, "service_container_id", return_value="gluetun-xyz"),
                mock.patch.object(guard, "container_running", side_effect=fake_running_succeeds),
                mock.patch.object(guard, "success") as mock_success,
                mock.patch.object(guard, "warn") as mock_warn,
            ):
                guard.stop_gluetun()
                self.assertIn(["docker", "stop", "-t", "5", "gluetun-xyz"], runner.calls)
                mock_success.assert_called_once_with("Gluetun VPN container is stopped.")
                mock_warn.assert_not_called()

            # Scenario 2: Both Compose stop and fallback docker stop fail
            # (container remains running)
            with (
                mock.patch.object(guard, "service_container_id", return_value="gluetun-xyz"),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "success") as mock_success,
                mock.patch.object(guard, "warn") as mock_warn,
            ):
                guard.stop_gluetun()
                mock_warn.assert_called_once()
                self.assertIn(
                    "FATAL: Gluetun VPN container could not be stopped",
                    mock_warn.call_args[0][0],
                )
                mock_success.assert_not_called()

    def test_stop_active_services_warns_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "warn") as mock_warn,
                mock.patch.object(guard, "success") as mock_success,
            ):
                guard.stop_active_services(["stremio"])
                mock_warn.assert_called_once()
                self.assertIn("Failed to confirm shutdown", mock_warn.call_args[0][0])
                mock_success.assert_not_called()

    def test_check_vpn_lockout_fails_closed_on_corrupt_or_empty_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))

            # Empty file
            guard.config.vpn_lockout_file.write_text("", encoding="utf-8")
            with self.assertRaises(RuntimeError) as ctx:
                guard.check_vpn_lockout(allow_recovery=False)
            self.assertIn("VPN circuit breaker is active", str(ctx.exception))
            self.assertIn("corrupted or malformed", str(ctx.exception))

            # Invalid JSON
            guard.config.vpn_lockout_file.write_text("{not valid json...", encoding="utf-8")
            with self.assertRaises(RuntimeError) as ctx:
                guard.check_vpn_lockout(allow_recovery=False)
            self.assertIn("VPN circuit breaker is active", str(ctx.exception))

    def test_clear_vpn_lockout_raises_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            guard.config.vpn_lockout_file.write_text("{}", encoding="utf-8")

            with mock.patch.object(Path, "unlink", side_effect=PermissionError("read-only")):
                with self.assertRaises(RuntimeError) as ctx:
                    guard.clear_vpn_lockout()
                self.assertIn("Failed to remove VPN lockout marker", str(ctx.exception))

    def test_gluetun_recent_logs_passes_bounded_tail_and_since(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-abc"):
                guard.gluetun_recent_logs(lines=30, since_epoch=1700000000.0)
            self.assertIn(
                ["docker", "logs", "--tail", "30", "--since", "1700000000", "gluetun-abc"],
                runner.calls,
            )

    def test_gluetun_compose_projects_server_filters_to_environment(self) -> None:
        compose_content = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(
            encoding="utf-8"
        )
        for key in (
            "SERVER_COUNTRIES",
            "SERVER_REGIONS",
            "SERVER_CITIES",
            "SERVER_HOSTNAMES",
            "SERVER_CATEGORIES",
            "OPENVPN_ENDPOINT_IP",
            "WIREGUARD_ENDPOINT_IP",
        ):
            self.assertIn(f'{key}: "${{{key}:-}}"', compose_content)

    def test_restart_gluetun_force_refreshes_dynamic_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "SERVER_COUNTRIES=United States\n"
                "SERVER_CITIES=Seattle\n",
                encoding="utf-8",
            )
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with (
                mock.patch(
                    "stremioguard.resolver.resolve_nordvpn_endpoint",
                    return_value=("us-new.nordvpn.com", "187.15.99.99"),
                ) as mock_resolve,
                mock.patch.object(guard, "compose") as mock_compose,
            ):
                guard.restart_gluetun()
                mock_resolve.assert_called_once()
                self.assertTrue(mock_resolve.call_args[1]["force_refresh"])
                mock_compose.assert_called_once_with(
                    "up",
                    "-d",
                    "--force-recreate",
                    "gluetun",
                    check=False,
                    env={
                        "OPENVPN_ENDPOINT_IP": "187.15.99.99",
                        "WIREGUARD_ENDPOINT_IP": "187.15.99.99",
                    },
                )

    def test_restart_gluetun_relaxed_clears_endpoint_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with mock.patch.object(guard, "compose") as mock_compose:
                guard.restart_gluetun_relaxed()
                mock_compose.assert_called_once_with(
                    "up",
                    "-d",
                    "--force-recreate",
                    "gluetun",
                    check=False,
                    env={
                        "SERVER_REGIONS": "",
                        "SERVER_CITIES": "",
                        "SERVER_HOSTNAMES": "",
                        "SERVER_CATEGORIES": "",
                        "OPENVPN_ENDPOINT_IP": "",
                        "WIREGUARD_ENDPOINT_IP": "",
                    },
                )
