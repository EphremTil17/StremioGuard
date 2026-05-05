"""Tests for stremioguard.guard — GluetunGuard verification core."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard import config as config_mod
from stremioguard import guard as guard_mod
from stremioguard import preflight as preflight_mod
from stremioguard.guard import GluetunGuard

from .conftest import FakeRunner, completed, make_config

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


if __name__ == "__main__":
    unittest.main()
