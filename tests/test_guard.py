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

from .conftest import (
    FakeRunner,
    completed,
    compose_args_prefix,
    compose_stack_responses,
    make_config,
)

GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    guard_mod.GLUETUN_STATE_FORMAT,
    "gluetun",
)
GLUETUN_STARTED_AT = "2026-11-11T10:00:00.123456789Z"


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
                {
                    **compose_stack_responses(tmp_path),
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"healthy|{GLUETUN_STARTED_AT}\n"
                    ),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertTrue(guard.gluetun_healthy())
            # One inspect answers health and identity, and it is bounded.
            self.assertEqual(
                guard.last_gluetun_state,
                guard_mod.GluetunState("gluetun", "healthy", GLUETUN_STARTED_AT),
            )
            assert guard.last_gluetun_state is not None
            self.assertEqual(guard.last_gluetun_state.identity, ("gluetun", GLUETUN_STARTED_AT))
            inspect_index = runner.calls.index(list(GLUETUN_HEALTH_INSPECT))
            self.assertEqual(
                runner.timeouts[inspect_index], config_mod.DOCKER_QUERY_TIMEOUT_SECONDS
            )

    def test_gluetun_healthy_returns_false_when_inspect_shows_starting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"starting|{GLUETUN_STARTED_AT}\n"
                    ),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())
            self.assertIn(list(GLUETUN_HEALTH_INSPECT), runner.calls)
            assert guard.last_gluetun_state is not None
            self.assertEqual(guard.last_gluetun_state.health, "starting")

    def test_gluetun_healthy_returns_false_when_container_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT),
                        "",
                        "Error: No such object: gluetun\n",
                        returncode=1,
                    ),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())
            self.assertIn(list(GLUETUN_HEALTH_INSPECT), runner.calls)
            # A failed inspect is no identity: namespace checks must not run on it.
            self.assertEqual(
                guard.last_gluetun_state, guard_mod.GluetunState("gluetun", None, None)
            )
            assert guard.last_gluetun_state is not None
            self.assertIsNone(guard.last_gluetun_state.identity)

    def test_gluetun_recent_logs_combines_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            docker_logs_args = ("docker", "logs", "--tail", "20", "gluetun")
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    docker_logs_args: completed(
                        list(docker_logs_args), stdout="stdout line\n", stderr="stderr line\n"
                    ),
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
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"starting|{GLUETUN_STARTED_AT}\n"
                    )
                }
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
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"starting|{GLUETUN_STARTED_AT}\n"
                    )
                }
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
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"starting|{GLUETUN_STARTED_AT}\n"
                    )
                }
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
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-qO-",
                "https://example.test/ip",
            )
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    exec_call: completed(list(exec_call), "203.0.113.20\n"),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertEqual(guard.public_ip_via_gluetun(), "203.0.113.20")
            self.assertIn(list(exec_call), runner.calls)

    def test_public_ip_safe_accepts_non_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = GluetunGuard(cfg, FakeRunner({}))
            with (
                mock.patch.object(guard, "public_ip_via_gluetun", return_value="203.0.113.20"),
                mock.patch.object(guard, "public_ip", return_value=None),
            ):
                self.assertTrue(guard.public_ip_safe())

    def test_public_ip_safe_rejects_saved_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = GluetunGuard(cfg, FakeRunner({}))
            with (
                mock.patch.object(guard, "public_ip_via_gluetun", return_value="198.51.100.10"),
                mock.patch.object(guard, "public_ip", return_value=None),
            ):
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
                mock.patch.object(guard, "public_ip", return_value=None),
                mock.patch.object(guard, "warn", side_effect=warnings.append),
            ):
                # force_probe: re-read the baseline on each call, not a cached SAFE.
                for _ in range(2):
                    self.assertEqual(
                        guard.public_ip_assessment(force_probe=True), PublicIPAssessment.SAFE
                    )
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
                mock.patch.object(guard, "public_ip", return_value=None),
                mock.patch.object(guard, "warn", side_effect=warnings.append),
            ):
                self.assertTrue(guard.public_ip_safe())
            self.assertFalse(any("days old" in w for w in warnings))

    def test_compose_override_uses_bind_address_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text(
                "STREMIO_BIND_ADDRS=192.168.1.10,100.64.0.10\nSTREMIO_HOST_PORT=12470\n",
                encoding="utf-8",
            )
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            guard.write_compose_override()
            override = (tmp_path / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn('"192.168.1.10:12470:11470"', override)
            self.assertIn('"100.64.0.10:12470:11470"', override)

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
                mock.patch.object(guard_mod, "parse_bind_addresses") as mock_bind,
            ):
                guard.check_bind_addresses()
                mock_bind.assert_not_called()

    def test_check_bind_addresses_skips_when_no_external_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(
                    guard_mod, "parse_bind_addresses", return_value=["127.0.0.1", "0.0.0.0"]
                ),
                mock.patch.object(guard.runner, "run") as mock_run,
            ):
                guard.check_bind_addresses()
                mock_run.assert_not_called()

    def test_check_bind_addresses_retries_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(guard_mod, "parse_bind_addresses", return_value=["10.0.0.5"]),
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
                mock.patch.object(guard_mod, "parse_bind_addresses", return_value=["100.0.0.5"]),
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
            # Not `start`'s keep-running mode: no endpoint pinning env.
            compose_fresh_mock.assert_called_once_with(
                "up", "-d", "gluetun", capture=False, env=None
            )
            compose_mock.assert_not_called()

    def test_preflight_keep_running_gluetun_reuses_the_running_endpoint(self) -> None:
        # `./stremio start` against a running tunnel must hand Compose the
        # endpoint the container already has, so a fresh NordVPN
        # recommendation does not recreate a healthy gluetun. Asserted on the
        # env the `up` subprocess actually receives.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            (tmp_path / ".env").write_text(
                "STREMIO_BIND_ADDRS=127.0.0.1\nOPENVPN_ENDPOINT_IP=198.51.100.1\n"
                "VPN_TYPE=openvpn\nSERVER_COUNTRIES=Canada\n",
                encoding="utf-8",
            )
            env_inspect = ("docker", "inspect", "--format", "{{json .Config.Env}}", "gluetun")
            up_cmd = [*compose_args_prefix(tmp_path), "up", "-d", "gluetun"]
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), f"healthy|{GLUETUN_STARTED_AT}\n"
                    ),
                    env_inspect: completed(
                        list(env_inspect),
                        '["PATH=/bin","OPENVPN_ENDPOINT_IP=203.0.113.7",'
                        '"WIREGUARD_ENDPOINT_IP=","VPN_TYPE=openvpn","SERVER_COUNTRIES=Canada"]\n',
                    ),
                    tuple(up_cmd): completed(up_cmd),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "check_bind_addresses"),
                mock.patch.object(guard, "refresh_gluetun_image"),
                mock.patch.object(guard, "wait_for_gluetun_healthy"),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
            ):
                self.assertTrue(guard.preflight(keep_running_gluetun=True))
            up_index = next(
                i for i, call in enumerate(runner.calls) if call[-3:] == ["up", "-d", "gluetun"]
            )
            env = runner.envs[up_index]
            assert env is not None
            # Only the running container's non-empty endpoint is added on top
            # of the caller's environment: an empty WIREGUARD_ENDPOINT_IP is
            # not pinned, and no other container setting leaks into Compose.
            self.assertEqual(env[config_mod.MANAGED_STACK_ENV], "1")
            added = {
                k: v
                for k, v in env.items()
                if os.environ.get(k) != v and k != config_mod.MANAGED_STACK_ENV
            }
            self.assertEqual(added, {"OPENVPN_ENDPOINT_IP": "203.0.113.7"})

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

            compose_fresh_mock.assert_called_once_with(
                "up", "-d", "gluetun", capture=False, env=None
            )
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
        cfg = make_config(tmp_path)
        for suffix in (["pull", "gluetun"], ["up", "-d", "gluetun"]):
            cmd = [*compose_args_prefix(tmp_path), *suffix]
            runner.responses.setdefault(tuple(cmd), completed(cmd))
        guard = GluetunGuard(cfg, runner)
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
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-O-",
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
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-O-",
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
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-O-",
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
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-O-",
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


if __name__ == "__main__":
    unittest.main()


class ComposeOverrideBootstrapTests(unittest.TestCase):
    """A stack whose generated override is missing must still be
    inspectable and stoppable, and must be able to bootstrap itself."""

    def _guard(self, tmp_path: Path, runner: FakeRunner) -> GluetunGuard:
        config = make_config(tmp_path)
        (
            config.root_dir / ".stremio" / "docker-compose.bindings.yml"
        ).unlink()  # never published yet
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
            self.assertFalse(
                (guard.config.root_dir / ".stremio" / "docker-compose.bindings.yml").exists()
            )


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
            guard = GluetunGuard(
                make_config(tmp_path),
                FakeRunner(
                    {
                        ("docker", "compose", "version"): completed(
                            ["docker", "compose", "version"]
                        ),
                        ("docker", "ps", "--format", "{{.ID}}"): completed(
                            ["docker", "ps", "--format", "{{.ID}}"]
                        ),
                    }
                ),
            )
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
            prefix = compose_args_prefix(tmp_path)
            stop_cmd = [*prefix, "stop", "stremio"]
            runner = FakeRunner({tuple(stop_cmd): completed(stop_cmd)})
            guard = GluetunGuard(make_config(tmp_path), runner)

            # When containers are NOT running, compose stop is skipped
            with mock.patch.object(guard, "running_services", return_value=set()):
                self.assertTrue(guard.stop_active_services(["stremio"]))
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)

            # When containers ARE running, compose stop is executed
            with mock.patch.object(guard, "running_services", side_effect=[{"stremio"}, set()]):
                self.assertTrue(guard.stop_active_services(["stremio"]))
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)

            # When Docker cannot say, stop everything named rather than guess
            runner.calls.clear()
            with mock.patch.object(guard, "running_services", return_value=None):
                self.assertFalse(guard.stop_active_services(["stremio"]))
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)

    def test_stop_and_restart_gluetun_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            prefix = compose_args_prefix(tmp_path)
            logs_cmd = ["docker", "logs", "--tail", "60", "gluetun"]
            stop_cmd = [*prefix, "stop", "gluetun"]
            restart_cmd = [*prefix, "restart", "gluetun"]
            up_cmd = [*prefix, "up", "-d", "--no-deps", "--force-recreate", "gluetun"]
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    tuple(logs_cmd): completed(logs_cmd),
                    tuple(stop_cmd): completed(stop_cmd),
                    tuple(restart_cmd): completed(restart_cmd),
                    tuple(up_cmd): completed(up_cmd),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)

            guard.stop_gluetun()
            self.assertIn([*prefix, "stop", "gluetun"], runner.calls)

            runner.calls.clear()
            self.assertTrue(guard.restart_gluetun())
            # The log is copied into the run log BEFORE the restart.
            logs_index = runner.calls.index(["docker", "logs", "--tail", "60", "gluetun"])
            restart_index = runner.calls.index([*prefix, "restart", "gluetun"])
            self.assertLess(logs_index, restart_index)

            runner.calls.clear()
            self.assertTrue(guard.restart_gluetun_relaxed())
            # `--no-deps`: recovery never depends on the compose gate service.
            up_call = [*prefix, "up", "-d", "--no-deps", "--force-recreate", "gluetun"]
            self.assertIn(up_call, runner.calls)
            # The second capture only asks for what was logged since the first.
            log_calls = [call for call in runner.calls if call[:2] == ["docker", "logs"]]
            self.assertEqual(len(log_calls), 1)
            self.assertIn("--since", log_calls[0])
            self.assertLess(runner.calls.index(log_calls[0]), runner.calls.index(up_call))

    def test_restart_gluetun_reports_and_warns_when_compose_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            prefix = compose_args_prefix(tmp_path)
            restart = (*prefix, "restart", "gluetun")
            recreate = (*prefix, "up", "-d", "--no-deps", "--force-recreate", "gluetun")
            runner = FakeRunner(
                {
                    restart: completed(list(restart), "", "Error: daemon busy\n", returncode=1),
                    recreate: completed(list(recreate), "", "pull access denied\n", returncode=17),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            warnings: list[str] = []
            with mock.patch.object(guard, "warn", side_effect=warnings.append):
                self.assertFalse(guard.restart_gluetun())
                self.assertFalse(guard.restart_gluetun_relaxed())
            self.assertTrue(any("exit 1" in w and "daemon busy" in w for w in warnings))
            self.assertTrue(any("exit 17" in w and "pull access denied" in w for w in warnings))

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

    def _running_query(self, tmp_path: Path, *services: str) -> tuple[str, ...]:
        return (
            *compose_args_prefix(tmp_path),
            "ps",
            "--status",
            "running",
            "--services",
            *services,
        )

    def test_stop_active_services_warns_when_container_still_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {self._running_query(tmp_path, "stremio"): completed([], stdout="stremio\n")}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "warn") as mock_warn,
                mock.patch.object(guard, "success") as mock_success,
            ):
                self.assertFalse(guard.stop_active_services(["stremio"]))
                mock_warn.assert_called_once()
                self.assertIn("Failed to confirm shutdown", mock_warn.call_args[0][0])
                mock_success.assert_not_called()

    def test_stop_active_services_treats_unanswered_query_as_not_stopped(self) -> None:
        # `container_running` reads a failed query as "not running"; the
        # shutdown proof must not, or an unreachable daemon looks stopped.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {self._running_query(tmp_path, "stremio"): completed([], returncode=1)}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)

            self.assertFalse(guard.stop_active_services(["stremio"]))

    def test_stop_active_services_confirms_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            stop_cmd = [*compose_args_prefix(tmp_path), "stop", "stremio"]
            guard = GluetunGuard(
                make_config(tmp_path), FakeRunner({tuple(stop_cmd): completed(stop_cmd)})
            )

            with (
                mock.patch.object(guard, "running_services", side_effect=[{"stremio"}, set()]),
                mock.patch.object(guard, "success") as mock_success,
            ):
                self.assertTrue(guard.stop_active_services(["stremio"]))
            mock_success.assert_called_once()

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

    def test_gluetun_recent_logs_omits_tail_when_since_is_given(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch.object(guard, "service_container_id", return_value="gluetun-abc"):
                guard.gluetun_recent_logs(lines=30, since_epoch=1700000000.0)
            self.assertIn(
                ["docker", "logs", "--since", "1700000000", "gluetun-abc"],
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
                "SERVER_CITIES=Denver\n",
                encoding="utf-8",
            )
            up_call = [
                *compose_args_prefix(tmp_path),
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "gluetun",
            ]
            runner = FakeRunner({tuple(up_call): completed(up_call)})
            guard = GluetunGuard(make_config(tmp_path), runner)
            with mock.patch(
                "stremioguard.resolver.resolve_nordvpn_endpoint",
                return_value=("us-new.nordvpn.com", "203.0.113.99"),
            ) as mock_resolve:
                self.assertTrue(guard.restart_gluetun())
            mock_resolve.assert_called_once()
            self.assertTrue(mock_resolve.call_args[1]["force_refresh"])
            self.assertIn(up_call, runner.calls)
            self.assertNotIn([*compose_args_prefix(tmp_path), "restart", "gluetun"], runner.calls)
            env = runner.envs[runner.calls.index(up_call)]
            assert env is not None
            self.assertEqual(env["OPENVPN_ENDPOINT_IP"], "203.0.113.99")
            self.assertEqual(env["WIREGUARD_ENDPOINT_IP"], "203.0.113.99")

    def test_restart_gluetun_relaxed_clears_endpoint_ips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            up_call = [
                *compose_args_prefix(tmp_path),
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "gluetun",
            ]
            runner = FakeRunner({tuple(up_call): completed(up_call)})
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertTrue(guard.restart_gluetun_relaxed())
            env = runner.envs[runner.calls.index(up_call)]
            assert env is not None
            for key in (
                "SERVER_REGIONS",
                "SERVER_CITIES",
                "SERVER_HOSTNAMES",
                "SERVER_CATEGORIES",
                "OPENVPN_ENDPOINT_IP",
                "WIREGUARD_ENDPOINT_IP",
            ):
                self.assertEqual(env[key], "", key)


class EgressAssessmentTests(unittest.TestCase):
    """The live in-tunnel probe is the egress authority; gluetun's control-server
    IP is a once-per-start snapshot and only a change trigger."""

    HOST = "198.51.100.10"
    EGRESS = "203.0.113.171"
    SNAPSHOT = "203.0.113.169"

    def _guard(self, tmp_path: Path, **overrides: object) -> GluetunGuard:
        return GluetunGuard(make_config(tmp_path, **overrides), FakeRunner({}))

    def _probes(
        self,
        guard: GluetunGuard,
        *,
        control: str | None = SNAPSHOT,
        egress: str | None = EGRESS,
        host: str | None = HOST,
    ):
        warnings: list[str] = []
        patches = (
            mock.patch.object(guard, "public_ip_via_control_server", return_value=control),
            mock.patch.object(guard, "public_ip_via_gluetun", return_value=egress),
            mock.patch.object(guard, "public_ip", return_value=host),
            mock.patch.object(guard, "warn", side_effect=warnings.append),
        )
        return patches, warnings

    def _assess(self, guard: GluetunGuard, patches, **kwargs: bool) -> PublicIPAssessment:
        with patches[0], patches[1], patches[2], patches[3]:
            return guard.public_ip_assessment(**kwargs)

    def test_stale_control_snapshot_stays_safe_and_warns_once(self) -> None:
        # Regression: 2026-09 restart loop. Gluetun kept its first public-IP
        # fetch after an in-tunnel reconnect moved the egress to another IP.
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, warnings = self._probes(guard)
            for _ in range(3):
                self.assertEqual(
                    self._assess(guard, patches, force_probe=True), PublicIPAssessment.SAFE
                )
            self.assertEqual(guard.last_observed_ip, self.EGRESS)
            snapshot_warnings = [w for w in warnings if "Gluetun control server reports" in w]
            self.assertEqual(len(snapshot_warnings), 1)

    def test_new_snapshot_pair_warns_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, warnings = self._probes(guard)
            self._assess(guard, patches, force_probe=True)
            patches, more = self._probes(guard, egress="203.0.113.172")
            self._assess(guard, patches, force_probe=True)
            self.assertEqual(
                len([w for w in warnings + more if "Gluetun control server reports" in w]), 2
            )

    def test_egress_equal_to_host_direct_ip_is_definitive_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, warnings = self._probes(guard, egress=self.HOST)
            self.assertEqual(self._assess(guard, patches), PublicIPAssessment.UNSAFE_DEFINITIVE)
            self.assertTrue(any("not leaving through the VPN" in w for w in warnings))

    def test_host_probe_uses_egress_ip_family(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, _ = self._probes(guard)
            with patches[0], patches[1], patches[2] as host_probe, patches[3]:
                guard.public_ip_assessment()
            host_probe.assert_called_once_with(version=4)

    def test_tunnel_probe_failure_is_unknown_and_not_cached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, _ = self._probes(guard, egress=None)
            with patches[0], patches[1] as egress_probe, patches[2], patches[3]:
                self.assertEqual(guard.public_ip_assessment(), PublicIPAssessment.UNKNOWN)
                self.assertEqual(guard.public_ip_assessment(), PublicIPAssessment.UNKNOWN)
            self.assertEqual(egress_probe.call_count, 2)

    def test_host_probe_failure_without_baseline_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            patches, warnings = self._probes(guard, host=None)
            self.assertEqual(self._assess(guard, patches), PublicIPAssessment.UNKNOWN)
            self.assertTrue(any("record-home-ip" in w for w in warnings))

    def test_malformed_baseline_cannot_replace_failed_host_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory))
            guard.config.home_ip_file.write_text("\x00garbage", encoding="utf-8")
            patches, _ = self._probes(guard, host=None)
            self.assertEqual(self._assess(guard, patches), PublicIPAssessment.UNKNOWN)

    def test_host_probe_failure_falls_back_to_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = self._guard(tmp_path)
            guard.config.home_ip_file.write_text(f"{self.HOST}\n", encoding="utf-8")
            patches, _ = self._probes(guard, host=None)
            self.assertEqual(self._assess(guard, patches), PublicIPAssessment.SAFE)
            patches, _ = self._probes(guard, host=None, egress=self.HOST)
            self.assertEqual(
                self._assess(guard, patches, force_probe=True),
                PublicIPAssessment.UNSAFE_DEFINITIVE,
            )

    def test_verified_egress_is_trusted_until_interval_elapses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory), egress_probe_interval_seconds=300)
            patches, _ = self._probes(guard)
            with (
                patches[0],
                patches[1] as egress_probe,
                patches[2],
                patches[3],
                mock.patch.object(
                    guard_mod.time, "monotonic", side_effect=[1000.0, 1299.0, 1300.0]
                ),
            ):
                for _ in range(3):
                    self.assertEqual(guard.public_ip_assessment(), PublicIPAssessment.SAFE)
            # t=1000 probes, t=1299 is inside the interval, t=1300 is due again.
            self.assertEqual(egress_probe.call_count, 2)

    def test_control_ip_change_forces_probe_before_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory), egress_probe_interval_seconds=300)
            with (
                mock.patch.object(
                    guard,
                    "public_ip_via_control_server",
                    side_effect=[self.SNAPSHOT, "203.0.113.200"],
                ),
                mock.patch.object(guard, "public_ip_via_gluetun", return_value=self.EGRESS) as p,
                mock.patch.object(guard, "public_ip", return_value=self.HOST),
                mock.patch.object(guard, "warn"),
            ):
                guard.public_ip_assessment()
                guard.public_ip_assessment()
            self.assertEqual(p.call_count, 2)

    def test_force_probe_ignores_cached_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory), egress_probe_interval_seconds=300)
            patches, _ = self._probes(guard)
            with patches[0], patches[1] as egress_probe, patches[2], patches[3]:
                guard.public_ip_assessment()
                guard.public_ip_assessment(force_probe=True)
            self.assertEqual(egress_probe.call_count, 2)

    def test_unsafe_outcome_is_not_cached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = self._guard(Path(directory), egress_probe_interval_seconds=300)
            patches, _ = self._probes(guard, egress=self.HOST)
            with patches[0], patches[1] as egress_probe, patches[2], patches[3]:
                self.assertEqual(guard.public_ip_assessment(), PublicIPAssessment.UNSAFE_DEFINITIVE)
                self.assertEqual(guard.public_ip_assessment(), PublicIPAssessment.UNSAFE_DEFINITIVE)
            self.assertEqual(egress_probe.call_count, 2)

    def test_public_ip_skips_answers_of_the_wrong_family(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(
                    Path(directory),
                    ip_check_urls=("https://v6.example.test", "https://v4.example.test"),
                ),
                FakeRunner({}),
            )
            answers = {
                "https://v6.example.test": b"2001:db8::1\n",
                "https://v4.example.test": b"198.51.100.10\n",
            }

            class Opener:
                def open(self, request, timeout):  # noqa: ANN001
                    body = answers[request.full_url]
                    response = mock.MagicMock()
                    response.__enter__.return_value.read.return_value = body
                    return response

            with mock.patch.object(guard_mod.urllib.request, "build_opener", return_value=Opener()):
                self.assertEqual(guard.public_ip(version=4), "198.51.100.10")
                self.assertEqual(guard.public_ip(), "2001:db8::1")


def test_running_check_is_one_query_and_unknown_is_none(tmp_path: Path) -> None:
    runner = FakeRunner(
        compose_stack_responses(
            tmp_path,
            running=("comet", "stremthru"),
            running_query_services=("comet", "stremthru"),
        )
    )
    guard = GluetunGuard(make_config(tmp_path), runner)
    assert guard.container_running(["comet", "stremthru"]) is True
    assert len(runner.calls) == 1
    query = (*compose_args_prefix(tmp_path), "ps", "--status", "running", "--services", "comet")
    runner.responses[query] = completed([], returncode=1)
    assert guard.running_services(["comet"]) is None
    assert guard.container_running(["comet"]) is None
    assert guard.services_confirmed_stopped(["comet"]) is False


# --- Frozen (watchdog) guard ---------------------------------------------------


def _publish_generation(root: Path, bind: str = "127.0.0.1") -> None:
    from stremioguard.publishing import StackPublisher

    (root / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (root / ".env").write_text(
        f"STREMIO_BIND_ADDRS={bind}\nSTREMIO_HOST_PORT=11470\n", encoding="utf-8"
    )
    StackPublisher(root).publish()


def test_frozen_compose_fresh_never_republishes_after_an_env_edit(tmp_path: Path) -> None:
    from stremioguard.config import PUBLISHED_COMPOSE_FILE, PUBLISHED_ENV_FILE

    config = make_config(tmp_path)
    _publish_generation(tmp_path)
    state = tmp_path / ".stremio"
    published = {
        name: (state / name).read_bytes()
        for name in ("docker-compose.bindings.yml", "env.snapshot", "gluetun.env")
    }
    base_copy = (tmp_path / PUBLISHED_COMPOSE_FILE).read_bytes()
    # An undeployed edit: a new bind address and a working-tree change.
    (tmp_path / ".env").write_text(
        "STREMIO_BIND_ADDRS=10.9.9.9\nSTREMIO_HOST_PORT=19999\n", encoding="utf-8"
    )
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    runner = FakeRunner({})
    guard = GluetunGuard(config, runner, frozen=True)
    guard.compose_fresh("up", "-d", "--no-deps", "stremio", check=False)

    for name, content in published.items():
        assert (state / name).read_bytes() == content, name
    assert (tmp_path / PUBLISHED_COMPOSE_FILE).read_bytes() == base_copy
    assert b"10.9.9.9" not in published["docker-compose.bindings.yml"]
    # The call ran against the published generation, bounded in time.
    assert runner.calls == [
        [
            "docker",
            "compose",
            "--project-directory",
            str(tmp_path),
            "--env-file",
            str(tmp_path / PUBLISHED_ENV_FILE),
            "-f",
            str(tmp_path / PUBLISHED_COMPOSE_FILE),
            "-f",
            str(state / "docker-compose.bindings.yml"),
            "up",
            "-d",
            "--no-deps",
            "stremio",
        ]
    ]
    assert runner.timeouts == [config_mod.WATCHDOG_MUTATION_TIMEOUT_SECONDS]


def test_unfrozen_compose_fresh_does_republish(tmp_path: Path) -> None:
    # Control for the test above: the CLI path picks the edit up.
    config = make_config(tmp_path)
    _publish_generation(tmp_path)
    (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=10.9.9.9\n", encoding="utf-8")
    runner = FakeRunner({})
    GluetunGuard(config, runner).compose_fresh("up", "-d", "--no-deps", "stremio", check=False)
    override = (tmp_path / ".stremio" / "docker-compose.bindings.yml").read_text()
    assert "10.9.9.9" in override
    assert runner.timeouts == [None]


def test_frozen_compose_fresh_refuses_without_a_published_override(tmp_path: Path) -> None:
    import pytest

    config = make_config(tmp_path)
    (tmp_path / ".stremio" / "docker-compose.bindings.yml").unlink()
    (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
    runner = FakeRunner({})
    guard = GluetunGuard(config, runner, frozen=True)
    with pytest.raises(RuntimeError, match="No published stack configuration"):
        guard.compose_fresh("up", "-d", "--no-deps", "stremio")
    assert runner.calls == []
    # And it did not render one on the way.
    assert not (tmp_path / ".stremio" / "docker-compose.bindings.yml").exists()


# --- Stale network namespace -------------------------------------------------

NAMESPACE_FORMAT = "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}|{{.HostConfig.NetworkMode}}"


def _namespace_inspect(*ids: str) -> tuple[str, ...]:
    return ("docker", "inspect", "--format", NAMESPACE_FORMAT, *ids)


def test_started_at_key_orders_variable_length_fractions() -> None:
    key = guard_mod._started_at_key
    day = "2026-11-11T10:00:01"
    # Plain string comparison gets every one of these wrong except the first.
    assert key(f"{day}.25Z") < key(f"{day}.5Z")
    assert key(f"{day}.5Z") < key(f"{day}.55Z")
    assert f"{day}.5Z" > f"{day}.55Z"  # the raw-string misorder being guarded
    assert key(f"{day}Z") < key(f"{day}.000000001Z")
    assert f"{day}Z" > f"{day}.000000001Z"
    assert key(f"{day}.999999999Z") < key("2026-11-11T10:00:02Z")
    # Docker's nanosecond form and a shorter one denote the same instant.
    assert key(f"{day}.5Z") == key(f"{day}.500000000Z")


def test_stale_namespace_services_flags_only_running_services_on_an_old_namespace(
    tmp_path: Path,
) -> None:
    gluetun = guard_mod.GluetunState("gluetun-new", "healthy", "2026-11-11T10:00:05.5Z")
    services = ["stremio", "comet", "comet-gateway", "comet-postgres", "stremthru"]
    inspect = _namespace_inspect(*services)
    runner = FakeRunner(
        {
            **compose_stack_responses(tmp_path, containers=tuple(services)),
            inspect: completed(
                list(inspect),
                # Started before gluetun did: joined the namespace gluetun had then.
                "stremio|true|2026-11-11T10:00:01.9Z|container:gluetun-new\n"
                # Names a container that is no longer gluetun.
                "comet|true|2026-11-11T10:00:09Z|container:gluetun-old\n"
                # Stopped: nothing to rejoin.
                "comet-gateway|false|2026-11-11T09:00:00Z|container:gluetun-old\n"
                # Started after gluetun: fine.
                "comet-postgres|true|2026-11-11T10:00:06Z|container:gluetun-new\n"
                # Started 50ms after gluetun; ".55Z" < ".5Z" as raw strings.
                "stremthru|true|2026-11-11T10:00:05.55Z|container:gluetun-new\n",
            ),
        }
    )
    guard = GluetunGuard(make_config(tmp_path), runner)
    assert guard.stale_namespace_services(services, gluetun) == ["stremio", "comet"]
    assert runner.timeouts[runner.calls.index(list(inspect))] == (
        config_mod.DOCKER_QUERY_TIMEOUT_SECONDS
    )


def test_stale_namespace_services_is_unknown_when_docker_cannot_answer(tmp_path: Path) -> None:
    gluetun = guard_mod.GluetunState("gluetun-new", "healthy", "2026-11-11T10:00:05Z")
    inspect = _namespace_inspect("stremio")
    failing = FakeRunner(
        {
            **compose_stack_responses(tmp_path, containers=("stremio",)),
            inspect: completed(list(inspect), "", "daemon gone", returncode=1),
        }
    )
    assert (
        GluetunGuard(make_config(tmp_path), failing).stale_namespace_services(["stremio"], gluetun)
        is None
    )
    malformed = FakeRunner(
        {
            **compose_stack_responses(tmp_path, containers=("stremio",)),
            inspect: completed(list(inspect), "stremio|true\n"),
        }
    )
    assert (
        GluetunGuard(make_config(tmp_path), malformed).stale_namespace_services(
            ["stremio"], gluetun
        )
        is None
    )
    # No identity (gluetun not inspectable) is unknown too, without a query.
    runner = FakeRunner({})
    unknown = guard_mod.GluetunState("gluetun-new", None, None)
    assert (
        GluetunGuard(make_config(tmp_path), runner).stale_namespace_services(["stremio"], unknown)
        is None
    )
    assert runner.calls == []


def test_stale_namespace_services_is_empty_when_nothing_exists(tmp_path: Path) -> None:
    gluetun = guard_mod.GluetunState("gluetun-new", "healthy", "2026-11-11T10:00:05Z")
    ps = (*compose_args_prefix(tmp_path), "ps", "-q", "stremio")
    runner = FakeRunner({ps: completed(list(ps), "")})
    assert (
        GluetunGuard(make_config(tmp_path), runner).stale_namespace_services(["stremio"], gluetun)
        == []
    )
    assert not any(call[:2] == ["docker", "inspect"] for call in runner.calls)


def test_write_vpn_lockout_records_bounded_evidence(tmp_path: Path) -> None:
    import json

    guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
    guard.write_vpn_lockout(reason="egress_leak", evidence="x" * 1000)
    marker = json.loads(guard.config.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "egress_leak"
    assert marker["evidence"] == "x" * guard_mod.EVIDENCE_LINE_LIMIT
    assert "kill switch" in marker["remediation"]
    assert guard.config.vpn_lockout_file.stat().st_mode & 0o777 == 0o600
    guard.write_vpn_lockout(reason="auth_rejected")
    assert "evidence" not in json.loads(guard.config.vpn_lockout_file.read_text())


def test_running_endpoint_is_not_reused_after_a_location_change(tmp_path: Path) -> None:
    # The container was created for Canada; .env now says Germany. Reusing
    # its endpoint would recreate gluetun with German filters pinned to a
    # Canadian server, so nothing is carried over and the caller's freshly
    # resolved endpoint stands.
    (tmp_path / ".env").write_text("VPN_TYPE=openvpn\nSERVER_COUNTRIES=Germany\n", encoding="utf-8")
    env_inspect = ("docker", "inspect", "--format", "{{json .Config.Env}}", "gluetun")
    state_inspect = ("docker", "inspect", "--format", guard_mod.GLUETUN_STATE_FORMAT, "gluetun")
    runner = FakeRunner(
        {
            **compose_stack_responses(tmp_path),
            state_inspect: completed(list(state_inspect), "healthy|2026-11-11T10:00:00Z\n"),
            env_inspect: completed(
                list(env_inspect),
                '["OPENVPN_ENDPOINT_IP=203.0.113.7","VPN_TYPE=openvpn","SERVER_COUNTRIES=Canada"]\n',
            ),
        }
    )
    guard = GluetunGuard(make_config(tmp_path), runner)
    assert guard.running_gluetun_endpoint_env() == {}
    # Same container, configuration back in agreement: the endpoint is kept.
    (tmp_path / ".env").write_text("VPN_TYPE=openvpn\nSERVER_COUNTRIES=Canada\n", encoding="utf-8")
    assert guard.running_gluetun_endpoint_env() == {"OPENVPN_ENDPOINT_IP": "203.0.113.7"}


def test_stale_namespace_services_is_unknown_when_the_two_queries_disagree(
    tmp_path: Path,
) -> None:
    # `compose ps -q` named one container and `docker inspect` answered about
    # another (or about fewer): nothing was verified, so the answer is None,
    # never "nothing is stale".
    gluetun = guard_mod.GluetunState("gluetun-new", "healthy", "2026-11-11T10:00:05Z")
    inspect = _namespace_inspect("stremio")
    other = FakeRunner(
        {
            **compose_stack_responses(tmp_path, containers=("stremio",)),
            inspect: completed(
                list(inspect), "someone-else|true|2026-11-11T10:00:06Z|container:gluetun-new\n"
            ),
        }
    )
    guard = GluetunGuard(make_config(tmp_path), other)
    assert guard.stale_namespace_services(["stremio"], gluetun) is None
    silent = FakeRunner(
        {
            **compose_stack_responses(tmp_path, containers=("stremio",)),
            inspect: completed(list(inspect), "\n"),
        }
    )
    assert (
        GluetunGuard(make_config(tmp_path), silent).stale_namespace_services(["stremio"], gluetun)
        is None
    )


def test_frozen_guard_never_rebuilds_from_the_working_tree(tmp_path: Path) -> None:
    # A build reads docker/stremio/ from the checkout; the watchdog must not
    # deploy it. The CLI's own guard still builds when asked to.
    for frozen, expected in (
        (True, ["up", "-d", "--no-deps", "stremio"]),
        (False, ["up", "-d", "--no-deps", "--build", "stremio"]),
    ):
        cfg = make_config(tmp_path)
        cmd = [*compose_args_prefix(tmp_path), *expected]
        runner = FakeRunner({tuple(cmd): completed(cmd)})
        guard = GluetunGuard(cfg, runner, frozen=frozen)
        with mock.patch.object(guard, "write_compose_override"):
            assert guard.start_services(["stremio"], build=True, check=False) is True
        assert runner.calls[-1] == cmd


def test_public_ip_via_gluetun_skips_exec_without_container(tmp_path: Path) -> None:
    runner = FakeRunner({})
    guard = GluetunGuard(make_config(tmp_path), runner)
    assert guard.public_ip_via_gluetun() is None
    assert not any(call[:2] == ["docker", "exec"] for call in runner.calls)


def test_stop_active_services_falls_back_to_docker_stop_when_compose_fails(tmp_path: Path) -> None:
    from stremioguard.config import compose_command

    cfg = make_config(tmp_path)
    cfg_cmd = compose_command(tmp_path, "config", "--services")
    stop_cmd = compose_command(tmp_path, "stop", "stremio")
    ps_stremio = compose_command(tmp_path, "ps", "-q", "stremio")
    status_cmd = compose_command(tmp_path, "ps", "--status", "running", "--services", "stremio")

    docker_stopped = False

    def boom_on_compose(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal docker_stopped
        if args == cfg_cmd:
            raise subprocess.SubprocessError("yaml broken")
        if args == stop_cmd:
            return completed(args, returncode=1, stderr="compose stop failed")
        if args == ps_stremio:
            return completed(args, stdout="stremio-cid\n")
        if args == ["docker", "stop", "-t", "5", "stremio-cid"]:
            docker_stopped = True
            return completed(args)
        if args == status_cmd:
            return completed(args, stdout="" if docker_stopped else "stremio\n")
        return completed(args)

    runner = FakeRunner({})

    def run_side_effect(
        args: list[str], *, check: bool = False, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        res = boom_on_compose(args)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, args, res.stdout, res.stderr)
        return res

    runner.run = run_side_effect  # type: ignore[method-assign]
    calls: list[list[str]] = []
    orig = runner.run

    def tracking(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return orig(args, **kwargs)  # type: ignore[arg-type]

    runner.run = tracking  # type: ignore[method-assign]
    guard = GluetunGuard(cfg, runner)
    assert guard.stop_active_services() is True
    assert ["docker", "stop", "-t", "5", "stremio-cid"] in calls
