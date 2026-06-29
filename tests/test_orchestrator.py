"""Tests for stremioguard.orchestrator — lifecycle and watchdog loop."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard import guard as guard_mod
from stremioguard.guard import GluetunGuard, PublicIPAssessment
from stremioguard.orchestrator import Orchestrator

from .conftest import (
    FakeRunner,
    completed,
    compose_args_prefix,
    make_comet_config,
    make_comet_gateway_config,
    make_config,
)

GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    "{{.State.Health.Status}}",
    "gluetun",
)


class OrchestratorTests(unittest.TestCase):
    def test_setup_resets_builds_and_starts_compose_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {("docker", "compose", "version"): completed(["docker", "compose", "version"])}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
            ):
                orch.setup_active_services(reset=True)

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "down", "--remove-orphans", "--timeout", "10"], runner.calls)
            self.assertIn([*prefix, "build", "stremio"], runner.calls)
            self.assertIn([*prefix, "up", "-d", "stremio"], runner.calls)

    def test_start_runs_setup_when_no_compose_instance_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            ps_args = (*compose_args_prefix(tmp_path), "ps", "-a", "-q", "stremio")
            runner = FakeRunner({ps_args: completed(list(ps_args), "")})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
            ):
                orch.start_active_services()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "build", "stremio"], runner.calls)
            self.assertIn([*prefix, "up", "-d", "stremio"], runner.calls)
            self.assertNotIn([*prefix, "down", "--remove-orphans", "--timeout", "10"], runner.calls)

    def test_watch_once_stops_stremio_when_gluetun_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with mock.patch.object(guard, "gluetun_healthy", return_value=False):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertNotIn([*prefix, "up", "-d", "stremio"], runner.calls)
            self.assertEqual(orch.vpn_drop_count, 1)

    def test_watch_once_stops_stremio_when_ip_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNSAFE_DEFINITIVE
                ),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)

    def test_watch_once_auto_starts_stremio_when_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "container_running", return_value=False),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "up", "-d", "stremio"], runner.calls)

    def test_watch_once_does_not_log_healthy_tick_before_summary_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "log") as log_mock,
            ):
                orch.watch_once()

            log_messages = [call.args[0] for call in log_mock.call_args_list]
            self.assertFalse(any("Watchdog summary" in msg for msg in log_messages))

    def test_watch_once_logs_summary_after_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(
                make_config(tmp_path, watchdog_log_interval_seconds=5), FakeRunner({})
            )
            orch = Orchestrator(guard)
            orch.last_public_ip = "203.0.113.20"
            orch.summary_started_at = 10.0

            with (
                mock.patch.object(guard_mod.time, "monotonic", return_value=16.0),
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "log") as log_mock,
            ):
                orch.watch_once()

            log_messages = [call.args[0] for call in log_mock.call_args_list]
            self.assertTrue(any("Watchdog summary" in msg for msg in log_messages))
            self.assertEqual(orch.checks_since_summary, 0)
            self.assertEqual(orch.summary_started_at, 16.0)

    def test_record_home_ip_refuses_when_gluetun_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "healthy\n")}
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "public_ip", return_value="203.0.113.20"),
                self.assertRaises(RuntimeError) as ctx,
            ):
                orch.record_home_ip()

            self.assertIn("healthy", str(ctx.exception).lower())
            self.assertFalse(guard.config.home_ip_file.exists())

    def test_record_home_ip_writes_when_gluetun_not_running(self) -> None:
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
            orch = Orchestrator(guard)

            with mock.patch.object(guard, "public_ip", return_value="198.51.100.10"):
                orch.record_home_ip()

            self.assertEqual(
                guard.config.home_ip_file.read_text(encoding="utf-8").strip(), "198.51.100.10"
            )

    def test_setup_active_services_comet_only_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {("docker", "compose", "version"): completed(["docker", "compose", "version"])}
            )
            # Create a Stremio-disabled config
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)
            orch = Orchestrator(guard)

            comet_cfg = make_comet_config(tmp_path, enabled=True)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=True)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
                mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.guard.CometGatewayConfig.from_env", return_value=gateway_cfg
                ),
                mock.patch(
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                orch.setup_active_services(reset=True)

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "down", "--remove-orphans", "--timeout", "10"], runner.calls)
            self.assertIn(
                [*prefix, "build", "comet", "comet-postgres", "comet-gateway"], runner.calls
            )
            self.assertIn(
                [*prefix, "up", "-d", "comet", "comet-postgres", "comet-gateway"], runner.calls
            )
            self.assertNotIn([*prefix, "build", "stremio"], runner.calls)

    def test_watch_once_stops_comet_only_services_when_gluetun_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)
            orch = Orchestrator(guard)

            comet_cfg = make_comet_config(tmp_path, enabled=True)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=True)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.guard.CometGatewayConfig.from_env", return_value=gateway_cfg
                ),
                mock.patch(
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn(
                [*prefix, "stop", "comet", "comet-postgres", "comet-gateway"], runner.calls
            )
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.vpn_drop_count, 1)

    def test_watch_once_auto_starts_comet_only_services_when_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)
            orch = Orchestrator(guard)

            comet_cfg = make_comet_config(tmp_path, enabled=True)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=True)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "container_running", return_value=False),
                mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.guard.CometGatewayConfig.from_env", return_value=gateway_cfg
                ),
                mock.patch(
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn(
                [*prefix, "up", "-d", "comet", "comet-postgres", "comet-gateway"], runner.calls
            )
            self.assertNotIn([*prefix, "up", "-d", "stremio"], runner.calls)

    def test_watch_once_unknown_debounce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path, public_ip_failure_threshold=3), runner)
            orch = Orchestrator(guard)

            # 1st UNKNOWN: should warn but NOT stop stremio
            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNKNOWN
                ),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.consecutive_ip_unknowns, 1)

            # 2nd UNKNOWN: should warn but NOT stop stremio
            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNKNOWN
                ),
            ):
                orch.watch_once()
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.consecutive_ip_unknowns, 2)

            # 3rd UNKNOWN: should stop stremio
            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNKNOWN
                ),
            ):
                orch.watch_once()
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.consecutive_ip_unknowns, 3)

    def test_watch_once_unsafe_stops_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            # 1st UNSAFE: should stop stremio immediately
            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNSAFE_DEFINITIVE
                ),
            ):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.consecutive_ip_unknowns, 0)

    def test_watch_stremio_loop_exception_survival(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            call_count = 0

            def mock_watch_once():
                nonlocal call_count
                call_count += 1
                if call_count <= 3:
                    raise RuntimeError("Transient loop error")
                raise KeyboardInterrupt("Stop loop")

            with (
                mock.patch.object(orch, "watch_once", side_effect=mock_watch_once),
                mock.patch("stremioguard.orchestrator.time.sleep", side_effect=lambda s: None),
                mock.patch.object(guard, "stop_active_services") as stop_mock,
                self.assertRaises(KeyboardInterrupt),
            ):
                orch.watch_stremio()

            self.assertEqual(orch.consecutive_loop_errors, 3)
            self.assertEqual(orch.loop_error_count, 3)
            stop_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
