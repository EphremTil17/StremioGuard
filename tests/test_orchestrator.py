"""Tests for stremioguard.orchestrator — lifecycle and watchdog loop."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

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
    write_minimal_bundle_manifest,
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

    def test_setup_active_services_skips_comet_advisory_when_comet_disabled(self) -> None:
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
                mock.patch("stremioguard.comet.CometManager") as manager_cls,
            ):
                orch.setup_active_services(reset=True)

            manager_cls.assert_not_called()

    def test_setup_active_services_runs_comet_advisory_check_after_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {("docker", "compose", "version"): completed(["docker", "compose", "version"])}
            )
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)
            orch = Orchestrator(guard)

            comet_cfg = make_comet_config(tmp_path, enabled=True)
            write_minimal_bundle_manifest(comet_cfg)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=False)

            advisory_manager = mock.MagicMock()
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
                mock.patch(
                    "stremioguard.comet.CometManager", return_value=advisory_manager
                ) as manager_cls,
            ):
                orch.setup_active_services(reset=True)

            manager_cls.assert_called_once_with(comet_cfg, runner)
            advisory_manager.advisory_update_check.assert_called_once()

    def test_comet_advisory_error_never_fails_a_successful_start(self) -> None:
        # Plan 5.2: no advisory-path exception may escape — the services are
        # already up, and a bad mid-flight .env edit or manager error must not
        # turn a successful start into a failed one.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {("docker", "compose", "version"): completed(["docker", "compose", "version"])}
            )
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)
            orch = Orchestrator(guard)

            comet_cfg = make_comet_config(tmp_path, enabled=True)
            write_minimal_bundle_manifest(comet_cfg)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=False)

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
                mock.patch(
                    "stremioguard.comet.CometManager",
                    side_effect=RuntimeError("mid-flight .env edit"),
                ),
            ):
                orch.setup_active_services(reset=True)  # must not raise

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

    def test_setup_defers_service_activation_until_watchdog_owns_vpn_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "preflight", return_value=False) as preflight_mock,
                mock.patch.object(guard, "compose_fresh") as compose_fresh_mock,
            ):
                orch.setup_active_services(reset=False)

            preflight_mock.assert_called_once_with(allow_recovery=True, defer_vpn_recovery=True)
            compose_fresh_mock.assert_not_called()

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
            self.assertIn([*prefix, "up", "-d", "--build", "stremio"], runner.calls)

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
            write_minimal_bundle_manifest(comet_cfg)
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
            write_minimal_bundle_manifest(comet_cfg)
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
            write_minimal_bundle_manifest(comet_cfg)
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
                [*prefix, "up", "-d", "--build", "comet", "comet-postgres", "comet-gateway"],
                runner.calls,
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

    def test_watch_stremio_loop_escapes_exit_78(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(orch, "watch_once", side_effect=typer.Exit(code=78)),
                mock.patch("stremioguard.orchestrator.time.sleep", side_effect=lambda s: None),
            ):
                with self.assertRaises(typer.Exit) as ctx:
                    orch.watch_stremio()
                self.assertEqual(ctx.exception.exit_code, 78)

    def test_immediate_trip_on_first_tick_auth_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(
                    guard, "gluetun_auth_failed", return_value=True
                ) as mock_auth_failed,
                mock.patch.object(guard, "stop_active_services") as mock_stop_services,
                mock.patch.object(guard, "stop_gluetun") as mock_stop_gluetun,
                mock.patch.object(guard, "write_vpn_lockout") as mock_write_lockout,
                mock.patch("time.monotonic", return_value=1000.0),
            ):
                with self.assertRaises(typer.Exit) as ctx:
                    orch.watch_once()

                self.assertEqual(ctx.exception.exit_code, 78)
                mock_auth_failed.assert_called_once_with(lines=100, since_epoch=None)
                mock_stop_services.assert_called()
                mock_stop_gluetun.assert_called_once()
                mock_write_lockout.assert_called_once_with(
                    reason="auth_rejected", outage_duration_seconds=0.0
                )

    def test_outage_restart_cycling_and_budget_exhaustion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path, vpn_recovery_budget_seconds=300, vpn_restart_cadence_seconds=45
            )
            guard = GluetunGuard(cfg, FakeRunner({}))
            orch = Orchestrator(guard)

            current_time = 1000.0

            def fake_time():
                return current_time

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_failed", return_value=False),
                mock.patch.object(guard, "stop_active_services") as mock_stop_services,
                mock.patch.object(guard, "restart_gluetun") as mock_restart,
                mock.patch.object(guard, "stop_gluetun") as mock_stop_gluetun,
                mock.patch.object(guard, "write_vpn_lockout") as mock_write_lockout,
                mock.patch("time.monotonic", side_effect=fake_time),
                mock.patch("time.time", side_effect=fake_time),
            ):
                # Tick 1: Outage start -> enters recovery window, restarts gluetun
                orch.watch_once()
                self.assertIsNotNone(orch.outage_started_at)
                mock_stop_services.assert_called_once()
                mock_restart.assert_called_once()
                mock_restart.reset_mock()

                # Tick 2: Elapsed 30s < 45s cadence -> no restart yet
                current_time = 1030.0
                orch.watch_once()
                mock_restart.assert_not_called()

                # Tick 3: Elapsed 50s >= 45s cadence -> triggers restart
                current_time = 1050.0
                orch.watch_once()
                mock_restart.assert_called_once()
                mock_restart.reset_mock()

                # Tick 4: Elapsed 301s >= 300s budget -> trips circuit breaker
                current_time = 1301.0
                with self.assertRaises(typer.Exit) as ctx:
                    orch.watch_once()

                self.assertEqual(ctx.exception.exit_code, 78)
                mock_stop_gluetun.assert_called_once()
                mock_write_lockout.assert_called_once_with(
                    reason="recovery_budget_exhausted", outage_duration_seconds=301.0
                )

    def test_hybrid_failover_escalates_to_broad_country(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path,
                server_countries="United States",
                server_cities="Seattle",
                vpn_recovery_budget_seconds=300,
                vpn_restart_cadence_seconds=45,
            )
            guard = GluetunGuard(cfg, FakeRunner({}))
            orch = Orchestrator(guard)

            current_time = 1000.0

            def fake_time():
                return current_time

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_failed", return_value=False),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "restart_gluetun") as mock_restart_preferred,
                mock.patch.object(guard, "restart_gluetun_relaxed") as mock_restart_relaxed,
                mock.patch("time.monotonic", side_effect=fake_time),
                mock.patch("time.time", side_effect=fake_time),
            ):
                # Tick 1: Outage start -> preferred restart
                orch.watch_once()
                mock_restart_preferred.assert_called_once()
                mock_restart_relaxed.assert_not_called()
                mock_restart_preferred.reset_mock()

                # Tick 2: At 150s (50% of 300s budget), escalates to broad pool
                current_time = 1150.0
                orch.watch_once()
                self.assertTrue(orch.escalation_triggered)
                mock_restart_relaxed.assert_called_once()
                mock_restart_preferred.assert_not_called()
                mock_restart_relaxed.reset_mock()

                # Tick 3: Subsequent cadence restart uses relaxed mode
                current_time = 1200.0
                orch.watch_once()
                mock_restart_relaxed.assert_called_once()
                mock_restart_preferred.assert_not_called()

    def test_recovery_resumes_services_and_clears_outage_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            # Set ongoing outage state
            orch.outage_started_at = 1000.0
            orch.outage_start_wall = 1000.0
            orch.escalation_triggered = True

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "clear_vpn_lockout") as mock_clear_lockout,
                mock.patch.object(guard, "container_running", return_value=False),
                mock.patch.object(guard, "compose_fresh") as mock_compose_fresh,
            ):
                orch.watch_once()

                mock_clear_lockout.assert_called_once()
                mock_compose_fresh.assert_called_once()
                self.assertIsNone(orch.outage_started_at)
                self.assertEqual(
                    mock_compose_fresh.call_args.args,
                    ("up", "-d", "--build", "stremio"),
                )
                self.assertIsNone(orch.outage_start_wall)
                self.assertFalse(orch.escalation_triggered)

    def test_circuit_breaker_writes_marker_before_stopping_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            call_order: list[str] = []

            def record_write(*args: object, **kwargs: object):
                call_order.append("write_vpn_lockout")

            def record_stop_services(*args: object, **kwargs: object):
                call_order.append("stop_active_services")

            def record_stop_gluetun(*args: object, **kwargs: object):
                call_order.append("stop_gluetun")

            with (
                mock.patch.object(guard, "write_vpn_lockout", side_effect=record_write),
                mock.patch.object(guard, "stop_active_services", side_effect=record_stop_services),
                mock.patch.object(guard, "stop_gluetun", side_effect=record_stop_gluetun),
                self.assertRaises(typer.Exit),
            ):
                orch._trip_circuit_breaker(reason="auth_rejected")

            self.assertEqual(
                call_order,
                ["write_vpn_lockout", "stop_active_services", "stop_gluetun"],
            )

    def test_incremental_log_cursor_during_outage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            auth_calls: list[tuple[int, float | None]] = []

            def mock_auth_failed(lines: int = 50, since_epoch: float | None = None) -> bool:
                auth_calls.append((lines, since_epoch))
                return False

            current_time = 1000.0

            def fake_time():
                return current_time

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_failed", side_effect=mock_auth_failed),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "restart_gluetun"),
                mock.patch("time.monotonic", side_effect=fake_time),
                mock.patch("time.time", side_effect=fake_time),
            ):
                # Tick 1: t=1000 -> initial tail-only check (lines=100, since_epoch=None)
                orch.watch_once()
                self.assertEqual(auth_calls, [(100, None)])

                # Tick 2: t=1010 -> incremental check since 1000, updates cursor to 1010
                current_time = 1010.0
                orch.watch_once()
                self.assertEqual(auth_calls, [(100, None), (50, 1000.0)])

                # Tick 3: t=1020 -> incremental check since 1010
                current_time = 1020.0
                orch.watch_once()
                self.assertEqual(auth_calls, [(100, None), (50, 1000.0), (50, 1010.0)])

    def test_hybrid_failover_escalates_on_region_only_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path,
                server_countries="United States",
                server_regions="Europe",
                vpn_recovery_budget_seconds=300,
                vpn_restart_cadence_seconds=45,
            )
            guard = GluetunGuard(cfg, FakeRunner({}))
            orch = Orchestrator(guard)

            current_time = 1000.0

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_failed", return_value=False),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "restart_gluetun"),
                mock.patch.object(guard, "restart_gluetun_relaxed") as mock_restart_relaxed,
                mock.patch("time.monotonic", side_effect=lambda: current_time),
                mock.patch("time.time", side_effect=lambda: current_time),
            ):
                orch.watch_once()
                self.assertFalse(orch.escalation_triggered)

                current_time = 1150.0
                orch.watch_once()
                self.assertTrue(orch.escalation_triggered)
                mock_restart_relaxed.assert_called_once()

    def test_hybrid_failover_escalates_on_category_only_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path,
                server_countries="United States",
                server_categories="P2P",
                vpn_recovery_budget_seconds=300,
                vpn_restart_cadence_seconds=45,
            )
            guard = GluetunGuard(cfg, FakeRunner({}))
            orch = Orchestrator(guard)

            current_time = 1000.0

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_failed", return_value=False),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "restart_gluetun"),
                mock.patch.object(guard, "restart_gluetun_relaxed") as mock_restart_relaxed,
                mock.patch("time.monotonic", side_effect=lambda: current_time),
                mock.patch("time.time", side_effect=lambda: current_time),
            ):
                orch.watch_once()
                self.assertFalse(orch.escalation_triggered)

                current_time = 1150.0
                orch.watch_once()
                self.assertTrue(orch.escalation_triggered)
                mock_restart_relaxed.assert_called_once()

    def test_circuit_breaker_stops_services_and_exits_even_if_lockout_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(
                    guard, "write_vpn_lockout", side_effect=OSError("Read-only filesystem")
                ),
                mock.patch.object(guard, "stop_active_services") as mock_stop_services,
                mock.patch.object(guard, "stop_gluetun") as mock_stop_gluetun,
            ):
                with self.assertRaises(typer.Exit) as ctx:
                    orch._trip_circuit_breaker(reason="auth_rejected")

                self.assertEqual(ctx.exception.exit_code, 78)
                mock_stop_services.assert_called_once()
                mock_stop_gluetun.assert_called_once()


if __name__ == "__main__":
    unittest.main()
