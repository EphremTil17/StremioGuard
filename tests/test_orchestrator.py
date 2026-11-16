"""Tests for stremioguard.orchestrator — lifecycle and watchdog loop."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import typer

from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard.guard import GluetunGuard, LockoutActiveError, PublicIPAssessment
from stremioguard.orchestrator import Orchestrator

from .conftest import (
    FakeRunner,
    completed,
    compose_args_prefix,
    compose_stack_responses,
    make_comet_config,
    make_comet_gateway_config,
    make_config,
    write_minimal_bundle_manifest,
)

GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    guard_mod.GLUETUN_STATE_FORMAT,
    "gluetun",
)


def _setup_responses(
    tmp_path: Path, *services: str, reset: bool = True
) -> dict[
    tuple[str, ...], list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str]
]:
    prefix = compose_args_prefix(tmp_path)
    commands: list[list[str]] = [
        ["docker", "compose", "version"],
        [*prefix, "build", *services],
        [*prefix, "up", "-d", "--no-deps", *services],
    ]
    if reset:
        commands.append([*prefix, "down", "--remove-orphans", "--timeout", "10"])
    return {tuple(cmd): completed(cmd) for cmd in commands}


class OrchestratorTests(unittest.TestCase):
    def test_setup_resets_builds_and_starts_compose_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(_setup_responses(tmp_path, "stremio"))
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
            self.assertIn([*prefix, "up", "-d", "--no-deps", "stremio"], runner.calls)

    def test_setup_active_services_skips_comet_advisory_when_comet_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(_setup_responses(tmp_path, "stremio"))
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
            runner = FakeRunner(_setup_responses(tmp_path))
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
            # No gateway, no public addon path to canary.
            advisory_manager.log_canary.assert_not_called()

    def test_start_runs_log_canary_advisory_when_gateway_enabled(self) -> None:
        for canary_error in (None, RuntimeError("proxy unreachable")):
            with self.subTest(error=canary_error), tempfile.TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                runner = FakeRunner(_setup_responses(tmp_path))
                guard = GluetunGuard(make_config(tmp_path, stremio_enabled=False), runner)
                orch = Orchestrator(guard)
                comet_cfg = make_comet_config(tmp_path, enabled=True, gateway_enabled=True)
                write_minimal_bundle_manifest(comet_cfg)
                gateway_cfg = make_comet_gateway_config(tmp_path, enabled=False)
                advisory_manager = mock.MagicMock()
                advisory_manager.log_canary.side_effect = canary_error
                with (
                    mock.patch.object(guard, "require_commands", return_value=None),
                    mock.patch.object(guard, "preflight", return_value=None),
                    mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                    mock.patch(
                        "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                        return_value=gateway_cfg,
                    ),
                    mock.patch("stremioguard.comet.CometManager", return_value=advisory_manager),
                    mock.patch("stremioguard.orchestrator.time.sleep"),
                ):
                    orch.setup_active_services(reset=True)  # a canary error must not raise

                advisory_manager.log_canary.assert_called_once()

    def test_comet_advisory_error_never_fails_a_successful_start(self) -> None:
        # Plan 5.2: no advisory-path exception may escape — the services are
        # already up, and a bad mid-flight .env edit or manager error must not
        # turn a successful start into a failed one.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(_setup_responses(tmp_path))
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
            runner = FakeRunner(
                {
                    **_setup_responses(tmp_path, "stremio", reset=False),
                    ps_args: completed(list(ps_args), ""),
                }
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
            ):
                orch.start_active_services()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "build", "stremio"], runner.calls)
            self.assertIn([*prefix, "up", "-d", "--no-deps", "stremio"], runner.calls)
            self.assertNotIn([*prefix, "down", "--remove-orphans", "--timeout", "10"], runner.calls)

    def test_setup_defers_service_activation_until_watchdog_owns_vpn_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)

            with (
                mock.patch.object(guard, "preflight", return_value=False) as preflight_mock,
                mock.patch.object(guard, "stop_active_services", return_value=True) as stop_mock,
                mock.patch.object(guard, "compose_fresh") as compose_fresh_mock,
            ):
                orch.setup_active_services(reset=False)

            # First-time setup reached from `start` is not a recovery request:
            # it must honour a lockout like any other start.
            # Not a reset either: a running gluetun keeps its endpoint.
            preflight_mock.assert_called_once_with(
                allow_recovery=False, defer_vpn_recovery=True, keep_running_gluetun=True
            )
            stop_mock.assert_called_once_with()
            compose_fresh_mock.assert_not_called()

    def test_first_time_setup_never_clears_a_lockout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(make_config(Path(directory)), FakeRunner({}))
            guard.config.vpn_lockout_file.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(guard, "preflight", return_value=False),
                mock.patch.object(guard, "stop_active_services", return_value=True),
            ):
                Orchestrator(guard).setup_active_services(reset=False)
            self.assertTrue(guard.config.vpn_lockout_file.exists())

    def test_watch_once_stops_stremio_when_gluetun_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    containers=("gluetun", "stremio"),
                    running=("stremio",),
                    compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
                )
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            orch = Orchestrator(guard)

            with mock.patch.object(guard, "gluetun_healthy", return_value=False):
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertNotIn([*prefix, "up", "-d", "--no-deps", "stremio"], runner.calls)
            self.assertEqual(orch.vpn_drops_since_summary, 1)

    def test_watch_once_stops_stremio_when_ip_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    containers=("gluetun", "stremio"),
                    running=("stremio",),
                    compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
                )
            )
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
            self.assertIn([*prefix, "up", "-d", "--no-deps", "--build", "stremio"], runner.calls)

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

    def _run_healthy_ticks(
        self, orch: Orchestrator, guard: GluetunGuard, ticks: int, *, step: float = 10.0
    ) -> list[str]:
        """Run steady-state ticks `step` seconds apart; return the summary lines logged."""
        clock = {"now": 1000.0}
        orch.summary_started_at = clock["now"]

        def advance() -> float:
            return clock["now"]

        messages: list[str] = []
        with (
            mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=advance),
            mock.patch.object(guard, "gluetun_healthy", return_value=True),
            mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
            mock.patch.object(guard, "container_running", return_value=True),
            mock.patch.object(guard, "log", side_effect=messages.append),
        ):
            for _ in range(ticks):
                clock["now"] += step
                orch.watch_once()
        return [m for m in messages if "Watchdog summary" in m]

    def test_quiet_windows_log_only_an_hourly_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(Path(directory), watchdog_log_interval_seconds=300), FakeRunner({})
            )
            orch = Orchestrator(guard)
            orch.last_public_ip = orch.summary_public_ip = "203.0.113.20"

            # Two hours of 10 s ticks in which nothing happens.
            summaries = self._run_healthy_ticks(orch, guard, 720)

            self.assertEqual(len(summaries), 2)
            self.assertIn("window_seconds=3600 checks=360 ", summaries[0])

    def test_first_summary_and_ip_change_log_on_the_regular_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(Path(directory), watchdog_log_interval_seconds=300), FakeRunner({})
            )
            orch = Orchestrator(guard)
            orch.last_public_ip = "203.0.113.20"  # never reported yet

            summaries = self._run_healthy_ticks(orch, guard, 30)
            self.assertEqual(len(summaries), 1)
            self.assertIn("window_seconds=300 ", summaries[0])

            orch.last_public_ip = "203.0.113.99"  # the VPN moved servers
            summaries = self._run_healthy_ticks(orch, guard, 30)
            self.assertEqual(len(summaries), 1)
            self.assertIn("last_public_ip=203.0.113.99", summaries[0])

    def test_eventful_window_logs_on_the_regular_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(Path(directory), watchdog_log_interval_seconds=300), FakeRunner({})
            )
            orch = Orchestrator(guard)
            orch.last_public_ip = orch.summary_public_ip = "203.0.113.20"
            orch.auto_starts_since_summary = 1

            summaries = self._run_healthy_ticks(orch, guard, 30)

            self.assertEqual(len(summaries), 1)
            self.assertIn("auto_starts=1 ", summaries[0])

    def test_ongoing_outage_keeps_the_regular_summary_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(Path(directory), watchdog_log_interval_seconds=300), FakeRunner({})
            )
            orch = Orchestrator(guard)
            orch.last_public_ip = orch.summary_public_ip = "203.0.113.20"
            orch.summary_started_at = 0.0
            orch.outage_started_at = 0.0  # counters already reset by an earlier window

            self.assertTrue(orch._summary_eventful())
            with (
                mock.patch.object(orchestrator_mod.time, "monotonic", return_value=301.0),
                mock.patch.object(guard, "log") as log_mock,
            ):
                orch._maybe_log_summary()
            self.assertTrue(any("Watchdog summary" in c.args[0] for c in log_mock.call_args_list))

    def test_persistent_unknown_ip_warns_at_a_bounded_rate_but_stops_every_tick(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            guard = GluetunGuard(
                make_config(Path(directory), public_ip_failure_threshold=3), FakeRunner({})
            )
            orch = Orchestrator(guard)
            clock = {"now": 1000.0}
            orch.summary_started_at = clock["now"]
            warnings: list[str] = []
            logs: list[str] = []
            with (
                mock.patch.object(
                    orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]
                ),
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.UNKNOWN
                ),
                mock.patch.object(guard, "stop_active_services", return_value=True) as stop,
                mock.patch.object(guard, "warn", side_effect=warnings.append),
                mock.patch.object(guard, "log", side_effect=logs.append),
            ):
                # One hour of a public-IP checker outage, 10 s ticks.
                for _ in range(360):
                    clock["now"] += 10.0
                    orch.watch_once()

            # Fail-closed is not rate-limited: every tick past the threshold stops.
            self.assertEqual(stop.call_count, 360 - 2)
            # 2 below-threshold warnings, 1 on crossing, then one per 5 minutes.
            self.assertLessEqual(len(warnings), 3 + 3600 // orchestrator_mod.REPEAT_WARNING_SECONDS)
            self.assertIn("Stopping active services to fail closed", warnings[2])
            self.assertTrue(any("still failing" in w for w in warnings[3:]))
            # The window stays eventful, so the summary keeps the regular cadence.
            self.assertGreaterEqual(sum("Watchdog summary" in m for m in logs), 11)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(
                    guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE
                ),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "log", side_effect=logs.append),
            ):
                orch.watch_once()
            self.assertTrue(any("recovered after 360 failures" in m for m in logs))
            self.assertIsNone(orch.ip_failure_warned_at)

    def test_record_home_ip_refuses_when_gluetun_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    **compose_stack_responses(tmp_path),
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT), "healthy|2026-11-11T10:00:00Z\n"
                    ),
                }
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

            with mock.patch.object(guard, "public_ip", return_value="198.51.100.10") as probe:
                orch.record_home_ip()

            # An IPv6 baseline could never match the IPv4 tunnel egress.
            probe.assert_called_once_with(version=4)

            self.assertEqual(
                guard.config.home_ip_file.read_text(encoding="utf-8").strip(), "198.51.100.10"
            )

    def test_setup_active_services_comet_only_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                _setup_responses(tmp_path, "comet-postgres", "stremthru", "comet", "comet-gateway")
            )
            # Create a Stremio-disabled config
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)

            comet_cfg = make_comet_config(tmp_path, enabled=True, gateway_enabled=True)
            write_minimal_bundle_manifest(comet_cfg)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=True)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
                mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                # Created under the mocks: the guard reads Comet config once.
                orch = Orchestrator(guard)
                orch.setup_active_services(reset=True)

            prefix = compose_args_prefix(tmp_path)
            self.assertIn([*prefix, "down", "--remove-orphans", "--timeout", "10"], runner.calls)
            self.assertIn(
                [*prefix, "build", "comet-postgres", "stremthru", "comet", "comet-gateway"],
                runner.calls,
            )
            self.assertIn(
                [
                    *prefix,
                    "up",
                    "-d",
                    "--no-deps",
                    "comet-postgres",
                    "stremthru",
                    "comet",
                    "comet-gateway",
                ],
                runner.calls,
            )
            self.assertNotIn([*prefix, "build", "stremio"], runner.calls)

    def test_watch_once_stops_comet_only_services_when_gluetun_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            comet_services = ("comet-postgres", "stremthru", "comet", "comet-gateway")
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    containers=("gluetun", *comet_services),
                    running=comet_services,
                    compose_services=("use-stremio-start-instead", "gluetun", *comet_services),
                )
            )
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)

            comet_cfg = make_comet_config(tmp_path, enabled=True, gateway_enabled=True)
            write_minimal_bundle_manifest(comet_cfg)
            gateway_cfg = make_comet_gateway_config(tmp_path, enabled=True)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch("stremioguard.config.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                # Created under the mocks: the guard reads Comet config once.
                orch = Orchestrator(guard)
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn(
                [*prefix, "stop", "comet-postgres", "stremthru", "comet", "comet-gateway"],
                runner.calls,
            )
            self.assertNotIn([*prefix, "stop", "stremio"], runner.calls)
            self.assertEqual(orch.vpn_drops_since_summary, 1)

    def test_watch_once_auto_starts_comet_only_services_when_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            cfg = make_config(tmp_path, stremio_enabled=False)
            guard = GluetunGuard(cfg, runner)

            comet_cfg = make_comet_config(tmp_path, enabled=True, gateway_enabled=True)
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
                    "stremioguard.comet_gateway.CometGatewayConfig.from_env",
                    return_value=gateway_cfg,
                ),
            ):
                # Created under the mocks: the guard reads Comet config once.
                orch = Orchestrator(guard)
                orch.watch_once()

            prefix = compose_args_prefix(tmp_path)
            self.assertIn(
                [
                    *prefix,
                    "up",
                    "-d",
                    "--no-deps",
                    "--build",
                    "comet-postgres",
                    "stremthru",
                    "comet",
                    "comet-gateway",
                ],
                runner.calls,
            )
            self.assertNotIn([*prefix, "up", "-d", "--no-deps", "stremio"], runner.calls)

    def test_watch_once_unknown_debounce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    containers=("gluetun", "stremio"),
                    running=("stremio",),
                    compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
                )
            )
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
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    containers=("gluetun", "stremio"),
                    running=("stremio",),
                    compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
                )
            )
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
            runner = FakeRunner(
                {
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed(
                        ["docker", "ps", "--format", "{{.ID}}"]
                    ),
                }
            )
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
                mock.patch.object(guard, "stop_active_services", return_value=True) as stop_mock,
                self.assertRaises(KeyboardInterrupt),
            ):
                orch.watch_stremio()

            self.assertEqual(orch.consecutive_loop_errors, 3)
            self.assertEqual(orch.loop_errors_since_summary, 3)
            stop_mock.assert_called_once()

    def test_watch_stremio_loop_escapes_exit_78(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
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
            orch = Orchestrator(guard)

            with (
                mock.patch.object(orch, "watch_once", side_effect=typer.Exit(code=78)),
                mock.patch("stremioguard.orchestrator.time.sleep", side_effect=lambda s: None),
            ):
                with self.assertRaises(typer.Exit) as ctx:
                    orch.watch_stremio()
                self.assertEqual(ctx.exception.exit_code, 78)

    def test_first_tick_auth_rejection_alone_does_not_lock_out(self) -> None:
        # Providers also answer AUTH_FAILED for a connection limit or a busy
        # server: one sighting restarts gluetun, it does not lock out.
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
            orch = Orchestrator(guard)
            line = (
                "2026-11-11T10:00:00Z ERROR [openvpn] AUTH: Received control message: AUTH_FAILED"
            )

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_evidence", return_value=line) as evidence,
                mock.patch.object(guard, "stop_active_services") as mock_stop_services,
                mock.patch.object(guard, "restart_gluetun") as mock_restart,
                mock.patch.object(guard, "stop_gluetun") as mock_stop_gluetun,
                mock.patch("time.monotonic", return_value=1000.0),
                mock.patch("time.time", return_value=5000.0),
            ):
                orch.watch_once()

            evidence.assert_called_once_with(lines=200, since_epoch=5000.0 - 600)
            mock_stop_services.assert_called()
            mock_restart.assert_called_once()
            mock_stop_gluetun.assert_not_called()
            self.assertFalse(guard.config.vpn_lockout_file.exists())
            self.assertEqual(orch.auth_rejection_generations, {0})

    def test_auth_rejection_in_two_restart_generations_locks_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path, vpn_recovery_budget_seconds=1000, vpn_restart_cadence_seconds=45
            )
            guard = GluetunGuard(cfg, FakeRunner({}))
            orch = Orchestrator(guard)

            def line(stamp: str) -> str:
                # Gluetun timestamps every line, which is what tells a new
                # rejection apart from the same line read again.
                return f"2026-11-11T10:00:{stamp}Z ERROR [openvpn] AUTH_FAILED"

            answers: list[str | None] = []
            now = [1000.0]

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(
                    guard, "gluetun_auth_evidence", side_effect=lambda **_: answers.pop(0)
                ),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "services_confirmed_stopped", return_value=True),
                mock.patch.object(guard, "restart_gluetun") as mock_restart,
                mock.patch.object(guard, "stop_gluetun") as mock_stop_gluetun,
                mock.patch("time.monotonic", side_effect=lambda: now[0]),
                mock.patch("time.time", side_effect=lambda: now[0]),
            ):
                # Tick 1 (generation 0): clean log; restart -> generation 1.
                answers.append(None)
                orch.watch_once()
                self.assertEqual(orch.restart_generation, 1)

                # Ticks 2 and 3 (generation 1, before the next cadence
                # restart): the rejection twice in ONE generation is still
                # one sighting.
                for t, stamp in ((1010.0, "10"), (1020.0, "20")):
                    now[0] = t
                    answers.append(line(stamp))
                    orch.watch_once()
                self.assertFalse(cfg.vpn_lockout_file.exists())
                mock_stop_gluetun.assert_not_called()

                # Tick 4: cadence restart -> generation 2 (clean log).
                now[0] = 1050.0
                answers.append(None)
                orch.watch_once()
                self.assertEqual(mock_restart.call_count, 2)
                self.assertEqual(orch.restart_generation, 2)

                # Tick 5: generation 2 re-reads generation 1's last line
                # (`docker logs --since` has one-second resolution). The same
                # event must not count as a second generation.
                now[0] = 1055.0
                answers.append(line("20"))
                orch.watch_once()
                self.assertFalse(cfg.vpn_lockout_file.exists())

                # Tick 6: a new rejection after gluetun was restarted onto
                # another server: confirmed.
                now[0] = 1060.0
                answers.append(line("58"))
                with self.assertRaises(typer.Exit) as ctx:
                    orch.watch_once()

            self.assertEqual(ctx.exception.exit_code, 78)
            mock_stop_gluetun.assert_called_once()
            marker = json.loads(cfg.vpn_lockout_file.read_text(encoding="utf-8"))
            self.assertEqual(marker["reason"], "auth_rejected")
            self.assertEqual(marker["evidence"], line("58"))
            self.assertIn("credentials", marker["remediation"].lower())

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
                mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
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
                    reason="recovery_budget_exhausted",
                    outage_duration_seconds=301.0,
                    evidence="gluetun stayed unhealthy for 301s across 2 restart attempts",
                )

    def test_hybrid_failover_escalates_to_broad_country(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(
                tmp_path,
                server_countries="United States",
                server_cities="Denver",
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
                mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
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
                ) as mock_assessment,
                mock.patch.object(guard, "clear_vpn_lockout") as mock_clear_lockout,
                mock.patch.object(guard, "container_running", return_value=False),
                mock.patch.object(guard, "compose_fresh") as mock_compose_fresh,
            ):
                orch.watch_once()

                # Egress changes on reconnect: recovery must not trust a cached SAFE.
                mock_assessment.assert_called_once_with(force_probe=True)
                # Only an operator lifts a lockout; the loop never writes one
                # it keeps running under, so there is nothing to clear here.
                mock_clear_lockout.assert_not_called()
                mock_compose_fresh.assert_called_once()
                self.assertIsNone(orch.outage_started_at)
                self.assertEqual(
                    mock_compose_fresh.call_args.args,
                    ("up", "-d", "--no-deps", "--build", "stremio"),
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

            def mock_auth_evidence(lines: int = 50, since_epoch: float | None = None) -> str | None:
                auth_calls.append((lines, since_epoch))
                return None

            current_time = 1000.0

            def fake_time():
                return current_time

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=False),
                mock.patch.object(guard, "gluetun_auth_evidence", side_effect=mock_auth_evidence),
                mock.patch.object(guard, "stop_active_services"),
                mock.patch.object(guard, "restart_gluetun"),
                mock.patch("time.monotonic", side_effect=fake_time),
                mock.patch("time.time", side_effect=fake_time),
            ):
                # Tick 1: t=1000 -> look back a bounded 600s for the rejection
                # that caused the outage; an older one must not count.
                orch.watch_once()
                self.assertEqual(auth_calls, [(200, 400.0)])

                # Tick 2: t=1010 -> incremental check since 1000, updates cursor to 1010
                current_time = 1010.0
                orch.watch_once()
                self.assertEqual(auth_calls, [(200, 400.0), (200, 1000.0)])

                # Tick 3: t=1020 -> incremental check since 1010
                current_time = 1020.0
                orch.watch_once()
                self.assertEqual(auth_calls, [(200, 400.0), (200, 1000.0), (200, 1010.0)])

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
                mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
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
                mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
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


class SupervisedWatchdogTests(unittest.TestCase):
    """Behaviour the systemd unit relies on: lockout gate, heartbeat, fail-safe."""

    def _orchestrator(self, tmp_path: Path) -> Orchestrator:
        return Orchestrator(GluetunGuard(make_config(tmp_path), FakeRunner({})))

    def test_watchdog_refuses_to_run_under_a_lockout(self) -> None:
        # A systemd restart or manual `systemctl start` must not resume
        # services that the circuit breaker or the fail-safe shut down.
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            orch.guard.config.vpn_lockout_file.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(orch.guard, "require_commands"),
                mock.patch.object(orchestrator_mod, "notify") as notify,
                mock.patch.object(orch, "_watch_loop") as loop,
                self.assertRaises(LockoutActiveError),
            ):
                orch.watch_stremio()
            loop.assert_not_called()
            notify.assert_not_called()

    def test_lockout_maps_to_exit_status_78(self) -> None:
        with (
            mock.patch.object(orchestrator_mod.Config, "from_env"),
            mock.patch.object(orchestrator_mod, "configure_file_logging"),
            mock.patch.object(orchestrator_mod, "GluetunGuard"),
            mock.patch.object(orchestrator_mod, "Orchestrator"),
            self.assertRaises(typer.Exit) as ctx,
        ):
            orchestrator_mod._run_command(
                lambda o: (_ for _ in ()).throw(LockoutActiveError("locked"))
            )
        self.assertEqual(ctx.exception.exit_code, 78)

    def test_watchdog_reports_ready_only_after_preconditions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            events: list[str] = []
            with (
                mock.patch.object(
                    orch.guard, "require_commands", side_effect=lambda: events.append("checked")
                ),
                mock.patch.object(
                    orchestrator_mod, "notify", side_effect=lambda state: events.append(state)
                ),
                mock.patch.object(orch, "_watch_loop", side_effect=lambda: events.append("loop")),
            ):
                orch.watch_stremio()
            self.assertEqual(events, ["checked", "READY=1", "loop"])

    def test_second_watchdog_instance_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = self._orchestrator(Path(directory))
            second = self._orchestrator(Path(directory))
            held = first._acquire_instance_lock()
            try:
                with self.assertRaises(RuntimeError):
                    second._acquire_instance_lock()
            finally:
                held.close()
            # Released with its holder, so a restarted watchdog gets it back.
            second._acquire_instance_lock().close()

    def test_sleep_pings_systemd_at_least_every_chunk(self) -> None:
        clock = {"now": 0.0}

        def fake_sleep(seconds: float) -> None:
            clock["now"] += seconds

        with (
            mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
            mock.patch.object(orchestrator_mod.time, "sleep", side_effect=fake_sleep) as sleep,
            mock.patch.object(orchestrator_mod, "notify") as notify,
        ):
            Orchestrator._sleep(100, heartbeat=True)
        chunk = orchestrator_mod.HEARTBEAT_SLEEP_CHUNK_SECONDS
        self.assertTrue(all(call.args[0] <= chunk for call in sleep.call_args_list))
        self.assertEqual(notify.call_count, sleep.call_count)

    def test_fail_safe_locks_out_and_stops_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            g = orch.guard
            with (
                mock.patch.object(g, "require_commands"),
                mock.patch.object(g, "stop_active_services", return_value=True) as stop,
            ):
                orch.fail_safe()
            stop.assert_called_once_with()
            self.assertEqual(g.read_vpn_lockout()["reason"], "watchdog_unstable")  # type: ignore[index]

    def test_fail_safe_keeps_the_original_lockout_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            g = orch.guard
            g.config.vpn_lockout_file.write_text('{"reason": "auth_rejected"}', encoding="utf-8")
            with (
                mock.patch.object(g, "require_commands"),
                mock.patch.object(g, "stop_active_services", return_value=True),
            ):
                orch.fail_safe()
            self.assertEqual(g.read_vpn_lockout(), {"reason": "auth_rejected"})

    def test_fail_safe_stops_services_and_raises_if_marker_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            g = orch.guard
            with (
                mock.patch.object(g, "write_vpn_lockout", side_effect=OSError("read-only")),
                mock.patch.object(g, "require_commands"),
                mock.patch.object(g, "stop_active_services", return_value=True) as stop,
                self.assertRaises(RuntimeError),
            ):
                orch.fail_safe()
            stop.assert_called_once()

    def test_fail_safe_fails_when_shutdown_is_unconfirmed(self) -> None:
        # A nonzero exit makes systemd retry the fail-safe unit.
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            g = orch.guard
            with (
                mock.patch.object(g, "require_commands"),
                mock.patch.object(g, "stop_active_services", return_value=False),
                self.assertRaises(RuntimeError),
            ):
                orch.fail_safe()

    def test_failed_tick_sends_no_heartbeat_even_while_sleeping(self) -> None:
        # A watchdog that cannot check must look stalled to systemd.
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            with (
                mock.patch.object(orch, "watch_once", side_effect=RuntimeError("bad .env")),
                mock.patch.object(orchestrator_mod, "notify") as notify,
            ):
                self.assertFalse(orch._tick())
                clock = {"now": 0.0}
                with (
                    mock.patch.object(
                        orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]
                    ),
                    mock.patch.object(
                        orchestrator_mod.time,
                        "sleep",
                        side_effect=lambda seconds: clock.update(now=clock["now"] + seconds),
                    ),
                ):
                    Orchestrator._sleep(100, heartbeat=False)
            notify.assert_not_called()

    def test_successful_tick_sends_a_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            with (
                mock.patch.object(orch, "watch_once"),
                mock.patch.object(orchestrator_mod, "notify") as notify,
            ):
                self.assertTrue(orch._tick())
            notify.assert_called_once_with("WATCHDOG=1")

    def test_exits_when_it_can_neither_check_nor_confirm_a_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            orch.consecutive_loop_errors = 2
            with (
                mock.patch.object(orch, "watch_once", side_effect=RuntimeError("bad .env")),
                mock.patch.object(orch.guard, "stop_active_services", return_value=False),
                self.assertRaises(RuntimeError),
            ):
                orch._tick()

    def test_keeps_looping_once_services_are_confirmed_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            orch.consecutive_loop_errors = 2
            with (
                mock.patch.object(orch, "watch_once", side_effect=RuntimeError("bad .env")),
                mock.patch.object(orch.guard, "stop_active_services", return_value=True),
            ):
                self.assertFalse(orch._tick())

    def test_outage_ticks_retry_a_stop_that_did_not_take(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            orch.outage_started_at = orch.outage_start_wall = time.monotonic()
            g = orch.guard
            with (
                mock.patch.object(g, "gluetun_healthy", return_value=False),
                mock.patch.object(g, "gluetun_auth_evidence", return_value=None),
                mock.patch.object(g, "services_confirmed_stopped", return_value=False),
                mock.patch.object(g, "stop_active_services") as stop,
            ):
                orch.watch_once()
            stop.assert_called_once_with(services=["stremio"])

    def test_teardown_ignores_a_dotenv_that_no_longer_parses(self) -> None:
        calls: list[object] = []
        real = orchestrator_mod.Config.from_env

        def from_env(root_dir: Path | None = None, *, env_file: Path | None = None):
            if env_file is None:
                raise RuntimeError("Invalid WATCH_INTERVAL_SECONDS value")
            return real(root_dir, env_file=env_file)

        with (
            mock.patch.object(orchestrator_mod.Config, "from_env", side_effect=from_env),
            mock.patch.object(orchestrator_mod, "configure_file_logging"),
        ):
            orchestrator_mod._run_command(calls.append, teardown=True)
            with self.assertRaises(RuntimeError):
                orchestrator_mod._run_command(calls.append)
        self.assertEqual(len(calls), 1)

    def test_protected_services_come_from_compose_not_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                compose_stack_responses(
                    tmp_path,
                    compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
                )
            )
            guard = GluetunGuard(make_config(tmp_path), runner)
            self.assertEqual(guard.protected_services(), ["stremio"])

    def test_deferred_recovery_hands_the_lockout_to_the_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            orch = self._orchestrator(Path(directory))
            g = orch.guard
            g.config.vpn_lockout_file.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(g, "compose"),
                mock.patch.object(g, "preflight", return_value=False),
                mock.patch.object(g, "stop_active_services", return_value=True) as stop_services,
                mock.patch.object(g, "start_services") as start_services,
                mock.patch.object(orchestrator_mod.time, "sleep"),
            ):
                orch.setup_active_services(reset=True)
            stop_services.assert_called_once_with()
            self.assertFalse(g.config.vpn_lockout_file.exists())
            start_services.assert_not_called()


if __name__ == "__main__":
    unittest.main()


def test_run_logs_are_owner_only(tmp_path: Path) -> None:
    from stremioguard.orchestrator import configure_file_logging

    log_file = tmp_path / "logs" / "run.log"
    configure_file_logging(make_config(tmp_path, log_file=log_file))
    assert (tmp_path / "logs").stat().st_mode & 0o777 == 0o700
    assert log_file.stat().st_mode & 0o777 == 0o600


# --- Gluetun namespace identity ----------------------------------------------

NAMESPACE_INSPECT = (
    "docker",
    "inspect",
    "--format",
    "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}|{{.HostConfig.NetworkMode}}",
    "stremio",
)


def test_gluetun_identity_change_restarts_a_stale_service(tmp_path: Path) -> None:
    from stremioguard.config import PUBLISHED_COMPOSE_FILE, PUBLISHED_ENV_FILE, compose_command

    t1, t2 = "2026-11-11T10:00:00.5Z", "2026-11-11T11:00:00Z"
    config = make_config(tmp_path)
    (tmp_path / PUBLISHED_COMPOSE_FILE).touch()
    (tmp_path / PUBLISHED_ENV_FILE).touch()
    runner = FakeRunner(
        {
            **compose_stack_responses(
                tmp_path,
                containers=("gluetun", "stremio"),
                compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
            ),
            GLUETUN_HEALTH_INSPECT: [
                completed(list(GLUETUN_HEALTH_INSPECT), f"healthy|{started}\n")
                for started in (t1, t1, t2)
            ],
            NAMESPACE_INSPECT: [
                # Tick 1: stremio predates this gluetun (it was restarted
                # outside the watchdog), so it holds a dead namespace.
                completed(
                    list(NAMESPACE_INSPECT), "stremio|true|2026-11-11T09:00:00Z|container:gluetun\n"
                ),
                # Tick 3: after gluetun restarted again at t2.
                completed(
                    list(NAMESPACE_INSPECT), "stremio|true|2026-11-11T10:00:01Z|container:gluetun\n"
                ),
            ],
        }
    )
    guard = GluetunGuard(config, runner, frozen=True)
    orch = Orchestrator(guard)
    events: list[str] = []
    running = {"stremio": True}
    real_start = guard.start_services

    def stop(*, services: list[str] | None = None) -> bool:
        events.append(f"stop:{','.join(services or [])}")
        running.update(dict.fromkeys(services or [], False))
        return True

    def start(services: list[str], **kwargs: object) -> bool:
        events.append(f"start:{','.join(services)}")
        running.update(dict.fromkeys(services, True))
        return real_start(services, **kwargs)  # type: ignore[arg-type]

    with (
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "stop_active_services", side_effect=stop),
        mock.patch.object(guard, "start_services", side_effect=start),
        mock.patch.object(
            guard,
            "container_running",
            side_effect=lambda services: all(running[s] for s in services),
        ),
    ):
        orch.watch_once()
        assert events == ["stop:stremio", "start:stremio"]
        assert orch.gluetun_identity == ("gluetun", t1)
        assert orch.namespace_rejoins_since_summary == 1
        # The restart actually reached Compose.
        # Without --build: the frozen watchdog never rebuilds from the tree.
        up = [*compose_command(tmp_path), "up", "-d", "--no-deps", "stremio"]
        assert runner.calls.count(up) == 1

        # Tick 2: same gluetun, nothing to reconcile and no Docker query for it.
        orch.watch_once()
        assert events == ["stop:stremio", "start:stremio"]
        assert runner.calls.count(list(NAMESPACE_INSPECT)) == 1

        # Tick 3: gluetun restarted on its own at t2.
        orch.watch_once()
        assert events == ["stop:stremio", "start:stremio"] * 2
        assert orch.gluetun_identity == ("gluetun", t2)
        assert runner.calls.count(up) == 2


def test_unverifiable_namespace_keeps_identity_unverified(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            **compose_stack_responses(
                tmp_path,
                containers=("gluetun", "stremio"),
                compose_services=("use-stremio-start-instead", "gluetun", "stremio"),
            ),
            GLUETUN_HEALTH_INSPECT: completed(
                list(GLUETUN_HEALTH_INSPECT), "healthy|2026-11-11T10:00:00Z\n"
            ),
            NAMESPACE_INSPECT: completed(list(NAMESPACE_INSPECT), "", "boom", returncode=1),
        }
    )
    guard = GluetunGuard(make_config(tmp_path), runner, frozen=True)
    orch = Orchestrator(guard)
    with (
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "stop_active_services") as stop,
    ):
        orch.watch_once()
        orch.watch_once()
    stop.assert_not_called()
    # Not marked verified, so every tick retries the check.
    assert orch.gluetun_identity is None
    assert runner.calls.count(list(NAMESPACE_INSPECT)) == 2


# --- Leak verdicts --------------------------------------------------------------


def _leak_orchestrator(tmp_path: Path, **overrides: object):
    guard = GluetunGuard(make_config(tmp_path, **overrides), FakeRunner({}))
    return guard, Orchestrator(guard)


def test_second_consecutive_leak_verdict_locks_out(tmp_path: Path) -> None:
    import pytest

    guard, orch = _leak_orchestrator(tmp_path)
    with (
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(
            guard,
            "public_ip_assessment",
            side_effect=[PublicIPAssessment.UNSAFE_DEFINITIVE] * 2,
        ),
        mock.patch.object(guard, "stop_active_services", return_value=True) as stop,
        mock.patch.object(guard, "stop_gluetun") as stop_gluetun,
        mock.patch.object(guard, "start_services") as start,
    ):
        # First verdict: services stop at once, no lockout yet.
        orch.watch_once()
        stop.assert_called_once_with(services=["stremio"])
        assert not guard.config.vpn_lockout_file.exists()
        stop_gluetun.assert_not_called()

        with pytest.raises(typer.Exit) as excinfo:
            orch.watch_once()
    assert excinfo.value.exit_code == 78
    marker = json.loads(guard.config.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "egress_leak"
    assert "within 24 hours" in marker["evidence"]
    stop_gluetun.assert_called_once()
    start.assert_not_called()


def test_single_leak_verdict_followed_by_safe_resumes_then_second_locks_out(
    tmp_path: Path,
) -> None:
    import pytest

    guard, orch = _leak_orchestrator(tmp_path)
    with (
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(
            guard,
            "public_ip_assessment",
            side_effect=[
                PublicIPAssessment.UNSAFE_DEFINITIVE,
                PublicIPAssessment.SAFE,
                PublicIPAssessment.UNSAFE_DEFINITIVE,
            ],
        ),
        mock.patch.object(guard, "stop_active_services", return_value=True) as stop,
        mock.patch.object(guard, "stop_gluetun") as stop_gluetun,
        mock.patch.object(guard, "container_running", return_value=False),
        mock.patch.object(guard, "start_services") as start,
    ):
        orch.watch_once()
        orch.watch_once()
        start.assert_called_once_with(["stremio"], build=True, check=False)
        assert len(orch.leak_verdict_times) == 1
        # A second verdict within 24 hours locks out even after a SAFE tick.
        with pytest.raises(typer.Exit) as excinfo:
            orch.watch_once()
    assert excinfo.value.exit_code == 78
    assert stop.call_count == 3
    stop_gluetun.assert_called_once()
    assert guard.config.vpn_lockout_file.exists()


# --- Auto-start loop limit --------------------------------------------------------


def test_auto_start_limit_trips_service_flapping(tmp_path: Path) -> None:
    import pytest

    guard, orch = _leak_orchestrator(tmp_path, max_auto_starts_per_hour=3)
    clock = {"now": 10_000.0}
    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "container_running", return_value=False),
        mock.patch.object(guard, "start_services") as start,
        mock.patch.object(guard, "stop_active_services", return_value=True) as stop,
        mock.patch.object(guard, "stop_gluetun"),
    ):
        for _ in range(3):
            clock["now"] += 60
            orch.watch_once()
        assert start.call_count == 3
        clock["now"] += 60
        with pytest.raises(typer.Exit) as excinfo:
            orch.watch_once()
    assert excinfo.value.exit_code == 78
    assert start.call_count == 3
    stop.assert_called()
    marker = json.loads(guard.config.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "service_flapping"
    assert marker["evidence"] == "3 automatic starts within the last hour"


def test_auto_starts_older_than_an_hour_do_not_count(tmp_path: Path) -> None:
    guard, orch = _leak_orchestrator(tmp_path, max_auto_starts_per_hour=2)
    clock = {"now": 10_000.0}
    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "container_running", return_value=False),
        mock.patch.object(guard, "start_services") as start,
    ):
        for _ in range(6):
            clock["now"] += 1801  # two per hour at most
            orch.watch_once()
    assert start.call_count == 6
    assert not guard.config.vpn_lockout_file.exists()


def test_auto_start_limit_zero_disables_it(tmp_path: Path) -> None:
    guard, orch = _leak_orchestrator(tmp_path, max_auto_starts_per_hour=0)
    with (
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "container_running", return_value=False),
        mock.patch.object(guard, "start_services") as start,
    ):
        for _ in range(25):
            orch.watch_once()
    assert start.call_count == 25
    assert not guard.config.vpn_lockout_file.exists()


# --- Stack lock deferral ------------------------------------------------------------


def test_tick_defers_while_another_holder_has_the_stack_lock(tmp_path: Path) -> None:
    import fcntl
    import os

    from stremioguard.stacklock import stack_lock_path

    guard, orch = _leak_orchestrator(tmp_path)
    lock_path = stack_lock_path(tmp_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # A CLI command in another process: a separate open file description.
    holder = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    clock = {"now": 500.0}
    held_during_check: list[bool] = []

    def check() -> None:
        probe = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            held_during_check.append(True)
        else:
            held_during_check.append(False)
        finally:
            os.close(probe)

    try:
        with (
            mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
            mock.patch.object(orch, "watch_once", side_effect=check) as watch_once,
            mock.patch.object(orchestrator_mod, "notify"),
        ):
            # Deferred: alive (True), but no check ran.
            assert orch._tick() is True
            clock["now"] += orchestrator_mod.STACK_LOCK_MAX_DEFER_SECONDS - 1
            assert orch._tick() is True
            watch_once.assert_not_called()

            # Released: the next tick checks, holding the lock itself.
            os.close(holder)
            holder = -1
            assert orch._tick() is True
            assert watch_once.call_count == 1
            assert held_during_check == [True]
            assert orch.lock_deferred_since is None
    finally:
        if holder >= 0:
            os.close(holder)


def test_tick_stops_deferring_after_the_maximum(tmp_path: Path) -> None:
    import fcntl
    import os

    from stremioguard.stacklock import stack_lock_path

    guard, orch = _leak_orchestrator(tmp_path)
    lock_path = stack_lock_path(tmp_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    clock = {"now": 500.0}
    try:
        with (
            mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
            mock.patch.object(orch, "watch_once") as watch_once,
            mock.patch.object(orchestrator_mod, "notify"),
        ):
            assert orch._tick() is True
            watch_once.assert_not_called()
            # A hung command must not blind the watchdog indefinitely.
            clock["now"] += orchestrator_mod.STACK_LOCK_MAX_DEFER_SECONDS
            assert orch._tick() is True
            watch_once.assert_called_once()
    finally:
        os.close(holder)


# --- Alerts never get in the way of a shutdown --------------------------------------


def test_breaker_stops_everything_and_exits_78_when_alerting_raises(tmp_path: Path) -> None:
    import pytest

    guard, orch = _leak_orchestrator(tmp_path, alert_url="https://alerts.example.test/topic")
    order: list[str] = []

    def exploding_alert(*args: object, **kwargs: object) -> bool:
        order.append("alert")
        raise RuntimeError("alert endpoint exploded")

    with (
        mock.patch.object(orchestrator_mod, "send_alert", side_effect=exploding_alert) as send,
        mock.patch.object(
            guard, "stop_active_services", side_effect=lambda **_: order.append("stop_services")
        ),
        mock.patch.object(guard, "stop_gluetun", side_effect=lambda: order.append("stop_gluetun")),
        pytest.raises(typer.Exit) as excinfo,
    ):
        orch._trip_circuit_breaker("egress_leak", evidence="probe saw the home IP")
    assert excinfo.value.exit_code == 78
    assert order == ["stop_services", "stop_gluetun", "alert"]
    send.assert_called_once()
    assert send.call_args.args[0] == "https://alerts.example.test/topic"
    marker = json.loads(guard.config.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "egress_leak"
    assert marker["evidence"] == "probe saw the home IP"


def test_alerts_are_rate_limited_per_event(tmp_path: Path) -> None:
    guard, orch = _leak_orchestrator(tmp_path, alert_url="https://alerts.example.test/topic")
    clock = {"now": 0.0}
    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod, "send_alert", return_value=True) as send,
    ):
        orch._alert("leak_verdict", "t", "m")
        orch._alert("leak_verdict", "t", "m")
        orch._alert("namespace_stale", "t", "m")
        clock["now"] += orchestrator_mod.ALERT_REPEAT_SECONDS
        orch._alert("leak_verdict", "t", "m")
    assert [c.args[0] for c in send.call_args_list] == ["https://alerts.example.test/topic"] * 3


def test_deferred_tick_still_stops_services_on_a_definitive_leak(tmp_path: Path) -> None:
    import fcntl
    import os

    from stremioguard.stacklock import stack_lock_path

    guard, orch = _leak_orchestrator(tmp_path)
    lock_path = stack_lock_path(tmp_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with (
            mock.patch.object(guard, "gluetun_healthy", return_value=True),
            mock.patch.object(
                guard,
                "public_ip_assessment",
                side_effect=[PublicIPAssessment.SAFE, PublicIPAssessment.UNSAFE_DEFINITIVE],
            ),
            mock.patch.object(guard, "stop_active_services", return_value=True) as stop,
            mock.patch.object(guard, "start_services") as start,
            mock.patch.object(guard, "restart_gluetun") as restart,
            mock.patch.object(orch, "watch_once") as watch_once,
            mock.patch.object(orchestrator_mod, "notify"),
        ):
            # Safe: the watchdog stands aside completely.
            assert orch._tick() is True
            stop.assert_not_called()
            # Leak: it stops the services without the lock, and does nothing else.
            assert orch._tick() is True
            stop.assert_called_once_with(services=guard.enabled_runtime_services())
            watch_once.assert_not_called()
            start.assert_not_called()
            restart.assert_not_called()
        assert not guard.config.vpn_lockout_file.exists()
    finally:
        os.close(holder)


def test_restart_moves_the_auth_scan_cursor_past_the_restart(tmp_path: Path) -> None:
    # A rejection the OLD gluetun process logged between this check's scan
    # and its restart must not be read by the next check and counted as a
    # second, post-restart sighting.
    guard, orch = _leak_orchestrator(tmp_path)
    orch.last_auth_check_wall = 1000.0
    with (
        mock.patch.object(guard, "restart_gluetun", return_value=True),
        mock.patch.object(orchestrator_mod.time, "time", return_value=1042.0),
    ):
        orch._restart_gluetun(relaxed=False)
    assert orch.restart_generation == 1
    assert orch.last_auth_check_wall == 1042.0


def test_failed_restart_does_not_increment_generation_or_trip_false_auth_lockout(
    tmp_path: Path,
) -> None:
    guard, orch = _leak_orchestrator(tmp_path)
    orch.outage_started_at = 900.0
    orch.outage_start_wall = 900.0
    orch.restart_generation = 0
    with (
        mock.patch.object(guard, "gluetun_healthy", return_value=False),
        mock.patch.object(guard, "services_confirmed_stopped", return_value=True),
        mock.patch.object(
            guard,
            "gluetun_auth_evidence",
            return_value="AUTH error from server A",
        ),
        mock.patch.object(guard, "restart_gluetun", return_value=False),
        mock.patch.object(orchestrator_mod.time, "monotonic", return_value=920.0),
        mock.patch.object(orchestrator_mod.time, "time", return_value=920.0),
    ):
        orch._note_auth_rejection("AUTH error from server A")
        orch.watch_once()
    assert orch.restart_generation == 0
    assert not guard.config.vpn_lockout_file.exists()
