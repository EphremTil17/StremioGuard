"""Worst-case Orchestrator._tick() measurement and heartbeat bounds (AC-1 through AC-6)."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import typer

from stremioguard import alerts as alerts_mod
from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard import resolver as resolver_mod
from stremioguard.cli.supervisor import WATCHDOG_SEC, WATCHDOG_STEP_MARGIN_SECONDS
from stremioguard.config import (
    DOCKER_QUERY_TIMEOUT_SECONDS,
    PUBLIC_IP_TIMEOUT_MAX_SECONDS,
    WATCHDOG_MUTATION_TIMEOUT_SECONDS,
    CometConfig,
    Config,
)
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import (
    HEARTBEAT_SLEEP_CHUNK_SECONDS,
    TICK_HEARTBEAT_CEILING_SECONDS,
    Orchestrator,
)
from stremioguard.stacklock import stack_lock_path
from tests.conftest import PUBLIC_IPV4_EGRESS, PUBLIC_IPV4_HOST, PUBLIC_IPV4_STATION, completed

ALL_PATHS = (
    "steady_state_all_ip_stalling",
    "first_outage_tick",
    "mid_outage_relaxed_restart",
    "recovery_tick",
    "trip_tick",
    "second_leak_verdict",
    "deferred_lock_leak_stop",
)
MODELS = ("all_timeouts", "slow_success")


class _SentinelAbort(BaseException):
    """Sentinel BaseException to abort an endless-loop test cleanly."""


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.mono = start
        self.wall = 1_700_000_000.0

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += seconds


@dataclass
class _TickRun:
    path_name: str
    model: str
    tick_total: float
    timeline_end: float
    tick_start: float
    tick_end: float
    outcome: str  # "completed", "deferred", "failed", "exit_78", "aborted"
    heartbeats: list[float]
    steps: list[tuple[float, float, str]]
    events: list[str]
    runner_calls: list[tuple[list[str], float | None]]
    unbounded_calls: list[str]
    host_probe_timeouts: list[float] = field(default_factory=list)

    @property
    def timeline_points(self) -> list[float]:
        return [self.tick_start, *self.heartbeats, self.timeline_end]

    @property
    def gaps(self) -> list[float]:
        pts = self.timeline_points
        return [b - a for a, b in zip(pts, pts[1:], strict=False)]

    @property
    def longest_gap(self) -> float:
        return max(self.gaps)


def _make_prod_like_config(root: Path, *, public_ip_timeout_seconds: int = 5) -> Config:
    state_dir = root / ".stremio"
    state_dir.mkdir(parents=True, exist_ok=True)
    # A complete published generation: the frozen guard refuses to start
    # services from a partial one (missing_published_files).
    (state_dir / "docker-compose.bindings.yml").touch()
    (state_dir / "compose.base.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (state_dir / "env.snapshot").touch()
    (root / "docker-compose.yml").write_text("services:\n  gluetun: {}\n", encoding="utf-8")
    (root / ".env").write_text(
        "VPN_SERVICE_PROVIDER=nordvpn\n"
        "SERVER_COUNTRIES=United States\n"
        "SERVER_CITIES=Denver\n"
        "STREMIO_ENABLED=1\n"
        "COMET_ENABLED=1\n"
        "COMET_GATEWAY_ENABLED=1\n",
        encoding="utf-8",
    )
    return Config(
        root_dir=root,
        gluetun_healthy_timeout_seconds=60,
        watch_interval_seconds=10,
        watchdog_log_interval_seconds=300,
        public_ip_timeout_seconds=public_ip_timeout_seconds,
        home_ip_file=state_dir / "home-ip",
        expected_vpn_ip=None,
        ip_check_urls=(
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
        ),
        install_missing=False,
        run_id="tick-bound-measure",
        log_file=None,
        log_session=False,
        stremio_enabled=True,
        egress_probe_interval_seconds=300,
        public_ip_failure_threshold=1,
        vpn_recovery_budget_seconds=300,
        vpn_restart_cadence_seconds=45,
        vpn_lockout_file=state_dir / "vpn-lockout",
        server_countries="United States",
        server_regions=None,
        server_cities="Denver",
        server_hostnames=None,
        server_categories=None,
        env_file=root / ".env",
        alert_url="https://ntfy.example.test/topic",
    )


def _run_tick_case(
    tmp_path: Path,
    *,
    path_name: str,
    model: str,
    monkeypatch: pytest.MonkeyPatch,
    subdir: str | None = None,
    attach_heartbeat: bool = True,
    public_ip_timeout_seconds: int = 5,
    initial_loop_errors: int = 0,
    compose_stop_delay: float | None = None,
    lockout_write_delay: float | None = None,
    raise_on_docker_logs: bool = False,
    endless_stop: bool = False,
    notify_raises: bool = False,
) -> _TickRun:
    """Execute one Orchestrator._tick() run under the fake-clock harness."""
    root = tmp_path / (subdir or f"{path_name}_{model}")
    root.mkdir(parents=True, exist_ok=True)
    cfg = _make_prod_like_config(root, public_ip_timeout_seconds=public_ip_timeout_seconds)
    clock = _FakeClock()

    for mod in (orchestrator_mod, guard_mod, resolver_mod):
        monkeypatch.setattr(mod.time, "monotonic", clock.monotonic)
        monkeypatch.setattr(mod.time, "time", clock.time)

    comet_cfg = CometConfig.from_env(root, env_file=root / ".env")
    services = ["stremio", *comet_cfg.runtime_services]
    events: list[str] = []
    steps: list[tuple[float, float, str]] = []
    heartbeats: list[float] = []
    runner_calls: list[tuple[list[str], float | None]] = []
    unbounded_calls: list[str] = []
    host_probe_timeouts: list[float] = []

    want_healthy = path_name in {
        "steady_state_all_ip_stalling",
        "recovery_tick",
        "second_leak_verdict",
        "deferred_lock_leak_stop",
    }
    leak_path = path_name in {"second_leak_verdict", "deferred_lock_leak_stop"}
    all_timeouts = model == "all_timeouts"
    ps_running_calls = 0

    class _TimingRunner:
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            runner_calls.append((list(args), timeout))
            step_start = clock.monotonic()
            cmd_str = " ".join(args)
            if timeout is None:
                unbounded_calls.append(cmd_str)
            elif (
                compose_stop_delay is not None
                and "stop" in args
                and args[:2] == ["docker", "compose"]
                and "gluetun" not in args
            ):
                clock.advance(compose_stop_delay)
            else:
                clock.advance(timeout)
            step_end = clock.monotonic()
            steps.append((step_start, step_end, cmd_str))

            if endless_stop and step_end > start_mono + TICK_HEARTBEAT_CEILING_SECONDS + (
                2 * WATCHDOG_SEC
            ):
                raise _SentinelAbort("endless stop abort")

            if args[-3:] == ["ps", "-q", "gluetun"]:
                return completed(args, "gluetun-cid\n")
            if (
                args[:3] == ["docker", "inspect", "--format"]
                and "{{.State.Health.Status}}" in args[3]
            ):
                status = "healthy" if want_healthy else "unhealthy"
                return completed(args, f"{status}|2026-11-16T00:00:00Z\n")

            if len(args) >= 3 and args[-3:-1] == ["ps", "-q"]:
                svc = args[-1]
                return completed(args, f"{svc}-cid\n")

            if args[:2] == ["docker", "logs"] and ("--since" in args or "--tail" in args):
                if raise_on_docker_logs and "--since" in args:
                    raise RuntimeError("synthetic docker logs failure")
                return completed(args, "")

            if "http://127.0.0.1:18080/v1/publicip/ip" in args:
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f'{{"public_ip": "{PUBLIC_IPV4_EGRESS}"}}')

            if "iptables" in args:
                if all_timeouts and path_name != "steady_state_all_ip_stalling" and not leak_path:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f"-P OUTPUT DROP\n{guard_mod.DNS_BLOCK_RULE}\n")

            if "-qO-" in args:
                events.append("egress_probe")
                if leak_path:
                    return completed(args, f"{PUBLIC_IPV4_EGRESS}\n")
                if all_timeouts or path_name == "steady_state_all_ip_stalling":
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f"{PUBLIC_IPV4_EGRESS}\n")

            if (
                args[:3] == ["docker", "inspect", "--format"]
                and "{{.HostConfig.NetworkMode}}" in args[3]
            ):
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                lines = "\n".join(
                    f"{s}-cid|true|2026-11-16T00:01:00Z|container:gluetun-cid" for s in services
                )
                return completed(args, lines + "\n")

            if args[-2:] == ["config", "--services"]:
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, "\n".join(["gluetun", *services]) + "\n")

            if "--status" in args and "running" in args:
                nonlocal ps_running_calls
                ps_running_calls += 1
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                if path_name == "recovery_tick":
                    return completed(args, "")
                if path_name == "mid_outage_relaxed_restart" and ps_running_calls == 1:
                    return completed(args, "\n".join(services) + "\n")
                if ps_running_calls % 2 == 1:
                    return completed(args, "\n".join(services) + "\n")
                return completed(args, "")

            if "stop" in args and args[:2] == ["docker", "compose"]:
                events.append("compose_stop")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            if args[:2] == ["docker", "stop"]:
                events.append("docker_stop")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            if "up" in args and args[:2] == ["docker", "compose"]:
                events.append("compose_up")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            if "restart" in args and args[:2] == ["docker", "compose"]:
                events.append("compose_restart")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            raise AssertionError(f"Unexpected runner command: {cmd_str}")

    def fake_fetch_ip_url(_opener: object, _url: str, timeout: float, **_kw: object) -> str | None:
        events.append("host_probe")
        host_probe_timeouts.append(timeout)
        step_start = clock.monotonic()
        clock.advance(timeout)
        steps.append((step_start, clock.monotonic(), "host_probe"))
        if leak_path:
            return f"{PUBLIC_IPV4_EGRESS}\n"
        if all_timeouts or path_name == "steady_state_all_ip_stalling":
            return None
        return f"{PUBLIC_IPV4_HOST}\n"

    def fake_fetch_recs(
        *, country_id: int | None = None, timeout_seconds: float = 8.0
    ) -> list[dict[str, object]]:
        events.append("resolver")
        step_start = clock.monotonic()
        clock.advance(timeout_seconds)
        steps.append((step_start, clock.monotonic(), "resolver"))
        if all_timeouts:
            raise urllib.error.URLError("timeout")
        return [
            {
                "hostname": "us1.nordvpn.com",
                "station": PUBLIC_IPV4_STATION,
                "status": "online",
                "load": 10,
                "locations": [{"country": {"name": "United States", "city": {"name": "Denver"}}}],
            }
        ]

    def fake_send_alert(url: str | None, *, title: str, message: str, urgent: bool = True) -> bool:
        events.append("alert")
        step_start = clock.monotonic()
        clock.advance(alerts_mod.ALERT_TIMEOUT_SECONDS)
        steps.append((step_start, clock.monotonic(), "alert"))
        return not all_timeouts

    def fake_notify(state: str) -> bool:
        if notify_raises:
            raise RuntimeError("notify failure")
        if state == "WATCHDOG=1":
            heartbeats.append(clock.monotonic())
        return True

    monkeypatch.setattr(GluetunGuard, "_fetch_ip_url", staticmethod(fake_fetch_ip_url))
    monkeypatch.setattr(resolver_mod, "_fetch_nordvpn_recommendations", fake_fetch_recs)
    monkeypatch.setattr(orchestrator_mod, "send_alert", fake_send_alert)
    monkeypatch.setattr(orchestrator_mod, "notify", fake_notify)

    if lockout_write_delay is not None:
        real_atomic_write = guard_mod.atomic_write_text

        def delayed_atomic_write(path: Path, content: str, *, mode: int = 0o644) -> None:
            if path == cfg.vpn_lockout_file:
                clock.advance(lockout_write_delay)
            real_atomic_write(path, content, mode=mode)

        monkeypatch.setattr(guard_mod, "atomic_write_text", delayed_atomic_write)

    guard = GluetunGuard(cfg, _TimingRunner(), frozen=True)
    orch = Orchestrator(guard)
    if attach_heartbeat:
        orch._attach_step_heartbeat()
    orch.consecutive_loop_errors = initial_loop_errors

    if endless_stop:

        def endless_stop_services(*, services: list[str] | None = None) -> bool:
            while True:
                guard.runner.run(["docker", "compose", "stop", "stremio"], timeout=30)

        monkeypatch.setattr(guard, "stop_active_services", endless_stop_services)

    if path_name == "mid_outage_relaxed_restart":
        orch.outage_started_at = clock.monotonic() - 150.0
        orch.outage_start_wall = clock.time() - 150.0
        orch.unhealthy_elapsed_seconds = 140.0
        orch.last_watch_tick_at = clock.monotonic() - 10.0
        orch.last_auth_check_wall = clock.time() - 10.0
        orch.last_restart_at = clock.monotonic() - 100.0
    elif path_name == "recovery_tick":
        orch.outage_started_at = clock.monotonic() - 100.0
        orch.outage_start_wall = clock.time() - 100.0
        orch.unhealthy_elapsed_seconds = 90.0
        orch.last_watch_tick_at = clock.monotonic() - 10.0
        orch.last_auth_check_wall = clock.time() - 10.0
        orch.last_restart_at = clock.monotonic() - 45.0
    elif path_name == "trip_tick":
        orch.outage_started_at = clock.monotonic() - 310.0
        orch.outage_start_wall = clock.time() - 310.0
        orch.unhealthy_elapsed_seconds = 290.0
        orch.last_watch_tick_at = clock.monotonic() - 10.0
        orch.last_auth_check_wall = clock.time() - 10.0
        orch.last_restart_at = clock.monotonic() - 20.0
    elif path_name == "second_leak_verdict":
        orch.leak_verdict_times.append(clock.monotonic() - 60.0)

    lock_fd: int | None = None
    if path_name == "deferred_lock_leak_stop":
        lock_file = stack_lock_path(root)
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    start_mono = clock.monotonic()
    outcome = "completed"
    try:
        completed_ok = orch._tick()
        if path_name == "deferred_lock_leak_stop":
            assert completed_ok is True
            outcome = "deferred"
        elif not completed_ok:
            outcome = "failed"
    except typer.Exit as exc:
        events.append(f"exit_{exc.exit_code}")
        outcome = f"exit_{exc.exit_code}"
    except _SentinelAbort:
        outcome = "aborted"
    finally:
        if lock_fd is not None:
            os.close(lock_fd)

    tick_end = clock.monotonic()
    if outcome == "deferred":
        timeline_end = tick_end + min(cfg.watch_interval_seconds, HEARTBEAT_SLEEP_CHUNK_SECONDS)
    elif outcome == "failed":
        timeline_end = tick_end + cfg.watch_interval_seconds
    else:
        timeline_end = tick_end

    return _TickRun(
        path_name=path_name,
        model=model,
        tick_total=tick_end - start_mono,
        timeline_end=timeline_end,
        tick_start=start_mono,
        tick_end=tick_end,
        outcome=outcome,
        heartbeats=heartbeats,
        steps=steps,
        events=events,
        runner_calls=runner_calls,
        unbounded_calls=unbounded_calls,
        host_probe_timeouts=host_probe_timeouts,
    )


def _assert_path_taken(run: _TickRun, root: Path) -> None:
    path_name = run.path_name
    all_timeouts = run.model == "all_timeouts"
    lockout_file = root / ".stremio" / "vpn-lockout"
    if path_name == "steady_state_all_ip_stalling":
        assert "egress_probe" in run.events
        assert "compose_stop" in run.events
    elif path_name == "first_outage_tick":
        assert "compose_stop" in run.events
        assert "resolver" in run.events
        if not all_timeouts:
            assert "compose_up" in run.events
    elif path_name == "mid_outage_relaxed_restart":
        if all_timeouts:
            assert "compose_stop" in run.events
        assert "compose_up" in run.events
    elif path_name == "recovery_tick":
        if all_timeouts:
            assert "compose_stop" in run.events
        else:
            assert "egress_probe" in run.events
            assert "host_probe" in run.events
            assert "compose_up" in run.events
    elif path_name == "trip_tick":
        assert "exit_78" in run.events
        assert lockout_file.exists()
        marker = json.loads(lockout_file.read_text(encoding="utf-8"))
        assert marker["reason"] == "recovery_budget_exhausted"
        assert "compose_stop" in run.events
        assert "alert" in run.events
    elif path_name == "second_leak_verdict":
        assert "exit_78" in run.events
        assert lockout_file.exists()
        marker = json.loads(lockout_file.read_text(encoding="utf-8"))
        assert marker["reason"] == "egress_leak"
        assert "compose_stop" in run.events
        assert "alert" in run.events
    elif path_name == "deferred_lock_leak_stop":
        assert run.outcome == "deferred"
        assert "compose_stop" in run.events
        assert "alert" in run.events


def _assert_ac1_invariants(run: _TickRun, *, watch_interval_seconds: int = 10) -> None:
    assert not run.unbounded_calls, f"Unexpected timeout=None runner calls: {run.unbounded_calls}"
    max_step_gap = WATCHDOG_SEC - WATCHDOG_STEP_MARGIN_SECONDS
    gaps = run.gaps
    if run.outcome == "failed":
        assert all(g <= max_step_gap for g in gaps[:-1]), (run.path_name, run.model, gaps)
        assert gaps[-1] <= max_step_gap + watch_interval_seconds, (run.path_name, run.model, gaps)
    else:
        assert all(g <= max_step_gap for g in gaps), (run.path_name, run.model, gaps)

    pts = run.timeline_points
    for a, b in zip(pts, pts[1:], strict=False):
        starts_in_gap = [s for s in run.steps if a <= s[0] < b]
        assert len(starts_in_gap) <= 1, (
            f"Multiple steps started in gap [{a}, {b}) for "
            f"{run.path_name}/{run.model}: {starts_in_gap}"
        )

    assert run.tick_total <= TICK_HEARTBEAT_CEILING_SECONDS / 1.5


def test_ac01_worst_case_tick_heartbeats_and_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1 (INV-1, INV-7, D1-D3): 7 paths x 2 models stay within step margin."""
    runs: list[_TickRun] = []
    for path_name in ALL_PATHS:
        for model in MODELS:
            run = _run_tick_case(
                tmp_path, path_name=path_name, model=model, monkeypatch=monkeypatch
            )
            _assert_path_taken(run, tmp_path / f"{path_name}_{model}")
            _assert_ac1_invariants(run)
            runs.append(run)

    print("\n--- AC-1 Orchestrator._tick() with step heartbeats (WatchdogSec=300, margin=60) ---")
    print(f"{'Path':<30} {'Model':<14} {'Total(s)':>9} {'MaxGap(s)':>10} {'HBs':>5} {'Steps':>6}")
    for run in runs:
        print(
            f"{run.path_name:<30} {run.model:<14} {run.tick_total:9.1f} "
            f"{run.longest_gap:10.1f} {len(run.heartbeats):5d} {len(run.steps):6d}"
        )

    assert len(runs) == 14
    assert DOCKER_QUERY_TIMEOUT_SECONDS == 30
    assert WATCHDOG_MUTATION_TIMEOUT_SECONDS == 240


def test_ac02_probe_timeout_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-2 (INV-7, D9): public_ip_timeout_seconds=600 is capped at 60; 8 stays 8."""
    for path_name in ("steady_state_all_ip_stalling", "recovery_tick"):
        for model in MODELS:
            run = _run_tick_case(
                tmp_path,
                path_name=path_name,
                model=model,
                monkeypatch=monkeypatch,
                subdir=f"cap600_{path_name}_{model}",
                public_ip_timeout_seconds=600,
            )
            _assert_path_taken(run, tmp_path / f"cap600_{path_name}_{model}")
            _assert_ac1_invariants(run)

            tunnel_probes = [c for c in run.runner_calls if "-qO-" in c[0]]
            control_probes = [
                c for c in run.runner_calls if "http://127.0.0.1:18080/v1/publicip/ip" in c[0]
            ]
            assert control_probes
            if not (path_name == "recovery_tick" and model == "all_timeouts"):
                assert tunnel_probes
            for argv, timeout in [*tunnel_probes, *control_probes]:
                assert "KILL" in argv
                assert str(PUBLIC_IP_TIMEOUT_MAX_SECONDS) in argv
                assert f"--timeout={PUBLIC_IP_TIMEOUT_MAX_SECONDS}" in argv
                assert timeout == PUBLIC_IP_TIMEOUT_MAX_SECONDS + 2

            for probe_timeout in run.host_probe_timeouts:
                assert probe_timeout == PUBLIC_IP_TIMEOUT_MAX_SECONDS

    # Values <= 60 (specifically 8) stay unchanged.
    run_8 = _run_tick_case(
        tmp_path,
        path_name="recovery_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="cap8_recovery_slow_success",
        public_ip_timeout_seconds=8,
    )
    _assert_ac1_invariants(run_8)
    tunnel_probes_8 = [c for c in run_8.runner_calls if "-qO-" in c[0]]
    assert tunnel_probes_8
    for argv, timeout in tunnel_probes_8:
        assert "KILL" in argv
        assert "8" in argv
        assert "--timeout=8" in argv
        assert timeout == 10
    assert run_8.host_probe_timeouts == [8.0]


def test_ac03_wedge_still_exceeds_watchdog_sec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3 (INV-2): a wedged step or wedged non-step code still triggers WatchdogSec."""
    # (a) compose stop takes WATCHDOG_SEC + 100
    run_a = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="wedge_a",
        compose_stop_delay=WATCHDOG_SEC + 100.0,
    )
    assert any(g > WATCHDOG_SEC for g in run_a.gaps)
    assert run_a.longest_gap >= WATCHDOG_SEC + 100.0

    # (b) atomic_write_text for lockout marker takes WATCHDOG_SEC + 50
    run_b = _run_tick_case(
        tmp_path,
        path_name="trip_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="wedge_b",
        lockout_write_delay=WATCHDOG_SEC + 50.0,
    )
    assert "exit_78" in run_b.events
    assert (tmp_path / "wedge_b" / ".stremio" / "vpn-lockout").exists()
    assert any(g > WATCHDOG_SEC for g in run_b.gaps)
    assert run_b.longest_gap >= WATCHDOG_SEC + 50.0


def test_ac04_tick_heartbeat_ceiling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-4 (INV-3, D3): endless runner loop stops heartbeating at ceiling."""
    run = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="ceiling",
        endless_stop=True,
    )
    assert run.outcome == "aborted"
    ceiling = run.tick_start + TICK_HEARTBEAT_CEILING_SECONDS
    assert run.heartbeats
    assert max(run.heartbeats) >= ceiling - 31.0
    assert all(hb < ceiling for hb in run.heartbeats)
    assert run.gaps[-1] > WATCHDOG_SEC


def test_ac05_loop_error_gate_and_non_check_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-5 (INV-4, D3, D4): loop-error gate and non-check execution send no step heartbeats."""
    # (a) consecutive_loop_errors = 1 -> mid-check heartbeats active
    run_a = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="gate_a",
        initial_loop_errors=1,
    )
    assert len(run_a.heartbeats) > 1
    _assert_ac1_invariants(run_a)

    # (b) consecutive_loop_errors = 3 -> no step heartbeats, only end-of-tick WATCHDOG=1
    run_b = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="gate_b",
        initial_loop_errors=3,
    )
    assert run_b.heartbeats == [run_b.tick_end]
    assert run_b.longest_gap > WATCHDOG_SEC

    # (c) consecutive_loop_errors = 2, docker logs raises -> _stop_after_loop_errors runs silently
    run_c = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="gate_c",
        initial_loop_errors=2,
        raise_on_docker_logs=True,
    )
    assert run_c.outcome == "failed"
    logs_idx = next(
        i
        for i, (argv, _) in enumerate(run_c.runner_calls)
        if argv[:2] == ["docker", "logs"] and "--since" in argv
    )
    logs_step_start = run_c.steps[logs_idx][0]
    assert run_c.heartbeats
    assert all(hb <= logs_step_start for hb in run_c.heartbeats)
    assert max(run_c.heartbeats) == logs_step_start
    # _stop_after_loop_errors() ran Docker calls after the raising step
    assert len(run_c.runner_calls) > logs_idx + 1

    # (d) consecutive_loop_errors = 0, docker logs raises -> heartbeats up to raising step
    run_d = _run_tick_case(
        tmp_path,
        path_name="first_outage_tick",
        model="slow_success",
        monkeypatch=monkeypatch,
        subdir="gate_d",
        initial_loop_errors=0,
        raise_on_docker_logs=True,
    )
    assert run_d.outcome == "failed"
    logs_idx_d = next(
        i
        for i, (argv, _) in enumerate(run_d.runner_calls)
        if argv[:2] == ["docker", "logs"] and "--since" in argv
    )
    logs_step_start_d = run_d.steps[logs_idx_d][0]
    assert run_d.heartbeats
    assert all(hb <= logs_step_start_d for hb in run_d.heartbeats)
    assert max(run_d.heartbeats) == logs_step_start_d

    # (e) _step_heartbeat(), attached runner outside _tick(), and fail_safe() send no WATCHDOG=1
    root_e = tmp_path / "gate_e"
    root_e.mkdir(parents=True, exist_ok=True)
    cfg_e = _make_prod_like_config(root_e)
    sent: list[str] = []
    monkeypatch.setattr(orchestrator_mod, "notify", lambda s: sent.append(s) or True)
    monkeypatch.setattr(orchestrator_mod, "send_alert", lambda *a, **kw: True)

    class _FailSafeRunner:
        def run(self, args: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
            if args[-2:] == ["config", "--services"]:
                return completed(args, "gluetun\nstremio\n")
            if args[:2] == ["docker", "info"]:
                return completed(args, "daemon-a\n")
            return completed(args, "")

    guard_e = GluetunGuard(cfg_e, _FailSafeRunner(), teardown=True)
    monkeypatch.setattr(guard_e, "require_commands", lambda: None)
    orch_e = Orchestrator(guard_e)
    orch_e._attach_step_heartbeat()
    orch_e._step_heartbeat()
    guard_e.runner.run(["docker", "ps"], timeout=30)
    orch_e.fail_safe()
    assert sent == []


def test_ac06_emergency_stops_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6 (INV-5): runner argv/timeouts stay identical with/without step heartbeats."""
    for path_name in ALL_PATHS:
        for model in MODELS:
            subdir = f"ac6_{path_name}_{model}"
            lockout_file = tmp_path / subdir / ".stremio" / "vpn-lockout"
            with_hb = _run_tick_case(
                tmp_path,
                path_name=path_name,
                model=model,
                monkeypatch=monkeypatch,
                subdir=subdir,
                attach_heartbeat=True,
            )
            lockout_file.unlink(missing_ok=True)
            without_hb = _run_tick_case(
                tmp_path,
                path_name=path_name,
                model=model,
                monkeypatch=monkeypatch,
                subdir=subdir,
                attach_heartbeat=False,
            )
            assert with_hb.runner_calls == without_hb.runner_calls

            if path_name in {"trip_tick", "second_leak_verdict"}:
                lockout_file.unlink(missing_ok=True)
                raising_hb = _run_tick_case(
                    tmp_path,
                    path_name=path_name,
                    model=model,
                    monkeypatch=monkeypatch,
                    subdir=subdir,
                    attach_heartbeat=True,
                    notify_raises=True,
                )
                assert raising_hb.runner_calls == with_hb.runner_calls
                assert "exit_78" in raising_hb.events
                assert lockout_file.exists()
