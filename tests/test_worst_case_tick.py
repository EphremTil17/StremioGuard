"""Worst-case Orchestrator._tick() measurement across all 5 paths and 2 models (AC-16 / D17)."""

from __future__ import annotations

import json
import subprocess
import urllib.error
from pathlib import Path

import pytest
import typer

from stremioguard import alerts as alerts_mod
from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard import resolver as resolver_mod
from stremioguard.config import (
    DOCKER_QUERY_TIMEOUT_SECONDS,
    WATCHDOG_MUTATION_TIMEOUT_SECONDS,
    CometConfig,
    Config,
)
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import Orchestrator
from tests.conftest import PUBLIC_IPV4_EGRESS, PUBLIC_IPV4_HOST, PUBLIC_IPV4_STATION, completed


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


def _make_prod_like_config(root: Path) -> Config:
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
        public_ip_timeout_seconds=5,
        home_ip_file=state_dir / "home-ip",
        expected_vpn_ip=None,
        ip_check_urls=(
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
        ),
        install_missing=False,
        run_id="d17-measure",
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
    )


def _measure_path(
    tmp_path: Path,
    *,
    path_name: str,
    model: str,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[float, list[str]]:
    """Measure one Orchestrator._tick() path under 'all_timeouts' or 'slow_success'."""
    root = tmp_path / f"{path_name}_{model}"
    root.mkdir(parents=True, exist_ok=True)
    cfg = _make_prod_like_config(root)
    clock = _FakeClock()

    # Patch time across all modules used during _tick()
    for mod in (orchestrator_mod, guard_mod, resolver_mod):
        monkeypatch.setattr(mod.time, "monotonic", clock.monotonic)
        monkeypatch.setattr(mod.time, "time", clock.time)

    # Also keep cached comet config deterministic (all 5 runtime services)
    comet_cfg = CometConfig.from_env(root, env_file=root / ".env")
    services = ["stremio", *comet_cfg.runtime_services]
    events: list[str] = []
    unbounded_calls: list[str] = []

    want_healthy = path_name in {"steady_state_all_ip_stalling", "recovery_tick"}
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
            if timeout is None:
                unbounded_calls.append(" ".join(args))
            else:
                clock.advance(timeout)

            cmd_str = " ".join(args)

            # Gluetun health check (uncaught on ps -q / inspect)
            if args[-3:] == ["ps", "-q", "gluetun"]:
                return completed(args, "gluetun-cid\n")
            if (
                args[:3] == ["docker", "inspect", "--format"]
                and "{{.State.Health.Status}}" in args[3]
            ):
                status = "healthy" if want_healthy else "unhealthy"
                return completed(args, f"{status}|2026-11-16T00:00:00Z\n")

            # Service container IDs
            if len(args) >= 3 and args[-3:-1] == ["ps", "-q"]:
                svc = args[-1]
                return completed(args, f"{svc}-cid\n")

            # Auth evidence scan (`docker logs`) - uncaught in gluetun_auth_evidence,
            # caught in capture_gluetun_evidence.
            if args[:2] == ["docker", "logs"] and ("--since" in args or "--tail" in args):
                return completed(args, "")

            # Control server probe
            if "http://127.0.0.1:18080/v1/publicip/ip" in args:
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f'{{"public_ip": "{PUBLIC_IPV4_EGRESS}"}}')

            # DNS block check
            if "iptables" in args:
                if all_timeouts and path_name != "steady_state_all_ip_stalling":
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f"-P OUTPUT DROP\n{guard_mod.DNS_BLOCK_RULE}\n")

            # In-gluetun IP probe (`wget ... -qO- <url>`)
            if "-qO-" in args:
                events.append("egress_probe")
                if all_timeouts or path_name == "steady_state_all_ip_stalling":
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, f"{PUBLIC_IPV4_EGRESS}\n")

            # Namespace inspect
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

            # Compose config --services
            if args[-2:] == ["config", "--services"]:
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args, "\n".join(["gluetun", *services]) + "\n")

            # Compose ps --status running --services
            if "--status" in args and "running" in args:
                nonlocal ps_running_calls
                ps_running_calls += 1
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                if path_name == "recovery_tick":
                    return completed(args, "")
                if path_name == "mid_outage_relaxed_restart" and ps_running_calls == 1:
                    # Simulate first stop had failed, so mid-outage tick stops again
                    return completed(args, "\n".join(services) + "\n")
                # Slow success: first query sees running, post-stop query sees stopped
                if ps_running_calls % 2 == 1:
                    return completed(args, "\n".join(services) + "\n")
                return completed(args, "")

            # Compose stop
            if "stop" in args and args[:2] == ["docker", "compose"]:
                events.append("compose_stop")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            # Direct docker stop fallback
            if args[:2] == ["docker", "stop"]:
                events.append("docker_stop")
                if all_timeouts:
                    raise subprocess.TimeoutExpired(args, timeout or 1)
                return completed(args)

            # Compose up (recreate gluetun or start services)
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
        clock.advance(timeout)
        if all_timeouts or path_name == "steady_state_all_ip_stalling":
            return None
        return f"{PUBLIC_IPV4_HOST}\n"

    def fake_fetch_recs(
        *, country_id: int | None = None, timeout_seconds: float = 8.0
    ) -> list[dict[str, object]]:
        events.append("resolver")
        clock.advance(timeout_seconds)
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
        clock.advance(alerts_mod.ALERT_TIMEOUT_SECONDS)
        return not all_timeouts

    monkeypatch.setattr(GluetunGuard, "_fetch_ip_url", staticmethod(fake_fetch_ip_url))
    monkeypatch.setattr(resolver_mod, "_fetch_nordvpn_recommendations", fake_fetch_recs)
    monkeypatch.setattr(orchestrator_mod, "send_alert", fake_send_alert)
    monkeypatch.setattr(orchestrator_mod, "notify", lambda _state: None)

    guard = GluetunGuard(cfg, _TimingRunner(), frozen=True)
    orch = Orchestrator(guard)
    # Give alert_url so _alert exercises send_alert if triggered
    cfg_dict = dict(cfg.__dict__)
    cfg_dict["alert_url"] = "https://ntfy.example.test/topic"
    guard.config = Config(**cfg_dict)  # type: ignore[arg-type]

    # Set pre-conditions for each path
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

    start_mono = clock.monotonic()
    try:
        orch._tick()
    except typer.Exit as exc:
        events.append(f"exit_{exc.exit_code}")

    elapsed = clock.monotonic() - start_mono
    assert not unbounded_calls, f"Unexpected timeout=None runner calls: {unbounded_calls}"

    # Verify the expected path was actually taken
    if path_name == "steady_state_all_ip_stalling":
        assert "egress_probe" in events
        if all_timeouts:
            assert "compose_stop" in events
        else:
            # slow_success: DNS block + egress all fail -> host probe isn't reached if egress fails,
            # and threshold=1 triggers stop_active_services -> compose_stop!
            assert "compose_stop" in events
    elif path_name == "first_outage_tick":
        assert "compose_stop" in events
        assert "resolver" in events
        if not all_timeouts:
            assert "compose_up" in events
    elif path_name == "mid_outage_relaxed_restart":
        if all_timeouts:
            assert "compose_stop" in events
        assert "compose_up" in events
    elif path_name == "recovery_tick":
        if all_timeouts:
            assert "compose_stop" in events
        else:
            assert "egress_probe" in events
            assert "host_probe" in events
            assert "compose_up" in events
    elif path_name == "trip_tick":
        assert "exit_78" in events
        assert cfg.vpn_lockout_file.exists()
        marker = json.loads(cfg.vpn_lockout_file.read_text(encoding="utf-8"))
        assert marker["reason"] == "recovery_budget_exhausted"
        assert "compose_stop" in events
        assert "alert" in events

    return elapsed, events


def test_ac16_measure_worst_case_tick_across_all_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-16 (D17, INV-11): measure Orchestrator._tick() under all_timeouts and slow_success."""
    paths = (
        "steady_state_all_ip_stalling",
        "first_outage_tick",
        "mid_outage_relaxed_restart",
        "recovery_tick",
        "trip_tick",
    )
    models = ("all_timeouts", "slow_success")

    rows: list[tuple[str, str, float, list[str]]] = []
    for path_name in paths:
        for model in models:
            elapsed, events = _measure_path(
                tmp_path, path_name=path_name, model=model, monkeypatch=monkeypatch
            )
            rows.append((path_name, model, elapsed, events))

    print("\n--- D17 Worst-case Orchestrator._tick() measurements (WatchdogSec=300) ---")
    print(f"{'Path':<30} {'Model':<14} {'Total(s)':>9} {'vs 300s':>10}  Events")
    for path_name, model, elapsed, events in rows:
        delta = elapsed - 300.0
        sign = "+" if delta > 0 else ""
        print(f"{path_name:<30} {model:<14} {elapsed:9.1f} {sign}{delta:9.1f}  {','.join(events)}")

    assert len(rows) == 10
    assert DOCKER_QUERY_TIMEOUT_SECONDS == 30
    assert WATCHDOG_MUTATION_TIMEOUT_SECONDS == 240
