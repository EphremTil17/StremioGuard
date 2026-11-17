"""Real-systemd proof that step heartbeats keep WatchdogSec=3 alive across >12s ticks (AC-12)."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_SYSTEMD_TESTS") != "1",
    reason="needs a live systemd user manager; set STREMIOGUARD_SYSTEMD_TESTS=1",
)

PAYLOAD = textwrap.dedent(
    """\
    import subprocess
    import sys
    import time
    from pathlib import Path

    from stremioguard.config import Config
    from stremioguard.guard import GluetunGuard
    from stremioguard.orchestrator import Orchestrator

    root = Path(sys.argv[1])
    wedge = sys.argv[2] == "wedge"

    state_dir = root / ".stremio"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "docker-compose.bindings.yml").touch()
    (state_dir / "compose.base.yml").write_text("services:\\n  gluetun: {}\\n", encoding="utf-8")
    (state_dir / "env.snapshot").touch()
    (root / "docker-compose.yml").write_text("services:\\n  gluetun: {}\\n", encoding="utf-8")
    (root / ".env").write_text(
        "VPN_SERVICE_PROVIDER=custom\\nSTREMIO_ENABLED=1\\n",
        encoding="utf-8",
    )

    cfg = Config(
        root_dir=root,
        gluetun_healthy_timeout_seconds=60,
        watch_interval_seconds=1,
        watchdog_log_interval_seconds=300,
        public_ip_timeout_seconds=5,
        home_ip_file=state_dir / "home-ip",
        expected_vpn_ip=None,
        ip_check_urls=("https://127.0.0.1:1/ip",),
        install_missing=False,
        run_id="ac12-systemd",
        log_file=None,
        log_session=True,
        stremio_enabled=True,
        egress_probe_interval_seconds=300,
        public_ip_failure_threshold=3,
        vpn_recovery_budget_seconds=300,
        vpn_restart_cadence_seconds=45,
        vpn_lockout_file=state_dir / "vpn-lockout",
        server_countries=None,
        server_regions=None,
        server_cities=None,
        server_hostnames=None,
        server_categories=None,
        env_file=root / ".env",
        alert_url=None,
    )

    class _SlowFakeRunner:
        def __init__(self) -> None:
            self.calls = 0
            self.ps_running = 0

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
            self.calls += 1
            if wedge and self.calls == 4:
                time.sleep(6.0)
            else:
                time.sleep(1.5)

            if args[-3:] == ["ps", "-q", "gluetun"]:
                return subprocess.CompletedProcess(args, 0, "gluetun-cid\\n", "")
            if args[:3] == ["docker", "inspect", "--format"]:
                return subprocess.CompletedProcess(args, 0, "unhealthy|2026-11-16T00:00:00Z\\n", "")
            if "--status" in args and "running" in args:
                self.ps_running += 1
                out = "stremio\\n" if self.ps_running <= 2 else ""
                return subprocess.CompletedProcess(args, 0, out, "")
            if "stop" in args and args[:2] == ["docker", "compose"]:
                return subprocess.CompletedProcess(args, 1, "", "stop failed")
            if args[:2] == ["docker", "stop"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if len(args) >= 3 and args[-3:-1] == ["ps", "-q"]:
                return subprocess.CompletedProcess(args, 0, "stremio-cid\\n", "")
            if args[:2] == ["docker", "logs"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if "restart" in args and args[:2] == ["docker", "compose"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

    runner = _SlowFakeRunner()
    guard = GluetunGuard(cfg, runner, frozen=True)
    guard.require_commands = lambda: None  # type: ignore[method-assign]
    orch = Orchestrator(guard)

    orig_watch_once = orch.watch_once
    checks = {"count": 0}

    def _bounded_watch_once() -> None:
        checks["count"] += 1
        if checks["count"] >= 2:
            if runner.calls < 8:
                raise SystemExit(2)
            raise SystemExit(0)
        orig_watch_once()

    orch.watch_once = _bounded_watch_once  # type: ignore[method-assign]
    orch.watch_stremio()
    """
)


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return subprocess.run(
        ["systemctl", "--user", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _unit_props(unit: str) -> dict[str, str]:
    res = _systemctl(
        "show",
        unit,
        "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus",
    )
    return dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)


def _run_transient_unit(
    tmp_path: Path,
    *,
    unit_name: str,
    mode: str,
) -> tuple[dict[str, str], float]:
    script = tmp_path / f"payload_{mode}.py"
    script.write_text(PAYLOAD, encoding="utf-8")
    work_root = tmp_path / f"root_{mode}"
    work_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    src_path = str(Path(__file__).resolve().parent.parent / "src")

    start = time.monotonic()
    run_res = subprocess.run(
        [
            "systemd-run",
            "--user",
            f"--unit={unit_name}",
            "-p",
            "Type=notify",
            "-p",
            "NotifyAccess=main",
            "-p",
            "WatchdogSec=3",
            "-p",
            "Restart=no",
            "-E",
            f"PYTHONPATH={src_path}",
            sys.executable,
            str(script),
            str(work_root),
            mode,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert run_res.returncode == 0, run_res.stderr

    deadline = time.monotonic() + 40.0
    props: dict[str, str] = {}
    while time.monotonic() < deadline:
        props = _unit_props(unit_name)
        if props.get("ActiveState") in {"inactive", "failed"}:
            break
        time.sleep(0.25)
    elapsed = time.monotonic() - start
    return props, elapsed


def test_ac12_real_systemd_step_heartbeats_and_wedge(tmp_path: Path) -> None:
    """AC-12 (INV-1, INV-2): real systemd keeps WatchdogSec=3 alive and kills a wedge."""
    prefix = os.environ.get("STREMIOGUARD_TEST_PREFIX", "sgtest-")
    normal_unit = f"{prefix}hb-{uuid.uuid4().hex[:8]}.service"
    wedge_unit = f"{prefix}hb-{uuid.uuid4().hex[:8]}.service"

    try:
        props_ok, elapsed_ok = _run_transient_unit(tmp_path, unit_name=normal_unit, mode="normal")
        assert props_ok.get("Result") == "success", props_ok
        assert props_ok.get("ExecMainStatus") == "0", props_ok
        assert elapsed_ok > 12.0, elapsed_ok

        props_wedge, _ = _run_transient_unit(tmp_path, unit_name=wedge_unit, mode="wedge")
        assert props_wedge.get("Result") == "watchdog", props_wedge
        assert props_wedge.get("ExecMainCode") == "3", props_wedge
        assert props_wedge.get("ExecMainStatus") == "6", props_wedge
    finally:
        for unit in (normal_unit, wedge_unit):
            _systemctl("stop", unit)
            _systemctl("reset-failed", unit)

    listing = _systemctl("list-units", "--all", f"{prefix}*", "--no-legend")
    assert listing.stdout.strip() == "", listing.stdout
