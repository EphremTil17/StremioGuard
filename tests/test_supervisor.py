"""Tests for the systemd user-service supervision of the watchdog."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest
import typer

from stremioguard.cli import supervisor
from stremioguard.cli.context import RunContext


class FakeSystemctl:
    """Scripted `systemctl --user`: a state per unit, recorded calls."""

    def __init__(self, unit_dir: Path, **states: str) -> None:
        self.unit_dir = unit_dir
        self.calls: list[tuple[str, ...]] = []
        self.states = {supervisor.WATCHDOG_UNIT: "inactive", **states}
        self.fail_verbs: set[str] = set()
        self.fragment_override: str | None = None

    def __call__(self, *args: str) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        verb = args[0]
        if verb in self.fail_verbs:
            return subprocess.CompletedProcess(args, 1, "", f"{verb} failed")
        if verb in {"start", "restart"}:
            self.states[args[1]] = "running"
        elif verb == "stop":
            self.states[args[1]] = "inactive"
        elif verb == "show" and len(args) > 1 and not args[1].startswith("--"):
            return subprocess.CompletedProcess(args, 0, self._show(args[1]), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def _show(self, unit: str) -> str:
        state = self.states.get(unit, "inactive")
        active = {"running": "active", "stuck": "deactivating"}.get(state, "inactive")
        pid = "4242" if state == "running" else "0"
        fragment = self.fragment_override or str(self.unit_dir / unit)
        return (
            f"LoadState=loaded\nActiveState={active}\nSubState={state}\nMainPID={pid}\n"
            f"NRestarts=0\nResult=success\nUnitFileState=disabled\nFragmentPath={fragment}\n"
        )

    def verbs(self) -> list[str]:
        return [call[0] for call in self.calls]


@pytest.fixture
def systemctl(isolate_user_systemd: Path, monkeypatch: pytest.MonkeyPatch) -> FakeSystemctl:
    fake = FakeSystemctl(isolate_user_systemd)
    monkeypatch.setattr(supervisor, "_systemctl", fake)
    return fake


@pytest.fixture
def context(sandbox_deployment_paths: Path) -> RunContext:
    return RunContext(run_id="run-1", log_file=sandbox_deployment_paths / "logs" / "run-1.log")


# --- Unit rendering -----------------------------------------------------------


def test_watchdog_unit_encodes_backoff_heartbeat_and_fail_safe() -> None:
    unit = supervisor.render_watchdog_unit()
    for directive in (
        "Type=notify",
        "NotifyAccess=main",
        "Restart=always",
        # Without it systemd fires OnFailure= on the first crash, not the last.
        "RestartMode=direct",
        f"RestartSec={supervisor.RESTART_SEC}",
        f"RestartSteps={supervisor.RESTART_STEPS}",
        f"RestartMaxDelaySec={supervisor.RESTART_MAX_DELAY_SEC}",
        "RestartPreventExitStatus=78",
        f"StartLimitBurst={supervisor.START_LIMIT_BURST}",
        f"WatchdogSec={supervisor.WATCHDOG_SEC}",
        f"OnFailure={supervisor.FAILSAFE_UNIT}",
        f"EnvironmentFile={supervisor.watchdog_env_file()}",
    ):
        assert f"\n{directive}\n" in unit, directive
    # The heartbeat must outlast the longest sleep between pings.
    from stremioguard.orchestrator import HEARTBEAT_SLEEP_CHUNK_SECONDS

    assert supervisor.WATCHDOG_SEC > 2 * HEARTBEAT_SLEEP_CHUNK_SECONDS


def test_unit_quoting_survives_specifiers_and_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor, "_python", lambda: '/opt/my "env"/50%/$HOME/bin/python')
    unit = supervisor.render_watchdog_unit()
    assert 'ExecStart="/opt/my \\"env\\"/50%%/$$HOME/bin/python" -m' in unit
    monkeypatch.setattr(supervisor, "_python", lambda: "/opt/env\n/bin/python")
    with pytest.raises(ValueError):
        supervisor.render_watchdog_unit()


def test_boot_unit_is_opt_in_and_does_not_loop_on_lockout() -> None:
    unit = supervisor.render_boot_unit()
    assert "WantedBy=default.target" in unit
    assert "RestartPreventExitStatus=78" in unit
    assert f'\nExecStart="{supervisor.ROOT_DIR / "stremio"}" start\n' in unit


# --- Environment forwarding ---------------------------------------------------


def test_env_file_forwards_only_known_keys_with_private_mode() -> None:
    env = {
        "WATCH_INTERVAL_SECONDS": "5",
        "WIREGUARD_ENDPOINT_IP": "203.0.113.7",
        "DOCKER_HOST": "unix:///run/user/1000/docker.sock",
        "EXPECTED_VPN_IP": 'a "quoted" \\ value',
        "OPENVPN_PASSWORD": "secret",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "IP_CHECK_URLS": "",
    }
    supervisor.write_watchdog_env(env)
    path = supervisor.watchdog_env_file()
    content = path.read_text(encoding="utf-8")
    assert 'WATCH_INTERVAL_SECONDS="5"\n' in content
    assert 'DOCKER_HOST="unix:///run/user/1000/docker.sock"\n' in content
    assert 'EXPECTED_VPN_IP="a \\"quoted\\" \\\\ value"\n' in content
    assert "OPENVPN_PASSWORD" not in content
    assert "SSH_AUTH_SOCK" not in content
    assert "IP_CHECK_URLS" not in content
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_env_file_change_detection_ignores_per_run_identity() -> None:
    base = {
        "STREMIO_RUN_ID": "a",
        "STREMIO_LOG_FILE": "/logs/a.log",
        "WATCH_INTERVAL_SECONDS": "10",
    }
    assert supervisor.write_watchdog_env(base) is True
    assert supervisor.write_watchdog_env({**base, "STREMIO_RUN_ID": "b"}) is False
    # The file still follows the newest run, so a restarted watchdog logs there.
    assert 'STREMIO_RUN_ID="b"' in supervisor.watchdog_env_file().read_text(encoding="utf-8")
    assert supervisor.write_watchdog_env({**base, "WATCH_INTERVAL_SECONDS": "5"}) is True


def test_env_file_rejects_newlines() -> None:
    with pytest.raises(ValueError):
        supervisor.write_watchdog_env({"EXPECTED_VPN_IP": "1.2.3.4\nEVIL=1"})


# --- Installation -------------------------------------------------------------


def test_install_units_reloads_only_when_files_change(systemctl: FakeSystemctl) -> None:
    assert supervisor.install_units() is True
    assert "daemon-reload" in systemctl.verbs()
    for unit in (supervisor.WATCHDOG_UNIT, supervisor.FAILSAFE_UNIT, supervisor.BOOT_UNIT):
        assert (systemctl.unit_dir / unit).exists()

    systemctl.calls.clear()
    assert supervisor.install_units() is False
    assert "daemon-reload" not in systemctl.verbs()


def test_install_units_fails_when_manager_loads_a_different_file(
    systemctl: FakeSystemctl,
) -> None:
    systemctl.fragment_override = "/etc/systemd/user/stremioguard-watchdog.service"
    with pytest.raises(typer.Exit):
        supervisor.install_units()


def test_install_units_warns_about_legacy_unit(systemctl: FakeSystemctl) -> None:
    systemctl.unit_dir.mkdir(parents=True)
    (systemctl.unit_dir / supervisor.LEGACY_UNIT).write_text("[Service]\n", encoding="utf-8")
    with mock.patch.object(supervisor, "logger") as log:
        supervisor.install_units()
    assert supervisor.LEGACY_UNIT in log.warning.call_args.args[0]


def test_require_user_systemd_refuses_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 0)
    with pytest.raises(typer.Exit):
        supervisor.require_user_systemd()


def test_require_user_systemd_refuses_old_systemd(
    systemctl: FakeSystemctl, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(supervisor.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        supervisor,
        "_systemctl",
        lambda *args: subprocess.CompletedProcess(args, 0, "249.11-0ubuntu3\n", ""),
    )
    with pytest.raises(typer.Exit):
        supervisor.require_user_systemd()


def test_require_user_systemd_refuses_without_linger(
    systemctl: FakeSystemctl, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(supervisor.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(supervisor.Path, "exists", lambda self: False)
    with pytest.raises(typer.Exit):
        supervisor.require_user_systemd()


# --- Start / stop -------------------------------------------------------------


def test_start_watchdog_starts_and_verifies(systemctl: FakeSystemctl, context: RunContext) -> None:
    supervisor.start_watchdog(context, units_changed=False)
    assert systemctl.verbs() == ["show", "reset-failed", "start", "show"]
    assert systemctl.states[supervisor.WATCHDOG_UNIT] == "running"


def test_start_watchdog_leaves_healthy_unchanged_watchdog_alone(
    systemctl: FakeSystemctl, context: RunContext
) -> None:
    supervisor.write_watchdog_env(context.env())
    systemctl.states[supervisor.WATCHDOG_UNIT] = "running"
    supervisor.start_watchdog(context, units_changed=False)
    assert "start" not in systemctl.verbs()
    assert "restart" not in systemctl.verbs()


def test_start_watchdog_restarts_when_definition_changed(
    systemctl: FakeSystemctl, context: RunContext
) -> None:
    supervisor.write_watchdog_env(context.env())
    systemctl.states[supervisor.WATCHDOG_UNIT] = "running"
    supervisor.start_watchdog(context, units_changed=True)
    assert "restart" in systemctl.verbs()


def test_start_watchdog_fails_when_unit_does_not_come_up(
    systemctl: FakeSystemctl, context: RunContext
) -> None:
    systemctl.fail_verbs.add("start")
    with pytest.raises(typer.Exit):
        supervisor.start_watchdog(context, units_changed=False)


def test_stop_watchdog_reports_proven_stop(systemctl: FakeSystemctl) -> None:
    systemctl.states[supervisor.WATCHDOG_UNIT] = "running"
    assert supervisor.stop_watchdog() is True


def test_stop_watchdog_reports_unit_that_stays_up(systemctl: FakeSystemctl) -> None:
    systemctl.states[supervisor.WATCHDOG_UNIT] = "running"
    systemctl.fail_verbs.add("stop")
    assert supervisor.stop_watchdog() is False


# --- Legacy migration ---------------------------------------------------------


def test_retire_legacy_watchdog_ignores_unrelated_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    pid_file = supervisor.STATE_DIR / "watchdog.pid"
    pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
    sent: list[int] = []
    monkeypatch.setattr(supervisor.os, "kill", lambda pid, sig: sent.append(sig))
    # This test process is alive but is no watchdog: it must not be signalled.
    supervisor.retire_legacy_watchdog()
    assert [sig for sig in sent if sig != 0] == []
    assert not pid_file.exists()


def test_retire_legacy_watchdog_terminates_recorded_watchdog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid_file = supervisor.STATE_DIR / "watchdog.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    alive = {"value": True}

    def fake_kill(pid: int, sig: int) -> None:
        if sig == signal.SIGTERM:
            alive["value"] = False
        elif not alive["value"]:
            raise ProcessLookupError

    monkeypatch.setattr(supervisor.os, "kill", fake_kill)
    monkeypatch.setattr(supervisor, "_is_legacy_watchdog", lambda pid: pid == 4321)
    supervisor.retire_legacy_watchdog()
    assert alive["value"] is False
    assert not pid_file.exists()
