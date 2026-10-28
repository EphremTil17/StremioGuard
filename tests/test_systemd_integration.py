"""Real-systemd proof of the watchdog unit's supervision semantics.

Opt-in (`STREMIOGUARD_SYSTEMD_TESTS=1 uv run pytest tests/test_systemd_integration.py`):
it loads the units rendered by `supervisor` into the live user manager, under
throwaway names in the runtime unit directory, with timings shortened and a
stand-in payload in place of the watchdog. Mocks can prove the CLI sent the
right commands; only the manager itself can prove backoff, the start limit,
OnFailure=, WatchdogSec= and the EnvironmentFile= quoting actually behave.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import textwrap
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from stremioguard.cli import supervisor

REAL_SYSTEMCTL = supervisor._systemctl

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_SYSTEMD_TESTS") != "1",
    reason="needs a live systemd user manager; set STREMIOGUARD_SYSTEMD_TESTS=1",
)

PAYLOAD = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    # Stand-in for `python -m stremioguard.orchestrator watchdog|failsafe`.
    import json, os, socket, sys, time
    from pathlib import Path

    role = sys.argv[-1]
    events = Path.cwd() / f"{role}.events"
    with events.open("a") as handle:
        handle.write(f"{time.monotonic():.2f}\\n")
    if role == "failsafe":
        sys.exit(0)
    keys = ("EXPECTED_VPN_IP", "STREMIOGUARD_MANAGED", "STREMIO_BACKGROUND")
    Path("env.json").write_text(json.dumps({k: os.environ.get(k) for k in keys}))

    def mode():
        return Path("mode").read_text().strip()

    def notify(state):
        address = os.environ["NOTIFY_SOCKET"]
        if address.startswith("@"):
            address = "\\0" + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.send(state.encode())

    if mode() == "crash":
        sys.exit(1)
    if mode() == "exit78":
        sys.exit(78)
    notify("READY=1")
    while True:
        if mode() != "hang":
            notify("WATCHDOG=1")
        time.sleep(0.2)
    """
)


def _runtime_unit_dir() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return Path(runtime) / "systemd" / "user"


@pytest.fixture
def units(
    sandbox_deployment_paths: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[str, str, Path]]:
    root = sandbox_deployment_paths
    suffix = uuid.uuid4().hex[:8]
    watchdog_unit = f"sgtest-{suffix}-watchdog.service"
    failsafe_unit = f"sgtest-{suffix}-failsafe.service"
    payload = root / "payload.py"
    payload.write_text(PAYLOAD, encoding="utf-8")
    payload.chmod(0o755)

    monkeypatch.setattr(supervisor, "_systemctl", REAL_SYSTEMCTL)
    monkeypatch.setattr(supervisor, "unit_dir", _runtime_unit_dir)
    monkeypatch.setattr(supervisor, "WATCHDOG_UNIT", watchdog_unit)
    monkeypatch.setattr(supervisor, "FAILSAFE_UNIT", failsafe_unit)
    monkeypatch.setattr(supervisor, "_python", lambda: str(payload))
    monkeypatch.setattr(supervisor, "RESTART_SEC", 1)
    monkeypatch.setattr(supervisor, "RESTART_STEPS", 3)
    monkeypatch.setattr(supervisor, "RESTART_MAX_DELAY_SEC", 8)
    monkeypatch.setattr(supervisor, "START_LIMIT_BURST", 4)
    monkeypatch.setattr(supervisor, "WATCHDOG_SEC", 2)

    directory = _runtime_unit_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / watchdog_unit).write_text(supervisor.render_watchdog_unit(), encoding="utf-8")
    (directory / failsafe_unit).write_text(supervisor.render_failsafe_unit(), encoding="utf-8")
    (root / "mode").write_text("run", encoding="utf-8")
    supervisor.write_watchdog_env({"EXPECTED_VPN_IP": 'a "quoted" $HOME %h \\ value'})
    REAL_SYSTEMCTL("daemon-reload")
    try:
        yield watchdog_unit, failsafe_unit, root
    finally:
        REAL_SYSTEMCTL("stop", watchdog_unit, failsafe_unit)
        REAL_SYSTEMCTL("reset-failed", watchdog_unit, failsafe_unit)
        for unit in (watchdog_unit, failsafe_unit):
            (directory / unit).unlink(missing_ok=True)
        REAL_SYSTEMCTL("daemon-reload")


def _wait_for(predicate, timeout: float, step: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


def _events(root: Path, role: str) -> list[float]:
    path = root / f"{role}.events"
    if not path.exists():
        return []
    return [float(line) for line in path.read_text(encoding="utf-8").split()]


def test_rendered_units_pass_systemd_analyze(units: tuple[str, str, Path]) -> None:
    watchdog_unit, failsafe_unit, _ = units
    directory = _runtime_unit_dir()
    result = subprocess.run(
        ["systemd-analyze", "--user", "verify", str(directory / watchdog_unit)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_start_waits_for_ready_and_forwards_environment_verbatim(
    units: tuple[str, str, Path],
) -> None:
    watchdog_unit, _, root = units
    assert REAL_SYSTEMCTL("start", watchdog_unit).returncode == 0
    assert supervisor.unit_state(watchdog_unit).running
    env = json.loads((root / "env.json").read_text(encoding="utf-8"))
    assert env == {
        "EXPECTED_VPN_IP": 'a "quoted" $HOME %h \\ value',
        "STREMIOGUARD_MANAGED": "1",
        "STREMIO_BACKGROUND": "1",
    }


def test_watchdog_outlives_the_scope_that_started_it(units: tuple[str, str, Path]) -> None:
    # The original failure: a detached child died when its caller's scope was
    # torn down. Here the caller's scope is killed outright.
    watchdog_unit, _, _ = units
    scope = f"sgtest-caller-{uuid.uuid4().hex[:8]}.scope"
    caller = subprocess.Popen(
        [
            "systemd-run",
            "--user",
            "--scope",
            f"--unit={scope}",
            "sh",
            "-c",
            f"systemctl --user start {watchdog_unit}; sleep 30",
        ],
        env={**os.environ, "XDG_RUNTIME_DIR": str(_runtime_unit_dir().parent.parent)},
    )
    try:
        assert _wait_for(lambda: supervisor.unit_state(watchdog_unit).running, 15)
        pid = supervisor.unit_state(watchdog_unit).main_pid
        REAL_SYSTEMCTL("kill", "--signal=SIGKILL", scope)
        caller.wait(timeout=10)
        time.sleep(1)
        state = supervisor.unit_state(watchdog_unit)
        assert state.running and state.main_pid == pid
    finally:
        caller.kill()


def test_missed_heartbeat_restarts_a_hung_watchdog(units: tuple[str, str, Path]) -> None:
    watchdog_unit, _, root = units
    REAL_SYSTEMCTL("start", watchdog_unit)
    first_pid = supervisor.unit_state(watchdog_unit).main_pid
    (root / "mode").write_text("hang", encoding="utf-8")
    assert _wait_for(lambda: supervisor.unit_state(watchdog_unit).main_pid != first_pid, 15)
    (root / "mode").write_text("run", encoding="utf-8")
    assert _wait_for(lambda: supervisor.unit_state(watchdog_unit).running, 15)
    # One recovered hang is a retry, not a reason to lock out.
    assert _events(root, "failsafe") == []


def test_crash_loop_backs_off_then_fails_into_the_fail_safe(
    units: tuple[str, str, Path],
) -> None:
    watchdog_unit, failsafe_unit, root = units
    REAL_SYSTEMCTL("start", watchdog_unit)
    (root / "mode").write_text("crash", encoding="utf-8")
    os.kill(supervisor.unit_state(watchdog_unit).main_pid, signal.SIGKILL)

    assert _wait_for(lambda: _events(root, "failsafe"), 60, step=0.5)
    time.sleep(2)
    # Result= keeps the last crash's reason; the start limit shows as "failed"
    # with no restart pending.
    assert supervisor.unit_state(watchdog_unit).active_state == "failed"
    starts = _events(root, "watchdog")
    assert len(starts) == supervisor.START_LIMIT_BURST
    gaps = [later - earlier for earlier, later in zip(starts[1:], starts[2:], strict=False)]
    assert gaps == sorted(gaps) and gaps[-1] > gaps[0] * 1.5, gaps
    # The fail-safe ran once, after the retries were exhausted, not per crash.
    failsafe_runs = _events(root, "failsafe")
    assert len(failsafe_runs) == 1 and failsafe_runs[0] > starts[-1]
    assert supervisor.unit_state(failsafe_unit).result == "success"


def test_exit_78_is_not_retried_and_runs_the_fail_safe(units: tuple[str, str, Path]) -> None:
    watchdog_unit, _, root = units
    REAL_SYSTEMCTL("start", watchdog_unit)
    (root / "mode").write_text("exit78", encoding="utf-8")
    os.kill(supervisor.unit_state(watchdog_unit).main_pid, signal.SIGKILL)
    assert _wait_for(lambda: _events(root, "failsafe"), 30, step=0.5)
    # One start, one restart after the SIGKILL that then exited 78: no more.
    time.sleep(3)
    assert len(_events(root, "watchdog")) == 2
    assert supervisor.unit_state(watchdog_unit).active_state == "failed"
