"""Run the watchdog as a systemd user service instead of a child of the CLI.

A detached child process dies with whatever owns its cgroup: an agent job
scope, an SSH session, a terminal. A unit in the user's service manager
outlives its caller, is restarted with exponential backoff when it crashes or
stops sending heartbeats, and hands over to a fail-safe unit that locks out
and stops the protected services once restarts are exhausted.
"""

from __future__ import annotations

import os
import pwd
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from stremioguard.cli.context import ROOT_DIR, STATE_DIR, RunContext
from stremioguard.config import CONFIG_ENV_KEYS
from stremioguard.env import atomic_write_text, fail

WATCHDOG_UNIT = "stremioguard-watchdog.service"
FAILSAFE_UNIT = "stremioguard-failsafe.service"
BOOT_UNIT = "stremioguard.service"
# Hand-installed unit from before the CLI managed systemd itself.
LEGACY_UNIT = "stremio-vpn-watch.service"

# Restart policy: 5s, ~10s, ~20s ... capped at 5 min. The 7th start inside an
# hour is refused, the unit fails, and OnFailure= runs the fail-safe. That
# bounds the unwatched window to roughly five minutes of retries.
# RestartMode=direct is what keeps the fail-safe out of the retries: without
# it systemd passes through "failed" on every crash and fires OnFailure= at
# the first one (observed on systemd 255). It and RestartSteps= need 254.
MIN_SYSTEMD_VERSION = 254
RESTART_SEC = 5
RESTART_STEPS = 6
RESTART_MAX_DELAY_SEC = 300
START_LIMIT_INTERVAL_SEC = 3600
START_LIMIT_BURST = 6
# Upper bound on one watchdog tick (a Docker call, a cached image build)
# before systemd treats the process as hung and restarts it.
WATCHDOG_SEC = 600

_DOCKER_CLIENT_KEYS = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)
# Compose interpolates these into gluetun's config; see nordvpn_endpoint_env.
_ENDPOINT_KEYS = ("OPENVPN_ENDPOINT_IP", "WIREGUARD_ENDPOINT_IP")
# The only process environment that reaches the supervised watchdog. Anything
# else exported in the shell that ran `./stremio start` must live in .env.
FORWARDED_ENV_KEYS = (*CONFIG_ENV_KEYS, *_ENDPOINT_KEYS, *_DOCKER_CLIENT_KEYS)
# Every start mints a new run id and log file. Those alone do not justify
# restarting a running watchdog, which would reset an outage in progress.
_PER_RUN_KEYS = frozenset({"STREMIO_RUN_ID", "STREMIO_LOG_FILE"})

_MANAGED_HEADER = "# Managed by StremioGuard: `./stremio start` rewrites this file.\n"


@dataclass(frozen=True)
class UnitState:
    load_state: str
    active_state: str
    sub_state: str
    main_pid: int
    restarts: str
    result: str
    unit_file_state: str

    @property
    def running(self) -> bool:
        return self.active_state == "active" and self.sub_state == "running" and self.main_pid > 0

    @property
    def stopped(self) -> bool:
        return self.load_state == "not-found" or self.active_state in {"inactive", "failed"}


def unit_dir() -> Path:
    # The user manager's own search path. pw_dir rather than $HOME, which
    # `runuser`/`sudo -u` callers may leave pointing at the invoking user.
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".config" / "systemd" / "user"


def watchdog_env_file() -> Path:
    return STATE_DIR / "watchdog.env"


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    # Callers such as cron or `runuser` carry no session environment; this is
    # where the user manager listens regardless.
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return subprocess.run(
        ["systemctl", "--user", *args], capture_output=True, text=True, env=env, check=False
    )


def _systemctl_detail(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or f"exit status {result.returncode}").strip()


def unit_state(unit: str) -> UnitState:
    properties = "LoadState,ActiveState,SubState,MainPID,NRestarts,Result,UnitFileState"
    result = _systemctl("show", unit, f"--property={properties}")
    if result.returncode != 0:
        raise RuntimeError(f"Could not query {unit}: {_systemctl_detail(result)}")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError:
        main_pid = 0
    return UnitState(
        load_state=values.get("LoadState", ""),
        active_state=values.get("ActiveState", ""),
        sub_state=values.get("SubState", ""),
        main_pid=main_pid,
        restarts=values.get("NRestarts", "?"),
        result=values.get("Result", ""),
        unit_file_state=values.get("UnitFileState", ""),
    )


def require_user_systemd() -> None:
    """Fail before any container starts if the watchdog could not be supervised."""
    if os.geteuid() == 0:
        fail(
            "Run ./stremio as the user that owns the stack, not root: the watchdog runs "
            "in that user's systemd manager (e.g. `runuser -u <owner> -- ./stremio start`)."
        )
    if not shutil.which("systemctl"):
        fail(
            "systemd is required to supervise the watchdog, but systemctl was not found. "
            "Without it, run `uv run python -m stremioguard.orchestrator start` and keep "
            "`uv run python -m stremioguard.orchestrator watchdog` running under your own "
            "supervisor."
        )
    result = _systemctl("show", "--property=Version", "--value")
    if result.returncode != 0:
        fail(f"The systemd user manager is unreachable: {_systemctl_detail(result)}")
    version = result.stdout.strip().split(".", 1)[0].split(" ", 1)[0]
    if not version.isdigit() or int(version) < MIN_SYSTEMD_VERSION:
        fail(
            f"systemd {MIN_SYSTEMD_VERSION}+ is required to supervise the watchdog with "
            f"backoff (found {result.stdout.strip() or 'unknown'})."
        )
    user = pwd.getpwuid(os.getuid()).pw_name
    if not (Path("/var/lib/systemd/linger") / user).exists():
        # Without lingering the manager, and the watchdog with it, stops at
        # logout while the containers keep running.
        fail(
            f"Lingering is disabled for {user}, so the watchdog would stop when you log out. "
            f"Enable it with `loginctl enable-linger {user}` and rerun."
        )


def _unit_value(value: object) -> str:
    text = str(value)
    if "\n" in text:
        raise ValueError(f"Refusing to write a newline into a unit file: {text!r}")
    return text.replace("%", "%%")


def _quoted(value: object) -> str:
    text = _unit_value(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _exec_arg(value: object) -> str:
    # ExecStart= also expands $VAR, unlike Environment=.
    return _quoted(value).replace("$", "$$")


def _python() -> str:
    # The venv interpreter `./stremio` is running under. Not resolved: the
    # venv's bin/python is a symlink, and only the unresolved path finds the
    # venv's site-packages.
    return sys.executable


def render_watchdog_unit() -> str:
    return (
        _MANAGED_HEADER
        + f"""[Unit]
Description=StremioGuard VPN watchdog
Documentation=file://{_unit_value(ROOT_DIR / "README.md")}
After=docker.service
StartLimitIntervalSec={START_LIMIT_INTERVAL_SEC}
StartLimitBurst={START_LIMIT_BURST}
OnFailure={FAILSAFE_UNIT}

[Service]
Type=notify
NotifyAccess=main
WorkingDirectory={_unit_value(ROOT_DIR)}
Environment=STREMIOGUARD_MANAGED=1 STREMIO_BACKGROUND=1 PYTHONUNBUFFERED=1
EnvironmentFile={_unit_value(watchdog_env_file())}
ExecStart={_exec_arg(_python())} -m stremioguard.orchestrator watchdog
Restart=always
RestartMode=direct
RestartSec={RESTART_SEC}
RestartSteps={RESTART_STEPS}
RestartMaxDelaySec={RESTART_MAX_DELAY_SEC}
RestartPreventExitStatus=78
TimeoutStartSec=120
WatchdogSec={WATCHDOG_SEC}
"""
    )


def render_failsafe_unit() -> str:
    return (
        _MANAGED_HEADER
        + f"""[Unit]
Description=StremioGuard fail-safe: lock out and stop services after watchdog failure
StartLimitIntervalSec={START_LIMIT_INTERVAL_SEC}
StartLimitBurst=10

[Service]
Type=oneshot
WorkingDirectory={_unit_value(ROOT_DIR)}
Environment=STREMIOGUARD_MANAGED=1 PYTHONUNBUFFERED=1
EnvironmentFile=-{_unit_value(watchdog_env_file())}
ExecStart={_exec_arg(_python())} -m stremioguard.orchestrator failsafe
Restart=on-failure
RestartSec=30
"""
    )


def render_boot_unit() -> str:
    uv = shutil.which("uv")
    path_dirs = [str(Path(uv).parent)] if uv else []
    path_dirs += ["/usr/local/bin", "/usr/bin", "/bin"]
    return (
        _MANAGED_HEADER
        + f"""# Opt-in: `systemctl --user enable {BOOT_UNIT}` starts the stack at boot.
[Unit]
Description=Start the StremioGuard stack
Wants=docker.service
After=docker.service
StartLimitIntervalSec={START_LIMIT_INTERVAL_SEC}
StartLimitBurst=5

[Service]
Type=oneshot
WorkingDirectory={_unit_value(ROOT_DIR)}
Environment={_quoted("PATH=" + ":".join(dict.fromkeys(path_dirs)))}
ExecStart={_exec_arg(ROOT_DIR / "stremio")} start
TimeoutStartSec=1800
Restart=on-failure
RestartSec=60
RestartPreventExitStatus=78

[Install]
WantedBy=default.target
"""
    )


def install_units() -> bool:
    """Write the unit files and prove the manager loaded them from here.

    Returns whether any file changed.
    """
    directory = unit_dir()
    rendered = {
        WATCHDOG_UNIT: render_watchdog_unit(),
        FAILSAFE_UNIT: render_failsafe_unit(),
        BOOT_UNIT: render_boot_unit(),
    }
    changed = False
    for name, content in rendered.items():
        path = directory / name
        try:
            current = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            current = None
        if current != content:
            atomic_write_text(path, content, mode=0o644)
            changed = True

    if (directory / LEGACY_UNIT).exists():
        logger.warning(
            f"{directory / LEGACY_UNIT} is superseded by {WATCHDOG_UNIT}. Remove it: "
            f"`systemctl --user disable --now {LEGACY_UNIT} && rm {directory / LEGACY_UNIT}`."
        )

    if changed:
        result = _systemctl("daemon-reload")
        if result.returncode != 0:
            fail(f"systemctl --user daemon-reload failed: {_systemctl_detail(result)}")

    for name in (WATCHDOG_UNIT, FAILSAFE_UNIT):
        result = _systemctl("show", name, "--property=LoadState,FragmentPath")
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if values.get("LoadState") != "loaded" or values.get("FragmentPath") != str(
            directory / name
        ):
            fail(
                f"systemd did not load {name} from {directory / name} "
                f"(LoadState={values.get('LoadState', '?')}, "
                f"FragmentPath={values.get('FragmentPath') or '?'}). "
                "Check `systemctl --user cat` for an overriding unit."
            )
    return changed


def _env_line(key: str, value: str) -> str:
    if "\n" in value:
        raise ValueError(f"{key} contains a newline; refusing to forward it to the watchdog.")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{key}="{escaped}"\n'


def _settings_view(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.split("=", 1)[0] not in _PER_RUN_KEYS]


def write_watchdog_env(env: Mapping[str, str]) -> bool:
    """Persist the forwarded settings for the unit's EnvironmentFile=.

    Returns whether a setting other than the per-run log identity changed.
    """
    path = watchdog_env_file()
    content = "".join(_env_line(key, env[key]) for key in FORWARDED_ENV_KEYS if env.get(key))
    try:
        previous = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        previous = None
    if previous != content:
        atomic_write_text(path, content, mode=0o600)
    return previous is None or _settings_view(previous) != _settings_view(content)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_exit(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _pid_alive(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return True


def _is_legacy_watchdog(pid: int) -> bool:
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
        cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
    except (OSError, UnicodeDecodeError):
        return False
    return (
        "stremioguard.orchestrator" in cmdline
        and "watchdog" in cmdline
        and cwd == ROOT_DIR.resolve()
    )


def retire_legacy_watchdog() -> None:
    """Stop a watchdog started by a pre-systemd CLI, recorded in watchdog.pid.

    Left running it would fight the supervised one over the same containers,
    and `./stremio stop` would no longer reach it.
    """
    pid_file = STATE_DIR / "watchdog.pid"
    try:
        raw = pid_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return
    pid = int(raw) if raw.isdigit() else 0
    if pid and _pid_alive(pid) and _is_legacy_watchdog(pid):
        logger.warning(f"Stopping the pre-systemd watchdog (PID {pid}); systemd supervises it now.")
        os.kill(pid, signal.SIGTERM)
        if not _wait_for_exit(pid, 5):
            os.kill(pid, signal.SIGKILL)
            if not _wait_for_exit(pid, 3):
                fail(f"The pre-systemd watchdog (PID {pid}) did not exit; stop it manually.")
    pid_file.unlink(missing_ok=True)


def prepare_supervision() -> bool:
    """Everything that must hold before protected services may start.

    Returns whether the unit files changed.
    """
    require_user_systemd()
    retire_legacy_watchdog()
    return install_units()


def start_watchdog(context: RunContext, *, units_changed: bool) -> None:
    """Start (or restart, if its definition changed) the supervised watchdog.

    Type=notify makes `systemctl start` wait until the watchdog reports
    READY=1; the state query afterwards is the proof it is running.
    """
    settings_changed = write_watchdog_env(context.env())
    before = unit_state(WATCHDOG_UNIT)
    # Clears a start-limit hit. Only reached after `run_guard("start")`
    # passed the lockout check, so this never bypasses a fail-safe lockout.
    _systemctl("reset-failed", WATCHDOG_UNIT, FAILSAFE_UNIT)
    if before.running and not (units_changed or settings_changed):
        logger.info(f"Watchdog already running under systemd (PID {before.main_pid}).")
        return
    verb = "restart" if before.running else "start"
    if verb == "restart":
        logger.info("Watchdog settings changed; restarting it to apply them.")
    result = _systemctl(verb, WATCHDOG_UNIT)
    after = unit_state(WATCHDOG_UNIT)
    if result.returncode != 0 or not after.running:
        fail(
            f"The watchdog did not start ({_systemctl_detail(result)}; state "
            f"{after.active_state}/{after.sub_state}). systemd retries it with backoff and "
            "stops protected services if it keeps failing. Inspect: "
            f"journalctl --user -u {WATCHDOG_UNIT} -n 50"
        )
    logger.success(f"Watchdog running under systemd as {WATCHDOG_UNIT} (PID {after.main_pid}).")


def stop_watchdog() -> bool:
    """Stop the supervised watchdog; return whether it is proven stopped."""
    retire_legacy_watchdog()
    if not shutil.which("systemctl"):
        return True
    result = _systemctl("stop", WATCHDOG_UNIT)
    try:
        state = unit_state(WATCHDOG_UNIT)
    except RuntimeError as error:
        logger.error(str(error))
        return False
    if not state.stopped:
        logger.error(
            f"{WATCHDOG_UNIT} is still {state.active_state}/{state.sub_state} after stop "
            f"({_systemctl_detail(result)})."
        )
        return False
    return True


def status_lines() -> list[str]:
    try:
        watchdog = unit_state(WATCHDOG_UNIT)
        boot = unit_state(BOOT_UNIT)
    except (RuntimeError, OSError) as error:
        return [f"unavailable: {error}"]
    if watchdog.load_state == "not-found":
        return ["not installed (`./stremio start` installs it)"]
    pid = f", PID {watchdog.main_pid}" if watchdog.main_pid else ""
    return [
        f"{WATCHDOG_UNIT}: {watchdog.active_state}/{watchdog.sub_state}{pid}, "
        f"restarts={watchdog.restarts}, last result={watchdog.result}",
        f"start at boot: {boot.unit_file_state or 'unknown'}"
        + ("" if boot.unit_file_state == "enabled" else f" (systemctl --user enable {BOOT_UNIT})"),
    ]
