#!/usr/bin/env python3
"""Public Stremio orchestration CLI."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import NoReturn

import typer
from loguru import logger

APP = typer.Typer(
    help="Start and guard Stremio behind the gluetun VPN container.",
    no_args_is_help=False,
)

ROOT_DIR = Path(__file__).resolve().parent
GUARD = ROOT_DIR / "bin" / "stremio-vpn"
LOG_DIR = ROOT_DIR / "logs"
STATE_DIR = ROOT_DIR / ".stremio"
PID_FILE = STATE_DIR / "watchdog.pid"
UV_CACHE = ROOT_DIR / ".uv-cache"
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE = ROOT_DIR / ".env.example"
WIREGUARD_KEY_PLACEHOLDER = "<paste-key-here>"
OPENVPN_USER_PLACEHOLDER = "<paste-service-username-here>"
OPENVPN_PASSWORD_PLACEHOLDER = "<paste-service-password-here>"
WIREGUARD_KEY_LINE = re.compile(r"^WIREGUARD_PRIVATE_KEY=.*$", re.MULTILINE)
ENV_LINE_TEMPLATE = r"^{key}=.*$"

logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
    "<cyan>stremio</cyan> | <level>{message}</level>",
    level="INFO",
    colorize=sys.stdout.isatty(),
)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    log_file: Path

    @classmethod
    def create(cls) -> RunContext:
        run_id = os.environ.get("STREMIO_RUN_ID") or datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = Path(os.environ.get("STREMIO_LOG_FILE", LOG_DIR / f"stremio-{run_id}.log"))
        return cls(run_id=run_id, log_file=log_file)

    def env(self, *, background: bool = False, file_logging: bool = True) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("INSTALL_MISSING_DEPS", "1")
        env["STREMIO_RUN_ID"] = self.run_id
        if file_logging:
            env["STREMIO_LOG_FILE"] = str(self.log_file)
            env["STREMIO_LOG_SESSION"] = "1"
        else:
            env.pop("STREMIO_LOG_FILE", None)
            env["STREMIO_LOG_SESSION"] = "0"
        if background:
            env["STREMIO_BACKGROUND"] = "1"
        return env


def fail(message: str) -> NoReturn:
    logger.error(message)
    raise typer.Exit(1)


def require_uv() -> None:
    if shutil.which("uv"):
        return
    fail(
        "uv is required to run this project. Run ./stremio, which bootstraps uv "
        "automatically, or install it manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def uv_command(*args: str) -> list[str]:
    return ["uv", "--cache-dir", str(UV_CACHE), "run", *args]


def guard_command(*args: str) -> list[str]:
    return uv_command("python", str(GUARD), *args)


def run_guard(
    *args: str,
    context: RunContext | None = None,
    file_logging: bool = True,
) -> None:
    require_uv()
    context = context or RunContext.create()
    if file_logging:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(guard_command(*args), check=True, env=context.env(file_logging=file_logging))
    except subprocess.CalledProcessError as error:
        raise typer.Exit(error.returncode or 1) from None


WATCHDOG_CMDLINE_MARKER = "stremio-vpn"


def _pid_is_our_watchdog(pid: int) -> bool:
    """Confirm the PID corresponds to our watchdog and not a recycled unrelated process."""
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        cmdline = cmdline_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return WATCHDOG_CMDLINE_MARKER in cmdline and "watchdog" in cmdline


def watchdog_pid() -> int | None:
    if not PID_FILE.exists():
        return None

    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except ValueError:
        return None

    try:
        os.kill(pid, 0)
    except OSError:
        return None

    if not _pid_is_our_watchdog(pid):
        return None
    return pid


def start_watchdog(context: RunContext) -> None:
    require_uv()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    pid = watchdog_pid()
    if pid:
        logger.info(f"Watchdog already running with PID {pid}.")
        return

    logger.info(f"Starting background watchdog. Logs: {context.log_file}")
    with context.log_file.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            guard_command("watchdog"),
            cwd=ROOT_DIR,
            env=context.env(background=True),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")
    logger.success(f"Watchdog started with PID {process.pid}.")


def _wait_for_exit(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, 0)
    except OSError:
        return True
    return False


def stop_watchdog() -> None:
    pid = watchdog_pid()
    if not pid:
        PID_FILE.unlink(missing_ok=True)
        return

    logger.info(f"Stopping background watchdog PID {pid}.")
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        PID_FILE.unlink(missing_ok=True)
        return

    if _wait_for_exit(pid, 5):
        PID_FILE.unlink(missing_ok=True)
        return

    logger.warning(f"Watchdog PID {pid} did not exit after SIGTERM; sending SIGKILL.")
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        PID_FILE.unlink(missing_ok=True)
        return

    if not _wait_for_exit(pid, 3):
        logger.error(f"Watchdog PID {pid} did not exit after SIGKILL; leaving PID file in place.")
        return

    PID_FILE.unlink(missing_ok=True)


def latest_log() -> Path | None:
    if not LOG_DIR.exists():
        return None

    logs = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


def env_needs_init(env_path: Path = ENV_FILE) -> bool:
    """Return True when .env is missing or the chosen VPN auth fields are unpopulated."""
    if not env_path.exists():
        return True
    provider = (_read_env_provider(env_path) or "nordvpn").lower()
    vpn_type = (env_file_value(env_path, "VPN_TYPE") or "wireguard").strip().lower()

    if provider != "nordvpn":
        if vpn_type == "openvpn":
            user = env_file_value(env_path, "OPENVPN_USER")
            password = env_file_value(env_path, "OPENVPN_PASSWORD")
            return not user or not password

        key = env_file_value(env_path, "WIREGUARD_PRIVATE_KEY")
        return key in {None, "", WIREGUARD_KEY_PLACEHOLDER}

    if vpn_type == "openvpn":
        user = env_file_value(env_path, "OPENVPN_USER")
        password = env_file_value(env_path, "OPENVPN_PASSWORD")
        return user in {None, "", OPENVPN_USER_PLACEHOLDER} or password in {
            None,
            "",
            OPENVPN_PASSWORD_PLACEHOLDER,
        }

    key = env_file_value(env_path, "WIREGUARD_PRIVATE_KEY")
    return key in {None, "", WIREGUARD_KEY_PLACEHOLDER}


def write_wireguard_key(env_path: Path, key: str) -> None:
    """Replace WIREGUARD_PRIVATE_KEY=... in env_path with the given key."""
    write_env_setting(env_path, "WIREGUARD_PRIVATE_KEY", key)


def write_openvpn_credentials(env_path: Path, username: str, password: str) -> None:
    """Replace OPENVPN_USER/PASSWORD in env_path with the given values."""
    write_env_setting(env_path, "OPENVPN_USER", username)
    write_env_setting(env_path, "OPENVPN_PASSWORD", password)


def write_env_setting(env_path: Path, key: str, value: str) -> None:
    """Replace KEY=... in env_path with the given value, or append it if missing."""
    content = env_path.read_text(encoding="utf-8")
    pattern = re.compile(ENV_LINE_TEMPLATE.format(key=re.escape(key)), re.MULTILINE)
    new_line = f"{key}={value}"
    if pattern.search(content):
        content = pattern.sub(new_line, content, count=1)
    else:
        content = content.rstrip("\n") + f"\n{new_line}\n"
    env_path.write_text(content, encoding="utf-8")


def env_file_value(env_path: Path, key: str) -> str | None:
    if not env_path.exists():
        return None
    pattern = re.compile(ENV_LINE_TEMPLATE.format(key=re.escape(key)), re.MULTILINE)
    match = pattern.search(env_path.read_text(encoding="utf-8"))
    if not match:
        return None
    return match.group(0).split("=", 1)[1].strip()


def env_flag_enabled(key: str, default: bool, *, env_path: Path = ENV_FILE) -> bool:
    value = env_file_value(env_path, key)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def _prompt_yes_no(message: str, *, default: bool) -> bool:
    return typer.confirm(message, default=default)


def _prompt_nordvpn_key_setup_mode() -> str:
    """Ask how to obtain the NordVPN WireGuard private key."""
    typer.echo("")
    typer.echo("NordVPN WireGuard key setup:")
    typer.echo("  1) Paste an existing WireGuard private key  (recommended)")
    typer.echo("  2) Extract automatically via host NordVPN CLI")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    if choice in {"2", "auto", "extract", "cli"}:
        return "auto"
    return "manual"


def _prompt_nordvpn_protocol() -> str:
    typer.echo("")
    typer.echo("NordVPN protocol:")
    typer.echo("  1) WireGuard / NordLynx  (recommended)")
    typer.echo("  2) OpenVPN               (manual service credentials)")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    if choice in {"2", "openvpn"}:
        return "openvpn"
    return "wireguard"


def _prompt_manual_wireguard_key() -> str:
    logger.info("Recommended path selected: manual WireGuard key entry.")
    typer.echo("")
    typer.echo("Paste an existing NordVPN WireGuard private key below.")
    typer.echo("If you do not already have one, cancel and choose the host-side extraction")
    typer.echo("path instead, or switch to OpenVPN and use NordVPN service credentials.")
    return typer.prompt("WireGuard private key", hide_input=True).strip()


def _prompt_openvpn_credentials() -> tuple[str, str]:
    logger.info("OpenVPN selected: enter your NordVPN service credentials.")
    typer.echo("")
    typer.echo("Retrieve the credentials from Nord Account:")
    typer.echo("  1. Log in to your Nord Account.")
    typer.echo("  2. Open NordVPN -> Set up NordVPN manually.")
    typer.echo("  3. Open the Service credentials section.")
    typer.echo("  4. Paste the username and password below.")
    username = typer.prompt("OpenVPN service username").strip()
    password = typer.prompt("OpenVPN service password", hide_input=True).strip()
    if not username or not password:
        fail("OpenVPN service credentials were not provided; aborting.")
    return username, password


def _configure_external_access(env_path: Path) -> None:
    logger.info("Network access:")
    if _prompt_yes_no("Will clients use a public HTTPS domain to reach Stremio?", default=False):
        external_url = typer.prompt(
            "Public HTTPS URL",
            default="https://stremio.example.com",
        ).strip()
        external_url = external_url.rstrip("/")
        write_env_setting(env_path, "EXTERNAL_BASE_URL", external_url)
        logger.info(f"Using public client origin: {external_url}")
        return

    write_env_setting(env_path, "EXTERNAL_BASE_URL", "")
    logger.info(
        "No public domain configured. Stremio will use the same host and port clients "
        "connect to, such as a local IP address and port."
    )


def _configure_optional_stremio_settings(env_path: Path) -> None:
    logger.info("Optional Stremio tweaks:")
    apply_patches = _prompt_yes_no(
        "Enable the Stremio compatibility patch bundle?",
        default=True,
    )
    write_env_setting(env_path, "STREMIO_APPLY_PATCHES", "1" if apply_patches else "0")
    if not apply_patches:
        logger.warning(
            "Compatibility patch bundle disabled. This restores upstream behavior and may "
            "break HTTPS reverse-proxy redirects, internal self-probe rewriting, and the "
            "casting endpoint stub."
        )

    skip_hw_probe = _prompt_yes_no(
        "Skip repeated hardware probe checks to keep reconnect logs quieter?",
        default=True,
    )
    write_env_setting(env_path, "STREMIO_SKIP_HW_PROBE", "1" if skip_hw_probe else "0")
    if skip_hw_probe:
        logger.info("Hardware probe skip enabled for quieter /device-info reconnect logs.")
    elif apply_patches:
        logger.warning(
            "Hardware probe skip disabled. Stremio may re-run qsv/nvenc/vaapi checks on "
            "reconnect and produce noisy logs."
        )
    else:
        logger.warning(
            "Hardware probe skip disabled and compatibility patches are off, so upstream "
            "hardware probing behavior will be used in full."
        )


def _warn_for_optional_stremio_settings() -> None:
    patches_enabled = env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=ENV_FILE)
    skip_hw_probe_enabled = env_flag_enabled("STREMIO_SKIP_HW_PROBE", True, env_path=ENV_FILE)

    if not patches_enabled:
        logger.warning(
            "STREMIO_APPLY_PATCHES=0. Running the upstream Stremio image behavior without "
            "the local compatibility fixes. Use `./stremio restart` after changing this "
            "setting so Docker rebuilds the image."
        )
    elif not skip_hw_probe_enabled:
        logger.warning(
            "STREMIO_SKIP_HW_PROBE=0. /device-info may re-run hardware probe checks and "
            "add noisy reconnect logs."
        )


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _vpn_setup_checklist(provider: str = "general") -> str:
    checklist = [
        "- Docker with the Compose plugin installed and working.",
        "- /dev/net/tun available on the Linux host or WSL2 guest.",
        "- A VPN provider account and the client or credentials needed for your chosen setup.",
    ]
    if provider == "nordvpn":
        checklist.extend(
            [
                "- nordvpn CLI installed and available on PATH.",
                "- nordvpn logged in already (`nordvpn login`).",
                "- wireguard-tools installed so the `wg` command is available.",
            ]
        )
    return "Required for VPN setup on Linux:\n" + "\n".join(checklist)


def _missing_nordvpn_dependencies() -> list[str]:
    missing: list[str] = []
    if not shutil.which("nordvpn"):
        missing.append(
            "- nordvpn CLI: install it from https://nordvpn.com/download/linux/ "
            "and make sure `nordvpn` is on PATH."
        )
    if not shutil.which("wg"):
        missing.append(
            "- wireguard-tools (`wg`): install it with `sudo apt install wireguard-tools` "
            "(or your distro's equivalent)."
        )
    return missing


def _preflight_nordvpn_setup() -> None:
    missing = _missing_nordvpn_dependencies()
    if missing:
        details = "\n".join(missing)
        fail(
            f"{_vpn_setup_checklist('nordvpn')}\n\n"
            "NordVPN first-run prerequisites are missing:\n"
            f"{details}\n"
            "Install the missing dependencies first, then re-run `./stremio init`."
        )

    result = subprocess.run(["nordvpn", "account"], capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or "(no output)"
        fail(
            f"{_vpn_setup_checklist('nordvpn')}\n\n"
            "NordVPN CLI is installed, but it is not ready yet.\n"
            "Run `nordvpn login`, finish the OAuth flow, and then re-run `./stremio init`.\n"
            f"  output: {detail}"
        )


def _run_nordvpn_streaming(cmd: list[str], *, check: bool = True) -> int:
    """Run a nordvpn command, streaming each output line through loguru."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.rstrip()
        if not line:
            continue
        level = "WARNING" if "already set" in line.lower() else "INFO"
        logger.log(level, f"nordvpn: {line}")
    rc = proc.wait()
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)
    return rc


def _extract_wireguard_key() -> str:
    """Drive nordvpn nordlynx connect, capture the WG key, then disconnect."""
    _preflight_nordvpn_setup()

    logger.info("Setting NordVPN technology to nordlynx (WireGuard).")
    _run_nordvpn_streaming(["nordvpn", "set", "technology", "nordlynx"])

    logger.info("Connecting to NordVPN. This temporarily routes your host through the VPN.")
    _run_nordvpn_streaming(["nordvpn", "connect"])

    try:
        logger.info("Reading WireGuard private key (sudo will prompt).")
        result = subprocess.run(
            ["sudo", "wg", "show", "nordlynx", "private-key"],
            capture_output=True,
            text=True,
        )
        key = (result.stdout or "").strip()
        if result.returncode != 0 or not key:
            logger.warning("Auto-extraction failed. Run this in another terminal and paste below:")
            logger.warning("    sudo wg show nordlynx private-key")
            key = typer.prompt("WireGuard private key").strip()
    finally:
        logger.info("Disconnecting NordVPN.")
        _run_nordvpn_streaming(["nordvpn", "disconnect"], check=False)

    if not key:
        fail("No WireGuard key captured; aborting.")
    return key


def _get_nordvpn_wireguard_key() -> str:
    mode = _prompt_nordvpn_key_setup_mode()
    if mode == "manual":
        key = _prompt_manual_wireguard_key()
        if not key:
            fail("No WireGuard key entered; aborting.")
        return key

    logger.warning(
        "Automatic extraction temporarily connects this Linux host to NordVPN and may "
        "interrupt SSH, LAN access, or other active connections."
    )
    if not _prompt_yes_no("Continue with host-side NordVPN key extraction?", default=False):
        fail(
            "Automatic extraction cancelled. Re-run `./stremio init` and choose the "
            "recommended manual key entry path instead."
        )

    logger.info("Checking NordVPN setup prerequisites before continuing.")
    _preflight_nordvpn_setup()
    return _extract_wireguard_key()


def _configure_nordvpn(env_path: Path) -> None:
    protocol = _prompt_nordvpn_protocol()
    write_env_setting(env_path, "VPN_TYPE", protocol)

    if protocol == "openvpn":
        username, password = _prompt_openvpn_credentials()
        write_openvpn_credentials(env_path, username, password)
        write_env_setting(env_path, "WIREGUARD_PRIVATE_KEY", "")
        logger.success("Stored NordVPN OpenVPN service credentials in .env.")
        return

    key = _get_nordvpn_wireguard_key()
    write_wireguard_key(env_path, key)
    write_env_setting(env_path, "OPENVPN_USER", "")
    write_env_setting(env_path, "OPENVPN_PASSWORD", "")
    logger.success(f"Wrote WireGuard key into {ENV_FILE.name}.")


@APP.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start Stremio when no command is provided."""
    if ctx.invoked_subcommand is None:
        if env_needs_init():
            if is_interactive():
                logger.info(".env not configured; running first-time setup.")
                init()
                return
            fail(".env missing or WIREGUARD_PRIVATE_KEY unpopulated. Run `./stremio init`.")
        start()


def _prompt_provider(default: str | None = None) -> str:
    """Ask which VPN provider to use. Returns 'nordvpn' or 'other'."""
    normalized_default = (default or "nordvpn").strip().lower()
    default_choice = "2" if normalized_default == "other" else "1"
    typer.echo("")
    typer.echo("VPN provider:")
    typer.echo("  1) NordVPN  (guided WireGuard or OpenVPN setup)")
    typer.echo("  2) Other    (manual setup — you edit .env yourself)")
    choice = typer.prompt("Choose [1-2]", default=default_choice).strip().lower()
    if choice in {"1", "nordvpn"}:
        return "nordvpn"
    return "other"


def _read_env_provider(env_path: Path) -> str:
    match = re.search(
        r"^VPN_SERVICE_PROVIDER=(.*)$", env_path.read_text(encoding="utf-8"), re.MULTILINE
    )
    return match.group(1).strip().lower() if match else ""


def _print_manual_setup_pointer() -> None:
    logger.info("Manual setup selected. Next steps:")
    typer.echo("  1. Open .env in your editor.")
    typer.echo("  2. Set VPN_SERVICE_PROVIDER to your gluetun-supported provider")
    typer.echo("     (mullvad, protonvpn, surfshark, expressvpn, etc.).")
    typer.echo("  3. Set VPN_TYPE (wireguard or openvpn) and the relevant credentials.")
    typer.echo("  4. Reference: https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers")
    typer.echo("  5. Run `./stremio start` once .env is populated.")


@APP.command()
def init() -> None:
    """First-time setup: create .env, configure VPN credentials, then start."""
    if not is_interactive():
        fail("`init` needs an interactive terminal (stdin/stdout must be a TTY).")

    if not ENV_FILE.exists():
        if not ENV_EXAMPLE.exists():
            fail(f"{ENV_EXAMPLE.name} not found; cannot bootstrap .env.")
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        logger.success(f"Created {ENV_FILE.name} from {ENV_EXAMPLE.name}.")
    else:
        logger.info(f"{ENV_FILE.name} already exists.")

    if not env_needs_init(ENV_FILE):
        logger.info("VPN credentials already set; skipping guided setup.")
        logger.info("Setup complete. Starting Stremio.")
        start()
        return

    untouched_template = ENV_EXAMPLE.exists() and ENV_FILE.read_bytes() == ENV_EXAMPLE.read_bytes()
    if untouched_template:
        _configure_external_access(ENV_FILE)
        _configure_optional_stremio_settings(ENV_FILE)
    provider = _prompt_provider(_read_env_provider(ENV_FILE))
    if provider == "nordvpn":
        logger.info("NordVPN credentials are unpopulated. Walking through protocol setup.")
        _configure_nordvpn(ENV_FILE)
        logger.info("Setup complete. Starting Stremio.")
        start()
        return

    _print_manual_setup_pointer()


@APP.command()
def start() -> None:
    """Initialize if needed, start Stremio, and launch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    run_guard("start", context=context)
    start_watchdog(context)


@APP.command()
def restart() -> None:
    """Reset/build/start Stremio and relaunch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    stop_watchdog()
    run_guard("reset", context=context)
    start_watchdog(context)


@APP.command()
def stop() -> None:
    """Stop the watchdog and Stremio."""
    stop_watchdog()
    run_guard("stop", file_logging=False)


@APP.command()
def status() -> None:
    """Show VPN, public IP, and container status."""
    run_guard("status", file_logging=False)


@APP.command()
def logs(lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show.")) -> None:
    """Tail the latest run log."""
    log_file = latest_log()
    if not log_file:
        fail(f"No run logs found in {LOG_DIR}.")

    logger.info(f"Tailing {log_file}")
    subprocess.run(["tail", "-n", str(lines), "-f", str(log_file)], check=False)


@APP.command("record-home-ip")
def record_home_ip() -> None:
    """Save current public IP as leak-detection baseline."""
    run_guard("record-home-ip", file_logging=False)


@APP.command()
def check() -> None:
    """Run Ruff, Pyright, and pytest through uv."""
    require_uv()
    subprocess.run(uv_command("ruff", "format", "--check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("ruff", "check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("pyright"), check=True, cwd=ROOT_DIR)
    subprocess.run(uv_command("pytest"), check=True, cwd=ROOT_DIR)


if __name__ == "__main__":
    APP()
