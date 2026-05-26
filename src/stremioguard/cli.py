"""Public Stremio orchestration CLI."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import typer
from loguru import logger

from stremioguard.comet import CometManager, prompt_comet_setup
from stremioguard.comet_gateway import CometGatewayConfig, CometGatewayManager
from stremioguard.config import CometConfig, Config
from stremioguard.env import (
    env_file_value,
    env_flag_enabled,
    env_needs_init,
    fail,
    read_env_provider,
    write_env_setting,
)
from stremioguard.init import (
    configure_external_access,
    configure_optional_stremio_settings,
    print_manual_setup_pointer,
    prompt_provider,
)
from stremioguard.nordvpn import configure_nordvpn

APP = typer.Typer(
    help="Start and guard Stremio behind the gluetun VPN container.",
    no_args_is_help=False,
)
COMET_APP = typer.Typer(
    help="Manage the modular Comet playback-proxy subsystem.",
)
APP.add_typer(COMET_APP, name="comet")
COMET_TOKEN_APP = typer.Typer(
    help="Manage token-gated Comet addon access.",
)
COMET_APP.add_typer(COMET_TOKEN_APP, name="token")

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = ROOT_DIR / "logs"
STATE_DIR = ROOT_DIR / ".stremio"
PID_FILE = STATE_DIR / "watchdog.pid"
UV_CACHE = ROOT_DIR / ".uv-cache"
ENV_FILE = ROOT_DIR / ".env"
ENV_EXAMPLE = ROOT_DIR / ".env.example"
WATCHDOG_CMDLINE_MARKERS = ("stremioguard.orchestrator", "stremio-vpn")

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


def _require_uv() -> None:
    if shutil.which("uv"):
        return
    fail(
        "uv is required to run this project. Run ./stremio, which bootstraps uv "
        "automatically, or install it manually: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def _uv_command(*args: str) -> list[str]:
    return ["uv", "--cache-dir", str(UV_CACHE), "run", *args]


def _guard_command(*args: str) -> list[str]:
    return _uv_command("python", "-m", "stremioguard.orchestrator", *args)


def run_guard(*args: str, context: RunContext | None = None, file_logging: bool = True) -> None:
    _require_uv()
    context = context or RunContext.create()
    if file_logging:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            _guard_command(*args), check=True, env=context.env(file_logging=file_logging)
        )
    except subprocess.CalledProcessError as error:
        raise typer.Exit(error.returncode or 1) from None


def _pid_is_our_watchdog(pid: int) -> bool:
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        cmdline = cmdline_path.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return False
    return "watchdog" in cmdline and any(marker in cmdline for marker in WATCHDOG_CMDLINE_MARKERS)


def _watchdog_pids() -> list[int]:
    discovered: list[int] = []
    seen: set[int] = set()

    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            pid = None
        if pid is not None:
            try:
                os.kill(pid, 0)
            except OSError:
                pass
            else:
                if _pid_is_our_watchdog(pid):
                    discovered.append(pid)
                    seen.add(pid)

    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except (FileNotFoundError, PermissionError, OSError):
        return discovered

    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in seen:
            continue
        if _pid_is_our_watchdog(pid):
            discovered.append(pid)
            seen.add(pid)

    return sorted(discovered)


def _watchdog_pid() -> int | None:
    pids = _watchdog_pids()
    return pids[0] if pids else None


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


def _start_watchdog(context: RunContext) -> None:
    _require_uv()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    pids = _watchdog_pids()
    if pids:
        PID_FILE.write_text(f"{pids[0]}\n", encoding="utf-8")
        logger.info(f"Watchdog already running with PID {pids[0]}.")
        return

    logger.info(f"Starting background watchdog. Logs: {context.log_file}")
    with context.log_file.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            _guard_command("watchdog"),
            cwd=ROOT_DIR,
            env=context.env(background=True),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")
    logger.success(f"Watchdog started with PID {process.pid}.")


def _stop_watchdog() -> None:
    pids = _watchdog_pids()
    if not pids:
        PID_FILE.unlink(missing_ok=True)
        return

    logger.info(f"Stopping background watchdog PID(s) {', '.join(str(pid) for pid in pids)}.")
    remaining: list[int] = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue

    for pid in pids:
        if not _wait_for_exit(pid, 5):
            remaining.append(pid)

    if remaining:
        logger.warning(
            "Watchdog PID(s) "
            f"{', '.join(str(pid) for pid in remaining)} did not exit after SIGTERM; "
            "sending SIGKILL."
        )
        stuck: list[int] = []
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                continue
            if not _wait_for_exit(pid, 3):
                stuck.append(pid)
        if stuck:
            PID_FILE.write_text(f"{stuck[0]}\n", encoding="utf-8")
            logger.error(
                "Watchdog PID(s) "
                f"{', '.join(str(pid) for pid in stuck)} did not exit after SIGKILL; "
                "leaving PID file in place."
            )
            return

    PID_FILE.unlink(missing_ok=True)


def _latest_log() -> Path | None:
    if not LOG_DIR.exists():
        return None
    logs = sorted(LOG_DIR.glob("*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


def _comet_manager() -> CometManager:
    return CometManager(CometConfig.from_env(ROOT_DIR))


def _comet_enabled() -> bool:
    return CometConfig.from_env(ROOT_DIR).enabled


def _comet_gateway_manager() -> CometGatewayManager:
    return CometGatewayManager(CometGatewayConfig.from_env(ROOT_DIR))


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


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


@APP.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Start Stremio when no command is provided."""
    if ctx.invoked_subcommand is None:
        if env_needs_init(ENV_FILE):
            if is_interactive():
                logger.info(".env not configured; running first-time setup.")
                init()
                return
            fail(".env missing or WIREGUARD_PRIVATE_KEY unpopulated. Run `./stremio init`.")
        start()


def print_welcome_banner() -> None:
    from contextlib import suppress

    typer.echo("")
    typer.echo("")
    typer.echo("")

    logo_path = ROOT_DIR / "assets" / "logo.txt"
    logo_content = ""
    with suppress(Exception):
        if logo_path.exists():
            logo_content = logo_path.read_text(encoding="utf-8")

    if logo_content:
        for line in logo_content.splitlines():
            typer.echo(line)
    else:
        typer.echo("=== STREMIOGUARD ===")

    typer.echo("")
    typer.echo("Welcome to StremioGuard!")
    typer.echo("The secure, self-hosted orchestrator for Stremio Streaming Server & Comet Proxy.")
    typer.echo("StremioGuard routes all playback, streaming, and debrid network egress through")
    typer.echo(
        "a hardened VPN container (Gluetun) to prevent IP/DNS leaks and secure your privacy."
    )
    typer.echo("")
    typer.echo("GitHub Repository: https://github.com/EphremTil17/StremioGuard")
    typer.echo("─" * 90)
    typer.echo("")


@APP.command()
def init() -> None:
    """First-time setup: create .env, configure VPN credentials, then start."""
    if not is_interactive():
        fail("`init` needs an interactive terminal (stdin/stdout must be a TTY).")

    print_welcome_banner()

    if not ENV_FILE.exists():
        if not ENV_EXAMPLE.exists():
            fail(f"{ENV_EXAMPLE.name} not found; cannot bootstrap .env.")
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        logger.success(f"Created {ENV_FILE.name} from {ENV_EXAMPLE.name}.")
    else:
        logger.info(f"{ENV_FILE.name} already exists.")

    profile_choice = "1"
    while True:
        typer.echo("")
        typer.echo("1. Deployment Profile")
        typer.echo("Select the architectural components you want to enable:")
        typer.echo("  1) Unified: Run both Stremio and Comet  [default]")
        typer.echo(
            "     Deploys both Stremio Streaming Server and the Comet metadata/playback proxy."
        )
        typer.echo("  2) Comet-Only: Run only the Comet proxy & gateway")
        typer.echo(
            "     Deploys only Comet (with optional gateway). Best if hosting Stremio elsewhere."
        )
        typer.echo("  3) Stremio-Only: Run only the Stremio server")
        typer.echo("     Deploys only the Stremio server. Best if you do not use Comet add-ons.")
        profile_choice = typer.prompt("Choose [1-3]", default="1").strip()
        if profile_choice in {"1", "2", "3"}:
            break
        typer.echo("Invalid choice. Please select 1, 2, or 3.")

    stremio_enabled = True
    comet_enabled = True
    if profile_choice == "2":
        stremio_enabled = False
    elif profile_choice == "3":
        comet_enabled = False

    write_env_setting(ENV_FILE, "STREMIO_ENABLED", "1" if stremio_enabled else "0")
    write_env_setting(ENV_FILE, "COMET_ENABLED", "1" if comet_enabled else "0")

    # Prompt for proxy deployment choice upfront:
    typer.echo("")
    typer.echo("2. Inbound Network Access")
    if stremio_enabled:
        typer.echo("Determine how clients will reach Stremio:")
    else:
        typer.echo("Determine how clients will reach your Comet proxy:")
    typer.echo("  1) LAN + Tailscale only — no public domain  [default]")
    typer.echo("     Clients connect via local IP or Tailscale. No public ports/domains required.")
    typer.echo("  2) Reverse-proxied behind a domain (NPM, Caddy, Traefik, raw nginx)")
    typer.echo("     Clients connect through a public domain and reverse proxy.")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    is_proxied = choice in {"2", "proxy", "domain", "reverse-proxy"}

    if is_proxied:
        typer.echo("")
        typer.echo("WARNING: REVERSE PROXY REQUIREMENTS")
        typer.echo("To expose your service securely behind a domain:")
        typer.echo("  * Domain Name & DNS: Ensure your domain/subdomain is registered and pointing")
        typer.echo("    to your proxy's public IP (e.g. via Cloudflare).")
        typer.echo(
            "  * Custom Headers (CRITICAL): Your proxy must be configured to forward standard"
        )
        typer.echo(
            "    headers (Host, X-Forwarded-Proto) and clear client IP headers (X-Forwarded-For,"
        )
        typer.echo("    X-Real-IP) to protect debrid access privacy.")
        typer.echo("  * Port target recommendations and configuration templates can be found in:")
        typer.echo("    - docs/comet-gateway.md  (for Comet metadata/playback proxy)")
        typer.echo("    - docs/secure-access.md   (for Stremio Streaming Server)")
        typer.echo("")

    # 1. Configure Stremio optional settings first if enabled:
    if stremio_enabled:
        configure_optional_stremio_settings(ENV_FILE)

    # 2. Configure Comet settings next if enabled:
    if comet_enabled:
        prompt_comet_setup(CometConfig.from_env(ROOT_DIR), is_proxied=is_proxied)

    # 3. Configure inbound external access guidance last, using correct ports/gateway status:
    configure_external_access(ENV_FILE, is_proxied=is_proxied, comet_only=not stremio_enabled)

    logger.info("Pulling the latest VPN container image...")
    run_guard("pull", file_logging=False)

    provider = prompt_provider(read_env_provider(ENV_FILE))
    if provider == "nordvpn":
        logger.info("Walking through NordVPN credential setup.")
        configure_nordvpn(ENV_FILE)
        logger.info("Setup complete. Restarting stack so Docker reloads the updated VPN config.")
        restart()
        return

    print_manual_setup_pointer()


@APP.command()
def start() -> None:
    """Initialize if needed, start active services, and launch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    run_guard("start", context=context)
    _start_watchdog(context)


@APP.command()
def restart() -> None:
    """Reset/build/start active services and relaunch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    _stop_watchdog()
    run_guard("reset", context=context)
    _start_watchdog(context)


@APP.command()
def stop() -> None:
    """Stop the watchdog and all active services."""
    _stop_watchdog()
    run_guard("stop", file_logging=False)


@APP.command()
def status() -> None:
    """Show VPN, public IP, and container status."""
    run_guard("status", file_logging=False)
    if _comet_enabled():
        logger.info("--- Comet ---")
        _comet_manager().status()


@APP.command()
def logs(lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show.")) -> None:
    """Tail the latest run log."""
    log_file = _latest_log()
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
    _require_uv()
    subprocess.run(_uv_command("ruff", "format", "--check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("ruff", "check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pyright"), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pytest"), check=True, cwd=ROOT_DIR)


@COMET_APP.command("install")
def comet_install() -> None:
    """Clone/pin Comet and write local runtime configuration."""
    config = CometConfig.from_env(ROOT_DIR)
    if not is_interactive():
        fail("`./stremio comet install` needs an interactive terminal.")
    # Detect if reverse-proxied from existing env values:
    env_file = ROOT_DIR / ".env"
    ext_url = env_file_value(env_file, "EXTERNAL_BASE_URL")
    comet_gateway_url = env_file_value(env_file, "COMET_GATEWAY_PUBLIC_BASE_URL")
    comet_url = env_file_value(env_file, "COMET_PUBLIC_BASE_URL")

    if (
        (ext_url is not None and ext_url.strip() != "")
        or (comet_gateway_url is not None and comet_gateway_url.strip() != "")
        or (comet_url is not None and comet_url.strip() != "")
    ):
        is_proxied = True
    else:
        typer.echo("How will clients reach your Comet proxy?")
        typer.echo("  1) LAN + Tailscale only — no public domain  [default]")
        typer.echo("  2) Reverse-proxied behind a domain (NPM, Caddy, Traefik, raw nginx)")
        choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
        is_proxied = choice in {"2", "proxy", "domain", "reverse-proxy"}

    prompt_comet_setup(config, is_proxied=is_proxied)
    manager = CometManager(CometConfig.from_env(ROOT_DIR))
    manager.install()
    logger.success("Comet is installed and configured locally.")


@COMET_APP.command("update")
def comet_update() -> None:
    """Fetch Comet upstream refs and re-checkout the pinned commit."""
    manager = _comet_manager()
    manager.fetch_and_checkout_pinned()
    logger.success("Comet checkout refreshed to the pinned commit.")


@COMET_APP.command("start")
def comet_start() -> None:
    """Start the Comet stack managed by StremioGuard."""
    manager = _comet_manager()
    manager.start()


@COMET_APP.command("stop")
def comet_stop() -> None:
    """Stop the Comet stack."""
    manager = _comet_manager()
    manager.stop()


@COMET_APP.command("status")
def comet_status() -> None:
    """Show Comet repo and container status."""
    manager = _comet_manager()
    manager.status()


@COMET_APP.command("doctor")
def comet_doctor() -> None:
    """Validate the local Comet proxy deployment."""
    manager = _comet_manager()
    manager.doctor()


@COMET_APP.command("probe-playback")
def comet_probe_playback(
    url: str = typer.Option(..., "--url", help="Comet playback URL to probe."),
) -> None:
    """Probe a Comet playback URL to verify it stays on the proxy path."""
    manager = _comet_manager()
    result = manager.probe_playback(url, expect_proxy=manager.config.proxy_debrid_stream)
    logger.info(
        f"Playback probe classification={result.classification} "
        f"status={result.status_code} location={result.location or '-'} "
        f"content_type={result.content_type or '-'}"
    )


@COMET_APP.command("logs")
def comet_logs(
    lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show."),
) -> None:
    """Tail the Comet service logs."""
    manager = _comet_manager()
    manager.prepare_runtime()
    root_config = Config.from_env()
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(root_config.compose_file),
            "-f",
            str(root_config.compose_override_file),
            "logs",
            "-f",
            "--tail",
            str(lines),
            manager.config.service_name,
            manager.config.postgres_service_name,
        ],
        check=False,
    )


# ── Comet gateway token commands ───────────────────────────────────


def _refresh_comet_gateway_after_token_change(manager: CometGatewayManager) -> None:
    # The token gate itself is already enforced by the token CRUD call (which
    # rewrites tokens.map and nginx.conf). Regenerating the full Comet override
    # bundle here only refreshes the configure-page install URL, so a drifted
    # scraper/stream patch must never block a token operation like revoke.
    if _comet_enabled():
        comet_manager = _comet_manager()
        if comet_manager.repo_exists():
            try:
                comet_manager.write_stack_override_file()
            except RuntimeError as error:
                logger.warning(
                    "Token gate updated, but refreshing the Comet override bundle failed: "
                    f"{error} Configure-page install links may be stale until the next "
                    "`./stremio restart`."
                )
    if manager.container_running():
        manager.reload_nginx()
        logger.info("Comet gateway config reloaded.")
    else:
        logger.info("Comet gateway is not running; token changes apply on next start.")


@COMET_TOKEN_APP.command("add")
def comet_token_add(
    label: str = typer.Argument(..., help='Token label (e.g., "Shared Addon").'),
    make_default: bool = typer.Option(False, "--default", help="Make this the default token."),
) -> None:
    """Generate a new Comet gateway token."""
    manager = _comet_gateway_manager()
    token_id, token_value = manager.add_token(label, make_default=make_default)
    logger.success(f"Token created: {token_id} ({label})")
    typer.echo(f"  Addon base: {manager.addon_base_url(token_value)}")
    typer.echo(f"  Token: {token_value}")
    _refresh_comet_gateway_after_token_change(manager)


@COMET_TOKEN_APP.command("revoke")
def comet_token_revoke(
    token_id: str = typer.Argument(..., help="Token ID to revoke."),
) -> None:
    """Revoke a Comet gateway token."""
    manager = _comet_gateway_manager()
    try:
        label = manager.revoke_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Token {token_id} ({label}) revoked.")
    _refresh_comet_gateway_after_token_change(manager)


@COMET_TOKEN_APP.command("list")
def comet_token_list() -> None:
    """Show all active Comet gateway tokens."""
    manager = _comet_gateway_manager()
    tokens = manager.list_tokens()
    if not tokens:
        logger.info("No tokens configured.")
        return
    for token in tokens:
        default_marker = "default" if token["default"] else ""
        typer.echo(
            f"  {token['id']}  {token['label']:<20}  {default_marker:<8}  "
            f"{manager.addon_base_url(token['token'])}"
        )


@COMET_TOKEN_APP.command("rotate")
def comet_token_rotate(
    token_id: str = typer.Argument(..., help="Token ID to rotate."),
) -> None:
    """Rotate a Comet gateway token and keep the same label/default status."""
    manager = _comet_gateway_manager()
    try:
        new_id, new_token = manager.rotate_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Token rotated: {new_id}")
    typer.echo(f"  New addon base: {manager.addon_base_url(new_token)}")
    typer.echo(f"  New Token: {new_token}")
    _refresh_comet_gateway_after_token_change(manager)


@COMET_TOKEN_APP.command("use")
def comet_token_use(
    token_id: str = typer.Argument(..., help="Token ID to make the default."),
) -> None:
    """Select the default token used by Comet configure-page install links."""
    manager = _comet_gateway_manager()
    try:
        label = manager.use_token(token_id)
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    logger.success(f"Default Comet gateway token is now {token_id} ({label}).")
    _refresh_comet_gateway_after_token_change(manager)


@COMET_TOKEN_APP.command("url")
def comet_token_url(
    token_id: str = typer.Argument(..., help="Token ID to use in the rewritten URL."),
    manifest: str = typer.Option(..., "--manifest", help="Existing Comet manifest URL."),
) -> None:
    """Rewrite an existing Comet manifest URL to use a selected gateway token."""
    manager = _comet_gateway_manager()
    try:
        typer.echo(manager.rewrite_manifest_url(manifest, token_id))
    except KeyError:
        fail(f"Token ID {token_id!r} not found.")
    except ValueError as error:
        fail(str(error))


@COMET_APP.command("gateway-logs")
def comet_gateway_logs(
    lines: int = typer.Option(100, "--lines", "-n", help="Number of log lines to show first."),
) -> None:
    """Tail the Comet gateway logs."""
    manager = _comet_gateway_manager()
    root_config = Config.from_env()
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(root_config.compose_file),
            "-f",
            str(root_config.compose_override_file),
            "logs",
            "-f",
            "--tail",
            str(lines),
            manager.config.service_name,
        ],
        check=False,
    )


if __name__ == "__main__":
    APP()
