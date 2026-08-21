from __future__ import annotations

import shutil
import subprocess
import sys
from contextlib import suppress

import typer
from loguru import logger

from stremioguard.cli.context import (
    ENV_EXAMPLE,
    ENV_FILE,
    LOG_DIR,
    ROOT_DIR,
    RunContext,
    _comet_enabled,
    _comet_manager,
)
from stremioguard.cli.watchdog import (
    _latest_log,
    _require_uv,
    _start_watchdog,
    _stop_watchdog,
    _uv_command,
    run_guard,
)
from stremioguard.comet import prompt_comet_setup
from stremioguard.env import (
    env_flag_enabled,
    env_needs_init,
    fail,
    read_env_provider,
    write_env_setting,
)
from stremioguard.init import (
    configure_external_access,
    configure_optional_stremio_settings,
    configured_access_choice,
    configured_profile_choice,
    existing_setup_summary,
    print_manual_setup_pointer,
    prompt_provider,
)
from stremioguard.nordvpn import configure_nordvpn


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


def print_welcome_banner() -> None:
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


def init() -> None:
    """Create or edit `.env`; a valid existing setup can be resumed without re-entry."""
    if not is_interactive():
        fail("`init` needs an interactive terminal (stdin/stdout must be a TTY).")

    print_welcome_banner()

    existing_setup = ENV_FILE.exists()
    if not existing_setup:
        if not ENV_EXAMPLE.exists():
            fail(f"{ENV_EXAMPLE.name} not found; cannot bootstrap .env.")
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        logger.success(f"Created {ENV_FILE.name} from {ENV_EXAMPLE.name}.")
    else:
        logger.info(f"{ENV_FILE.name} already exists.")

    if existing_setup and not env_needs_init(ENV_FILE):
        typer.echo("")
        for line in existing_setup_summary(ENV_FILE):
            typer.echo(line)
        typer.echo("")
        if typer.confirm("Reuse this setup and restart without changing it?", default=True):
            logger.info("Reusing the existing .env configuration; no secrets were read or changed.")
            _pull_and_restart()
            return

    profile_choice = configured_profile_choice(ENV_FILE)
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
        profile_choice = typer.prompt("Choose [1-3]", default=profile_choice).strip()
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
    choice = (
        typer.prompt(
            "Choose [1-2]",
            default=configured_access_choice(ENV_FILE, comet_only=not stremio_enabled),
        )
        .strip()
        .lower()
    )
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
        from stremioguard.config import CometConfig

        prompt_comet_setup(CometConfig.from_env(ROOT_DIR), is_proxied=is_proxied)

    # 3. Configure inbound external access guidance last, using correct ports/gateway status:
    configure_external_access(ENV_FILE, is_proxied=is_proxied, comet_only=not stremio_enabled)

    logger.info("Pulling the latest VPN container image...")
    run_guard("pull", file_logging=False)

    previous_provider = read_env_provider(ENV_FILE)
    provider = prompt_provider(previous_provider)
    if provider == "nordvpn":
        keep_existing_vpn = (
            previous_provider == "nordvpn"
            and not env_needs_init(ENV_FILE)
            and typer.confirm("Keep the existing NordVPN protocol and credentials?", default=True)
        )
        if keep_existing_vpn:
            logger.info(
                "Keeping existing NordVPN credentials; they were not displayed or rewritten."
            )
        else:
            logger.info("Walking through NordVPN credential setup.")
            configure_nordvpn(ENV_FILE)
        logger.info("Setup complete. Restarting stack so Docker reloads the VPN configuration.")
        restart()
        return

    print_manual_setup_pointer()


def _pull_and_restart() -> None:
    """Retain init's pull-before-restart lifecycle for new and resumed setups."""
    logger.info("Pulling the latest VPN container image...")
    run_guard("pull", file_logging=False)
    logger.info("Setup complete. Restarting stack so Docker reloads the VPN configuration.")
    restart()


def start() -> None:
    """Initialize if needed, start active services, and launch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    run_guard("start", context=context)
    _start_watchdog(context)


def restart() -> None:
    """Reset/build/start active services and relaunch the watchdog."""
    _warn_for_optional_stremio_settings()
    context = RunContext.create()
    _stop_watchdog()
    run_guard("reset", context=context)
    _start_watchdog(context)


def stop() -> None:
    """Stop the watchdog and all active services."""
    _stop_watchdog()
    run_guard("stop", file_logging=False)


def status() -> None:
    """Show VPN, public IP, and container status."""
    run_guard("status", file_logging=False)
    if _comet_enabled():
        logger.info("--- Comet ---")
        _comet_manager().status()


def logs(lines: int = typer.Option(120, "--lines", "-n", help="Initial lines to show.")) -> None:
    """Tail the latest run log."""
    log_file = _latest_log()
    if not log_file:
        fail(f"No run logs found in {LOG_DIR}.")
    logger.info(f"Tailing {log_file}")
    subprocess.run(["tail", "-n", str(lines), "-f", str(log_file)], check=False)


def record_home_ip() -> None:
    """Save current public IP as leak-detection baseline."""
    run_guard("record-home-ip", file_logging=False)


def unlock() -> None:
    """Inspect and clear an active VPN lockout marker."""
    lockout_file = ROOT_DIR / ".stremio" / "vpn-lockout.json"
    if not lockout_file.exists():
        logger.info("No VPN lockout is active.")
        return

    import json

    try:
        data = json.loads(lockout_file.read_text(encoding="utf-8"))
    except Exception:
        data = {}

    timestamp = data.get("timestamp", "unknown")
    reason = data.get("reason", "unknown")
    remediation = data.get("remediation", "unknown")
    duration = data.get("outage_duration_seconds", "unknown")

    logger.warning("Active VPN Lockout Marker:")
    logger.warning(f"  Timestamp: {timestamp}")
    logger.warning(f"  Reason: {reason}")
    logger.warning(f"  Outage Duration: {duration}s")
    logger.warning(f"  Remediation: {remediation}")
    typer.echo("")

    confirm = typer.confirm("Do you want to clear the VPN lockout marker?", default=False)
    if not confirm:
        logger.info("Lockout marker retained.")
        return

    try:
        lockout_file.unlink()
        logger.success("VPN lockout marker cleared successfully. Stack services were not started.")
    except OSError as error:
        fail(f"Failed to clear lockout marker: {error}")


def check() -> None:
    """Run Ruff, Pyright, and pytest through uv."""
    _require_uv()
    subprocess.run(_uv_command("ruff", "format", "--check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("ruff", "check", "."), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pyright"), check=True, cwd=ROOT_DIR)
    subprocess.run(_uv_command("pytest"), check=True, cwd=ROOT_DIR)


def register(app: typer.Typer) -> None:
    app.command()(init)
    app.command()(start)
    app.command()(restart)
    app.command()(stop)
    app.command()(status)
    app.command()(logs)
    app.command("record-home-ip")(record_home_ip)
    app.command()(unlock)
    app.command()(check)
