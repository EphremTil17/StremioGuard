"""NordVPN credential extraction and guided setup."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import typer
from loguru import logger

from stremioguard.env import (
    fail,
    write_env_setting,
    write_openvpn_credentials,
    write_wireguard_key,
)


def vpn_setup_checklist(provider: str = "general") -> str:
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


def missing_nordvpn_dependencies() -> list[str]:
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


def preflight_nordvpn_setup() -> None:
    missing = missing_nordvpn_dependencies()
    if missing:
        details = "\n".join(missing)
        fail(
            f"{vpn_setup_checklist('nordvpn')}\n\n"
            "NordVPN first-run prerequisites are missing:\n"
            f"{details}\n"
            "Install the missing dependencies first, then re-run `./stremio init`."
        )

    result = subprocess.run(["nordvpn", "account"], capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or "(no output)"
        fail(
            f"{vpn_setup_checklist('nordvpn')}\n\n"
            "NordVPN CLI is installed, but it is not ready yet.\n"
            "Run `nordvpn login`, finish the OAuth flow, and then re-run `./stremio init`.\n"
            f"  output: {detail}"
        )


def _run_nordvpn_streaming(cmd: list[str], *, check: bool = True) -> int:
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
    preflight_nordvpn_setup()
    logger.info("Setting NordVPN technology to nordlynx (WireGuard).")
    _run_nordvpn_streaming(["nordvpn", "set", "technology", "nordlynx"])
    logger.info("Connecting to NordVPN. This temporarily routes your host through the VPN.")
    _run_nordvpn_streaming(["nordvpn", "connect"])

    try:
        logger.info("Reading WireGuard private key (sudo will prompt).")
        result = subprocess.run(
            ["sudo", "wg", "show", "nordlynx", "private-key"], capture_output=True, text=True
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


def _prompt_nordvpn_key_setup_mode() -> str:
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


def get_nordvpn_wireguard_key() -> str:
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
    if not typer.confirm("Continue with host-side NordVPN key extraction?", default=False):
        fail(
            "Automatic extraction cancelled. Re-run `./stremio init` and choose the "
            "recommended manual key entry path instead."
        )

    logger.info("Checking NordVPN setup prerequisites before continuing.")
    preflight_nordvpn_setup()
    return _extract_wireguard_key()


def configure_nordvpn(env_path: Path) -> None:
    protocol = _prompt_nordvpn_protocol()
    write_env_setting(env_path, "VPN_TYPE", protocol)

    if protocol == "openvpn":
        username, password = _prompt_openvpn_credentials()
        write_openvpn_credentials(env_path, username, password)
        write_env_setting(env_path, "WIREGUARD_PRIVATE_KEY", "")
        logger.success("Stored NordVPN OpenVPN service credentials in .env.")
        return

    key = get_nordvpn_wireguard_key()
    write_wireguard_key(env_path, key)
    write_env_setting(env_path, "OPENVPN_USER", "")
    write_env_setting(env_path, "OPENVPN_PASSWORD", "")
    logger.success(f"Wrote WireGuard key into {env_path.name}.")
