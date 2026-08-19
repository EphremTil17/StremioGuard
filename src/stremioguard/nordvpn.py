"""NordVPN credential configuration and guided setup."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from pathlib import Path

import typer
from loguru import logger

from stremioguard.env import (
    fail,
    validate_wireguard_private_key,
    write_env_settings,
)

NORDVPN_CREDENTIALS_API_URL = "https://api.nordvpn.com/v1/users/services/credentials"
API_TIMEOUT_SECONDS = 15


def fetch_nordvpn_credentials_from_token(token: str) -> tuple[str, str, str]:
    """Fetch WireGuard private key and OpenVPN service credentials from NordVPN API."""
    cleaned_token = token.strip()
    if not cleaned_token:
        fail("NordVPN access token cannot be empty.")

    auth_str = f"token:{cleaned_token}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {auth_b64}",
        "User-Agent": "StremioGuard",
        "Accept": "application/json",
    }
    request = urllib.request.Request(NORDVPN_CREDENTIALS_API_URL, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
            raw_body = response.read().decode("utf-8")
            data = json.loads(raw_body)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            fail(
                "NordVPN rejected the access token (Authentication Failed).\n"
                "Please verify your access token at "
                "https://my.nordaccount.com/dashboard/nordvpn/access-tokens/ and try again."
            )
        fail(f"NordVPN API request failed with HTTP {error.code}: {error.reason}")
    except urllib.error.URLError as error:
        fail(f"Failed to connect to NordVPN API: {error.reason}")
    except (json.JSONDecodeError, OSError) as error:
        fail(f"Failed to parse NordVPN API response: {error}")

    if not isinstance(data, dict):
        fail("Invalid response structure received from NordVPN API.")

    private_key = data.get("nordlynx_private_key")
    if not private_key or not isinstance(private_key, str):
        fail(
            "NordVPN API did not return a WireGuard (NordLynx) private key.\n"
            "Ensure that your NordVPN subscription is active."
        )

    username = str(data.get("username") or "")
    password = str(data.get("password") or "")

    try:
        valid_key = validate_wireguard_private_key(private_key)
    except ValueError as error:
        fail(f"NordVPN API returned an invalid WireGuard key format: {error}")

    return valid_key, username, password


def fetch_nordvpn_wireguard_key_from_token(token: str) -> str:
    """Fetch the permanent WireGuard private key from NordVPN API using an access token."""
    key, _, _ = fetch_nordvpn_credentials_from_token(token)
    return key


def _prompt_nordvpn_protocol() -> str:
    typer.echo("")
    typer.echo("NordVPN protocol:")
    typer.echo("  1) WireGuard / NordLynx  (recommended for speed & stability)")
    typer.echo("  2) OpenVPN               (manual service credentials)")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    if choice in {"2", "openvpn"}:
        return "openvpn"
    return "wireguard"


def _prompt_nordvpn_key_setup_mode() -> str:
    typer.echo("")
    typer.echo("NordVPN WireGuard setup method:")
    typer.echo("  1) Generate via NordVPN Access Token  (recommended — automatic & permanent)")
    typer.echo("  2) Paste an existing WireGuard private key")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    if choice in {"2", "manual", "paste"}:
        return "manual"
    return "token"


def _prompt_nordvpn_access_token() -> str:
    logger.info("Access Token setup selected: generating permanent WireGuard key.")
    typer.echo("")
    typer.echo("To get your NordVPN Access Token:")
    typer.echo("  1. Log in to https://my.nordaccount.com/dashboard/nordvpn/access-tokens/")
    typer.echo("  2. Click 'Generate new token' (select any expiration or non-expiring).")
    typer.echo("  3. Copy the token and paste it below.")
    typer.echo("")
    token = typer.prompt("NordVPN Access Token", hide_input=True).strip()
    if not token:
        fail("No access token entered; aborting.")
    logger.info("Contacting NordVPN API to retrieve your permanent WireGuard private key...")
    key = fetch_nordvpn_wireguard_key_from_token(token)
    logger.success("Successfully retrieved permanent WireGuard private key from NordVPN.")
    return key


def _prompt_manual_wireguard_key() -> str:
    logger.info("Manual WireGuard private key entry selected.")
    typer.echo("")
    typer.echo("Paste your 44-character base64 NordVPN WireGuard private key below.")
    key = typer.prompt("WireGuard private key", hide_input=True).strip()
    if not key:
        fail("No WireGuard key entered; aborting.")
    try:
        return validate_wireguard_private_key(key)
    except ValueError as error:
        fail(str(error))


def _prompt_openvpn_credentials() -> tuple[str, str]:
    logger.info("OpenVPN selected: enter your NordVPN service credentials.")
    typer.echo("")
    typer.echo("Retrieve the credentials from Nord Account:")
    typer.echo("  1. Log in to https://my.nordaccount.com/")
    typer.echo("  2. Open NordVPN -> Set up NordVPN manually.")
    typer.echo("  3. Open the Service credentials section.")
    typer.echo("  4. Paste the username and password below.")
    username = typer.prompt("OpenVPN service username").strip()
    password = typer.prompt("OpenVPN service password", hide_input=True).strip()
    if not username or not password:
        fail("OpenVPN service credentials were not provided; aborting.")
    return username, password


def _prompt_nordvpn_openvpn_setup_mode() -> str:
    typer.echo("")
    typer.echo("NordVPN OpenVPN setup method:")
    typer.echo("  1) Fetch credentials via NordVPN Access Token (recommended)")
    typer.echo("  2) Enter manual service credentials (username/password)")
    choice = typer.prompt("Choose [1-2]", default="1").strip().lower()
    if choice in {"2", "manual", "paste"}:
        return "manual"
    return "token"


def configure_nordvpn(env_path: Path) -> None:
    """Configure NordVPN credentials in .env."""
    protocol = _prompt_nordvpn_protocol()
    if protocol == "openvpn":
        mode = _prompt_nordvpn_openvpn_setup_mode()
        if mode == "token":
            logger.info("Access Token setup selected: retrieving OpenVPN service credentials.")
            typer.echo("")
            typer.echo("To get your NordVPN Access Token:")
            typer.echo("  1. Log in to https://my.nordaccount.com/dashboard/nordvpn/access-tokens/")
            typer.echo("  2. Click 'Generate new token'.")
            typer.echo("  3. Copy the token and paste it below.")
            typer.echo("")
            token = typer.prompt("NordVPN Access Token", hide_input=True).strip()
            if not token:
                fail("No access token entered; aborting.")
            key, username, password = fetch_nordvpn_credentials_from_token(token)
            if not username or not password:
                fail("NordVPN API did not return service username/password for this account.")
        else:
            username, password = _prompt_openvpn_credentials()
            key = ""

        write_env_settings(
            env_path,
            {
                "VPN_TYPE": "openvpn",
                "OPENVPN_USER": username,
                "OPENVPN_PASSWORD": password,
                "WIREGUARD_PRIVATE_KEY": key,
                "WIREGUARD_ADDRESSES": "",
            },
        )
        logger.success("Stored NordVPN OpenVPN service credentials in .env.")
        return

    mode = _prompt_nordvpn_key_setup_mode()
    if mode == "token":
        logger.info("Access Token setup selected: generating permanent WireGuard key.")
        typer.echo("")
        typer.echo("To get your NordVPN Access Token:")
        typer.echo("  1. Log in to https://my.nordaccount.com/dashboard/nordvpn/access-tokens/")
        typer.echo("  2. Click 'Generate new token'.")
        typer.echo("  3. Copy the token and paste it below.")
        typer.echo("")
        token = typer.prompt("NordVPN Access Token", hide_input=True).strip()
        if not token:
            fail("No access token entered; aborting.")
        key, username, password = fetch_nordvpn_credentials_from_token(token)
    else:
        key = _prompt_manual_wireguard_key()
        username, password = "", ""

    settings: dict[str, str] = {
        "VPN_TYPE": "wireguard",
        "WIREGUARD_PRIVATE_KEY": key,
        "WIREGUARD_ADDRESSES": "10.5.0.2/32",
        "OPENVPN_USER": username,
        "OPENVPN_PASSWORD": password,
    }

    write_env_settings(env_path, settings)
    logger.success(f"Wrote WireGuard configuration into {env_path.name}.")
