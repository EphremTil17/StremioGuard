"""Dotenv read/write utilities and validation helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NoReturn

import typer
from loguru import logger

WIREGUARD_KEY_PLACEHOLDER = "<paste-key-here>"
OPENVPN_USER_PLACEHOLDER = "<paste-service-username-here>"
OPENVPN_PASSWORD_PLACEHOLDER = "<paste-service-password-here>"
ENV_LINE_TEMPLATE = r"^{key}=.*$"
DEFAULT_STREMIO_HOST_PORT = 11470


def fail(message: str) -> NoReturn:
    logger.error(message)
    raise typer.Exit(1)


def env_file_value(env_path: Path, key: str) -> str | None:
    if not env_path.exists():
        return None
    pattern = re.compile(ENV_LINE_TEMPLATE.format(key=re.escape(key)), re.MULTILINE)
    match = pattern.search(env_path.read_text(encoding="utf-8"))
    if not match:
        return None
    return match.group(0).split("=", 1)[1].strip()


def write_env_setting(env_path: Path, key: str, value: str) -> None:
    content = env_path.read_text(encoding="utf-8")
    pattern = re.compile(ENV_LINE_TEMPLATE.format(key=re.escape(key)), re.MULTILINE)
    new_line = f"{key}={value}"
    if pattern.search(content):
        content = pattern.sub(new_line, content, count=1)
    else:
        content = content.rstrip("\n") + f"\n{new_line}\n"
    env_path.write_text(content, encoding="utf-8")


def write_wireguard_key(env_path: Path, key: str) -> None:
    write_env_setting(env_path, "WIREGUARD_PRIVATE_KEY", key)


def write_openvpn_credentials(env_path: Path, username: str, password: str) -> None:
    write_env_setting(env_path, "OPENVPN_USER", username)
    write_env_setting(env_path, "OPENVPN_PASSWORD", password)


def env_flag_enabled(key: str, default: bool, *, env_path: Path) -> bool:
    value = env_file_value(env_path, key)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def env_port_value(env_path: Path, key: str, default: int) -> int:
    value = env_file_value(env_path, key)
    if value is None or value == "":
        return default
    try:
        port = int(value)
    except ValueError:
        fail(f"{key} must be a TCP port number; got {value!r}.")
    if port < 1 or port > 65535:
        fail(f"{key} must be between 1 and 65535; got {value!r}.")
    return port


def env_needs_init(env_path: Path) -> bool:
    if not env_path.exists():
        return True
    provider = (read_env_provider(env_path) or "nordvpn").lower()
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


def read_env_provider(env_path: Path) -> str:
    match = re.search(
        r"^VPN_SERVICE_PROVIDER=(.*)$", env_path.read_text(encoding="utf-8"), re.MULTILINE
    )
    return match.group(1).strip().lower() if match else ""
