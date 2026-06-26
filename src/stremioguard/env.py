"""Dotenv read/write utilities and validation helpers."""

from __future__ import annotations

import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

import typer
from loguru import logger

WIREGUARD_KEY_PLACEHOLDER = "<paste-key-here>"
OPENVPN_USER_PLACEHOLDER = "<paste-service-username-here>"
OPENVPN_PASSWORD_PLACEHOLDER = "<paste-service-password-here>"
ENV_LINE_TEMPLATE = r"^{key}=.*$"
DEFAULT_STREMIO_HOST_PORT = 11470
DEFAULT_STREMIO_CONTAINER_PORT = 11470


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
    atomic_write_text(env_path, content, mode=0o600)


def ensure_directory(path: Path, *, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode)


def atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    """Write a generated file without exposing partial contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    except BaseException:
        with suppress(OSError):
            os.close(fd)
        temporary_path.unlink(missing_ok=True)
        raise


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


def env_int_value(
    env_path: Path,
    key: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Read and validate an integer .env value, raising RuntimeError on error.

    This is the single integer/port parser for the project; callers that want a
    clean interactive exit (e.g. the guided setup) wrap it via env_port_value.
    """
    raw = env_file_value(env_path, key)
    if raw in {None, ""}:
        return default
    assert raw is not None
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"Invalid {key} value: {raw!r}") from error
    if minimum is not None and value < minimum:
        expected = f"{minimum}-{maximum}" if maximum is not None else f">= {minimum}"
        raise RuntimeError(f"Invalid {key} value: {raw!r}; expected {expected}")
    if maximum is not None and value > maximum:
        expected = f"{minimum}-{maximum}" if minimum is not None else f"<= {maximum}"
        raise RuntimeError(f"Invalid {key} value: {raw!r}; expected {expected}")
    return value


def env_port_value(env_path: Path, key: str, default: int) -> int:
    try:
        return env_int_value(env_path, key, default, minimum=1, maximum=65535)
    except RuntimeError as error:
        fail(str(error))


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
