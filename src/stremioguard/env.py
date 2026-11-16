"""Dotenv read/write utilities and validation helpers."""

from __future__ import annotations

import base64
import binascii
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

import typer
from loguru import logger

WIREGUARD_KEY_PLACEHOLDER = "<paste-key-here>"
OPENVPN_USER_PLACEHOLDER = "<paste-service-username-here>"
OPENVPN_PASSWORD_PLACEHOLDER = "<paste-service-password-here>"
DEFAULT_STREMIO_HOST_PORT = 11470
DEFAULT_STREMIO_CONTAINER_PORT = 11470


def fail(message: str) -> NoReturn:
    logger.error(message)
    raise typer.Exit(1)


_KEY_PATTERN = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$", re.DOTALL)
_DOUBLE_QUOTE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}
_ENV_CACHE: dict[str, tuple[tuple[int, int, int], dict[str, str]]] = {}


def _parse_quoted(raw: str, quote: str, *, source: str, line_number: int) -> str:
    """The value of a quoted assignment; whatever follows the closing quote is ignored."""
    chars: list[str] = []
    index = 1
    while index < len(raw):
        char = raw[index]
        if char == quote:
            return "".join(chars)
        if quote == '"' and char == "\\" and index + 1 < len(raw):
            following = raw[index + 1]
            chars.append(_DOUBLE_QUOTE_ESCAPES.get(following, following))
            index += 2
            continue
        chars.append(char)
        index += 1
    raise RuntimeError(f"{source}: line {line_number}: unterminated {quote} quote")


def parse_dotenv(text: str, *, source: str = ".env") -> dict[str, str]:
    """Parse dotenv text the one way every StremioGuard reader agrees on.

    The grammar is Docker Compose's, minus variable expansion: an optional
    `export ` prefix, single quotes (literal) and double quotes (backslash
    escapes), an unquoted value ending at whitespace followed by `#`, and the
    LAST assignment of a key winning. Values are literal: `$NAME` is never
    expanded, so a secret containing `$` survives. Compose never reads the raw
    file once `./stremio start` has published its normalized copy (see
    publishing.py), so the two cannot disagree about a value.
    """
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _KEY_PATTERN.match(stripped)
        if not match:
            # `KEY` alone means "inherit from the process environment" to
            # Compose. StremioGuard has no use for that; skip it.
            continue
        key, raw = match.group(1), match.group(2).strip()
        if raw[:1] in {"'", '"'}:
            values[key] = _parse_quoted(raw, raw[0], source=source, line_number=line_number)
            continue
        for index, char in enumerate(raw):
            if char == "#" and index > 0 and raw[index - 1].isspace():
                raw = raw[:index]
                break
        values[key] = raw.strip()
    return values


def read_env_file(env_path: Path) -> dict[str, str]:
    """Every assignment in ``env_path``; empty when the file does not exist."""
    try:
        stat = env_path.stat()
    except OSError:
        return {}
    # The inode too: an atomic replace within the same clock tick and of the
    # same length must still be seen as a new file.
    signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
    cached = _ENV_CACHE.get(str(env_path))
    if cached and cached[0] == signature:
        return cached[1]
    values = parse_dotenv(env_path.read_text(encoding="utf-8"), source=str(env_path))
    _ENV_CACHE[str(env_path)] = (signature, values)
    return values


def env_file_value(env_path: Path, key: str) -> str | None:
    return read_env_file(env_path).get(key)


def format_env_value(value: str) -> str:
    """Quote ``value`` so both this parser and Compose read it back exactly."""
    if "\n" in value or "\r" in value:
        raise ValueError("a dotenv value cannot contain a line break")
    # Single quotes are fully literal for both parsers, except that Compose
    # treats `\'` as an escaped quote, so a value containing a quote or
    # ending in a backslash needs double quotes instead.
    if "'" not in value and not value.endswith("\\"):
        return f"'{value}'"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def render_dotenv(values: Mapping[str, str], *, header: str = "") -> str:
    """A normalized dotenv file: one quoted assignment per key."""
    lines = [header] if header else []
    lines.extend(f"{key}={format_env_value(value)}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def _plain_value_safe(value: str) -> bool:
    if value != value.strip() or value[:1] in {"'", '"'}:
        return False
    return not re.search(r"\s#", value)


def render_env_value(value: str) -> str:
    """Format a dotenv value for ``write_env_settings``, preserving plain safe values."""
    return value if _plain_value_safe(value) else format_env_value(value)


def render_strict_env_value(value: str) -> str:
    """Format a generated dotenv value, quoting whenever whitespace or metacharacters appear."""
    if not value or re.fullmatch(r"[A-Za-z0-9_.:/@+=,-]+", value):
        return value
    return format_env_value(value)


def write_env_setting(env_path: Path, key: str, value: str) -> None:
    write_env_settings(env_path, {key: value})


def write_env_settings(env_path: Path, settings: Mapping[str, str]) -> None:
    """Atomically replace a related set of dotenv fields in one transaction.

    The LAST assignment of a key is the one every reader uses, so that is the
    line replaced; an `export ` prefix on it is kept.
    """
    lines = env_path.read_text(encoding="utf-8").splitlines()
    for key, value in settings.items():
        if "\n" in value or "\r" in value:
            raise ValueError(f"{key} cannot contain a line break")
        rendered = render_env_value(value)
        target = None
        for index, line in enumerate(lines):
            match = _KEY_PATTERN.match(line.strip())
            if match and match.group(1) == key and not line.lstrip().startswith("#"):
                target = index
        if target is None:
            lines.append(f"{key}={rendered}")
        else:
            prefix = "export " if re.match(r"^\s*export\s+", lines[target]) else ""
            lines[target] = f"{prefix}{key}={rendered}"
    atomic_write_text(env_path, "\n".join(lines) + "\n", mode=0o600)


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
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def validate_wireguard_private_key(value: str) -> str:
    """Return a canonical WireGuard private key or reject malformed input."""
    candidate = value.strip()
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(
            "WireGuard private key must be padded base64 for exactly 32 bytes."
        ) from error
    if len(decoded) != 32:
        raise ValueError("WireGuard private key must decode to exactly 32 bytes.")
    return candidate


def valid_wireguard_private_key(value: str | None) -> bool:
    if not isinstance(value, str) or value in {"", WIREGUARD_KEY_PLACEHOLDER}:
        return False
    try:
        validate_wireguard_private_key(value)
    except ValueError:
        return False
    return True


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
        return not valid_wireguard_private_key(env_file_value(env_path, "WIREGUARD_PRIVATE_KEY"))

    if vpn_type == "openvpn":
        user = env_file_value(env_path, "OPENVPN_USER")
        password = env_file_value(env_path, "OPENVPN_PASSWORD")
        return user in {None, "", OPENVPN_USER_PLACEHOLDER} or password in {
            None,
            "",
            OPENVPN_PASSWORD_PLACEHOLDER,
        }

    return not valid_wireguard_private_key(env_file_value(env_path, "WIREGUARD_PRIVATE_KEY"))


def read_env_provider(env_path: Path) -> str:
    return (env_file_value(env_path, "VPN_SERVICE_PROVIDER") or "").strip().lower()
