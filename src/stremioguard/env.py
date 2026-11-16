"""Dotenv read/write utilities and validation helpers."""

from __future__ import annotations

import base64
import binascii
import fcntl
import os
import re
import stat
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
_KEY_NAME_BEFORE_EQUALS = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*$")
_DOUBLE_QUOTE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}

# Exactly the characters str.splitlines() breaks on, plus NUL.
FORBIDDEN_ENV_CHARS: frozenset[str] = frozenset(
    {
        "\x00",
        "\n",
        "\r",
        "\v",
        "\f",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
    }
)


def _first_forbidden_env_char(text: str) -> str | None:
    for char in text:
        if char in FORBIDDEN_ENV_CHARS:
            return char
    return None


def check_env_value(value: str, *, key: str | None = None, label: str = "dotenv value") -> None:
    """Refuse any value containing a forbidden line separator or NUL without echoing it."""
    bad = _first_forbidden_env_char(value)
    if bad is not None:
        subject = key if key is not None else label
        raise ValueError(f"{subject} cannot contain forbidden character U+{ord(bad):04X}")


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

    Lines end at ``\\n`` only, with one trailing ``\\r`` dropped (CRLF files);
    any non-comment line containing another line separator or NUL (either
    literally or via a ``\\n``/``\\r`` escape) is refused with ``RuntimeError``.
    Blank lines and ``#`` comments (after ``.strip()``) are skipped, an
    optional ``export `` prefix is accepted, unquoted values end at whitespace
    followed by ``#``, and the last assignment of a key wins.

    Differences from Docker Compose:
    - The supported double-quote escapes are ``\\t``, ``\\\\``, ``\\"``, and
      ``\\$`` (producing a tab, ``\\``, ``"``, and ``$``, as in Compose); a
      ``\\n`` or ``\\r`` escape is refused like a literal line break; and any
      other escape drops its backslash, whereas Compose also expands ``\\v``,
      ``\\f``, ``\\a``, ``\\b``, octal escapes, and keeps ``\\'`` with its
      backslash.
    - ``$NAME`` is always kept literal instead of being expanded unquoted or in
      double quotes.
    - Non-comment lines with line separators other than LF/CRLF or NUL are
      refused instead of kept inside a value.

    This is safe because once ``./stremio start`` publishes a generation,
    Compose only ever reads the normalized, re-quoted files rendered by
    StremioGuard (see ``publishing.py``), never the raw ``.env``.
    """
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        bad = _first_forbidden_env_char(line)
        if bad is not None:
            key_match = (
                _KEY_NAME_BEFORE_EQUALS.match(line.split("=", 1)[0]) if "=" in line else None
            )
            if key_match:
                raise RuntimeError(
                    f"{source}: line {line_number}: {key_match.group(1)} "
                    f"contains forbidden character U+{ord(bad):04X}"
                )
            raise RuntimeError(
                f"{source}: line {line_number}: contains forbidden character U+{ord(bad):04X}"
            )
        match = _KEY_PATTERN.match(stripped)
        if not match:
            # `KEY` alone means "inherit from the process environment" to
            # Compose. StremioGuard has no use for that; skip it.
            continue
        key, raw = match.group(1), match.group(2).strip()
        if raw[:1] in {"'", '"'}:
            value = _parse_quoted(raw, raw[0], source=source, line_number=line_number)
            try:
                check_env_value(value, key=key)
            except ValueError as error:
                raise RuntimeError(f"{source}: line {line_number}: {error}") from error
            values[key] = value
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
        text = env_path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return {}
    return parse_dotenv(text, source=str(env_path))


def env_file_value(env_path: Path, key: str) -> str | None:
    return read_env_file(env_path).get(key)


def format_env_value(value: str, *, key: str | None = None) -> str:
    """Quote ``value`` so both this parser and Compose read it back exactly."""
    check_env_value(value, key=key, label="dotenv value")
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
    lines.extend(f"{key}={format_env_value(value, key=key)}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def _plain_value_safe(value: str) -> bool:
    if value != value.strip() or value[:1] in {"'", '"'}:
        return False
    return not re.search(r"\s#", value)


def render_env_value(value: str, *, key: str | None = None) -> str:
    """Format a dotenv value for ``write_env_settings``, preserving plain safe values."""
    check_env_value(value, key=key, label="dotenv value")
    return value if _plain_value_safe(value) else format_env_value(value, key=key)


def render_strict_env_value(value: str, *, key: str | None = None) -> str:
    """Format a generated dotenv value, quoting whenever whitespace or metacharacters appear."""
    check_env_value(value, key=key, label="dotenv value")
    if not value or re.fullmatch(r"[A-Za-z0-9_.:/@+=,-]+", value):
        return value
    return format_env_value(value, key=key)


def write_env_setting(env_path: Path, key: str, value: str) -> None:
    write_env_settings(env_path, {key: value})


def write_env_settings(env_path: Path, settings: Mapping[str, str]) -> None:
    """Atomically replace a related set of dotenv fields in one transaction.

    The LAST assignment of a key is the one every reader uses, so that is the
    line replaced; an `export ` prefix on it is kept.
    """
    dir_fd = os.open(env_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_EX)
        raw = env_path.read_bytes().decode("utf-8")
        if raw == "":
            lines: list[str] = []
        elif raw.endswith("\n"):
            lines = raw[:-1].split("\n")
        else:
            lines = raw.split("\n")
        for key, value in settings.items():
            rendered = render_env_value(value, key=key)
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
    finally:
        os.close(dir_fd)


def _mkdir_parents_private(directory: Path) -> None:
    """Create missing directories along ``directory`` at 0700, leaving existing ones."""
    abs_dir = Path(os.path.abspath(directory))
    parts = abs_dir.parts
    if not parts:
        return
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        if not os.path.lexists(current):
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                if not os.path.isdir(current):
                    raise


def ensure_directory(path: Path, *, mode: int = 0o700) -> None:
    """Create ``path`` (and missing parents at 0700) without following any symlink.

    Refuses with ``RuntimeError`` when any existing component of
    ``os.path.abspath(path)`` is a symlink or a non-directory, and sets the
    leaf's mode via ``fchmod`` on an ``O_NOFOLLOW | O_DIRECTORY`` descriptor.
    """
    abs_path = Path(os.path.abspath(path))
    parts = abs_path.parts
    if not parts:
        return
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except FileExistsError:
                st = os.lstat(current)
            else:
                continue
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"Refusing symlinked directory component {current} for {path}.")
        if not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"Refusing non-directory path {current} for {path}.")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(abs_path, flags)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def read_regular_file(path: Path, *, max_bytes: int) -> bytes | None:
    """Read up to ``max_bytes`` from a regular file without blocking or following symlinks.

    Returns ``None`` when ``path`` is missing, a symlink, not a regular file
    (e.g. FIFO or directory), larger than ``max_bytes``, or unreadable.
    """
    if max_bytes < 0:
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        limit = max_bytes + 1
        while total < limit:
            chunk = os.read(fd, limit - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        with suppress(OSError):
            os.close(fd)


def atomic_write_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write a generated file without exposing partial contents."""
    _mkdir_parents_private(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
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
