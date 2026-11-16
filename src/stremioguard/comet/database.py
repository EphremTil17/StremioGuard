"""Offline Comet Postgres authentication and password rotation helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from stremioguard.config import DOCKER_QUERY_TIMEOUT_SECONDS, compose_command

if TYPE_CHECKING:
    from stremioguard.comet.manager import CometManager

ROTATE_TIMEOUT_SECONDS = 120
_POSTGRES_DATA_MOUNT_TARGET = "/var/lib/postgresql"


def scram_sha256_verifier(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = 4096,
) -> str:
    """Compute a PostgreSQL SCRAM-SHA-256 verifier (RFC 5803 format) locally."""
    if not password:
        raise ValueError("password must not be empty")
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    actual_salt = os.urandom(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), actual_salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return (
        f"SCRAM-SHA-256${iterations}:{encode(actual_salt)}$"
        f"{encode(stored_key)}:{encode(server_key)}"
    )


def _decode_stream(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


def _redact_tail(text: str, *secrets_to_hide: str, max_lines: int = 20) -> str:
    redacted = text
    for secret in secrets_to_hide:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    lines = redacted.splitlines()
    return "\n".join(lines[-max_lines:]).strip()


def _resolve_postgres_compose_service(manager: CometManager) -> tuple[str, str]:
    """Read the pinned Postgres image and bind mount from Compose config."""
    try:
        result = manager.runner.run(
            compose_command(
                manager.config.root_dir,
                "config",
                "--format",
                "json",
                "--no-env-resolution",
                "comet-postgres",
            ),
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise RuntimeError(f"Failed to read Compose config for comet-postgres: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise RuntimeError(f"Failed to read Compose config for comet-postgres: {detail}")
    try:
        parsed = json.loads(result.stdout or "")
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Compose config for comet-postgres returned invalid JSON: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise RuntimeError("Compose config for comet-postgres did not return a JSON object.")

    services = parsed.get("services")
    if not isinstance(services, dict) or not isinstance(services.get("comet-postgres"), dict):
        raise RuntimeError("Compose config does not define the `comet-postgres` service.")
    pg = services["comet-postgres"]

    image = pg.get("image")
    if not isinstance(image, str) or "@sha256:" not in image or not image.split("@sha256:", 1)[1]:
        raise RuntimeError(
            f"Compose `comet-postgres` image ({image!r}) must be pinned with @sha256:."
        )

    volumes = pg.get("volumes")
    if not isinstance(volumes, list):
        raise RuntimeError("Compose `comet-postgres` has no volumes list.")
    matching_binds = [
        vol
        for vol in volumes
        if isinstance(vol, dict)
        and vol.get("type") == "bind"
        and isinstance(vol.get("target"), str)
        and vol["target"].rstrip("/") == _POSTGRES_DATA_MOUNT_TARGET
    ]
    if len(matching_binds) != 1:
        raise RuntimeError(
            "Compose `comet-postgres` must have exactly one bind mount targeting "
            f"{_POSTGRES_DATA_MOUNT_TARGET}."
        )
    source = matching_binds[0].get("source")
    if not isinstance(source, str) or not source:
        raise RuntimeError("Compose `comet-postgres` bind mount has no source path.")
    if Path(source).resolve() != manager.config.postgres_data_dir.resolve():
        raise RuntimeError(
            f"Compose `comet-postgres` bind source ({source}) does not match "
            f"configured postgres_data_dir ({manager.config.postgres_data_dir})."
        )
    return image, source


def rotate_postgres_password(manager: CometManager) -> None:
    """Rotate the Comet Postgres `comet` role password offline in single-user mode."""
    image, source = _resolve_postgres_compose_service(manager)

    data_dir = manager.config.postgres_data_dir
    if not data_dir.is_dir() or not any(data_dir.iterdir()):
        raise RuntimeError(
            f"Postgres data directory {data_dir} does not exist or is empty; "
            "a password is generated automatically on first start."
        )

    try:
        ps_result = manager.runner.run(
            ["docker", "ps", "-q", "--filter", f"volume={source}"],
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise RuntimeError(
            f"Could not verify whether any container mounts {source}: {error}"
        ) from error
    if ps_result.returncode != 0:
        detail = (ps_result.stderr or ps_result.stdout or "unknown Docker error").strip()
        raise RuntimeError(f"Could not verify whether any container mounts {source}: {detail}")
    running_ids = [line.strip() for line in (ps_result.stdout or "").splitlines() if line.strip()]
    if running_ids:
        raise RuntimeError(
            f"Refusing to rotate Postgres password while container(s) mount {source}: "
            f"{', '.join(running_ids)}. Stop the stack (`./stremio stop`) first."
        )

    new_password = secrets.token_urlsafe(18)
    verifier = scram_sha256_verifier(new_password)
    if "'" in verifier:
        raise RuntimeError("Generated SCRAM verifier contained an unexpected quote character.")

    container_name = f"stremioguard-comet-dbpw-{secrets.token_hex(4)}"
    statements = (
        f"ALTER ROLE comet PASSWORD '{verifier}';\n"
        f"SELECT rolpassword = '{verifier}' AS rotated FROM pg_authid WHERE rolname = 'comet';\n"
    )
    run_args = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--network",
        "none",
        "-v",
        f"{source}:/var/lib/postgresql/",
        image,
        "postgres",
        "--single",
        "comet",
    ]

    try:
        try:
            result = manager.runner.run(
                run_args,
                check=False,
                timeout=ROTATE_TIMEOUT_SECONDS,
                input=statements,
            )
        except subprocess.TimeoutExpired as error:
            output = f"{_decode_stream(error.stdout)}\n{_decode_stream(error.stderr)}"
            tail = _redact_tail(output, verifier, new_password)
            suffix = f"\n{tail}" if tail else ""
            raise RuntimeError(
                f"Offline Postgres password rotation timed out after {ROTATE_TIMEOUT_SECONDS}s."
                f"{suffix}"
            ) from None
        except (subprocess.SubprocessError, OSError) as error:
            detail = _redact_tail(str(error), verifier, new_password)
            raise RuntimeError(f"Offline Postgres password rotation failed: {detail}") from None
    finally:
        with suppress(subprocess.SubprocessError, OSError):
            manager.runner.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_SECONDS,
            )

    combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    if 'rotated = "t"' not in combined:
        tail = _redact_tail(combined, verifier, new_password)
        detail = f"\n{tail}" if tail else ""
        raise RuntimeError(
            "Offline Postgres password rotation did not confirm the new verifier in pg_authid."
            f"{detail}"
        )

    try:
        manager._write_postgres_env(new_password)
        manager.write_runtime_env()
    except Exception as error:
        detail = _redact_tail(str(error), verifier, new_password)
        raise RuntimeError(
            "The database already has a new password that could not be saved "
            f"({detail}). Rerun `./stremio comet rotate-db-password` to fix it "
            "without needing the old password."
        ) from None

    manager.success("Rotated the Comet Postgres password. Run `./stremio start` to apply it.")
