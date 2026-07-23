"""Pre-start validation: Docker availability and bind-address checks."""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable
from pathlib import Path

from stremioguard.config import Runner, docker_permission_help


def require_docker(
    runner: Runner,
    *,
    install_missing: bool = False,
    log: Callable[[str], None],
    warn: Callable[[str], None],
) -> None:
    missing = [cmd for cmd in ("docker",) if shutil.which(cmd) is None]
    if missing:
        if install_missing:
            _install_apt_packages(missing, runner, log=log, warn=warn)
            missing = [cmd for cmd in ("docker",) if shutil.which(cmd) is None]
        if missing:
            raise RuntimeError(
                f"Missing required command(s): {', '.join(missing)}\n{_install_hint(missing)}"
            )

    result = runner.run(["docker", "compose", "version"], check=False)
    if result.returncode != 0:
        detail = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
        help_text = docker_permission_help(detail)
        if help_text:
            raise RuntimeError(help_text)
        raise RuntimeError("Docker Compose plugin is not available.")

    daemon_result = runner.run(["docker", "ps", "--format", "{{.ID}}"], check=False)
    if daemon_result.returncode != 0:
        detail = f"{daemon_result.stdout or ''}\n{daemon_result.stderr or ''}".strip()
        help_text = docker_permission_help(detail)
        if help_text:
            raise RuntimeError(help_text)
        raise RuntimeError(
            "Docker is installed, but the daemon is not reachable from this shell. "
            "Run `docker ps` to confirm and fix Docker access before retrying."
        )


def require_matching_daemon(
    runner: Runner,
    record: Path,
    *,
    warn: Callable[[str], None],
) -> None:
    """Refuse to drive the stack from a different Docker daemon than made it.

    One host can run the rootful daemon and a rootless per-user daemon at the
    same time, and `docker context use` (or sudo, which reads root's contexts)
    switches between them silently. Both daemons see the same bind mounts, so
    starting the stack under the second one aims a second Postgres at the live
    data directory. The postmaster.pid lock cannot save us there: the running
    postmaster is in another PID namespace, so its PID either looks dead or
    collides with an unrelated process. Pin the daemon on first start and
    refuse to move without an explicit opt-out.
    """
    result = runner.run(["docker", "info", "--format", "{{.ID}}"], check=False)
    current = (result.stdout or "").strip()
    if result.returncode != 0 or not current:
        # Older engines and odd endpoints may not report an ID. A missing
        # identity is not a reason to block a stack that is otherwise fine.
        warn("Could not read the Docker daemon ID; skipping the daemon-identity check.")
        return

    if not record.exists():
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(f"{current}\n", encoding="utf-8")
        return

    previous = record.read_text(encoding="utf-8").strip()
    if not previous or previous == current:
        return

    raise RuntimeError(
        "This stack was created under a different Docker daemon.\n"
        f"  created under: {previous}\n"
        f"  this shell:    {current}\n"
        "Both daemons mount the same data directories, so starting the stack here "
        "would point a second Postgres at the live data directory and risk "
        "corrupting it.\n"
        "Run `docker context ls` to see which endpoint each context uses, then switch "
        "back with `docker context use <name>` (remember that sudo reads root's "
        "contexts, not yours).\n"
        f"If you moved daemons on purpose, confirm the old stack is fully removed and "
        f"delete {record} to re-pin."
    )


def _install_apt_packages(
    missing: list[str],
    runner: Runner,
    *,
    log: Callable[[str], None],
    warn: Callable[[str], None],
) -> None:
    if not shutil.which("apt"):
        warn("Automatic dependency installation is only supported on apt-based Linux.")
        return
    packages = []
    if "docker" in missing:
        packages.append("docker.io")
    if not packages:
        return
    log(f"Installing missing package(s): {', '.join(packages)}")
    runner.run(["sudo", "apt", "update"], check=True, capture=False)
    runner.run(["sudo", "apt", "install", "-y", *packages], check=True, capture=False)


def _install_hint(missing: list[str]) -> str:
    if "docker" in missing:
        return "Install Docker with Compose support inside WSL, then retry."
    return "Install the missing command(s), then retry."


def verify_bind_addresses(
    runner: Runner,
    addresses: list[str],
    *,
    log: Callable[[str], None],
    warn: Callable[[str], None],
) -> None:
    to_check = [a for a in addresses if a not in ("0.0.0.0", "127.0.0.1", "::", "::1")]
    if not to_check:
        return

    missing = list(to_check)
    for attempt in range(5):
        result = runner.run(["ip", "-j", "addr", "show"], check=False)
        if result.returncode != 0:
            warn(
                "Could not verify bind address availability (ip -j failed or unsupported); "
                "skipping preflight."
            )
            return

        host_ips: set[str] = set()
        output = result.stdout or ""
        if output.lstrip().startswith("["):
            try:
                data = json.loads(output)
                for iface in data:
                    for addr_info in iface.get("addr_info", []):
                        if "local" in addr_info:
                            host_ips.add(addr_info["local"])
            except ValueError:
                warn("Failed to parse ip -j JSON output; skipping preflight.")
                return
        else:
            warn("ip -j did not output JSON; skipping preflight.")
            return

        missing = [a for a in to_check if a not in host_ips]
        if not missing:
            return

        if attempt < 4:
            missing_str = ", ".join(missing)
            log(f"Waiting for bind address {missing_str} to appear on host interfaces...")
            time.sleep(1)

    missing_ip = missing[0]
    hint = "interface/service not up yet"
    if shutil.which("tailscale") and (
        missing_ip.startswith("100.") or missing_ip.startswith("fd7a:")
    ):
        hint += "; check tailscaled / tailscale status"
    raise RuntimeError(
        f"Configured bind IP {missing_ip} is missing from host interfaces.\nLikely cause: {hint}."
    )
