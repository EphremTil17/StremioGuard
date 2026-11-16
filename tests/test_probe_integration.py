"""Real-Docker proof of bounded in-gluetun IP probes (AC-1: INV-1, INV-3).

Opt-in: `STREMIOGUARD_DOCKER_TESTS=1 .venv/bin/python -m pytest -q tests/test_probe_integration.py`.
Runs the pinned gluetun image (entrypoint overridden to sleep, no VPN) and
busybox stub HTTP servers on an isolated ``--internal`` Docker network.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from stremioguard.config import SubprocessRunner, compose_command
from stremioguard.guard import GluetunGuard
from tests.conftest import make_config

CONTAINER_PREFIX = "sgfix7-"
GLUETUN_IMAGE = (
    "qmcgaw/gluetun@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027"
)
BUSYBOX_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
PROBE_TIMEOUT_SECONDS = 3

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="needs real Docker containers; set STREMIOGUARD_DOCKER_TESTS=1",
)


class _PsOverrideRunner:
    """Answers `compose ps -q gluetun` with the test ID; passes other calls through."""

    def __init__(self, root_dir: Path, container_id: str) -> None:
        self._root_dir = root_dir
        self._container_id = container_id
        self._real = SubprocessRunner()

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if args == compose_command(self._root_dir, "ps", "-q", "gluetun"):
            return subprocess.CompletedProcess(args, 0, f"{self._container_id}\n", "")
        return self._real.run(args, check=check, capture=capture, timeout=timeout, env=env)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _assert_no_probe_processes(container_name: str, *, window_seconds: float = 2.0) -> None:
    deadline = time.monotonic() + window_seconds
    while True:
        top = _docker("top", container_name, check=False)
        lines = (top.stdout or "").splitlines()[1:]
        offenders = [line for line in lines if "wget" in line or "timeout" in line]
        if not offenders:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"Probe process lingered in {container_name} after {window_seconds}s: {offenders}"
            )
        time.sleep(0.1)


@pytest.fixture
def docker_probe_sandbox(tmp_path: Path) -> Iterator[dict[str, str]]:
    suffix = uuid.uuid4().hex[:8]
    network = f"{CONTAINER_PREFIX}net-{suffix}"
    gluetun_name = f"{CONTAINER_PREFIX}gluetun-{suffix}"
    stall_name = f"{CONTAINER_PREFIX}stall-{suffix}"
    good_name = f"{CONTAINER_PREFIX}good-{suffix}"
    trickle_name = f"{CONTAINER_PREFIX}trickle-{suffix}"
    containers = [gluetun_name, stall_name, good_name, trickle_name]

    created_containers: list[str] = []
    network_created = False
    try:
        _docker("network", "create", "--internal", network)
        network_created = True

        res = _docker(
            "run",
            "-d",
            "--name",
            gluetun_name,
            "--network",
            network,
            "--entrypoint",
            "/bin/sh",
            GLUETUN_IMAGE,
            "-c",
            "sleep 300",
        )
        gluetun_id = res.stdout.strip()
        created_containers.append(gluetun_name)

        _docker(
            "run",
            "-d",
            "--name",
            stall_name,
            "--network",
            network,
            BUSYBOX_IMAGE,
            "nc",
            "-lk",
            "-p",
            "8080",
            "-e",
            "sleep",
            "60",
        )
        created_containers.append(stall_name)

        _docker(
            "run",
            "-d",
            "--name",
            good_name,
            "--network",
            network,
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            (
                "printf '#!/bin/sh\\n"
                'printf "HTTP/1.1 200 OK\\\\r\\\\nContent-Length: 13\\\\r\\\\n'
                'Connection: close\\\\r\\\\n\\\\r\\\\n203.0.113.42\\\\n"\\n'
                "' > /h.sh && chmod +x /h.sh && exec nc -lk -p 8080 -e /h.sh"
            ),
        )
        created_containers.append(good_name)

        trickle_step = PROBE_TIMEOUT_SECONDS - 1
        _docker(
            "run",
            "-d",
            "--name",
            trickle_name,
            "--network",
            network,
            BUSYBOX_IMAGE,
            "sh",
            "-c",
            (
                "printf '#!/bin/sh\\n"
                'printf "HTTP/1.1 200 OK\\\\r\\\\nContent-Type: text/plain\\\\r\\\\n'
                'Connection: close\\\\r\\\\n\\\\r\\\\n"\\n'
                f"i=0; while [ $i -lt 30 ]; do sleep {trickle_step}; "
                'printf "x"; i=$((i+1)); done\\n'
                "' > /h.sh && chmod +x /h.sh && exec nc -lk -p 8080 -e /h.sh"
            ),
        )
        created_containers.append(trickle_name)

        # Wait until the stub servers are listening inside the internal network.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            probe = _docker(
                "exec",
                gluetun_name,
                "timeout",
                "-s",
                "KILL",
                "2",
                "wget",
                "--tries=1",
                "--timeout=2",
                "-qO-",
                f"http://{good_name}:8080/",
                check=False,
            )
            if probe.returncode == 0 and "203.0.113.42" in probe.stdout:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Stub HTTP servers did not become ready within 10s")

        yield {
            "gluetun_id": gluetun_id,
            "gluetun_name": gluetun_name,
            "stall_url": f"http://{stall_name}:8080/",
            "good_url": f"http://{good_name}:8080/",
            "trickle_url": f"http://{trickle_name}:8080/",
        }
    finally:
        for name in reversed(containers):
            if name in created_containers:
                _docker("rm", "-f", "-v", name, check=False)
        if network_created:
            _docker("network", "rm", network, check=False)


def test_ac1_in_gluetun_probes_bound_stall_and_trickle(
    tmp_path: Path, docker_probe_sandbox: dict[str, str]
) -> None:
    """AC-1 (INV-1, INV-3): stall, both-stall, and trickle-then-good against real gluetun."""
    t = PROBE_TIMEOUT_SECONDS
    max_duration = 2 * t + 6
    runner = _PsOverrideRunner(tmp_path, docker_probe_sandbox["gluetun_id"])
    gluetun_name = docker_probe_sandbox["gluetun_name"]

    # 1. URL 1 stalls, URL 2 answers fixed address
    guard1 = GluetunGuard(
        make_config(
            tmp_path,
            public_ip_timeout_seconds=t,
            ip_check_urls=(docker_probe_sandbox["stall_url"], docker_probe_sandbox["good_url"]),
        ),
        runner,
    )
    start1 = time.monotonic()
    ip1 = guard1.public_ip_via_gluetun()
    dur1 = time.monotonic() - start1
    assert ip1 == "203.0.113.42"
    assert dur1 < max_duration, f"stall+good took {dur1:.2f}s >= {max_duration}s"
    _assert_no_probe_processes(gluetun_name)

    # 2. Both URLs stall -> None
    guard2 = GluetunGuard(
        make_config(
            tmp_path,
            public_ip_timeout_seconds=t,
            ip_check_urls=(docker_probe_sandbox["stall_url"], docker_probe_sandbox["stall_url"]),
        ),
        runner,
    )
    start2 = time.monotonic()
    ip2 = guard2.public_ip_via_gluetun()
    dur2 = time.monotonic() - start2
    assert ip2 is None
    assert dur2 < max_duration, f"both-stall took {dur2:.2f}s >= {max_duration}s"
    _assert_no_probe_processes(gluetun_name)

    # 3. URL 1 trickles 1 byte every (T-1)s after valid status line, URL 2 answers
    guard3 = GluetunGuard(
        make_config(
            tmp_path,
            public_ip_timeout_seconds=t,
            ip_check_urls=(docker_probe_sandbox["trickle_url"], docker_probe_sandbox["good_url"]),
        ),
        runner,
    )
    start3 = time.monotonic()
    ip3 = guard3.public_ip_via_gluetun()
    dur3 = time.monotonic() - start3
    assert ip3 == "203.0.113.42"
    assert dur3 < max_duration, f"trickle+good took {dur3:.2f}s >= {max_duration}s"
    _assert_no_probe_processes(gluetun_name)

    print(
        f"AC-1 measured durations (T={t}s, limit={max_duration}s): "
        f"stall+good={dur1:.2f}s, both-stall={dur2:.2f}s, trickle+good={dur3:.2f}s"
    )
