"""Whole watchdog scenarios: the real Orchestrator and GluetunGuard against FakeDocker.

The orchestrator's unit tests feed it the guard's answers directly, which is
the right way to cover its decisions. These run the two together against a
Docker that behaves like Docker (tests/docker_fake.py, checked against real
Docker by tests/test_docker_fake_contract_docker.py), so they catch what
neither side shows alone: a Compose command whose side effects undo what
the watchdog just did, or a stop that never reaches a container.

Each scenario asserts what Docker ends up doing: which containers run, in
which namespace, and what the watchdog wrote. Only the clock and the host's
own public IP (a probe from the host's network, not Docker) are patched.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest
import typer

from stremioguard import guard as guard_mod
from stremioguard.config import (
    GLUETUN_ENV_FILE,
    PUBLISHED_COMPOSE_FILE,
    PUBLISHED_ENV_FILE,
)
from stremioguard.guard import GluetunGuard
from stremioguard.orchestrator import Orchestrator
from tests.conftest import (
    PUBLIC_IPV4_EGRESS,
    PUBLIC_IPV4_HOST,
    make_config,
    seal_generation,
)
from tests.docker_fake import FakeDocker, State


@dataclass
class Watchdog:
    orch: Orchestrator
    guard: GluetunGuard
    docker: FakeDocker
    clock: list[float]

    def tick(self, at: float) -> None:
        self.clock[0] = at
        self.orch.watch_once()


@pytest.fixture
def watchdog(tmp_path: Path) -> Iterator[Watchdog]:
    """A frozen watchdog over a published stack: gluetun and stremio, both up."""
    config = make_config(tmp_path, vpn_recovery_budget_seconds=300, vpn_restart_cadence_seconds=45)
    for name in (GLUETUN_ENV_FILE, PUBLISHED_ENV_FILE, PUBLISHED_COMPOSE_FILE):
        (tmp_path / name).write_text("", encoding="utf-8")
    seal_generation(tmp_path)
    (tmp_path / ".stremio" / "home-ip").write_text(f"{PUBLIC_IPV4_HOST}\n", encoding="utf-8")
    states: dict[str, State] = {"gluetun": "running", "stremio": "running"}
    docker = FakeDocker(tmp_path, states)
    docker.tunnel.egress_ip = docker.tunnel.control_ip = PUBLIC_IPV4_EGRESS
    guard = GluetunGuard(config, docker, frozen=True)
    clock = [1000.0]
    with (
        mock.patch.object(guard_mod.time, "monotonic", side_effect=lambda: clock[0]),
        mock.patch("time.monotonic", side_effect=lambda: clock[0]),
        mock.patch("time.time", side_effect=lambda: clock[0]),
        mock.patch.object(guard, "public_ip", autospec=True, return_value=PUBLIC_IPV4_HOST),
        mock.patch.object(guard, "log", autospec=True),
        mock.patch.object(guard, "warn", autospec=True),
        mock.patch.object(guard, "success", autospec=True),
    ):
        yield Watchdog(Orchestrator(guard), guard, docker, clock)


def test_a_gluetun_restart_never_brings_back_the_services_an_outage_stopped(
    watchdog: Watchdog,
) -> None:
    # The outage stops stremio, then restarts gluetun to pick another server.
    # A plain `compose restart gluetun` also restarts every service in its
    # namespace, starting stremio again before the tunnel is verified.
    docker = watchdog.docker
    docker.set_health("gluetun", "unhealthy")

    watchdog.tick(1000.0)  # outage starts: stop, then restart gluetun
    assert docker.state("stremio") == "exited"
    watchdog.tick(1010.0)
    watchdog.tick(1050.0)  # the restart cadence restarts gluetun again
    assert docker.state("stremio") == "exited"


def test_services_resume_only_after_the_tunnel_is_verified_and_in_the_new_namespace(
    watchdog: Watchdog,
) -> None:
    docker = watchdog.docker
    docker.set_health("gluetun", "unhealthy")
    watchdog.tick(1000.0)
    assert docker.state("stremio") == "exited"

    # gluetun is healthy again, but its tunnel exits through the host's own IP.
    docker.set_health("gluetun", "healthy")
    docker.tunnel.egress_ip = PUBLIC_IPV4_HOST
    watchdog.tick(1010.0)
    assert docker.state("stremio") == "exited"

    # A proven tunnel: stremio comes back, in gluetun's current namespace.
    docker.tunnel.egress_ip = PUBLIC_IPV4_EGRESS
    for at in (1020.0, 1030.0, 1040.0):
        watchdog.tick(at)
        if docker.state("stremio") == "running":
            break
    assert docker.state("stremio") == "running"
    assert docker.joined("stremio") == docker.container_id("gluetun")


def test_rejected_credentials_lock_out_with_everything_really_stopped(
    watchdog: Watchdog,
) -> None:
    # The provider rejects the credentials after every restart. Two restart
    # generations with a rejection lock out well inside the outage budget.
    docker, config = watchdog.docker, watchdog.guard.config
    docker.set_health("gluetun", "unhealthy")
    at = 1000.0
    with pytest.raises(typer.Exit) as exited:
        while at < 1000.0 + config.vpn_recovery_budget_seconds:
            docker.log("gluetun", f"t={int(at)} ERROR [openvpn] AUTH_FAILED", at=at - 5.0)
            watchdog.tick(at)
            at += 10.0
    assert exited.value.exit_code == 78
    assert at < 1000.0 + config.vpn_recovery_budget_seconds / 2, "locked out on the budget instead"
    assert '"auth_rejected"' in config.vpn_lockout_file.read_text(encoding="utf-8")
    assert docker.state("stremio") == "exited"
    assert docker.state("gluetun") == "exited"


def test_two_leak_verdicts_lock_out_with_everything_really_stopped(watchdog: Watchdog) -> None:
    docker, config = watchdog.docker, watchdog.guard.config
    docker.tunnel.egress_ip = PUBLIC_IPV4_HOST  # traffic leaves through the host's own IP

    watchdog.tick(1000.0)  # first verdict: services stop at once
    assert docker.state("stremio") == "exited"
    assert docker.state("gluetun") == "running"
    with pytest.raises(typer.Exit) as exited:
        watchdog.tick(1010.0)
    assert exited.value.exit_code == 78
    assert '"egress_leak"' in config.vpn_lockout_file.read_text(encoding="utf-8")
    assert docker.state("stremio") == "exited"
    assert docker.state("gluetun") == "exited"


def test_a_crash_looping_gluetun_is_stopped_when_the_outage_budget_runs_out(
    watchdog: Watchdog,
) -> None:
    docker, config = watchdog.docker, watchdog.guard.config
    docker.set_health("gluetun", "unhealthy")
    at = 1000.0
    with pytest.raises(typer.Exit) as exited:
        while at < 1000.0 + 2 * config.vpn_recovery_budget_seconds:
            docker.set_state("gluetun", "restarting")  # it never stays up
            watchdog.tick(at)
            at += 10.0
    assert exited.value.exit_code == 78
    assert config.vpn_lockout_file.exists()
    assert docker.state("stremio") == "exited"
    assert docker.state("gluetun") == "exited"
