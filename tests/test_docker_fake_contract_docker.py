"""FakeDocker's contract: the same guard calls give the same answers on real Docker.

Starts a throwaway Compose project of busybox containers named like the
stack's services, one in each state the stop paths care about (a
crash-looping gluetun, running, paused, exited, created), and asks
GluetunGuard the same questions through a real SubprocessRunner and through
FakeDocker. Every answer must match, and each expected answer is also
stated, so this file records how Docker behaves as well as holding the fake
to it. If Docker or Compose changes behaviour, this fails before the unit
tests that rely on the fake can mislead.

Run with STREMIOGUARD_DOCKER_TESTS=1; projects are named `sgfake-<random>`
and removed afterwards.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest

from stremioguard.config import SubprocessRunner, compose_command
from stremioguard.guard import (
    ACTIVE_STATES,
    GLUETUN_STATE_FORMAT,
    RUNNING_STATES,
    GluetunGuard,
    compose_project_name,
)
from tests.conftest import make_config, seal_generation
from tests.docker_fake import FakeDocker, State

pytestmark = pytest.mark.skipif(
    os.environ.get("STREMIOGUARD_DOCKER_TESTS") != "1",
    reason="requires Docker; set STREMIOGUARD_DOCKER_TESTS=1",
)

REPO = Path(__file__).resolve().parents[1]
# The same pinned busybox as the stack's gate service, so nothing is pulled.
BUSYBOX = re.search(
    r"image: (busybox:\S+@sha256:[0-9a-f]{64})", (REPO / "docker-compose.yml").read_text()
).group(1)  # type: ignore[union-attr]

STATES: dict[str, State] = {
    "gluetun": "restarting",
    "comet": "running",
    "stremthru": "paused",
    "stremio": "exited",
    "comet-postgres": "created",
}
COMPOSE = f"""\
x-busybox: &busybox
  image: {BUSYBOX}
  network_mode: none
services:
  gluetun:  # crash-looping, like a gluetun whose credentials are rejected
    <<: *busybox
    command: ["sh", "-c", "exit 1"]
    restart: always
  comet:
    <<: *busybox
    command: ["sleep", "600"]
    init: true
  stremthru:  # paused below
    <<: *busybox
    command: ["sleep", "600"]
    init: true
  stremio:
    <<: *busybox
    command: ["true"]
    restart: "no"
  comet-postgres:  # created, never started
    <<: *busybox
    command: ["sleep", "600"]
"""
STOPPED = "Gluetun VPN container is stopped."


def _docker(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        compose_command(root, *args), check=True, capture_output=True, text=True, timeout=120
    )


def _status(container_id: str, field: str) -> str:
    return subprocess.run(
        ["docker", "inspect", "--format", field, container_id],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _labelled(project: str, service: str | None = None, *, all_states: bool = False) -> list[str]:
    """Container IDs found by Compose's labels, which needs no Compose file."""
    filters = ["--filter", f"label=com.docker.compose.project={project}"]
    if service:
        filters += ["--filter", f"label=com.docker.compose.service={service}"]
    return subprocess.run(
        ["docker", "ps", "-q", *(["-a"] if all_states else []), *filters],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.split()


def _compose_file(root: Path) -> Path:
    """The file Compose reads: the published copy, as on a deployed stack."""
    return root / ".stremio" / "compose.base.yml"


def _write_stack(root: Path) -> None:
    """A published generation, so every command runs with --project-directory like the
    live stack (the config's empty bindings override is part of the real command)."""
    make_config(root)
    (root / "docker-compose.yml").write_text(COMPOSE, encoding="utf-8")
    _compose_file(root).write_text(COMPOSE, encoding="utf-8")
    (root / ".stremio" / "env.snapshot").touch()


def _remove(root: Path, compose: str) -> None:
    _compose_file(root).write_text(compose, encoding="utf-8")
    subprocess.run(
        compose_command(root, "down", "-v", "-t", "1"),
        capture_output=True,
        timeout=120,
        check=False,
    )
    # Backstop that needs no Compose file: anything still carrying the
    # project's label goes too.
    leftover = _labelled(compose_project_name(root), all_states=True)
    if leftover:
        subprocess.run(["docker", "rm", "-f", *leftover], capture_output=True, timeout=120)


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Path]:
    # Mixed case and a dot: Compose's project-name rules, not just a plain name.
    root = tmp_path / f"SGFake.Contract_{uuid.uuid4().hex[:10]}"
    root.mkdir()
    _write_stack(root)
    try:
        _docker(root, "up", "-d", "gluetun", "comet", "stremthru", "stremio")
        _docker(root, "create", "comet-postgres")
        _docker(root, "pause", "stremthru")
        gluetun = _docker(root, "ps", "-aq", "gluetun").stdout.strip()
        # Wait out the fast restarts: from the 7th, Docker's backoff keeps the
        # container "restarting" for over 12 s, longer than the checks take.
        deadline = time.monotonic() + 90
        while not (
            _status(gluetun, "{{.State.Status}}") == "restarting"
            and int(_status(gluetun, "{{.RestartCount}}")) >= 7
        ):
            assert time.monotonic() < deadline, "gluetun never settled into a restart backoff"
            time.sleep(0.5)
        yield root
    finally:
        _remove(root, COMPOSE)


OTHER_STACK = f"""\
services:
  comet:  # another stack's service with the same name, like a second gluetun on the host
    image: {BUSYBOX}
    network_mode: none
    command: ["sleep", "600"]
    init: true
"""


@pytest.fixture
def other_stack(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / f"sgfake-other-{uuid.uuid4().hex[:10]}"
    (root / ".stremio").mkdir(parents=True)
    _compose_file(root).write_text(OTHER_STACK, encoding="utf-8")
    (root / ".stremio" / "docker-compose.bindings.yml").touch()
    (root / ".stremio" / "env.snapshot").touch()
    try:
        _docker(root, "up", "-d", "comet")
        yield root
    finally:
        _remove(root, OTHER_STACK)


def _guards(root: Path) -> tuple[GluetunGuard, GluetunGuard, FakeDocker]:
    config = make_config(root)
    fake = FakeDocker(root, STATES)
    return (
        GluetunGuard(config, SubprocessRunner(), frozen=True),
        GluetunGuard(config, fake, frozen=True),
        fake,
    )


def test_queries_agree_with_real_docker(project: Path, other_stack: Path) -> None:
    real, fake, docker = _guards(project)
    names = list(STATES)

    # Compose stamps the labels the guard derives for its own containers.
    comet = _docker(project, "ps", "-q", "comet").stdout.strip()
    assert compose_project_name(project).startswith("sgfakecontract_")
    assert _status(comet, '{{index .Config.Labels "com.docker.compose.project"}}') == (
        compose_project_name(project)
    )
    assert _status(
        comet, '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'
    ) == str(project)

    expected = {
        RUNNING_STATES: {"comet"},
        ACTIVE_STATES: {"gluetun", "comet", "stremthru"},
        ("restarting",): {"gluetun"},
        ("paused",): {"stremthru"},
        ("exited",): {"stremio"},
        ("created",): {"comet-postgres"},
    }
    for states, services in expected.items():
        assert real.running_services(names, states=states) == services, states
        assert fake.running_services(names, states=states) == services, states

    # A name that is not a service is an error ("no such service"), so the guard
    # reads it as unknown (maybe running), never as stopped.
    assert real.running_services(["no-such-service"], states=ACTIVE_STATES) is None
    assert fake.running_services(["no-such-service"], states=ACTIVE_STATES) is None
    assert real.services_confirmed_stopped(["no-such-service"]) is False
    assert fake.services_confirmed_stopped(["no-such-service"]) is False

    assert (
        set(real.protected_services()) == set(fake.protected_services()) == set(names) - {"gluetun"}
    )

    for service, state in STATES.items():
        real_id = real.service_container_id(service)
        fake_id = fake.service_container_id(service)
        listed = state in {"running", "restarting", "paused"}
        assert (real_id is not None) == (fake_id is not None) == listed, service
        assert (
            real.services_confirmed_stopped([service])
            == fake.services_confirmed_stopped([service])
            == (not listed)
        ), service
        if real_id and fake_id:
            for field, value in (("{{.State.Running}}", "true"), ("{{.State.Status}}", state)):
                assert _status(real_id, field) == value, (service, field)
                inspect = ["docker", "inspect", "--format", field, fake_id]
                assert docker.run(inspect).stdout.strip() == value, (service, field)
        # Found by labels, without Compose: the same containers as `compose ps -q`.
        assert real.stack_container_ids(service) == ([real_id] if real_id else []), service
        assert fake.stack_container_ids(service) == ([fake_id] if fake_id else []), service

    # Another stack's running "comet" is never this stack's.
    other_comet = _docker(other_stack, "ps", "-q", "comet").stdout.strip()
    assert other_comet and other_comet != comet
    assert real.stack_container_ids("comet") == [comet]


def _stop_gluetun(guard: GluetunGuard) -> list[str]:
    successes: list[str] = []
    with (
        mock.patch.object(guard, "success", autospec=True, side_effect=successes.append),
        mock.patch.object(guard, "warn", autospec=True),
    ):
        guard.stop_gluetun()
    return successes


def test_stops_agree_with_real_docker(project: Path) -> None:
    real, fake, docker = _guards(project)

    # A crash-looping gluetun is stopped for good, and confirmed stopped.
    assert _stop_gluetun(real) == _stop_gluetun(fake) == [STOPPED]
    assert real.services_confirmed_stopped(["gluetun"]) is True
    assert docker.state("gluetun") == "exited"
    time.sleep(3)  # the restart policy does not bring an explicitly stopped container back
    assert real.services_confirmed_stopped(["gluetun"]) is True

    # A paused and a running service stop through the protected-service path.
    with mock.patch.object(real, "success"), mock.patch.object(fake, "success"):
        assert real.stop_active_services(["stremthru", "comet"]) is True
        assert fake.stop_active_services(["stremthru", "comet"]) is True
    assert real.services_confirmed_stopped(["stremthru", "comet"]) is True
    assert {docker.state("stremthru"), docker.state("comet")} == {"exited"}

    # Stopping what is already stopped succeeds and changes nothing.
    assert _stop_gluetun(real) == _stop_gluetun(fake) == [STOPPED]


def test_unreachable_daemon_agrees_with_real_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / f"sgfake-{uuid.uuid4().hex[:10]}"
    root.mkdir()
    (root / "docker-compose.yml").write_text(COMPOSE, encoding="utf-8")
    config = make_config(root)
    monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path}/no-daemon.sock")
    real = GluetunGuard(config, SubprocessRunner(), frozen=True)
    fake = GluetunGuard(config, FakeDocker(root, STATES, unreachable=True), frozen=True)

    for guard in (real, fake):
        # Reading the Compose file needs no daemon; every container query fails closed.
        assert set(guard.protected_services()) == set(STATES) - {"gluetun"}
        assert guard.running_services(["gluetun"], states=ACTIVE_STATES) is None
        assert guard.service_container_id("gluetun") is None
        assert guard.stack_container_ids("gluetun") is None
        assert guard.services_confirmed_stopped(["gluetun"]) is False
        assert _stop_gluetun(guard) == []
        with mock.patch.object(guard, "warn", autospec=True):
            assert guard.stop_active_services() is False


def test_unreadable_compose_file_agrees_with_real_docker(project: Path) -> None:
    real, fake, docker = _guards(project)
    docker.compose_unreadable = True
    _compose_file(project).write_text(
        "services:\n  comet:\n    image: [unclosed\n", encoding="utf-8"
    )

    for guard in (real, fake):
        # Every `docker compose` command fails, `config` included.
        with pytest.raises(subprocess.CalledProcessError):
            guard.protected_services()
        assert guard.running_services(["comet"], states=ACTIVE_STATES) is None
        assert guard.service_container_id("comet") is None
        # The stop still reaches the container through its labels, but only
        # Compose can confirm it, so it is reported unconfirmed.
        with (
            mock.patch.object(
                guard, "enabled_runtime_services", autospec=True, return_value=["comet"]
            ),
            mock.patch.object(guard, "warn", autospec=True),
        ):
            assert guard.stop_active_services() is False

    assert _labelled(compose_project_name(project), "comet") == []  # no longer running
    assert docker.state("comet") == "exited"


# What a watchdog tick sees: a gluetun with a healthcheck and a service in its
# namespace, published like the live stack so a frozen guard may start services.

TICK_STACK = f"""\
x-busybox: &busybox
  image: {BUSYBOX}
  init: true
services:
  gluetun:
    <<: *busybox
    network_mode: none
    command: ["sh", "-c", "echo 'contract gluetun started'; sleep 600"]
    healthcheck: {{test: ["CMD", "true"], interval: 1s, start_period: 0s}}
  stremio:
    <<: *busybox
    network_mode: "service:gluetun"
    command: ["sleep", "600"]
"""


@pytest.fixture
def tick_stack(tmp_path: Path) -> Iterator[Path]:
    root = tmp_path / f"sgfake-tick-{uuid.uuid4().hex[:10]}"
    root.mkdir()
    make_config(root)
    for name in (".stremio/compose.base.yml", "docker-compose.yml"):
        (root / name).write_text(TICK_STACK, encoding="utf-8")
    for name in (".stremio/env.snapshot", ".stremio/gluetun.env"):
        (root / name).touch()
    seal_generation(root)
    try:
        _docker(root, "up", "-d")
        gluetun = _docker(root, "ps", "-q", "gluetun").stdout.strip()
        deadline = time.monotonic() + 60
        while _status(gluetun, "{{.State.Health.Status}}") != "healthy":
            assert time.monotonic() < deadline, "the contract gluetun never became healthy"
            time.sleep(0.5)
        yield root
    finally:
        _remove(root, TICK_STACK)


def _tick_guards(root: Path) -> tuple[GluetunGuard, GluetunGuard, FakeDocker]:
    config = make_config(root)
    fake = FakeDocker(root, {"gluetun": "running", "stremio": "running"})
    fake.log("gluetun", "contract gluetun started", at=time.time())
    return (
        GluetunGuard(config, SubprocessRunner(), frozen=True),
        GluetunGuard(config, fake, frozen=True),
        fake,
    )


def test_tick_queries_agree_with_real_docker(tick_stack: Path) -> None:
    real, fake, docker = _tick_guards(tick_stack)
    for guard in (real, fake):
        state = guard.gluetun_state()
        assert state.healthy and state.identity is not None
        assert guard.stale_namespace_services(["stremio"], state) == []
        assert guard.gluetun_recent_logs(lines=5) == "contract gluetun started"
    # No healthcheck, no health: Docker refuses the template rather than guess.
    for guard, runner in ((real, SubprocessRunner()), (fake, docker)):
        stremio = guard.service_container_id("stremio")
        assert stremio is not None
        inspect = ["docker", "inspect", "--format", GLUETUN_STATE_FORMAT, stremio]
        assert runner.run(inspect, check=False).returncode == 1


def test_restart_recreate_and_rejoin_agree_with_real_docker(tick_stack: Path) -> None:
    real, fake, docker = _tick_guards(tick_stack)
    real_runner = SubprocessRunner()
    for guard, runner in ((real, real_runner), (fake, docker)):
        before = guard.gluetun_state().identity
        assert before is not None
        with mock.patch.object(guard, "success", autospec=True):
            assert guard.stop_active_services(["stremio"]) is True

        # restart --no-deps: same container, new start time, stremio stays stopped.
        assert guard.restart_gluetun() is True
        after = guard.gluetun_state().identity
        assert after is not None and after[0] == before[0] and after[1] != before[1]
        assert guard.services_confirmed_stopped(["stremio"]) is True

        # A plain restart also starts the stopped services in gluetun's namespace:
        # the reason restart_gluetun passes --no-deps.
        plain = compose_command(tick_stack, "restart", "gluetun")
        assert runner.run(plain, check=False, timeout=120).returncode == 0
        assert guard.running_services(["stremio"]) == {"stremio"}
        with mock.patch.object(guard, "success", autospec=True):
            assert guard.stop_active_services(["stremio"]) is True

        # A recreate is a new container; stremio stays attached to the old one.
        assert guard.restart_gluetun_relaxed() is True
        recreated = guard.gluetun_state()
        assert recreated.identity is not None and recreated.identity[0] != before[0]

        # Starting stremio puts it in the new gluetun's namespace.
        assert guard.start_services(["stremio"], check=False) is True
        assert guard.running_services(["stremio"]) == {"stremio"}
        assert guard.stale_namespace_services(["stremio"], guard.gluetun_state()) == []
