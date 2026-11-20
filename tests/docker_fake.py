"""A stateful model of the Docker and Compose commands StremioGuard sends.

Use it where a test needs Docker to *behave*: the answer to every query
follows from each container's state, and stop commands change that state,
so the code under test is judged on what it concludes from Docker, not on
which call it dispatched.

Every answer follows behaviour recorded from real Docker 29 and Compose 5,
and `tests/test_docker_fake_contract_docker.py` runs the same guard calls
against real containers and this fake and requires identical results
(STREMIOGUARD_DOCKER_TESTS=1). When a test needs a command this fake does
not model, it fails loudly instead of answering; extend the model *and* the
contract test together.

Recorded behaviour the model encodes:

- `compose ps --status S [--status T ...] --services [names]` lists the
  services whose container is in any of the given states, sorted by name.
- A name that is not a service fails `ps` and `stop`: exit 1, "no such
  service: NAME". The guard therefore reads a misspelled service as unknown
  (maybe running), never as stopped.
- `compose ps -q NAME` lists running, restarting and paused containers, not
  exited or created ones; `-a` lists every container.
- `docker ps --no-trunc --filter label=com.docker.compose.service=NAME` lists
  the same containers as `compose ps -q` without reading the Compose file,
  with each container's project and working-directory labels. Containers of
  another stack (``foreign``) share service names but not those labels.
- `docker inspect --format {{.State.Running}}` is `true` for running,
  restarting *and* paused containers.
- `compose stop` and `docker stop` leave a running, restarting or paused
  container exited, and a restart policy does not bring it back; stopping an
  exited container succeeds.
- `compose config --services` lists every service, in no stable order.
- With the daemon unreachable every command exits 1, except
  `compose config`, which only reads the files and still answers.
- With the Compose file unreadable (``compose_unreadable``) every
  `docker compose` command exits 1, `config` included, while plain `docker`
  commands still work and the containers keep running.

What a watchdog tick sees (gluetun and the services in its namespace):

- `docker inspect --format {{.State.Health.Status}}|{{.State.StartedAt}}`
  answers `healthy|<time>` for a container with a healthcheck and exits 1
  ("map has no entry for key Health") for one without.
- `compose restart gluetun` keeps gluetun's ID and log, gives it a new start
  time and health `starting`, and also restarts every service in its
  namespace, *starting the stopped ones*; `restart --no-deps gluetun` leaves
  them as they are.
- `compose up -d --no-deps --force-recreate gluetun` gives gluetun a new ID
  and an empty log and leaves the services attached to the old namespace
  (`HostConfig.NetworkMode` still names the old container: stale).
- `compose up -d --no-deps NAME` starts NAME in the current gluetun's
  namespace (recreating it when it was attached to an older one).
- `docker logs --tail N` and `--since T` return what the container logged.

The tunnel itself is injected (``tunnel``): what the egress probe and the
control server answer from inside gluetun, and whether gluetun's OUTPUT chain
starts with the Docker DNS block. A busybox stand-in cannot have a VPN, so
those answers are not part of the contract.

Failure injection (not reproducible against real Docker on demand, so not
part of the contract): per service, a stop can "fail" (exit 1, nothing
changes), "come back" (exit 0, but a restart policy keeps it active) or
"hang"; and ``slow()`` makes the next calls to the daemon hang. A hanging
call times out if the caller set a timeout; with no timeout it would block
forever, so the fake raises instead of letting the test pass.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, NoReturn

from stremioguard.config import compose_command
from stremioguard.guard import (
    COMPOSE_GATE_SERVICE,
    COMPOSE_LABELS_FORMAT,
    DNS_BLOCK_RULE,
    GLUETUN_STATE_FORMAT,
    compose_project_name,
)
from stremioguard.guard import COMPOSE_SERVICE_LABEL as SERVICE_LABEL

# "removing" is too short-lived to produce on demand, so it is modelled by
# analogy with the recorded states (listed like any container holding a
# process), not recorded; the contract test covers every other state.
State = Literal["running", "restarting", "paused", "removing", "exited", "created"]
StopBehaviour = Literal["stops", "fails", "comes-back", "hangs"]

# `docker compose ps` without `-a` lists every container that holds a process.
_LISTED_WITHOUT_ALL = frozenset({"running", "restarting", "paused", "removing"})
_HOLDS_A_PROCESS = _LISTED_WITHOUT_ALL
FOREIGN_PROJECT = "another-stack"
FOREIGN_WORKING_DIR = "/srv/another-stack"
COMPOSE_UNREADABLE = (
    "go-yaml load error in parser (while parsing a flow sequence) at L3.C12-L4.C1: did not find "
    "expected ',' or ']'"
)
DAEMON_DOWN = (
    "failed to connect to the docker API at unix:///run/user/1000/docker.sock; check if the "
    "path is correct and if the daemon is running"
)


NAMESPACE_FORMAT = "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}|{{.HostConfig.NetworkMode}}"
CONTROL_SERVER_URL = "http://127.0.0.1:18080/v1/publicip/ip"
NO_HEALTHCHECK = (
    'template parsing error: template: :1:8: executing "" at <.State.Health.Status>: '
    'map has no entry for key "Health"'
)


@dataclass
class Tunnel:
    """What gluetun's tunnel answers from inside its namespace (injected, not recorded)."""

    egress_ip: str | None = None
    control_ip: str | None = None
    dns_block: bool = True


class UnmodelledCommandError(AssertionError):
    """The code under test sent a command this fake does not model."""


@dataclass
class _Container:
    service: str
    state: State
    project: str
    working_dir: str
    compose_stop: StopBehaviour = "stops"
    docker_stop: StopBehaviour = "stops"
    generation: int = 0  # a recreate is a new container with a new ID
    started_at: str = ""
    health: str | None = None  # None: the container has no healthcheck
    joined: str | None = None  # the gluetun container whose namespace it shares
    logs: list[tuple[float, str]] = field(default_factory=list)

    @property
    def container_id(self) -> str:
        key = f"fake-docker:{self.working_dir}:{self.service}:{self.generation}"
        return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class FakeDocker:
    """Docker and Compose for one project rooted at ``root_dir``.

    ``states`` maps each service to its container's state. A service with no
    container (never created, or removed) is simply left out.
    """

    root_dir: Path
    states: Mapping[str, State]
    foreign: Mapping[str, State] = field(default_factory=dict)
    unreachable: bool = False
    compose_unreadable: bool = False
    calls: list[list[str]] = field(default_factory=list)
    timeouts: list[float | None] = field(default_factory=list)
    _containers: dict[str, _Container] = field(init=False)
    _foreign: dict[str, _Container] = field(init=False)
    _slow_calls: int = field(init=False, default=0)
    tunnel: Tunnel = field(default_factory=Tunnel)
    _clock: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        project, here = compose_project_name(self.root_dir), str(self.root_dir)
        self._containers = {
            name: _Container(name, state, project, here) for name, state in self.states.items()
        }
        gluetun = self._containers.get("gluetun")
        if gluetun is not None:
            gluetun.started_at = self._now()
            gluetun.health = "healthy" if gluetun.state == "running" else "unhealthy"
        for container in self._containers.values():
            if container.service == "gluetun":
                continue
            container.started_at = self._now()
            if gluetun is not None and container.service != COMPOSE_GATE_SERVICE:
                container.joined = gluetun.container_id
        # Another Compose project on the same host, with services of the same names.
        self._foreign = {
            name: _Container(name, state, FOREIGN_PROJECT, FOREIGN_WORKING_DIR)
            for name, state in self.foreign.items()
        }

    # ── Test-facing controls ─────────────────────────────────────────

    def state(self, service: str) -> State:
        return self._containers[service].state

    def foreign_state(self, service: str) -> State:
        return self._foreign[service].state

    def relabel(
        self, service: str, *, project: str | None = None, working_dir: str | None = None
    ) -> None:
        """Give ``service``'s container other labels (a renamed project, a moved checkout)."""
        container = self._containers[service]
        if project is not None:
            container.project = project
        if working_dir is not None:
            container.working_dir = working_dir

    def set_state(self, service: str, state: State) -> None:
        self._containers[service].state = state

    def container_id(self, service: str) -> str:
        return self._containers[service].container_id

    def set_health(self, service: str, health: str | None) -> None:
        self._containers[service].health = health

    def log(self, service: str, line: str, *, at: float) -> None:
        """Append a line to ``service``'s log, as written at epoch ``at``."""
        self._containers[service].logs.append((at, line))

    def joined(self, service: str) -> str | None:
        """The gluetun container ID whose namespace ``service`` shares."""
        return self._containers[service].joined

    def slow(self, calls: int | None = None) -> None:
        """The next ``calls`` commands that need the daemon hang (all of them if None)."""
        self._slow_calls = -1 if calls is None else calls

    def on_stop(
        self,
        service: str,
        *,
        compose: StopBehaviour | None = None,
        docker: StopBehaviour | None = None,
    ) -> None:
        """Inject how ``compose stop`` and ``docker stop`` treat ``service``."""
        container = self._containers[service]
        if compose is not None:
            container.compose_stop = compose
        if docker is not None:
            container.docker_stop = docker

    # ── Runner protocol ──────────────────────────────────────────────

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del capture, env, input
        self.calls.append(list(args))
        self.timeouts.append(timeout)
        result = self._answer(list(args), timeout)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, args, result.stdout, result.stderr
            )
        return result

    # ── Model ────────────────────────────────────────────────────────

    def _answer(self, args: list[str], timeout: float | None) -> subprocess.CompletedProcess[str]:
        prefix = compose_command(self.root_dir)
        is_compose = args[: len(prefix)] == prefix
        if is_compose and self.compose_unreadable:
            return subprocess.CompletedProcess(args, 1, "", COMPOSE_UNREADABLE + "\n")
        offline = is_compose and args[len(prefix) : len(prefix) + 1] == ["config"]
        if self.unreachable and not offline:
            return subprocess.CompletedProcess(args, 1, "", DAEMON_DOWN + "\n")
        if self._slow_calls and not offline:
            if self._slow_calls > 0:
                self._slow_calls -= 1
            _hang(args, timeout)
        if args[: len(prefix)] == prefix:
            return self._compose(args, args[len(prefix) :], timeout)
        if args[:2] == ["docker", "ps"]:
            return self._docker_ps(args)
        if args[:2] == ["docker", "stop"]:
            return self._docker_stop(args, timeout)
        if args[:2] == ["docker", "inspect"]:
            return self._inspect(args)
        if args[:2] == ["docker", "exec"]:
            return self._exec(args)
        if args[:2] == ["docker", "logs"]:
            return self._logs(args)
        raise UnmodelledCommandError(f"FakeDocker does not model: {args}")

    def _compose(
        self, args: list[str], rest: list[str], timeout: float | None
    ) -> subprocess.CompletedProcess[str]:
        if rest == ["config", "--services"]:
            return _ok(args, "".join(f"{name}\n" for name in self._containers))
        if rest[:1] == ["ps"]:
            return self._ps(args, rest[1:])
        if rest[:1] == ["stop"] and all(not arg.startswith("-") for arg in rest[1:]):
            if unknown := self._unknown(args, rest[1:]):
                return unknown
            failed = False
            for name in rest[1:]:
                container = self._containers.get(name)
                if container is not None:
                    failed |= not self._stop(container, container.compose_stop, args, timeout)
            return subprocess.CompletedProcess(args, 1 if failed else 0, "", "")
        if rest in (["restart", "gluetun"], ["restart", "--no-deps", "gluetun"]):
            return self._restart_gluetun(args, with_dependents="--no-deps" not in rest)
        if rest == ["up", "-d", "--no-deps", "--force-recreate", "gluetun"]:
            return self._recreate_gluetun(args)
        if rest[:3] == ["up", "-d", "--no-deps"]:
            names = [name for name in rest[3:] if name != "--build"]
            if any(name.startswith("-") for name in names) or "gluetun" in names:
                raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
            if unknown := self._unknown(args, names):
                return unknown
            for name in names:
                self._start_in_namespace(self._containers[name])
            return _ok(args, "")
        raise UnmodelledCommandError(f"FakeDocker does not model: {args}")

    def _ps(self, args: list[str], rest: list[str]) -> subprocess.CompletedProcess[str]:
        statuses: set[str] = set()
        names: list[str] = []
        services_mode = quiet = show_all = False
        index = 0
        while index < len(rest):
            arg = rest[index]
            if arg == "--status":
                statuses.add(rest[index + 1])
                index += 2
                continue
            if arg == "--services":
                services_mode = True
            elif arg in {"-q", "--quiet"}:
                quiet = True
            elif arg in {"-a", "--all"}:
                show_all = True
            elif arg in {"-aq", "-qa"}:
                quiet = show_all = True
            elif arg.startswith("-"):
                raise UnmodelledCommandError(f"FakeDocker does not model ps option {arg}: {args}")
            else:
                names.append(arg)
            index += 1
        if services_mode == quiet:
            raise UnmodelledCommandError(f"FakeDocker models ps --services or -q: {args}")
        if unknown := self._unknown(args, names):
            return unknown
        if statuses:
            shown = statuses
        elif show_all:
            shown = {"running", "restarting", "paused", "removing", "exited", "created"}
        else:
            shown = set(_LISTED_WITHOUT_ALL)
        selected = sorted(
            (
                container
                for name, container in self._containers.items()
                if (not names or name in names) and container.state in shown
            ),
            key=lambda container: container.service,
        )
        lines = (c.service if services_mode else c.container_id for c in selected)
        return _ok(args, "".join(f"{line}\n" for line in lines))

    def _docker_stop(
        self, args: list[str], timeout: float | None
    ) -> subprocess.CompletedProcess[str]:
        if len(args) != 5 or args[2] != "-t":
            raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
        container = self._by_id(args[4])
        if container is None:
            return subprocess.CompletedProcess(
                args, 1, "", f"Error: No such container: {args[4]}\n"
            )
        ok = self._stop(container, container.docker_stop, args, timeout)
        return subprocess.CompletedProcess(args, 0 if ok else 1, f"{args[4]}\n" if ok else "", "")

    def _inspect(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if len(args) < 5 or args[2] != "--format":
            raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
        if args[3] == NAMESPACE_FORMAT:
            return self._inspect_namespace(args)
        if len(args) != 5:
            raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
        container = self._by_id(args[4])
        if container is None:
            return subprocess.CompletedProcess(args, 1, "", f"Error: No such object: {args[4]}\n")
        if args[3] == "{{.State.Running}}":
            return _ok(args, "true\n" if container.state in _HOLDS_A_PROCESS else "false\n")
        if args[3] == "{{.State.Status}}":
            return _ok(args, f"{container.state}\n")
        if args[3] == GLUETUN_STATE_FORMAT:
            if container.health is None:
                return subprocess.CompletedProcess(args, 1, "", NO_HEALTHCHECK + "\n")
            return _ok(args, f"{container.health}|{container.started_at}\n")
        raise UnmodelledCommandError(f"FakeDocker does not model inspect format: {args}")

    def _stop(
        self,
        container: _Container,
        behaviour: StopBehaviour,
        args: list[str],
        timeout: float | None,
    ) -> bool:
        if behaviour == "hangs":
            _hang(args, timeout)
        if behaviour == "fails":
            return False
        if behaviour == "stops" and container.state in _HOLDS_A_PROCESS:
            container.state = "exited"
        # "comes-back": exit 0, and the container is as active as before.
        return True

    def _unknown(
        self, args: list[str], names: list[str]
    ) -> subprocess.CompletedProcess[str] | None:
        missing = next((name for name in names if name not in self._containers), None)
        if missing is None:
            return None
        return subprocess.CompletedProcess(args, 1, "", f"no such service: {missing}\n")

    def _docker_ps(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if (
            len(args) != 7
            or args[:4] != ["docker", "ps", "--no-trunc", "--filter"]
            or not args[4].startswith(f"label={SERVICE_LABEL}=")
            or args[5:] != ["--format", COMPOSE_LABELS_FORMAT]
        ):
            raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
        service = args[4].split("=", 2)[2]
        matches = sorted(
            (
                container
                for container in (*self._containers.values(), *self._foreign.values())
                if container.service == service and container.state in _LISTED_WITHOUT_ALL
            ),
            key=lambda container: container.container_id,
        )
        lines = (f"{c.container_id}\t{c.project}\t{c.working_dir}\n" for c in matches)
        return _ok(args, "".join(lines))

    def _inspect_namespace(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        lines: list[str] = []
        for container_id in args[4:]:
            container = self._by_id(container_id)
            if container is None:
                return subprocess.CompletedProcess(
                    args, 1, "".join(lines), f"Error: No such object: {container_id}\n"
                )
            running = "true" if container.state in _HOLDS_A_PROCESS else "false"
            network = f"container:{container.joined}" if container.joined else "none"
            lines.append(f"{container.container_id}|{running}|{container.started_at}|{network}\n")
        return _ok(args, "".join(lines))

    def _exec(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        container = self._by_id(args[2]) if len(args) > 3 else None
        if container is None:
            return subprocess.CompletedProcess(
                args, 1, "", f"Error: No such container: {args[2]}\n"
            )
        if container.state not in {"running"}:
            return subprocess.CompletedProcess(
                args, 1, "", f"Error response from daemon: container {args[2]} is not running\n"
            )
        command = args[3:]
        if container.service == "gluetun" and command == ["iptables", "-S", "OUTPUT"]:
            rules = ["-P OUTPUT DROP"]
            if self.tunnel.dns_block:
                rules.append(DNS_BLOCK_RULE)
            rules.append("-A OUTPUT -o lo -j ACCEPT")
            return _ok(args, "\n".join(rules) + "\n")
        if container.service == "gluetun" and "wget" in command:
            if command[-1] == CONTROL_SERVER_URL and "-O-" in command:
                if self.tunnel.control_ip is None:
                    return subprocess.CompletedProcess(args, 1, "", "wget: download timed out\n")
                return _ok(args, f'{{"public_ip":"{self.tunnel.control_ip}"}}\n')
            if "-qO-" in command:
                if self.tunnel.egress_ip is None:
                    return subprocess.CompletedProcess(args, 1, "", "wget: download timed out\n")
                return _ok(args, f"{self.tunnel.egress_ip}\n")
        raise UnmodelledCommandError(f"FakeDocker does not model: {args}")

    def _logs(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if len(args) != 5 or args[2] not in {"--tail", "--since"}:
            raise UnmodelledCommandError(f"FakeDocker does not model: {args}")
        container = self._by_id(args[4])
        if container is None:
            return subprocess.CompletedProcess(
                args, 1, "", f"Error: No such container: {args[4]}\n"
            )
        if args[2] == "--tail":
            lines = [line for _, line in container.logs][-int(args[3]) :]
        else:
            lines = [line for at, line in container.logs if at >= float(args[3])]
        return _ok(args, "".join(f"{line}\n" for line in lines))

    def _now(self) -> str:
        self._clock += 1
        return f"2026-11-19T10:{self._clock // 60:02d}:{self._clock % 60:02d}.000000000Z"

    def _restart_gluetun(
        self, args: list[str], *, with_dependents: bool
    ) -> subprocess.CompletedProcess[str]:
        gluetun = self._containers["gluetun"]
        gluetun.state, gluetun.started_at, gluetun.health = "running", self._now(), "starting"
        if with_dependents:
            for container in self._containers.values():
                if container.joined == gluetun.container_id:
                    container.state, container.started_at = "running", self._now()
        return _ok(args, "")

    def _recreate_gluetun(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        gluetun = self._containers["gluetun"]
        gluetun.generation += 1
        gluetun.state, gluetun.started_at, gluetun.health = "running", self._now(), "starting"
        gluetun.logs = []
        return _ok(args, "")

    def _start_in_namespace(self, container: _Container) -> None:
        gluetun = self._containers.get("gluetun")
        current = gluetun.container_id if gluetun is not None else None
        recreated = container.joined != current  # attached to an older namespace
        if recreated:
            container.generation += 1
            container.joined = current
        if recreated or container.state not in _HOLDS_A_PROCESS:
            container.started_at = self._now()
        container.state = "running"

    def _by_id(self, container_id: str) -> _Container | None:
        return next(
            (
                c
                for c in (*self._containers.values(), *self._foreign.values())
                if c.container_id == container_id
            ),
            None,
        )


def _hang(args: list[str], timeout: float | None) -> NoReturn:
    if timeout is None:
        raise UnmodelledCommandError(
            f"{args} has no timeout and Docker never answers: this would block forever"
        )
    raise subprocess.TimeoutExpired(args, timeout)


def _ok(args: list[str], stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, 0, stdout, "")
