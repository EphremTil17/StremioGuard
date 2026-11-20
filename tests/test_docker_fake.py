"""FakeDocker's own guarantees: it never answers what it does not model.

Its recorded behaviour is checked against real Docker by
test_docker_fake_contract_docker.py; these check the failure modes a test
relies on to fail loudly instead of passing on an invented answer.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from stremioguard.config import compose_command
from tests.docker_fake import FakeDocker, UnmodelledCommandError


def test_an_unmodelled_command_fails_the_test(tmp_path: Path) -> None:
    docker = FakeDocker(tmp_path, {"gluetun": "running"})
    with pytest.raises(UnmodelledCommandError):
        docker.run(compose_command(tmp_path, "logs", "gluetun"))
    with pytest.raises(UnmodelledCommandError):
        docker.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", docker.container_id("gluetun")]
        )


def test_a_hanging_stop_without_a_timeout_fails_the_test(tmp_path: Path) -> None:
    docker = FakeDocker(tmp_path, {"gluetun": "restarting"})
    docker.on_stop("gluetun", compose="hangs")
    stop = compose_command(tmp_path, "stop", "gluetun")
    with pytest.raises(UnmodelledCommandError, match="block forever"):
        docker.run(stop)
    with pytest.raises(subprocess.TimeoutExpired):
        docker.run(stop, timeout=30)
    assert docker.state("gluetun") == "restarting"


def test_check_raises_like_the_real_runner(tmp_path: Path) -> None:
    docker = FakeDocker(tmp_path, {"gluetun": "running"}, unreachable=True)
    query = compose_command(tmp_path, "ps", "-q", "gluetun")
    assert docker.run(query).returncode == 1
    with pytest.raises(subprocess.CalledProcessError):
        docker.run(query, check=True)
    # Reading the Compose file needs no daemon.
    assert docker.run(compose_command(tmp_path, "config", "--services")).stdout == "gluetun\n"
