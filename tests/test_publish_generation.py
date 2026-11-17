"""A publish is one generation: cut short at any point, it never runs as a mix."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from stremioguard import publishing
from stremioguard.config import (
    GENERATION_FILES,
    PUBLISHED_GENERATION_FILE,
    compose_command,
    generation_problem,
)
from stremioguard.guard import GluetunGuard
from stremioguard.publishing import StackPublisher
from tests.conftest import (
    FakeRunner,
    completed,
    make_comet_config,
    make_comet_gateway_config,
    make_config,
)

WRITTEN = (*GENERATION_FILES, PUBLISHED_GENERATION_FILE)


def _publish(root: Path) -> None:
    with (
        mock.patch(
            "stremioguard.publishing.CometConfig.from_env",
            return_value=make_comet_config(root, enabled=False),
        ),
        mock.patch(
            "stremioguard.publishing.CometGatewayConfig.from_env",
            return_value=make_comet_gateway_config(root, enabled=False),
        ),
    ):
        StackPublisher(root).publish()


def _generation(root: Path, n: int) -> None:
    (root / ".env").write_text(f"STREMIO_BIND_ADDRS=127.0.0.{n}\nGEN={n}\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text(
        f"services:\n  gluetun: {{}}\n# generation {n}\n", encoding="utf-8"
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {name: (root / name).read_bytes() for name in GENERATION_FILES}


def test_a_complete_publish_is_one_generation(tmp_path: Path) -> None:
    _generation(tmp_path, 1)
    _publish(tmp_path)
    assert all((tmp_path / name).exists() for name in WRITTEN)
    assert generation_problem(tmp_path) is None
    # Republishing unchanged inputs keeps it valid.
    _publish(tmp_path)
    assert generation_problem(tmp_path) is None


@pytest.mark.parametrize("fail_at", range(1, len(WRITTEN) + 1))
def test_a_publish_cut_short_never_passes_as_a_generation(tmp_path: Path, fail_at: int) -> None:
    _generation(tmp_path, 1)
    _publish(tmp_path)
    first = _snapshot(tmp_path)
    _generation(tmp_path, 2)  # every generation file differs from here on

    real_write = publishing.atomic_write_text
    seen: list[str] = []

    def full_disk(path: Path, content: str, *, mode: int = 0o600) -> None:
        name = str(Path(path).relative_to(tmp_path))
        if name in WRITTEN:
            seen.append(name)
            if len(seen) == fail_at:
                raise OSError(28, "No space left on device")
        real_write(path, content, mode=mode)

    with (
        mock.patch.object(publishing, "atomic_write_text", full_disk),
        pytest.raises(OSError, match="No space"),
    ):
        _publish(tmp_path)
    assert seen[-1] == WRITTEN[fail_at - 1]

    now = _snapshot(tmp_path)
    if now == first:
        assert generation_problem(tmp_path) is None  # nothing changed: still the old one
    else:
        assert generation_problem(tmp_path) is not None, f"mixed generation accepted at {fail_at}"

    # The frozen watchdog refuses to start from a mix, before running anything;
    # stopping still works.
    stop = compose_command(tmp_path, "stop", "stremio")
    runner = FakeRunner({tuple(stop): completed(stop)})
    guard = GluetunGuard(make_config(tmp_path), runner, frozen=True)
    if now != first:
        with pytest.raises(RuntimeError, match="not one complete generation"):
            guard.compose_fresh("up", "-d", "--no-deps", "stremio")
        assert runner.calls == []
    assert guard.compose("stop", "stremio", check=False).returncode == 0

    # The deliberate fix: publish again.
    _publish(tmp_path)
    assert generation_problem(tmp_path) is None


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        (lambda m: m.unlink(), "is missing"),
        (lambda m: m.write_bytes(b""), "malformed"),
        (lambda m: m.write_bytes(b"{not json"), "malformed"),
        (lambda m: m.write_bytes(b"\xff\xfe"), "malformed"),
        (lambda m: m.write_text('{"version": 2, "files": {}}'), "malformed"),
        (lambda m: m.write_text('{"version": 1, "files": {"../x": "y"}}'), "malformed"),
        (lambda m: m.write_text('{"version": 1, "files": []}'), "malformed"),
        (lambda m: m.write_text('{"version": 1, "files": {}}'), "not part of"),
        (lambda m: (m.unlink(), os.mkfifo(m)), "not a readable regular file"),
    ],
)
def test_a_damaged_manifest_is_refused(tmp_path: Path, damage, expected: str) -> None:  # type: ignore[no-untyped-def]
    _generation(tmp_path, 1)
    _publish(tmp_path)
    damage(tmp_path / PUBLISHED_GENERATION_FILE)
    problem = generation_problem(tmp_path)
    assert problem is not None and expected in problem


def test_a_generation_file_edited_by_hand_is_refused(tmp_path: Path) -> None:
    _generation(tmp_path, 1)
    _publish(tmp_path)
    for name in GENERATION_FILES:
        path = tmp_path / name
        original = path.read_bytes()
        path.write_bytes(original + b"# edited\n")
        problem = generation_problem(tmp_path)
        assert problem is not None and name in problem
        path.write_bytes(original)
    assert generation_problem(tmp_path) is None
    (tmp_path / GENERATION_FILES[0]).unlink()
    assert "missing" in str(generation_problem(tmp_path))
