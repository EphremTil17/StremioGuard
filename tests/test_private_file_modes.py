"""`./stremio start` makes older StremioGuard files owner-only (F-16)."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from pathlib import Path
from unittest import mock

from stremioguard.env import tighten_private_files
from stremioguard.guard import GluetunGuard
from tests.conftest import FakeRunner, make_config


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_older_files_lose_group_and_other_access(tmp_path: Path) -> None:
    state = tmp_path / ".stremio"
    state.mkdir(mode=0o700)
    for name, mode in (("home-ip", 0o644), ("watchdog.instance.lock", 0o664), ("odd", 0o755)):
        (state / name).write_text("x\n")
        (state / name).chmod(mode)
    (state / "already").write_text("x\n")
    (state / "already").chmod(0o600)

    assert tighten_private_files(state) == ["home-ip", "odd", "watchdog.instance.lock"]
    assert _mode(state / "home-ip") == 0o600
    assert _mode(state / "watchdog.instance.lock") == 0o600
    assert _mode(state / "odd") == 0o700  # owner bits kept, the rest removed
    assert _mode(state / "already") == 0o600
    assert tighten_private_files(state) == []  # idempotent


def test_symlinks_subdirectories_and_fifos_are_left_alone(tmp_path: Path) -> None:
    state = tmp_path / ".stremio"
    state.mkdir(mode=0o700)
    outside = tmp_path / "outside.txt"
    outside.write_text("not ours to change\n")
    outside.chmod(0o644)
    (state / "link").symlink_to(outside)
    (state / "comet").mkdir(mode=0o755)
    (state / "comet" / "data.txt").write_text("x\n")
    (state / "comet" / "data.txt").chmod(0o644)
    os.mkfifo(state / "pipe", 0o644)

    started = time.monotonic()
    assert tighten_private_files(state) == []
    assert time.monotonic() - started < 2.0
    assert _mode(outside) == 0o644
    assert _mode(state / "comet") == 0o755
    assert _mode(state / "comet" / "data.txt") == 0o644
    assert stat.S_ISFIFO(os.lstat(state / "pipe").st_mode)


def test_a_missing_directory_is_not_an_error(tmp_path: Path) -> None:
    assert tighten_private_files(tmp_path / "absent") == []


def test_start_preflight_tightens_state_and_log_files() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".env").write_text(
            "STREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
            encoding="utf-8",
        )
        config = make_config(root, log_file=root / "logs" / "stremio-now.log")
        state_dir = config.vpn_lockout_file.parent
        state_dir.mkdir(parents=True, exist_ok=True)
        (state_dir / "daemon-id").write_text("x\n")
        (state_dir / "daemon-id").chmod(0o644)
        assert config.log_file is not None
        config.log_file.parent.mkdir(parents=True, exist_ok=True)
        old_log = config.log_file.parent / "stremio-old.log"
        old_log.write_text("x\n")
        old_log.chmod(0o644)
        guard = GluetunGuard(config, FakeRunner({}))
        with (
            mock.patch.object(guard, "require_commands"),
            mock.patch.object(guard, "check_bind_addresses"),
            mock.patch.object(guard, "wait_for_gluetun_healthy"),
            mock.patch.object(guard, "public_ip_safe", return_value=True),
            mock.patch.object(guard, "compose"),
            mock.patch.object(guard, "compose_fresh"),
        ):
            guard.preflight()
        assert _mode(state_dir / "daemon-id") == 0o600
        assert _mode(old_log) == 0o600


def _stremio_guard(root: Path, env: str) -> GluetunGuard:
    (root / ".env").write_text(env, encoding="utf-8")
    return GluetunGuard(make_config(root), FakeRunner({}))


def test_stremio_without_credentials_is_refused(tmp_path: Path) -> None:
    import pytest

    for env in (
        "STREMIO_ENABLED=1\n",
        "STREMIO_ENABLED=1\nSTREMIO_USERNAME=me\n",
        "STREMIO_ENABLED=1\nSTREMIO_USERNAME=me\nSTREMIO_PASSWORD=short\n",
        "STREMIO_USERNAME=me\nSTREMIO_PASSWORD=long-enough-pass\n".replace("me\n", "\n", 1),
        "",  # Stremio is on by default
    ):
        with pytest.raises(RuntimeError, match="STREMIO_PASSWORD"):
            _stremio_guard(tmp_path, env).check_stremio_auth()


def test_stremio_with_credentials_disabled_or_opted_out_passes(tmp_path: Path) -> None:
    for env in (
        "STREMIO_USERNAME=me\nSTREMIO_PASSWORD=long-enough-pass\n",
        "STREMIO_ENABLED=0\n",
        "STREMIO_ALLOW_NO_AUTH=1\n",
    ):
        guard = _stremio_guard(tmp_path, env)
        with mock.patch.object(guard, "warn") as warn:
            guard.check_stremio_auth()
        assert warn.called == ("ALLOW" in env)


def test_stremio_must_publish_the_port_where_auth_applies(tmp_path: Path) -> None:
    import pytest

    creds = "STREMIO_USERNAME=me\nSTREMIO_PASSWORD=long-enough-pass\n"
    with pytest.raises(RuntimeError, match="publishes a port without auth"):
        _stremio_guard(tmp_path, creds + "STREMIO_CONTAINER_PORT=11470\n").check_stremio_auth()
    _stremio_guard(tmp_path, creds + "STREMIO_CONTAINER_PORT=8080\n").check_stremio_auth()
    guard = _stremio_guard(tmp_path, "STREMIO_ALLOW_NO_AUTH=1\nSTREMIO_CONTAINER_PORT=11470\n")
    with mock.patch.object(guard, "warn"):
        guard.check_stremio_auth()
