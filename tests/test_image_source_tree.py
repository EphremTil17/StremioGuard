"""Tests for Comet image source tree verification and safe diagnostic reads."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from stremioguard.comet.manager import CometManager, extract_image_source
from tests.conftest import FakeRunner, completed, make_comet_config


def _write_clean_tree(source_root: Path) -> None:
    app = source_root / "comet" / "api" / "app.py"
    app.parent.mkdir(parents=True, exist_ok=True)
    app.write_text("print('clean')\n", encoding="utf-8")


class _CpFixtureRunner:
    """Fake runner that populates source_root on `docker cp` via a caller callback."""

    def __init__(self, container_id: str, populate: Callable[[Path], None]) -> None:
        self.container_id = container_id
        self.populate = populate
        self.calls: list[list[str]] = []

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
        self.calls.append(args)
        if args[:2] == ["docker", "create"]:
            return completed(args, f"{self.container_id}\n")
        if args[:2] == ["docker", "cp"]:
            self.populate(Path(args[3]))
            return completed(args)
        return completed(args)


# --- AC-10: extract_image_source tree verification --------------------------


@pytest.mark.parametrize(
    ("kind_expected", "setup_fn"),
    [
        (
            "symlink",
            lambda root, canary: (
                (root / "comet" / "api" / "endpoints").mkdir(parents=True, exist_ok=True),
                (root / "comet" / "api" / "endpoints" / "stream.py").symlink_to(canary),
            ),
        ),
        (
            "symlink",
            lambda root, canary: (
                (root / "comet" / "api").mkdir(parents=True, exist_ok=True),
                (root / "comet" / "api" / "rel_escape.py").symlink_to(Path("../../../canary.txt")),
            ),
        ),
        (
            "symlink",
            lambda root, _canary: (
                (root / "comet" / "api").mkdir(parents=True, exist_ok=True),
                (root / "comet" / "api" / "target.py").write_text("ok\n", encoding="utf-8"),
                (root / "comet" / "api" / "in_tree.py").symlink_to("target.py"),
            ),
        ),
        (
            "symlink",
            lambda root, canary: (
                (root / "comet").mkdir(parents=True, exist_ok=True),
                (root / "comet" / "dir_link").symlink_to(canary.parent),
            ),
        ),
        (
            "symlink",
            lambda root, canary: (
                (valid := canary.parent / "valid_comet_target").mkdir(exist_ok=True),
                (valid / "app.py").write_text("SGCANARY_SECRET\n", encoding="utf-8"),
                (root / "comet").symlink_to(valid),
            ),
        ),
        (
            "FIFO",
            lambda root, _canary: (
                (root / "comet").mkdir(parents=True, exist_ok=True),
                os.mkfifo(root / "comet" / "pipe"),
            ),
        ),
        (
            "socket",
            lambda root, _canary: (
                (root / "comet").mkdir(parents=True, exist_ok=True),
                _bind_unix_socket(root / "comet" / "sock"),
            ),
        ),
        (
            "hard link",
            lambda root, _canary: (
                (root / "comet").mkdir(parents=True, exist_ok=True),
                (root / "comet" / "a.py").write_text("x = 1\n", encoding="utf-8"),
                os.link(root / "comet" / "a.py", root / "comet" / "b.py"),
            ),
        ),
        (
            "unreadable directory",
            lambda root, canary: (
                (locked := root / "comet" / "locked").mkdir(parents=True, exist_ok=True),
                (locked / "secret.py").symlink_to(canary),
                locked.chmod(0o111),
            ),
        ),
    ],
    ids=[
        "abs_symlink",
        "rel_escape_symlink",
        "in_tree_symlink",
        "dir_symlink",
        "comet_root_symlink",
        "fifo",
        "socket",
        "hard_link",
        "mode_0111_dir",
    ],
)
def test_ac10_extract_image_source_refuses_hostile_entries(
    tmp_path: Path, kind_expected: str, setup_fn: Callable[[Path, Path], object]
) -> None:
    """AC-10 / INV-7 / D8: every hostile entry kind is refused before yield and cleaned up."""
    canary_dir = tmp_path / "canary_dir"
    canary_dir.mkdir()
    canary = canary_dir / "canary.txt"
    canary.write_text("SGCANARY_HOST_SECRET\n", encoding="utf-8")

    observed_temp_root: Path | None = None
    body_entered = False

    def populate(source_root: Path) -> None:
        nonlocal observed_temp_root
        observed_temp_root = source_root.parent
        setup_fn(source_root, canary)

    runner = _CpFixtureRunner("ctr-hostile-1", populate)
    with (
        pytest.raises(RuntimeError) as exc_info,
        extract_image_source(runner, "g0ldyy/comet@sha256:" + "a" * 64),
    ):
        body_entered = True

    assert body_entered is False
    message = str(exc_info.value)
    assert kind_expected in message
    assert "SGCANARY" not in message
    assert str(canary) not in message
    assert ["docker", "rm", "-f", "ctr-hostile-1"] in runner.calls
    assert observed_temp_root is not None and not observed_temp_root.exists()


def _bind_unix_socket(path: Path) -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
    finally:
        sock.close()


def test_ac10_hostile_name_with_terminal_escapes_is_escaped(tmp_path: Path) -> None:
    """AC-10 / INV-8: hostile filename with ESC and newline is escaped via ascii()."""
    canary = tmp_path / "canary.txt"
    canary.write_text("SECRET\n", encoding="utf-8")

    def populate(source_root: Path) -> None:
        (source_root / "comet").mkdir(parents=True, exist_ok=True)
        (source_root / "comet" / "\x1b[31m\nbad.py").symlink_to(canary)

    runner = _CpFixtureRunner("ctr-esc-1", populate)
    with (
        pytest.raises(RuntimeError) as exc_info,
        extract_image_source(runner, "g0ldyy/comet@sha256:" + "a" * 64),
    ):
        pass

    message = str(exc_info.value)
    assert "\x1b" not in message
    assert "\n" not in message
    assert "\\x1b[31m\\nbad.py" in message
    assert "symlink" in message


def test_ac10_clean_tree_yields_and_cleans_up() -> None:
    """AC-10 regression: clean tree of directories and single-link regular files yields normally."""
    runner = _CpFixtureRunner("ctr-clean-1", _write_clean_tree)
    with extract_image_source(runner, "g0ldyy/comet@sha256:" + "a" * 64) as source_root:
        assert (source_root / "comet" / "api" / "app.py").is_file()
        temp_root = source_root.parent
    assert not temp_root.exists()
    assert ["docker", "rm", "-f", "ctr-clean-1"] in runner.calls


# --- AC-12: _compatibility_diagnostic safe read ---------------------------


def _manager_for_diag(tmp_path: Path) -> CometManager:
    cfg = make_comet_config(tmp_path)
    image_ref = cfg.image
    inspect_cmd = ["docker", "image", "inspect", image_ref, "--format", "{{json .RepoDigests}}"]
    runner = FakeRunner(
        {
            tuple(inspect_cmd): completed(
                inspect_cmd,
                '["g0ldyy/comet@sha256:' + "a" * 64 + '"]\n',
            )
        }
    )
    return CometManager(cfg, runner)


def test_ac12_diagnostic_never_follows_symlinks_or_blocks_on_fifo(tmp_path: Path) -> None:
    """AC-12 / INV-8 / D9: diagnostic refuses symlinks at any level, skips FIFOs, bounds reads."""
    manager = _manager_for_diag(tmp_path)
    canary = tmp_path / "canary_host_secret.txt"
    canary.write_text("SGCANARY_DIAG_SECRET\n", encoding="utf-8")

    # (a) Target file itself is a symlink to a canary.
    root_a = tmp_path / "root_a"
    target_a = root_a / "comet" / "api" / "endpoints" / "stream.py"
    target_a.parent.mkdir(parents=True)
    target_a.symlink_to(canary)
    diag_a = manager._compatibility_diagnostic(RuntimeError("stream anchor missing"), root_a)
    assert "SGCANARY" not in diag_a

    # (b) Intermediate directory is a symlink to a canary tree.
    canary_tree = tmp_path / "canary_tree"
    (canary_tree / "endpoints").mkdir(parents=True)
    (canary_tree / "endpoints" / "stream.py").write_text("SGCANARY_TREE\n", encoding="utf-8")
    root_b = tmp_path / "root_b"
    (root_b / "comet").mkdir(parents=True)
    (root_b / "comet" / "api").symlink_to(canary_tree)
    diag_b = manager._compatibility_diagnostic(RuntimeError("stream anchor missing"), root_b)
    assert "SGCANARY" not in diag_b

    # (c) Target file is a FIFO: must return promptly without blocking.
    root_c = tmp_path / "root_c"
    target_c = root_c / "comet" / "api" / "endpoints" / "stream.py"
    target_c.parent.mkdir(parents=True)
    os.mkfifo(target_c)
    t0 = time.monotonic()
    diag_c = manager._compatibility_diagnostic(RuntimeError("stream anchor missing"), root_c)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert "not a regular file" in diag_c

    # (d) 5 MB file with no newline: bounded to <= 64 KiB read -> result < 70,000 chars.
    root_d = tmp_path / "root_d"
    target_d = root_d / "comet" / "api" / "endpoints" / "stream.py"
    target_d.parent.mkdir(parents=True)
    target_d.write_bytes(b"A" * (5 * 1024 * 1024))
    diag_d = manager._compatibility_diagnostic(RuntimeError("stream anchor missing"), root_d)
    assert len(diag_d) < 70000

    # (e) Normal file shows the first 30 lines as before.
    root_e = tmp_path / "root_e"
    target_e = root_e / "comet" / "api" / "endpoints" / "stream.py"
    target_e.parent.mkdir(parents=True)
    target_e.write_text("\n".join(f"line {i}" for i in range(1, 51)) + "\n", encoding="utf-8")
    diag_e = manager._compatibility_diagnostic(RuntimeError("stream anchor missing"), root_e)
    assert "line 1\n" in diag_e
    assert "line 30" in diag_e
    assert "line 31" not in diag_e
