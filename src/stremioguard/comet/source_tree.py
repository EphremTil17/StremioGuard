"""Verification of Comet source trees copied out of container images."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _entry_kind(st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return "device"
    if stat.S_ISREG(mode):
        return "hard link" if st.st_nlink != 1 else "regular file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "special file"


def verify_image_source_tree(source_root: Path) -> None:
    """Verify ``source_root`` holds only real directories and single-link regular files."""
    comet_root = source_root / "comet"
    try:
        root_stat = os.lstat(comet_root)
    except OSError as error:
        raise RuntimeError(
            f"Refusing image source tree: {ascii('comet')} could not be inspected "
            f"({error.strerror or type(error).__name__})."
        ) from error
    if not stat.S_ISDIR(root_stat.st_mode):
        raise RuntimeError(
            f"Refusing image source tree: {ascii('comet')} is a {_entry_kind(root_stat)}, "
            "expected a directory."
        )

    pending: list[Path] = [source_root]
    while pending:
        current = pending.pop()
        rel_dir = "." if current == source_root else current.relative_to(source_root).as_posix()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda entry: entry.name)
        except OSError as error:
            raise RuntimeError(
                f"Refusing image source tree: {ascii(rel_dir)} is an unreadable directory "
                f"({error.strerror or type(error).__name__})."
            ) from error

        subdirs: list[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            rel_path = entry_path.relative_to(source_root).as_posix()
            try:
                st = os.lstat(entry_path)
            except OSError as error:
                raise RuntimeError(
                    f"Refusing image source tree: {ascii(rel_path)} could not be inspected "
                    f"({error.strerror or type(error).__name__})."
                ) from error
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                subdirs.append(entry_path)
                continue
            if stat.S_ISREG(mode) and st.st_nlink == 1:
                continue
            raise RuntimeError(
                f"Refusing image source tree: {ascii(rel_path)} is a {_entry_kind(st)}."
            )
        pending.extend(reversed(subdirs))
