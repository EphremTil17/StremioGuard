#!/usr/bin/env python3
"""Were the lines a fix changed already executed by tests that passed before it?

For each fix commit, export its parent into a temporary directory, build a
throwaway venv there, run the default test suite under ``coverage``, and count
the fix's hunks whose pre-fix executable lines were executed. A high ratio
means the suite ran the defective code without asserting the property the fix
restored: coverage measured execution, not detection.

A "fix site" is one diff hunk in ``src/stremioguard`` with at least one
executable line on the parent side (a pure insertion is anchored to the lines
around it). Hunks include any refactoring that landed with the fix, so the
ratio is an approximation. Files that run only inside the Comet image (for
example ``overrides/stream_guard.py``) show as unexecuted, as in the unit
coverage map.

Nothing in the working tree changes. Docker and systemd suites stay off.

Usage:
    uv run python scripts/fix_site_coverage.py                      # fix: commits touching src/
    uv run python scripts/fix_site_coverage.py 284339d 04cc9e4      # chosen commits
    uv run python scripts/fix_site_coverage.py --since v0.4.0 --jobs 3
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = "src/stremioguard"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? ")


@dataclass
class Result:
    commit: str
    parent: str
    suite: str
    executed: int = 0
    sites: int = 0
    per_file: dict[str, list[int]] = field(default_factory=dict)
    error: str = ""


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], check=True, capture_output=True, text=True
    ).stdout


def default_commits(since: str | None) -> list[str]:
    rev = f"{since}..HEAD" if since else "HEAD"
    out = git("log", "--format=%h %s", rev, "--", SRC)
    commits = []
    for line in out.splitlines():
        sha, _, subject = line.partition(" ")
        if re.match(r"fix(\(|:|!)", subject):
            commits.append(sha)
    return commits


def hunks(parent: str, commit: str) -> list[tuple[str, list[int]]]:
    """(file relative to SRC, parent-side line numbers) for each Python hunk."""
    out = git("diff", "-U0", parent, commit, "--", SRC)
    found: list[tuple[str, list[int]]] = []
    current: str | None = None
    for line in out.splitlines():
        if line.startswith("--- "):
            current = line[len(f"--- a/{SRC}/") :] if line.startswith(f"--- a/{SRC}/") else None
            continue
        m = HUNK.match(line)
        if m and current and current.endswith(".py"):
            start, count = int(m.group(1)), int(m.group(2) or 1)
            found.append(
                (current, list(range(start, start + count)) if count else [start, start + 1])
            )
    return found


def statements(parent: str, rel: str) -> set[int]:
    from coverage.parser import PythonParser

    try:
        source = git("show", f"{parent}:{SRC}/{rel}")
        parser = PythonParser(text=source)
        parser.parse_source()
        return set(parser.statements)
    except Exception:  # unparsable or missing at the parent: no executable sites
        return set()


def run_parent_suite(commit: str, workdir: Path) -> Result:
    parent = git("rev-parse", "--short", f"{commit}^").strip()
    result = Result(commit=commit, parent=parent, suite="")
    tree, venv, data = (
        workdir / f"tree-{commit}",
        workdir / f"venv-{commit}",
        workdir / f"{commit}.cov",
    )
    tree.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", parent], check=True, capture_output=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(tree)], input=archive, check=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if k != "VIRTUAL_ENV" and not k.startswith("STREMIOGUARD_")
    }
    env["UV_PROJECT_ENVIRONMENT"] = str(venv)
    sync = subprocess.run(
        ["uv", "sync", "--frozen", "--quiet"], cwd=tree, env=env, capture_output=True, text=True
    )
    if sync.returncode:
        result.error = f"uv sync failed: {sync.stderr.strip()[-300:]}"
        return result
    python = str(venv / "bin" / "python")
    subprocess.run(
        ["uv", "pip", "install", "--quiet", "--python", python, "coverage"],
        cwd=tree,
        env=env,
        check=True,
        capture_output=True,
    )
    env["COVERAGE_FILE"] = str(data)
    run = subprocess.run(
        [
            python,
            "-m",
            "coverage",
            "run",
            "--branch",
            f"--source={SRC}",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--no-header",
        ],
        cwd=tree,
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    result.suite = (run.stdout.strip().splitlines() or ["(no output)"])[-1]

    from coverage import CoverageData

    cov = CoverageData(str(data))
    cov.read()
    executed = {f.split(f"/{SRC}/")[-1]: set(cov.lines(f) or []) for f in cov.measured_files()}
    cache: dict[str, set[int]] = {}
    for rel, lines in hunks(parent, commit):
        stmts = cache.setdefault(rel, statements(parent, rel))
        live = [n for n in lines if n in stmts]
        if not live:
            continue
        hit = any(n in executed.get(rel, set()) for n in live)
        counts = result.per_file.setdefault(rel, [0, 0])
        counts[0] += hit
        counts[1] += 1
        result.executed += hit
        result.sites += 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "commits", nargs="*", help="fix commits (default: fix: commits touching src/)"
    )
    parser.add_argument("--since", help="with no commits given, only fixes after this revision")
    parser.add_argument(
        "--jobs", type=int, default=3, help="parent suites run in parallel (default 3)"
    )
    args = parser.parse_args()

    commits = args.commits or default_commits(args.since)
    if not commits:
        print("no fix commits found", file=sys.stderr)
        return 1
    with (
        tempfile.TemporaryDirectory(prefix="fix-site-coverage-") as tmp,
        ThreadPoolExecutor(max_workers=args.jobs) as pool,
    ):
        results = list(pool.map(lambda c: run_parent_suite(c, Path(tmp)), commits))

    total_hit = total = 0
    for r in results:
        if r.error:
            print(f"{r.commit} (parent {r.parent}): {r.error}")
            continue
        files = ", ".join(f"{f} {a}/{b}" for f, (a, b) in sorted(r.per_file.items()))
        sites = f"{r.executed}/{r.sites} fix sites executed"
        print(f"{r.commit} (parent {r.parent}): {sites}  [{r.suite}]")
        if files:
            print(f"    {files}")
        total_hit += r.executed
        total += r.sites
    if total:
        share = f"{total_hit}/{total} fix sites ({100 * total_hit / total:.0f}%)"
        print(f"\nTOTAL: {share} were executed by passing tests before the fix")
    return 0


if __name__ == "__main__":
    sys.exit(main())
