#!/usr/bin/env python3
"""Which tests execute exactly the same code as another test, and which are irreplaceable?

Runs the default suite once with per-test coverage contexts (branch arcs) into a
temporary directory, then reports:

- groups of tests whose arc footprints are identical;
- tests whose footprint is a strict subset of one other test's;
- tests that are the only one to execute some arc (keep these);
- how many tests reach each module.

Identical or subset footprints are *candidates* for redundancy, not proof:
two tests can run the same path with different inputs and different
assertions (deliberate for canonicalisation cases such as line separators).
Mutation testing (``mutmut``, see ``[tool.mutmut]`` in pyproject.toml) is the
sound test of whether a test adds detection power.

Usage:
    uv run python scripts/test_overlap.py
    uv run python scripts/test_overlap.py --from-data path/to/.coverage --show-groups 10
"""

from __future__ import annotations

import argparse
import collections
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = "src/stremioguard"


def collect(data_file: Path) -> None:
    env = {**os.environ, "COVERAGE_FILE": str(data_file)}
    env = {k: v for k, v in env.items() if not k.startswith("STREMIOGUARD_")}
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--cov={SRC}",
            "--cov-branch",
            "--cov-context=test",
            "--cov-report=",
        ],
        cwd=REPO_ROOT,
        env=env,
        check=True,
    )


def footprints(data_file: Path) -> tuple[dict[str, frozenset], dict[int, str]]:
    db = sqlite3.connect(data_file)
    contexts = dict(db.execute("select id, context from context"))
    files = dict(db.execute("select id, path from file"))
    arcs: dict[str, set] = collections.defaultdict(set)
    for file_id, ctx_id, a, b in db.execute("select file_id, context_id, fromno, tono from arc"):
        name = contexts[ctx_id].split("|")[0]
        if name:
            arcs[name].add((file_id, a, b))
    return {t: frozenset(s) for t, s in arcs.items()}, files


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--from-data", type=Path, help="existing coverage data with test contexts")
    parser.add_argument(
        "--show-groups", type=int, default=0, help="print the N largest identical groups"
    )
    parser.add_argument("--show-unique", action="store_true", help="list the irreplaceable tests")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="test-overlap-") as tmp:
        data = args.from_data or Path(tmp) / ".coverage"
        if not args.from_data:
            collect(data)
        tests, files = footprints(data)

    print(f"tests with coverage: {len(tests)}")
    groups = collections.defaultdict(list)
    for t, fp in tests.items():
        groups[fp].append(t)
    same = sorted((g for g in groups.values() if len(g) > 1), key=len, reverse=True)
    print(f"identical footprints: {sum(map(len, same))} tests in {len(same)} groups")

    ordered = sorted(tests, key=lambda t: len(tests[t]))
    subset = [
        t
        for i, t in enumerate(ordered)
        if any(len(tests[u]) > len(tests[t]) and tests[t] <= tests[u] for u in ordered[i + 1 :])
    ]
    print(f"strict subset of one other test: {len(subset)}")

    counts = collections.Counter(a for fp in tests.values() for a in fp)
    unique = sorted(t for t, fp in tests.items() if any(counts[a] == 1 for a in fp))
    print(f"only test to execute some arc: {len(unique)}")

    per_module = collections.Counter()
    for fp in tests.values():
        for path in {files[a[0]] for a in fp}:
            per_module[path.split(f"/{SRC}/")[-1]] += 1
    print("\ntests reaching each module:")
    for module, n in per_module.most_common():
        print(f"{n:6d}  {module}")

    for g in same[: args.show_groups]:
        print(f"\nidentical group of {len(g)}:")
        for t in sorted(g):
            print(f"  {t}")
    if args.show_unique:
        print("\nirreplaceable tests:")
        for t in unique:
            print(f"  {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
