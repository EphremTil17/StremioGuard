#!/usr/bin/env python3
"""Measure Python line+branch unit-test coverage per security domain.

Runs ``pytest --cov=src/stremioguard --cov-branch --cov-report=json`` into a
temporary directory so the repository stays clean, then aggregates statement
and branch coverage using the explicit ``DOMAIN_FILES`` map below.

Usage:
    uv run python scripts/coverage_by_domain.py
    uv run python scripts/coverage_by_domain.py --from-json path/to/coverage.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PREFIX = Path("src/stremioguard")


@dataclass(frozen=True)
class DomainSpec:
    name: str
    files: tuple[str, ...]
    note: str = ""


DOMAIN_SPECS: tuple[DomainSpec, ...] = (
    DomainSpec(
        name="Gateway & public HTTP",
        files=("comet_gateway.py",),
    ),
    DomainSpec(
        name="Secret hygiene & log scrubbing",
        files=(
            "overrides/comet_log_scrubber.py",
            "overrides/logger.py",
            "comet/log_canary.py",
        ),
    ),
    DomainSpec(
        name="VPN egress & watchdog",
        files=(
            "guard.py",
            "orchestrator.py",
            "nordvpn.py",
            "httpdeadline.py",
            "preflight.py",
            "resolver.py",
            "alerts.py",
            "sdnotify.py",
        ),
    ),
    DomainSpec(
        name="Comet app & stream proxy",
        files=(
            "overrides/response_guard.py",
            "overrides/stream_guard.py",
            "overrides/stream.py",
            "overrides/config.py",
            "overrides/config_limits.py",
            "overrides/playback.py",
            "overrides/admin.py",
            "overrides/api_app.py",
            "metadata.py",
        ),
        note=(
            "overrides/stream_guard.py reads 0% under default unit tests "
            "(exercised inside the real Comet image via STREMIOGUARD_DOCKER_TESTS=1)"
        ),
    ),
    DomainSpec(
        name="Containers & supply chain",
        files=(
            "comet/validation.py",
            "comet/validate.py",
            "comet/source_tree.py",
            "digests.py",
            "overrides/bundle.py",
            "comet/state.py",
        ),
    ),
    DomainSpec(
        name="Host state & systemd",
        files=(
            "cli/supervisor.py",
            "stacklock.py",
            "publishing.py",
            "env.py",
            "config.py",
        ),
    ),
)

NON_PYTHON_DOMAINS: tuple[tuple[str, str], ...] = (
    ("Stremio profile (opt-in)", "n/a (JavaScript and nginx)"),
    ("Sidecars (StremThru & Postgres)", "n/a (third-party, isolated, not source-audited)"),
)


@dataclass(frozen=True)
class CoverageTotals:
    covered_lines: int
    num_statements: int
    covered_branches: int
    num_branches: int

    @property
    def combined_covered(self) -> int:
        return self.covered_lines + self.covered_branches

    @property
    def combined_total(self) -> int:
        return self.num_statements + self.num_branches

    @property
    def percent(self) -> float:
        if self.combined_total == 0:
            return 0.0
        return 100.0 * self.combined_covered / self.combined_total


def _normalize_files_map(raw_files: dict[str, dict[str, object]]) -> dict[str, dict[str, int]]:
    """Index coverage JSON file summaries by POSIX path relative to src/stremioguard."""
    normalized: dict[str, dict[str, int]] = {}
    prefix_str = SRC_PREFIX.as_posix() + "/"
    for key, entry in raw_files.items():
        posix = Path(key).as_posix()
        if posix.startswith(prefix_str):
            rel = posix[len(prefix_str) :]
        else:
            try:
                rel = Path(key).resolve().relative_to(REPO_ROOT / SRC_PREFIX).as_posix()
            except ValueError:
                continue
        summary = entry.get("summary")
        if not isinstance(summary, dict):
            continue
        normalized[rel] = {
            "covered_lines": int(summary["covered_lines"]),
            "num_statements": int(summary["num_statements"]),
            "covered_branches": int(summary["covered_branches"]),
            "num_branches": int(summary["num_branches"]),
        }
    return normalized


def aggregate_domain(
    spec: DomainSpec,
    summaries: dict[str, dict[str, int]],
) -> CoverageTotals:
    missing = [rel for rel in spec.files if rel not in summaries]
    if missing:
        raise KeyError(f"Domain {spec.name!r} references missing coverage entries: {missing}")
    return CoverageTotals(
        covered_lines=sum(summaries[rel]["covered_lines"] for rel in spec.files),
        num_statements=sum(summaries[rel]["num_statements"] for rel in spec.files),
        covered_branches=sum(summaries[rel]["covered_branches"] for rel in spec.files),
        num_branches=sum(summaries[rel]["num_branches"] for rel in spec.files),
    )


def run_pytest_coverage(json_path: Path, data_file: Path) -> None:
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--cov=src/stremioguard",
        "--cov-branch",
        f"--cov-report=json:{json_path}",
        "--cov-report=",
    ]
    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(data_file)
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def load_coverage_json(json_path: Path) -> dict[str, object]:
    with json_path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"Unexpected coverage JSON root in {json_path}")
    return payload


def format_report(payload: dict[str, object]) -> str:
    raw_files = payload.get("files")
    totals_raw = payload.get("totals")
    if not isinstance(raw_files, dict) or not isinstance(totals_raw, dict):
        raise ValueError("Coverage JSON missing 'files' or 'totals' keys")

    summaries = _normalize_files_map(raw_files)
    lines: list[str] = []
    header = f"{'Domain':<34} {'Line+Branch':>11}  {'Stmts':>11}  {'Branches':>11}"
    lines.append(header)
    lines.append("-" * len(header))

    notes: list[str] = []
    for spec in DOMAIN_SPECS:
        tot = aggregate_domain(spec, summaries)
        stmts = f"{tot.covered_lines}/{tot.num_statements}"
        branches = f"{tot.covered_branches}/{tot.num_branches}"
        lines.append(f"{spec.name:<34} {tot.percent:>10.1f}%  {stmts:>11}  {branches:>11}")
        if spec.note:
            notes.append(f"  - {spec.name}: {spec.note}")

    for name, reason in NON_PYTHON_DOMAINS:
        lines.append(f"{name:<34} {'n/a':>11}  {reason}")

    pkg = CoverageTotals(
        covered_lines=int(totals_raw["covered_lines"]),
        num_statements=int(totals_raw["num_statements"]),
        covered_branches=int(totals_raw["covered_branches"]),
        num_branches=int(totals_raw["num_branches"]),
    )
    lines.append("-" * len(header))
    pkg_stmts = f"{pkg.covered_lines}/{pkg.num_statements}"
    pkg_branches = f"{pkg.covered_branches}/{pkg.num_branches}"
    lines.append(
        f"{'Whole package (src/stremioguard)':<34} {pkg.percent:>10.1f}%  "
        f"{pkg_stmts:>11}  {pkg_branches:>11}"
    )

    sg = summaries.get("overrides/stream_guard.py")
    if sg is not None:
        sg_tot = CoverageTotals(**sg)
        notes.append(
            f"  - overrides/stream_guard.py alone: {sg_tot.percent:.1f}% "
            f"({sg_tot.covered_lines}/{sg_tot.num_statements} stmts, "
            f"{sg_tot.covered_branches}/{sg_tot.num_branches} branches)"
        )

    if notes:
        lines.append("")
        lines.append("Notes:")
        lines.extend(notes)

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-json",
        type=Path,
        default=None,
        help="Read an existing pytest-cov JSON report instead of running pytest.",
    )
    args = parser.parse_args(argv)

    if args.from_json is not None:
        payload = load_coverage_json(args.from_json)
    else:
        with tempfile.TemporaryDirectory(prefix="stremioguard-cov-") as tmp:
            tmp_dir = Path(tmp)
            json_path = tmp_dir / "coverage.json"
            data_file = tmp_dir / ".coverage"
            run_pytest_coverage(json_path, data_file)
            payload = load_coverage_json(json_path)

    print(format_report(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
