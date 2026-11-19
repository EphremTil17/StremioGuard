"""Tests for scripts/coverage_by_domain.py and README security-coverage SVGs."""

from __future__ import annotations

import importlib.util
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "coverage_by_domain.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("coverage_by_domain", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_domain_file_map_exists_and_has_no_duplicates() -> None:
    mod = _load_module()
    seen: set[str] = set()
    for domain in mod.DOMAIN_SPECS:
        assert domain.files, f"Domain {domain.name!r} must list at least one file"
        for rel in domain.files:
            assert rel not in seen, f"Duplicate file {rel!r} across domain specs"
            seen.add(rel)
            assert (REPO_ROOT / "src" / "stremioguard" / rel).is_file(), (
                f"Mapped file missing: src/stremioguard/{rel}"
            )


def test_aggregate_domain_computes_combined_line_and_branch_percent() -> None:
    mod = _load_module()
    spec = mod.DomainSpec(name="Sample", files=("a.py", "b.py"))
    summaries = {
        "a.py": {
            "covered_lines": 80,
            "num_statements": 100,
            "covered_branches": 10,
            "num_branches": 20,
        },
        "b.py": {
            "covered_lines": 40,
            "num_statements": 50,
            "covered_branches": 20,
            "num_branches": 30,
        },
    }
    totals = mod.aggregate_domain(spec, summaries)
    assert totals.combined_covered == 150
    assert totals.combined_total == 200
    assert totals.percent == pytest.approx(75.0)


def test_aggregate_domain_fails_closed_on_missing_file() -> None:
    mod = _load_module()
    spec = mod.DomainSpec(name="Sample", files=("a.py", "missing.py"))
    summaries = {
        "a.py": {
            "covered_lines": 1,
            "num_statements": 1,
            "covered_branches": 0,
            "num_branches": 0,
        },
    }
    with pytest.raises(KeyError, match="missing.py"):
        mod.aggregate_domain(spec, summaries)


def test_format_report_includes_domains_non_python_and_stream_guard_note() -> None:
    mod = _load_module()
    files_payload: dict[str, object] = {}
    for spec in mod.DOMAIN_SPECS:
        for rel in spec.files:
            covered = 0 if rel == "overrides/stream_guard.py" else 9
            branches = 0 if rel == "overrides/stream_guard.py" else 2
            files_payload[f"src/stremioguard/{rel}"] = {
                "summary": {
                    "covered_lines": covered,
                    "num_statements": 10,
                    "covered_branches": branches,
                    "num_branches": 2,
                }
            }
    payload = {
        "files": files_payload,
        "totals": {
            "covered_lines": 90,
            "num_statements": 100,
            "covered_branches": 18,
            "num_branches": 20,
        },
    }
    report = mod.format_report(payload)
    assert "Gateway & public HTTP" in report
    assert "Stremio profile (opt-in)" in report
    assert "n/a (JavaScript and nginx)" in report
    assert "isolated, not source-audited" in report
    assert "overrides/stream_guard.py alone: 0.0%" in report
    assert "Whole package (src/stremioguard)" in report


def test_readme_coverage_svgs_valid_and_differ_only_in_colors() -> None:
    dark_path = REPO_ROOT / "docs" / "assets" / "security-coverage-dark.svg"
    light_path = REPO_ROOT / "docs" / "assets" / "security-coverage-light.svg"

    dark = dark_path.read_text(encoding="utf-8")
    light = light_path.read_text(encoding="utf-8")

    for label, text in (("dark", dark), ("light", light)):
        root = ET.fromstring(text)
        assert root.tag.endswith("svg"), f"{label} root tag is not svg"
        lowered = text.lower()
        assert "<script" not in lowered, f"{label} SVG must not contain scripts"
        assert "foreignobject" not in lowered, f"{label} SVG must not contain foreignObject"
        assert "v0.4.2" in text
        assert "isolated, not source-audited" in text
        assert "real-container tests" in text
        assert "unreleased" not in text

    assert dark != light, "Dark and light SVGs must actually differ in colors"
    dark_stripped = re.sub(r"#[0-9a-fA-F]{6}\b", "#COLOR", dark)
    light_stripped = re.sub(r"#[0-9a-fA-F]{6}\b", "#COLOR", light)
    assert dark_stripped == light_stripped, (
        "Dark and light SVG variants must differ only in hex colors"
    )
