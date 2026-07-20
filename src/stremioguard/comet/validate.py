"""Standalone validator for CI and the daily canary (plan Phase 7).

Runs extract -> render -> compile -> import-smoke against an arbitrary image
reference, prints a machine-readable report, and exits nonzero on failure.
Deliberately not wired into the Typer CLI: this is a maintainer/CI entry
point (`python -m stremioguard.comet.validate`), not an operator command.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from stremioguard.cli.context import ROOT_DIR
from stremioguard.comet.manager import CometManager, extract_image_source
from stremioguard.comet.validation import import_smoke_test
from stremioguard.config import CometConfig, Runner, SubprocessRunner
from stremioguard.overrides import write_override_bundle


def _undefined_names(generated_root: Path) -> str:
    """Report undefined names (ruff F821) in the rendered bundle.

    A patch can compile cleanly and import cleanly while still calling a
    helper the current Comet version renamed or stopped importing — the
    NameError only surfaces when a request finally executes that line, which
    neither the compile nor the import-smoke stage reaches. Best-effort: an
    unavailable ruff yields no finding rather than a false failure.
    """
    try:
        result = subprocess.run(
            ["ruff", "check", "--isolated", "--select", "F821", "--quiet", str(generated_root)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "" if result.returncode == 0 else (result.stdout or result.stderr).strip()


def run_validation(runner: Runner, image_ref: str) -> dict[str, object]:
    """Validate `image_ref` and return a report dict.

    Report shape: {"status": "passed"|"failed", "stage": str, "detail": str}
    plus "applied"/"skipped" lists once the render has produced a manifest.
    """
    try:
        manager = CometManager(CometConfig.from_env(ROOT_DIR), runner)
        image_digest = manager.ensure_image(image_ref)
    except Exception as error:
        return {
            "status": "failed",
            "stage": "pull",
            "detail": f"could not pull or inspect {image_ref}: {error}",
        }

    try:
        with tempfile.TemporaryDirectory(prefix="stremioguard-comet-validate-") as directory:
            generated_root = Path(directory) / "generated"
            with extract_image_source(runner, image_ref) as source_root:
                if not (source_root / "comet").exists():
                    raise RuntimeError("the image does not contain /app/comet")

                # Render the SUPERSET bundle, never this machine's .env shape:
                # tested_digest must vouch for every deployment shape, so the
                # gate force-enables the gateway (making its specs required)
                # and episode packs, and uses the "plain" style — the one whose
                # formatter override actually renders ("emoji" skips it).
                write_override_bundle(
                    repo_dir=source_root,
                    state_dir=generated_root,
                    result_format_style="plain",
                    patch_episode_pack_results=True,
                    gateway_addon_base_url="/comet/canary",
                    gateway_enabled=True,
                    image_digest=image_digest,
                    patch_fingerprint=manager._managed_patch_fingerprint(),
                )
                for generated_file in sorted(generated_root.glob("*.py")):
                    compile(
                        generated_file.read_text(encoding="utf-8"),
                        str(generated_file),
                        "exec",
                    )
                manifest = json.loads(
                    (generated_root / "bundle-manifest.json").read_text(encoding="utf-8")
                )

            undefined = _undefined_names(generated_root)
            if undefined:
                return {
                    "status": "failed",
                    "stage": "lint",
                    "detail": (
                        "rendered overrides reference names this Comet version does not "
                        f"define:\n{undefined}"
                    ),
                }

            applied = manifest.get("applied", [])
            skipped = manifest.get("skipped", [])
            if skipped:
                # With every feature enabled nothing may legitimately be
                # "disabled by configuration"; any skip is upstream anchor
                # drift, and the canary must not bump tested_digest past a
                # degraded patch — even an OPTIONAL one.
                reasons = "; ".join(
                    f"{entry.get('name', '?')}: {entry.get('reason', '?')}" for entry in skipped
                )
                return {
                    "status": "failed",
                    "stage": "render",
                    "detail": f"overrides skipped (upstream drift): {reasons}",
                    "applied": applied,
                    "skipped": skipped,
                }

            smoke = import_smoke_test(
                runner, image_ref, manifest.get("outputs", {}), generated_root
            )
            if smoke["status"] != "passed":
                return {
                    "status": "failed",
                    "stage": "import",
                    "detail": str(smoke["detail"]),
                    "applied": applied,
                    "skipped": skipped,
                }

            return {
                "status": "passed",
                "stage": "import",
                "detail": f"{image_ref} passed render, compile, and import-smoke validation.",
                "applied": applied,
                "skipped": skipped,
            }
    except Exception as error:
        return {"status": "failed", "stage": "render", "detail": str(error)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a Comet candidate image (render + compile + import-smoke)."
    )
    parser.add_argument(
        "--image", required=True, help="Image reference to validate, e.g. g0ldyy/comet@sha256:..."
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    args = parser.parse_args()

    if args.json:
        # stdout IS the report: subprocesses inherit fd 1 and some docker
        # commands write to it (e.g. `docker pull` progress when the image
        # is missing locally), which would corrupt the JSON that the canary
        # pipes into jq. Point fd 1 at stderr while validating.
        saved_stdout = os.dup(1)
        os.dup2(2, 1)
        try:
            report = run_validation(SubprocessRunner(), args.image)
        finally:
            os.dup2(saved_stdout, 1)
            os.close(saved_stdout)
    else:
        report = run_validation(SubprocessRunner(), args.image)

    if args.json:
        print(json.dumps(report, indent=2))
    elif report["status"] == "passed":
        print(f"Validation passed: {report['detail']}")
    else:
        print(f"Validation failed [{report['stage']}]: {report['detail']}", file=sys.stderr)
    sys.exit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
