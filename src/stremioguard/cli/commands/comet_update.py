"""`./stremio comet update` — check/apply/rollback for the digest promotion
state machine (Phase 4). Never auto-applies: `check` only recommends,
`apply`/`rollback` require an explicit invocation of this command."""

from __future__ import annotations

import json

import typer
from loguru import logger

from stremioguard.cli.commands.general import is_interactive
from stremioguard.cli.context import _comet_manager
from stremioguard.comet.manager import CometManager
from stremioguard.env import fail


def _current_manifest_names(manager: CometManager) -> tuple[set[str], set[str]]:
    """Applied/skipped patch names from the manifest of the CURRENTLY active
    digest, for diffing against a validated candidate's report."""
    manifest_path = manager.config.state_dir / "bundle-manifest.json"
    if not manifest_path.exists():
        return set(), set()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set(), set()
    applied = set(manifest.get("applied", []))
    skipped = {entry.get("name") for entry in manifest.get("skipped", []) if entry.get("name")}
    return applied, skipped


def _log_feature_diff(manager: CometManager, report: dict[str, object]) -> None:
    current_applied, current_skipped = _current_manifest_names(manager)
    degraded_entries = report.get("degraded") or []
    candidate_degraded = {d["name"] for d in degraded_entries}  # type: ignore[union-attr]
    candidate_applied = set(report.get("applied") or [])  # type: ignore[arg-type]

    newly_degraded = candidate_degraded & current_applied
    newly_fixed = current_skipped & candidate_applied
    if newly_degraded:
        logger.warning(f"This update would newly degrade: {', '.join(sorted(newly_degraded))}")
    if newly_fixed:
        logger.info(f"This update restores: {', '.join(sorted(newly_fixed))}")


def comet_update_check(
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Also boot the candidate image ephemerally and check /health before recommending it.",
    ),
) -> None:
    """Compare the active Comet image against upstream `:latest` and validate
    any newer digest, without applying or touching running services."""
    manager = _comet_manager()
    state = manager.load_state()
    if state.active_digest is None:
        fail("Comet has no active image yet. Run `./stremio comet install` first.")

    # resolve_remote_digest, not check_remote: this explicit command must tell
    # "up to date" apart from "could not reach the registry" — reporting a
    # failed probe as up-to-date would be a confident false answer.
    new_digest = manager.resolve_remote_digest()
    if new_digest is None:
        fail(
            "Could not resolve the remote Comet digest (registry unreachable, "
            "rate-limited, or docker buildx missing). Try again later."
        )
    if new_digest == state.active_digest:
        logger.success(
            f"Comet is already up to date ({manager.config.image}@{state.active_digest})."
        )
        return

    logger.info(f"Update available: {manager.config.image}:latest -> {new_digest}")
    report = manager.validate_candidate(new_digest, deep=deep)
    if report["status"] == "passed":
        _log_feature_diff(manager, report)
        degraded = report.get("degraded") or []
        if degraded:
            names = ", ".join(d["name"] for d in degraded)  # type: ignore[union-attr]
            logger.warning(
                f"Update available and validated, with degraded optional features: {names}."
            )
        else:
            logger.success("Update available and validated — all patches applied cleanly.")
        logger.info("Run `./stremio comet update apply` to promote it.")
    else:
        logger.warning(
            "Update available but patches fail: staying on "
            f"{manager.config.image}@{state.active_digest}; a StremioGuard update is "
            f"needed.\n{report['detail']}"
        )


def comet_update_apply() -> None:
    """Promote the last validated candidate to active and restart the Comet stack."""
    manager = _comet_manager()
    state = manager.load_state()
    candidate = state.candidate
    if candidate is None:
        fail("No candidate digest recorded. Run `./stremio comet update check` first.")

    validation = candidate.validation or {}
    if validation.get("status") != "passed":
        fail(
            f"Candidate {candidate.digest} failed validation and cannot be applied; a "
            "StremioGuard update is needed. Run `./stremio comet update check` for details."
        )

    # A probe failure (None) does not block apply: the candidate was already
    # validated, and the staleness check is advisory. But any successfully
    # resolved digest that differs from the candidate — newer upstream OR an
    # upstream rollback to the active digest — means the candidate no longer
    # matches `:latest` and must be re-checked. check_remote can't express the
    # rollback case (it compares against active), hence resolve_remote_digest.
    remote_digest = manager.resolve_remote_digest()
    if remote_digest is not None and remote_digest != candidate.digest:
        fail(
            f"Upstream :latest ({manager.config.image}@{remote_digest}) no longer matches "
            "the validated candidate. Run `./stremio comet update check` again before "
            "applying."
        )

    manager.promote_candidate()
    logger.success(f"Comet promoted to {manager.config.image}@{candidate.digest}.")


def comet_update_rollback(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Roll Comet back to the previously active image, one step deep."""
    manager = _comet_manager()
    state = manager.load_state()
    if not state.previous_digest:
        fail("No previous digest recorded; nothing to roll back to.")

    if not yes:
        if not is_interactive():
            fail(
                "Refusing to roll back without confirmation in a non-interactive "
                "session. Pass --yes."
            )
        confirmed = typer.confirm(
            f"Roll back Comet from {manager.config.image}@{state.active_digest} to "
            f"{manager.config.image}@{state.previous_digest}?",
            default=False,
        )
        if not confirmed:
            logger.info("Rollback cancelled.")
            return

    target = state.previous_digest
    manager.rollback()
    logger.success(f"Comet rolled back to {manager.config.image}@{target}.")


def _update_default(ctx: typer.Context) -> None:
    """`./stremio comet update` with no subcommand defaults to `check`.

    Calls with an explicit `deep=False` rather than relying on
    `comet_update_check`'s parameter default — that default is a
    `typer.Option(...)` sentinel, only resolved to a real bool by Typer's own
    CLI dispatch, not by a direct Python call like this one."""
    if ctx.invoked_subcommand is None:
        comet_update_check(deep=False)


def register(update_app: typer.Typer) -> None:
    update_app.callback(invoke_without_command=True)(_update_default)
    update_app.command("check")(comet_update_check)
    update_app.command("apply")(comet_update_apply)
    update_app.command("rollback")(comet_update_rollback)
