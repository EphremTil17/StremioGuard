from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger

from stremioguard.env import atomic_write_text
from stremioguard.overrides.config import render_config_override
from stremioguard.overrides.filtering import render_filtering_override
from stremioguard.overrides.formatter import render_formatter_override
from stremioguard.overrides.orchestration import render_orchestration_override
from stremioguard.overrides.stream import render_stream_override
from stremioguard.overrides.template import render_configure_template_override
from stremioguard.overrides.torrentio import render_torrentio_override


class Requirement(Enum):
    REQUIRED = "REQUIRED"
    REQUIRED_WHEN_GATEWAY = "REQUIRED_WHEN_GATEWAY"
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True)
class RenderContext:
    result_format_style: str
    patch_episode_pack_results: bool
    gateway_addon_base_url: str | None = None


@dataclass(frozen=True)
class OverrideSpec:
    name: str  # e.g., "stream", "torrentio"
    feature: str  # user-facing description
    container_path: str  # target mount path in the container
    output_name: str  # target file name under state_dir
    requirement: Requirement
    render: Callable[[Path, RenderContext], str | None]


@dataclass(frozen=True)
class SkippedOverride:
    name: str
    feature: str
    reason: str


@dataclass(frozen=True)
class BundleReport:
    applied: list[str]
    skipped: list[SkippedOverride]


SPECS = [
    OverrideSpec(
        name="formatter",
        feature="custom format styles (e.g. emoji badges)",
        container_path="/app/comet/utils/formatting.py",
        output_name="formatting.py",
        requirement=Requirement.OPTIONAL,
        render=lambda repo_dir, ctx: render_formatter_override(repo_dir, ctx.result_format_style),
    ),
    OverrideSpec(
        name="stream",
        feature="TV-readable stream naming and gateway playback URLs",
        container_path="/app/comet/api/endpoints/stream.py",
        output_name="stream.py",
        requirement=Requirement.REQUIRED_WHEN_GATEWAY,
        render=lambda repo_dir, ctx: render_stream_override(repo_dir),
    ),
    OverrideSpec(
        name="config",
        feature="gateway configuration integration",
        container_path="/app/comet/api/endpoints/config.py",
        output_name="config.py",
        requirement=Requirement.REQUIRED_WHEN_GATEWAY,
        render=lambda repo_dir, ctx: render_config_override(repo_dir),
    ),
    OverrideSpec(
        name="template",
        feature="configure page install button redirection",
        container_path="/app/comet/templates/index.html",
        output_name="index.html",
        requirement=Requirement.REQUIRED_WHEN_GATEWAY,
        render=lambda repo_dir, ctx: render_configure_template_override(
            repo_dir, ctx.gateway_addon_base_url
        ),
    ),
    OverrideSpec(
        name="torrentio",
        feature="Torrentio scraper integration",
        container_path="/app/comet/scrapers/torrentio.py",
        output_name="torrentio.py",
        requirement=Requirement.OPTIONAL,
        render=lambda repo_dir, ctx: render_torrentio_override(repo_dir),
    ),
    OverrideSpec(
        name="filtering",
        feature="quality/debrid metadata filtering and sorting",
        container_path="/app/comet/services/filtering.py",
        output_name="filtering.py",
        requirement=Requirement.OPTIONAL,
        render=lambda repo_dir, ctx: render_filtering_override(repo_dir),
    ),
    OverrideSpec(
        name="orchestration",
        feature="episode-pack preservation and mapping",
        container_path="/app/comet/services/orchestration.py",
        output_name="orchestration.py",
        requirement=Requirement.OPTIONAL,
        render=lambda repo_dir, ctx: (
            render_orchestration_override(repo_dir) if ctx.patch_episode_pack_results else None
        ),
    ),
    OverrideSpec(
        name="metadata_service",
        feature="metadata lookup and caching helper",
        container_path="/app/comet/metadata_service.py",
        output_name="metadata_service.py",
        requirement=Requirement.OPTIONAL,
        render=lambda repo_dir, ctx: (
            (Path(__file__).parent.parent / "metadata.py").read_text(encoding="utf-8")
            if (Path(__file__).parent.parent / "metadata.py").exists()
            else None
        ),
    ),
]


def required_output_names(*, gateway_enabled: bool) -> list[str]:
    """Output files that must be present in a bundle for this deployment shape."""
    return [
        spec.output_name
        for spec in SPECS
        if spec.requirement == Requirement.REQUIRED
        or (gateway_enabled and spec.requirement == Requirement.REQUIRED_WHEN_GATEWAY)
    ]


def write_override_bundle(
    repo_dir: Path,
    state_dir: Path,
    result_format_style: str,
    *,
    patch_episode_pack_results: bool,
    gateway_addon_base_url: str | None = None,
    gateway_enabled: bool = False,
    image_digest: str = "",
    patch_fingerprint: str = "",
) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    ctx = RenderContext(
        result_format_style=result_format_style,
        patch_episode_pack_results=patch_episode_pack_results,
        gateway_addon_base_url=gateway_addon_base_url,
    )

    applied_names: list[str] = []
    skipped: list[SkippedOverride] = []
    outputs: dict[str, str] = {}

    for spec in SPECS:
        target_path = state_dir / spec.output_name
        try:
            content = spec.render(repo_dir, ctx)
            if content is None:
                reason = "disabled by configuration"
                skipped.append(SkippedOverride(spec.name, spec.feature, reason))
                if target_path.exists():
                    target_path.unlink()
            else:
                atomic_write_text(target_path, content, mode=0o644)
                applied_names.append(spec.name)
                outputs[spec.output_name] = spec.container_path
        except Exception as error:
            reason = str(error)
            skipped.append(SkippedOverride(spec.name, spec.feature, reason))
            if target_path.exists():
                target_path.unlink()

    # Create and write manifest atomically
    manifest = {
        "image_digest": image_digest,
        "patch_fingerprint": patch_fingerprint,
        "format_style": result_format_style,
        "patch_episode_pack": patch_episode_pack_results,
        "gateway_addon_base_url": gateway_addon_base_url,
        "applied": applied_names,
        "skipped": [{"name": s.name, "reason": s.reason} for s in skipped],
        "outputs": outputs,
    }
    manifest_path = state_dir / "bundle-manifest.json"
    atomic_write_text(manifest_path, json.dumps(manifest, indent=2) + "\n", mode=0o644)

    # Log applied/skipped summary
    for name in applied_names:
        logger.info(f"Applied patch: {name}")

    for s in skipped:
        logger.warning(f"Skipped patch '{s.name}' ({s.feature}): {s.reason}")

    # Enforce requirement validation
    for s in skipped:
        spec = next(sp for sp in SPECS if sp.name == s.name)
        is_required = spec.requirement == Requirement.REQUIRED or (
            gateway_enabled and spec.requirement == Requirement.REQUIRED_WHEN_GATEWAY
        )
        if is_required:
            raise RuntimeError(f"Required patch '{spec.name}' failed to apply: {s.reason}")
