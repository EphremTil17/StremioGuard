from __future__ import annotations

from pathlib import Path

from stremioguard.overrides.config import render_config_override
from stremioguard.overrides.filtering import render_filtering_override
from stremioguard.overrides.formatter import render_formatter_override
from stremioguard.overrides.orchestration import render_orchestration_override
from stremioguard.overrides.stream import render_stream_override
from stremioguard.overrides.template import render_configure_template_override
from stremioguard.overrides.torrentio import render_torrentio_override


def write_override_bundle(
    repo_dir: Path,
    state_dir: Path,
    result_format_style: str,
    *,
    patch_episode_pack_results: bool,
    gateway_addon_base_url: str | None = None,
) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)

    formatter_rendered = render_formatter_override(repo_dir, result_format_style)
    formatter_target = state_dir / "formatting.py"
    if formatter_rendered is None:
        if formatter_target.exists():
            formatter_target.unlink()
    else:
        formatter_target.write_text(formatter_rendered, encoding="utf-8")

    (state_dir / "stream.py").write_text(render_stream_override(repo_dir), encoding="utf-8")
    (state_dir / "config.py").write_text(render_config_override(repo_dir), encoding="utf-8")
    (state_dir / "index.html").write_text(
        render_configure_template_override(repo_dir, gateway_addon_base_url),
        encoding="utf-8",
    )
    (state_dir / "torrentio.py").write_text(render_torrentio_override(repo_dir), encoding="utf-8")
    (state_dir / "filtering.py").write_text(render_filtering_override(repo_dir), encoding="utf-8")
    orchestration_target = state_dir / "orchestration.py"
    if patch_episode_pack_results:
        orchestration_target.write_text(render_orchestration_override(repo_dir), encoding="utf-8")
    elif orchestration_target.exists():
        orchestration_target.unlink()

    # Note: metadata.py is located under stremioguard parent folder
    metadata_src = Path(__file__).parent.parent / "metadata.py"
    metadata_target = state_dir / "metadata_service.py"
    if metadata_src.exists():
        metadata_target.write_text(metadata_src.read_text(encoding="utf-8"), encoding="utf-8")
    elif metadata_target.exists():
        metadata_target.unlink()
