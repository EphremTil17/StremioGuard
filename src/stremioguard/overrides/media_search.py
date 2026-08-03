"""Forward-only RTN rank-context override for Comet's media-search boundary."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching


def render_media_search_override(repo_dir: Path) -> str:
    """Carry RTN's already-calculated numeric rank into MediaSearchResult."""
    source_file = repo_dir / "comet" / "services" / "media_search.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet media search file not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")

    result_field = "    ranked_info_hashes: list[str] = field(default_factory=list)\n"
    result_field_replacement = (
        result_field + "    rtn_ranks: dict[str, int] = field(default_factory=dict)\n"
    )
    content = replace_first_matching(
        content,
        ((result_field, result_field_replacement),),
        error=(
            "Unable to apply required RTN rank-context patch; Comet "
            "MediaSearchResult no longer exposes ranked_info_hashes."
        ),
    )

    ranked_hashes = "        ranked_info_hashes=list(torrent_manager.ranked_torrents),\n"
    ranked_hashes_replacement = (
        ranked_hashes
        + "        rtn_ranks={\n"
        + "            info_hash: ranked_torrent.rank\n"
        + "            for info_hash, ranked_torrent in torrent_manager.ranked_torrents.items()\n"
        + "        },\n"
    )
    return replace_first_matching(
        content,
        ((ranked_hashes, ranked_hashes_replacement),),
        error=(
            "Unable to apply required RTN rank-context patch; Comet media-search "
            "result construction has changed."
        ),
    )
