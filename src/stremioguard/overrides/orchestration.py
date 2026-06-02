from __future__ import annotations

from pathlib import Path


def render_orchestration_override(repo_dir: Path) -> str:
    # The orchestration patch exists because stock Comet is stricter than
    # native Torrentio about episode selection inside season packs. The goal is
    # not "accept everything", but "accept entries with strong season/file
    # evidence even when episode metadata is incomplete".
    orchestration_file = repo_dir / "comet" / "services" / "orchestration.py"
    if not orchestration_file.exists():
        raise RuntimeError(f"Comet orchestration file not found at {orchestration_file}.")
    content = orchestration_file.read_text(encoding="utf-8")
    init_marker = "        self.primary_cached = False\n"
    if "self.pack_backed_hashes = set()" not in content:
        if init_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet orchestration patch; upstream "
                "initializer has changed."
            )
        content = content.replace(
            init_marker,
            init_marker
            + "        self.pack_backed_hashes = set()\n"
            + "        self._pack_backed_candidates = {}\n",
            1,
        )

    helper_marker = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
    ) -> bool:
"""
    helper_block = """    def _record_pack_backed_candidate(
        self,
        info_hash: str,
        *,
        episode: int | None = None,
        file_index: int | None = None,
    ) -> None:
        if self.media_type != "series" or self.search_episode is None:
            return

        candidate = self._pack_backed_candidates.setdefault(
            info_hash, {"episodes": set(), "indexes": set()}
        )
        if episode is not None:
            candidate["episodes"].add(str(episode))
        if file_index is not None:
            candidate["indexes"].add(str(file_index))
        if (
            len(candidate["episodes"]) > 1
            or len(candidate["indexes"]) > 1
        ):
            self.pack_backed_hashes.add(info_hash)

    async def _is_pack_backed_candidate(
        self,
        parsed: ParsedData,
        *,
        info_hash: str,
        file_index: int | None = None,
    ) -> bool:
        if self.media_type != "series" or self.search_episode is None:
            return False
        if info_hash in self.pack_backed_hashes:
            return True

        parsed_episodes = parsed.episodes or []
        if len(parsed_episodes) > 1:
            try:
                from comet.metadata_service import get_season_episode_count
            except ImportError:
                from stremioguard.metadata import get_season_episode_count
            total_eps = await get_season_episode_count(self.media_id, self.search_season)
            if total_eps:
                return max(parsed_episodes) >= total_eps
            # Design Note: If metadata lookup fails (e.g. Cinemeta outage or database miss),
            # default to treating the multi-episode candidate as a season pack.
            return True
        if isinstance(file_index, int):
            return file_index > 0 or not parsed_episodes
        if isinstance(file_index, str) and file_index.isdigit():
            return int(file_index) > 0 or not parsed_episodes
        if file_index is None:
            return False
        return not parsed_episodes

"""
    if "_record_pack_backed_candidate(" not in content:
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet orchestration patch; upstream "
                "scope matcher has changed."
            )
        content = content.replace(helper_marker, helper_block + helper_marker, 1)

    original_method = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
    ) -> bool:
        reject_unknown = (
            self.reject_unknown_episode_files
            if reject_unknown_override is None
            else reject_unknown_override
        )
        return parsed_matches_target(
"""
    replacement_method = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        file_index: int | None = None,
        reject_unknown_override: bool | None = None,
    ) -> bool:
        reject_unknown = (
            self.reject_unknown_episode_files
            if reject_unknown_override is None
            else reject_unknown_override
        )
        if parsed_matches_target(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=reject_unknown,
        ):
            return True

        if not reject_unknown or self.search_episode is None or parsed.episodes:
            return False

        if (
            self.search_season is not None
            and parsed.seasons
            and self.search_season in parsed.seasons
        ):
            return True

        if file_index is None:
            return False

        return parsed_matches_target(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=False,
        )
"""
    replacement_signature = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        file_index: int | None = None,
        reject_unknown_override: bool | None = None,
    ) -> bool:
"""
    if replacement_signature not in content:
        if original_method not in content:
            raise RuntimeError(
                "Unable to apply managed Comet orchestration patch; upstream "
                "scope matcher has changed."
            )
        content = content.replace(original_method, replacement_method, 1)

    replacements = {
        "        for torrent in self.ready_to_cache:\n": (
            "        for torrent in self.ready_to_cache:\n"
            "            self._record_pack_backed_candidate(\n"
            '                torrent["infoHash"],\n'
            "                episode=self.search_episode,\n"
            '                file_index=torrent["fileIndex"],\n'
            "            )\n"
        ),
        'if not self._matches_requested_scope(torrent["parsed"]):': (
            "if not self._matches_requested_scope("
            'torrent["parsed"], file_index=torrent["fileIndex"]):'
        ),
        '                "parsed": torrent["parsed"],\n': (
            '                "parsed": torrent["parsed"],\n'
            '                "packBacked": await self._is_pack_backed_candidate(\n'
            '                    torrent["parsed"],\n'
            "                    info_hash=info_hash,\n"
            '                    file_index=torrent["fileIndex"],\n'
            "                ),\n"
        ),
        '            parsed_data = ParsedData(**orjson.loads(row["parsed_json"]))\n': (
            "            self._record_pack_backed_candidate(\n"
            '                row["info_hash"],\n'
            '                episode=row["episode"],\n'
            '                file_index=row["file_index"],\n'
            "            )\n"
            '            parsed_data = ParsedData(**orjson.loads(row["parsed_json"]))\n'
        ),
        "parsed_data, reject_unknown_override=reject_unknown_override": (
            "parsed_data, "
            'file_index=row["file_index"], '
            "reject_unknown_override=reject_unknown_override"
        ),
        '                "parsed": parsed_data,\n': (
            '                "parsed": parsed_data,\n'
            '                "packBacked": await self._is_pack_backed_candidate(\n'
            "                    parsed_data,\n"
            "                    info_hash=info_hash,\n"
            '                    file_index=row["file_index"],\n'
            "                ),\n"
        ),
        "parsed, reject_unknown_override=True": (
            'parsed, file_index=torrent["fileIndex"], reject_unknown_override=True'
        ),
    }
    for before, after in replacements.items():
        content = content.replace(before, after)

    return content
