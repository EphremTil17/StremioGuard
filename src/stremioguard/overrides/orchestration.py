from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

_SCOPE_SIGNATURES = (
    # 2026-07 added the scope_is_known keyword; older images lack it.
    """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
        scope_is_known: bool = False,
    ) -> bool:
""",
    """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
    ) -> bool:
""",
)


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

    helper_marker = next((sig for sig in _SCOPE_SIGNATURES if sig in content), None)
    if helper_marker is None:
        raise RuntimeError(
            "Unable to apply managed Comet orchestration patch; upstream scope matcher has changed."
        )
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
        content = content.replace(helper_marker, helper_block + helper_marker, 1)

    # 2026-07 routed scope matching through self.media_scope.matches_parsed and
    # dropped the parsed_matches_target import; the patched body must call
    # whichever primitive THIS version actually has in scope, or it would raise
    # NameError at request time — a failure the import-smoke stage cannot see.
    scope_original_new = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
        scope_is_known: bool = False,
    ) -> bool:
        reject_unknown = (
            self.reject_unknown_episode_files
            if reject_unknown_override is None
            else reject_unknown_override
        )
        return self.media_scope.matches_parsed(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=reject_unknown,
            scope_is_known=scope_is_known,
        )"""
    scope_replacement_new = """    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        file_index: int | None = None,
        reject_unknown_override: bool | None = None,
        scope_is_known: bool = False,
    ) -> bool:
        reject_unknown = (
            self.reject_unknown_episode_files
            if reject_unknown_override is None
            else reject_unknown_override
        )
        if self.media_scope.matches_parsed(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=reject_unknown,
            scope_is_known=scope_is_known,
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

        return self.media_scope.matches_parsed(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=False,
            scope_is_known=scope_is_known,
        )"""
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
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=reject_unknown,
        )"""
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
        )"""
    content = replace_first_matching(
        content,
        (
            (scope_original_new, scope_replacement_new),
            (original_method, replacement_method),
        ),
        error=(
            "Unable to apply managed Comet orchestration patch; upstream scope matcher has changed."
        ),
    )

    # Each edit below is verified: a silent no-op would ship a file that still
    # reports as applied while having lost the behavior it exists for. Where
    # upstream reformatted a call site, the older shape follows as a fallback.
    record_live = (
        "        for torrent in self.ready_to_cache:\n"
        "            self._record_pack_backed_candidate(\n"
        '                torrent["infoHash"],\n'
        "                episode=self.search_episode,\n"
        '                file_index=torrent["fileIndex"],\n'
        "            )\n"
    )
    record_cached = (
        "            self._record_pack_backed_candidate(\n"
        '                row["info_hash"],\n'
        '                episode=row["episode"],\n'
        '                file_index=row["file_index"],\n'
        "            )\n"
    )
    edits: tuple[tuple[str, tuple[tuple[str, str], ...], int | None], ...] = (
        (
            "pack-backed recording for live results",
            (("        for torrent in self.ready_to_cache:\n", record_live),),
            # Every ready_to_cache loop records candidates, however many
            # upstream happens to have.
            None,
        ),
        (
            "live scope call",
            (
                (
                    'if not self._matches_requested_scope(torrent["parsed"]):',
                    "if not self._matches_requested_scope("
                    'torrent["parsed"], file_index=torrent["fileIndex"]):',
                ),
            ),
            1,
        ),
        (
            "live packBacked flag",
            (
                (
                    '                "parsed": torrent["parsed"],\n',
                    '                "parsed": torrent["parsed"],\n'
                    '                "packBacked": await self._is_pack_backed_candidate(\n'
                    '                    torrent["parsed"],\n'
                    "                    info_hash=info_hash,\n"
                    '                    file_index=torrent["fileIndex"],\n'
                    "                ),\n",
                ),
            ),
            1,
        ),
        (
            "pack-backed recording for cached rows",
            (
                # 2026-07 replaced the inline orjson parse with load_cached_parsed.
                (
                    '            parsed_data = load_cached_parsed(row["parsed_json"])\n',
                    record_cached
                    + '            parsed_data = load_cached_parsed(row["parsed_json"])\n',
                ),
                (
                    '            parsed_data = ParsedData(**orjson.loads(row["parsed_json"]))\n',
                    record_cached
                    + '            parsed_data = ParsedData(**orjson.loads(row["parsed_json"]))\n',
                ),
            ),
            1,
        ),
        (
            "cached scope call",
            (
                # 2026-07 split this call across lines and added scope_is_known.
                (
                    "                parsed_data,\n"
                    "                reject_unknown_override=reject_unknown_override,\n",
                    "                parsed_data,\n"
                    '                file_index=row["file_index"],\n'
                    "                reject_unknown_override=reject_unknown_override,\n",
                ),
                (
                    "parsed_data, reject_unknown_override=reject_unknown_override",
                    "parsed_data, "
                    'file_index=row["file_index"], '
                    "reject_unknown_override=reject_unknown_override",
                ),
            ),
            1,
        ),
        (
            "cached packBacked flag",
            (
                (
                    '                "parsed": parsed_data,\n',
                    '                "parsed": parsed_data,\n'
                    '                "packBacked": await self._is_pack_backed_candidate(\n'
                    "                    parsed_data,\n"
                    "                    info_hash=info_hash,\n"
                    '                    file_index=row["file_index"],\n'
                    "                ),\n",
                ),
            ),
            1,
        ),
        (
            "cache file-info scope call",
            (
                (
                    "parsed, reject_unknown_override=True",
                    'parsed, file_index=torrent["fileIndex"], reject_unknown_override=True',
                ),
            ),
            1,
        ),
    )
    for description, candidates, expected in edits:
        content = replace_first_matching(
            content,
            candidates,
            error=(
                "Unable to apply managed Comet orchestration patch; "
                f"upstream {description} has changed."
            ),
            expected=expected,
        )

    return content
