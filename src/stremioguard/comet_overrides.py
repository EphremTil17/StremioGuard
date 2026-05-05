"""Managed Comet runtime override generation."""

from __future__ import annotations

from pathlib import Path


def render_formatter_override(repo_dir: Path, result_format_style: str) -> str | None:
    if result_format_style == "emoji":
        return None
    formatting_file = repo_dir / "comet" / "utils" / "formatting.py"
    if not formatting_file.exists():
        raise RuntimeError(f"Comet formatting file not found at {formatting_file}.")
    content = formatting_file.read_text(encoding="utf-8")
    emoji_block = """def get_formatted_components(
    data: ParsedData,
    ttitle: str,
    seeders: int,
    size: int,
    tracker: str,
    result_format: list,
):
    return _get_formatted_components(
        data, ttitle, seeders, size, tracker, result_format, _STYLE_EMOJI
    )
"""
    plain_block = """def get_formatted_components(
    data: ParsedData,
    ttitle: str,
    seeders: int,
    size: int,
    tracker: str,
    result_format: list,
):
    return _get_formatted_components(
        data, ttitle, seeders, size, tracker, result_format, _STYLE_PLAIN
    )
"""
    if plain_block in content:
        rendered = content
    else:
        if emoji_block not in content:
            raise RuntimeError(
                "Unable to apply managed Comet formatter patch; upstream formatting "
                "function signature has changed."
            )
        rendered = content.replace(emoji_block, plain_block, 1)
    replacements = {
        '    "title": "{}",': '    "title": "☰  {}",',
        '    "video": "{}",': '    "video": "📽 {}",',
        '    "audio": "{}",': '    "audio": "🕪  {}",',
        '    "quality": "{}",': '    "quality": "✦ {}",',
        '    "seeders": "Seeders: {}",': '    "seeders": "🗣 {}",',
        '    "size": "Size: {}",': '    "size": "⛃{}",',
        '    "tracker": "Source: {}",': '    "tracker": "🔍︎ {}",',
        '    "tracker_clean": "Source: Comet|{}",': '    "tracker_clean": "🔍︎ Comet|{}",',
        '    "languages": "Languages: {}",': '    "languages": "{}"',
    }
    for before, after in replacements.items():
        rendered = rendered.replace(before, after)
    return rendered


def render_stream_override(repo_dir: Path) -> str:
    stream_file = repo_dir / "comet" / "api" / "endpoints" / "stream.py"
    if not stream_file.exists():
        raise RuntimeError(f"Comet stream endpoint file not found at {stream_file}.")
    content = stream_file.read_text(encoding="utf-8")
    helper_marker = "def _build_stream_name(\n"
    if "_display_resolution_label(" not in content:
        helper = """
def _display_resolution_label(resolution) -> str:
    normalized = str(resolution).strip().upper()
    labels = {
        "4K": "UHD",
        "2160P": "UHD",
        "1440P": "QHD",
        "1080P": "FHD",
        "720P": "HD",
        "576P": "576p",
        "480P": "480p",
        "360P": "360p",
        "240P": "240p",
    }
    return labels.get(normalized, str(resolution))


"""
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream "
                "stream helper signature has changed."
            )
        content = content.replace(helper_marker, helper + helper_marker, 1)
    original = '        return f"[{service}{icon}] Comet {resolution}"'
    replacement = "        return _display_resolution_label(resolution)"
    if replacement not in content:
        if original not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream name format has changed."
            )
        content = content.replace(original, replacement, 1)
    return content


def render_torrentio_override(repo_dir: Path) -> str:
    # Keep the scraper patch focused on one job: preserve enough upstream
    # evidence from resolved/native-style Torrentio results for the rest of the
    # pipeline to reason about them. We do not try to fully reimplement
    # Torrentio here; we only normalize the result into the fields Comet
    # expects, with extra support for resolved URL / filename-derived data.
    scraper_file = repo_dir / "comet" / "scrapers" / "torrentio.py"
    if not scraper_file.exists():
        raise RuntimeError(f"Comet Torrentio scraper file not found at {scraper_file}.")
    content = scraper_file.read_text(encoding="utf-8")

    import_block = "import re\n"
    replacement_import_block = (
        "import re\n"
        "from urllib.parse import unquote, urlparse\n"
        "\n"
        "RESOLVE_INFOHASH_PATTERN = re.compile(\n"
        '    r"/resolve/[^/]+/[^/]+/([0-9a-fA-F]{40})/"\n'
        ")\n"
        "RESOLVE_FILE_INDEX_PATTERN = re.compile(\n"
        '    r"/resolve/[^/]+/[^/]+/[0-9a-fA-F]{40}/[^/]+/(\\\\d+)(?:/|$)"\n'
        ")\n"
    )
    if "RESOLVE_INFOHASH_PATTERN" not in content:
        if import_block not in content:
            raise RuntimeError(
                "Unable to apply managed Comet Torrentio scraper patch; upstream "
                "import block has changed."
            )
        content = content.replace(import_block, replacement_import_block, 1)

    if "RESOLVE_INFOHASH_PATTERN" in content and '"infoHash": info_hash.lower(),' in content:
        return content

    lines = content.splitlines()
    start = next((i for i, line in enumerate(lines) if "torrents.append(" in line), None)
    if start is None:
        raise RuntimeError(
            "Unable to apply managed Comet Torrentio scraper patch; upstream "
            "result extraction block has changed."
        )
    end = None
    for index in range(start, len(lines)):
        if lines[index].strip() == ")" and index > start:
            end = index
            break
    if end is None:
        raise RuntimeError(
            "Unable to apply managed Comet Torrentio scraper patch; upstream "
            "result extraction block terminator was not found."
        )

    indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
    inner = indent + "    "
    inner2 = inner + "    "
    replacement_lines = [
        f'{indent}info_hash = torrent.get("infoHash")',
        f'{indent}file_index = torrent.get("fileIdx", None)',
        f'{indent}behavior_hints = torrent.get("behaviorHints", {{}}) or {{}}',
        "",
        f"{indent}if not info_hash:",
        f'{inner}binge_group = behavior_hints.get("bingeGroup", "")',
        f'{inner}if "|" in binge_group:',
        f'{inner2}candidate_hash = binge_group.rsplit("|", 1)[-1].strip().lower()',
        f'{inner2}if re.fullmatch(r"[0-9a-f]{{40}}", candidate_hash):',
        f"{inner2}    info_hash = candidate_hash",
        "",
        f'{indent}resolved_url = torrent.get("url", "")',
        f"{indent}if not info_hash and resolved_url:",
        f"{inner}match = RESOLVE_INFOHASH_PATTERN.search(urlparse(resolved_url).path)",
        f"{inner}if match:",
        f"{inner}    info_hash = match.group(1).lower()",
        "",
        f"{indent}if file_index is None and resolved_url:",
        f"{inner}match = RESOLVE_FILE_INDEX_PATTERN.search(urlparse(resolved_url).path)",
        f"{inner}if match:",
        f"{inner}    try:",
        f"{inner}        file_index = int(unquote(match.group(1)))",
        f"{inner}    except ValueError:",
        f"{inner}        file_index = match.group(1)",
        "",
        f"{indent}if not info_hash:",
        f"{inner}continue",
        "",
        f"{indent}torrents.append(",
        f"{inner}{{",
        f'{inner2}"title": title,',
        f'{inner2}"sourceTitle": title_full,',
        f'{inner2}"resolvedFileName": behavior_hints.get("filename"),',
        f'{inner2}"infoHash": info_hash.lower(),',
        f'{inner2}"fileIndex": file_index,',
        f'{inner2}"seeders": seeders,',
        f'{inner2}"size": size,',
        f'{inner2}"tracker": f"Torrentio|{{tracker}}",',
        f'{inner2}"sources": torrent.get("sources", []),',
        f"{inner}}}",
        f"{indent})",
    ]
    lines[start : end + 1] = replacement_lines
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")


def render_orchestration_override(repo_dir: Path) -> str:
    # The orchestration patch exists because stock Comet is stricter than
    # native Torrentio about episode selection inside season packs. The goal is
    # not "accept everything", but "accept entries with strong season/file
    # evidence even when episode metadata is incomplete".
    orchestration_file = repo_dir / "comet" / "services" / "orchestration.py"
    if not orchestration_file.exists():
        raise RuntimeError(f"Comet orchestration file not found at {orchestration_file}.")
    content = orchestration_file.read_text(encoding="utf-8")

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
        )
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
    if "file_index: int | None = None" not in content:
        if original_method not in content:
            raise RuntimeError(
                "Unable to apply managed Comet orchestration patch; upstream "
                "scope matcher has changed."
            )
        content = content.replace(original_method, replacement_method, 1)

    replacements = {
        'if not self._matches_requested_scope(torrent["parsed"]):': (
            "if not self._matches_requested_scope("
            'torrent["parsed"], file_index=torrent["fileIndex"]):'
        ),
        "parsed_data, reject_unknown_override=reject_unknown_override": (
            "parsed_data, "
            'file_index=row["file_index"], '
            "reject_unknown_override=reject_unknown_override"
        ),
        "parsed, reject_unknown_override=True": (
            'parsed, file_index=torrent["fileIndex"], reject_unknown_override=True'
        ),
    }
    for before, after in replacements.items():
        content = content.replace(before, after)

    return content


def render_filtering_override(repo_dir: Path) -> str:
    # The filtering patch makes title matching more evidence-driven. If the
    # resolved filename or source title clearly contains the Stremio-requested
    # title phrase, we should not reject the result just because the outer
    # release title is branded, multilingual, or formatted differently.
    filtering_file = repo_dir / "comet" / "services" / "filtering.py"
    if not filtering_file.exists():
        raise RuntimeError(f"Comet filtering file not found at {filtering_file}.")
    content = filtering_file.read_text(encoding="utf-8")

    helper_marker = (
        "def quick_alias_match(text_normalized: str, ez_aliases_normalized: list[str]):\n"
    )
    if "_fallback_suffix_title_match(" not in content:
        helper = """
TITLE_TOKEN_STOPWORDS = {
    "a",
    "an",
    "and",
    "at",
    "for",
    "from",
    "in",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}


def _title_tokens(text: str) -> set[str]:
    return {
        token
        for token in scrub(text).split()
        if token and token not in TITLE_TOKEN_STOPWORDS
    }


def _candidate_titles(title: str, aliases: dict) -> set[str]:
    candidates = {scrub(title)}
    for alias_group in aliases.values():
        for alias in alias_group:
            scrubbed = scrub(alias)
            if scrubbed:
                candidates.add(scrubbed)
    return {candidate for candidate in candidates if candidate}


def _contains_title_phrase(text_normalized: str, candidate: str) -> bool:
    if not text_normalized or not candidate:
        return False
    if text_normalized == candidate:
        return True
    padded = f" {text_normalized} "
    if f" {candidate} " in padded:
        return True

    candidate_tokens = _title_tokens(candidate)
    if not candidate_tokens:
        return False
    return candidate_tokens.issubset(_title_tokens(text_normalized))


def _torrent_evidence_match(torrent: dict, title: str, parsed_title: str, aliases: dict) -> bool:
    candidates = _candidate_titles(title, aliases)
    evidence_texts = []
    # Prefer the resolved file name first. If Torrentio has already pointed us
    # at a concrete file inside a pack, that is better evidence than the noisy
    # outer release title.
    for key in ("resolvedFileName", "sourceTitle", "title"):
        value = torrent.get(key)
        if isinstance(value, str) and value:
            evidence_texts.append(value)
    evidence_texts.append(parsed_title)

    for evidence in evidence_texts:
        normalized = scrub(evidence)
        for candidate in candidates:
            if _contains_title_phrase(normalized, candidate):
                return True
        try:
            parsed = _parse_with_cache(evidence)
        except ValidationError:
            continue
        if parsed.parsed_title:
            normalized_parsed = scrub(parsed.parsed_title)
            for candidate in candidates:
                if _contains_title_phrase(normalized_parsed, candidate):
                    return True
    return False


def _titles_compat_match(torrent: dict, title: str, parsed_title: str, aliases: dict) -> bool:
    if title_match(title, parsed_title, aliases=aliases):
        return True
    return _torrent_evidence_match(torrent, title, parsed_title, aliases)


"""
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet filtering patch; upstream helper marker has changed."
            )
        content = content.replace(helper_marker, helper + helper_marker, 1)

    original_line = "if not title_match(title, parsed.parsed_title, aliases=aliases):"
    replacement_line = "if not _titles_compat_match(torrent, title, parsed.parsed_title, aliases):"
    if replacement_line not in content:
        if original_line not in content:
            raise RuntimeError(
                "Unable to apply managed Comet filtering patch; upstream "
                "title-match block has changed."
            )
        content = content.replace(original_line, replacement_line, 1)

    return content


def write_override_bundle(
    repo_dir: Path,
    state_dir: Path,
    result_format_style: str,
    *,
    patch_episode_pack_results: bool,
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
    (state_dir / "torrentio.py").write_text(render_torrentio_override(repo_dir), encoding="utf-8")
    (state_dir / "filtering.py").write_text(render_filtering_override(repo_dir), encoding="utf-8")
    orchestration_target = state_dir / "orchestration.py"
    if patch_episode_pack_results:
        orchestration_target.write_text(render_orchestration_override(repo_dir), encoding="utf-8")
    elif orchestration_target.exists():
        orchestration_target.unlink()
