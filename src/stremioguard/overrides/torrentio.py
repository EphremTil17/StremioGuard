from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching


def render_torrentio_override(repo_dir: Path) -> str:
    # Keep the scraper patch focused on one job: preserve enough upstream
    # evidence from resolved/native-style Torrentio results for the rest of the
    # pipeline to reason about them. We do not try to fully reimplement
    # Torrentio here; we only normalize the result into the fields Comet
    # expects, with extra support for resolved URL / filename-derived data.
    #
    # Important: native Torrentio returns a rich release title on the
    # first line and a concrete resolved filename on a later line. Comet needs
    # both:
    # - the rich release title for RTN parsing/ranking (resolution, HDR, season range, codec...)
    # - the resolved filename for exact episode/file matching
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

    if (
        "RESOLVE_INFOHASH_PATTERN" in content
        and '"infoHash": info_hash.lower(),' in content
        and '"sourceTitle": title_full,' in content
        and '"resolvedFileName": resolved_filename,' in content
        and '"fileIndex": file_index,' in content
        and "release_title" in content
    ):
        return content

    target_parse_stream = """    @staticmethod
    def _parse_stream(torrent):
        if not isinstance(torrent, dict):
            return None

        title_full = torrent.get("title")
        info_hash = torrent.get("infoHash")
        sources = torrent.get("sources", [])
        if (
            not isinstance(title_full, str)
            or not title_full
            or not isinstance(info_hash, str)
            or not info_hash
            or not isinstance(sources, list)
        ):
            return None

        if "\\n💾" in title_full:
            title = title_full.split("\\n💾")[0].split("\\n")[-1]
        else:
            title = title_full.split("\\n")[0]

        match = DATA_PATTERN.search(title_full)
        seeders = int(match.group(1)) if match and match.group(1) else None
        size = size_to_bytes(match.group(2)) if match and match.group(2) else None
        tracker = match.group(3) if match and match.group(3) else "KnightCrawler"

        return {
            "title": title,
            "infoHash": info_hash.lower(),
            "fileIndex": torrent.get("fileIdx"),
            "seeders": seeders,
            "size": size,
            "tracker": f"Torrentio|{tracker}",
            "sources": sources,
        }"""

    replacement_parse_stream = """    @staticmethod
    def _parse_stream(torrent):
        if not isinstance(torrent, dict):
            return None

        title_full = torrent.get("title")
        info_hash = torrent.get("infoHash")
        sources = torrent.get("sources", [])
        if not isinstance(title_full, str) or not title_full or not isinstance(sources, list):
            return None

        file_index = torrent.get("fileIdx", None)
        behavior_hints = torrent.get("behaviorHints", {}) or {}
        title_lines = [line.strip() for line in title_full.splitlines() if line.strip()]
        resolved_filename = behavior_hints.get("filename")
        metadata_lines = [
            line
            for line in title_lines
            if "💾" not in line and "👤" not in line and "⚙️" not in line and "🇬" not in line
        ]

        release_title = (
            metadata_lines[0]
            if metadata_lines
            else (title_lines[0] if title_lines else "")
        )
        if not resolved_filename and len(metadata_lines) > 1:
            resolved_filename = metadata_lines[-1]
        elif not resolved_filename and len(title_lines) > 1:
            for candidate in reversed(title_lines[1:]):
                if (
                    "💾" not in candidate
                    and "👤" not in candidate
                    and "⚙️" not in candidate
                    and "🇬" not in candidate
                ):
                    resolved_filename = candidate
                    break

        if not info_hash:
            binge_group = behavior_hints.get("bingeGroup", "")
            if "|" in binge_group:
                candidate_hash = binge_group.rsplit("|", 1)[-1].strip().lower()
                if re.fullmatch(r"[0-9a-f]{40}", candidate_hash):
                    info_hash = candidate_hash

        resolved_url = torrent.get("url", "")
        if not info_hash and resolved_url:
            match = RESOLVE_INFOHASH_PATTERN.search(urlparse(resolved_url).path)
            if match:
                info_hash = match.group(1).lower()

        if file_index is None and resolved_url:
            match = RESOLVE_FILE_INDEX_PATTERN.search(urlparse(resolved_url).path)
            if match:
                try:
                    file_index = int(unquote(match.group(1)))
                except ValueError:
                    file_index = match.group(1)

        if not info_hash or not isinstance(info_hash, str):
            return None

        match = DATA_PATTERN.search(title_full)
        seeders = int(match.group(1)) if match and match.group(1) else None
        size = size_to_bytes(match.group(2)) if match and match.group(2) else None
        tracker = match.group(3) if match and match.group(3) else "KnightCrawler"

        return {
            "title": release_title,
            "sourceTitle": title_full,
            "resolvedFileName": resolved_filename,
            "infoHash": info_hash.lower(),
            "fileIndex": file_index,
            "seeders": seeders,
            "size": size,
            "tracker": f"Torrentio|{tracker}",
            "sources": sources,
        }"""

    extraction_target_upstream = """            for torrent in results["streams"]:
                title_full = torrent["title"]

                if "\\n💾" in title_full:
                    title = title_full.split("\\n💾")[0].split("\\n")[-1]
                else:
                    title = title_full.split("\\n")[0]

                match = DATA_PATTERN.search(title_full)

                seeders = int(match.group(1)) if match and match.group(1) else None
                size = (
                    size_to_bytes(match.group(2)) if match and match.group(2) else None
                )
                tracker = (
                    match.group(3) if match and match.group(3) else "KnightCrawler"
                )

                torrents.append(
                    {
                        "title": title,
                        "infoHash": torrent["infoHash"].lower(),
                        "fileIndex": torrent.get("fileIdx", None),
                        "seeders": seeders,
                        "size": size,
                        "tracker": f"Torrentio|{tracker}",
                        "sources": torrent.get("sources", []),
                    }
                )"""

    extraction_replacement_upstream = """            for torrent in results["streams"]:
                title_full = torrent.get("title", "")
                if not isinstance(title_full, str) or not title_full:
                    continue

                info_hash = torrent.get("infoHash")
                file_index = torrent.get("fileIdx", None)
                behavior_hints = torrent.get("behaviorHints", {}) or {}
                title_lines = [line.strip() for line in title_full.splitlines() if line.strip()]
                resolved_filename = behavior_hints.get("filename")
                metadata_lines = [
                    line
                    for line in title_lines
                    if "💾" not in line and "👤" not in line and "⚙️" not in line and "🇬" not in line
                ]

                release_title = (
                    metadata_lines[0]
                    if metadata_lines
                    else (title_lines[0] if title_lines else "")
                )
                if not resolved_filename and len(metadata_lines) > 1:
                    resolved_filename = metadata_lines[-1]
                elif not resolved_filename and len(title_lines) > 1:
                    for candidate in reversed(title_lines[1:]):
                        if (
                            "💾" not in candidate
                            and "👤" not in candidate
                            and "⚙️" not in candidate
                            and "🇬" not in candidate
                        ):
                            resolved_filename = candidate
                            break

                if not info_hash:
                    binge_group = behavior_hints.get("bingeGroup", "")
                    if "|" in binge_group:
                        candidate_hash = binge_group.rsplit("|", 1)[-1].strip().lower()
                        if re.fullmatch(r"[0-9a-f]{40}", candidate_hash):
                            info_hash = candidate_hash

                resolved_url = torrent.get("url", "")
                if not info_hash and resolved_url:
                    match = RESOLVE_INFOHASH_PATTERN.search(urlparse(resolved_url).path)
                    if match:
                        info_hash = match.group(1).lower()

                if file_index is None and resolved_url:
                    match = RESOLVE_FILE_INDEX_PATTERN.search(urlparse(resolved_url).path)
                    if match:
                        try:
                            file_index = int(unquote(match.group(1)))
                        except ValueError:
                            file_index = match.group(1)

                if not info_hash:
                    continue

                match = DATA_PATTERN.search(title_full)
                seeders = int(match.group(1)) if match and match.group(1) else None
                size = size_to_bytes(match.group(2)) if match and match.group(2) else None
                tracker = match.group(3) if match and match.group(3) else "KnightCrawler"

                torrents.append(
                    {
                        "title": release_title,
                        "sourceTitle": title_full,
                        "resolvedFileName": resolved_filename,
                        "infoHash": info_hash.lower(),
                        "fileIndex": file_index,
                        "seeders": seeders,
                        "size": size,
                        "tracker": f"Torrentio|{tracker}",
                        "sources": torrent.get("sources", []),
                    }
                )"""

    extraction_target_8space = """        for torrent in results["streams"]:
            title_full = torrent["title"]

            if "\\n💾" in title_full:
                title = title_full.split("\\n💾")[0].split("\\n")[-1]
            else:
                title = title_full.split("\\n")[0]

            match = DATA_PATTERN.search(title_full)

            seeders = int(match.group(1)) if match and match.group(1) else None
            size = (
                size_to_bytes(match.group(2)) if match and match.group(2) else None
            )
            tracker = (
                match.group(3) if match and match.group(3) else "KnightCrawler"
            )

            torrents.append(
                {
                    "title": title,
                    "infoHash": torrent["infoHash"].lower(),
                    "fileIndex": torrent.get("fileIdx", None),
                    "seeders": seeders,
                    "size": size,
                    "tracker": f"Torrentio|{tracker}",
                    "sources": torrent.get("sources", []),
                }
            )"""

    extraction_replacement_8space = """        for torrent in results["streams"]:
            title_full = torrent.get("title", "")
            if not isinstance(title_full, str) or not title_full:
                continue

            info_hash = torrent.get("infoHash")
            file_index = torrent.get("fileIdx", None)
            behavior_hints = torrent.get("behaviorHints", {}) or {}
            title_lines = [line.strip() for line in title_full.splitlines() if line.strip()]
            resolved_filename = behavior_hints.get("filename")
            metadata_lines = [
                line
                for line in title_lines
                if "💾" not in line and "👤" not in line and "⚙️" not in line and "🇬" not in line
            ]

            release_title = (
                metadata_lines[0]
                if metadata_lines
                else (title_lines[0] if title_lines else "")
            )
            if not resolved_filename and len(metadata_lines) > 1:
                resolved_filename = metadata_lines[-1]
            elif not resolved_filename and len(title_lines) > 1:
                for candidate in reversed(title_lines[1:]):
                    if (
                        "💾" not in candidate
                        and "👤" not in candidate
                        and "⚙️" not in candidate
                        and "🇬" not in candidate
                    ):
                        resolved_filename = candidate
                        break

            if not info_hash:
                binge_group = behavior_hints.get("bingeGroup", "")
                if "|" in binge_group:
                    candidate_hash = binge_group.rsplit("|", 1)[-1].strip().lower()
                    if re.fullmatch(r"[0-9a-f]{40}", candidate_hash):
                        info_hash = candidate_hash

            resolved_url = torrent.get("url", "")
            if not info_hash and resolved_url:
                match = RESOLVE_INFOHASH_PATTERN.search(urlparse(resolved_url).path)
                if match:
                    info_hash = match.group(1).lower()

            if file_index is None and resolved_url:
                match = RESOLVE_FILE_INDEX_PATTERN.search(urlparse(resolved_url).path)
                if match:
                    try:
                        file_index = int(unquote(match.group(1)))
                    except ValueError:
                        file_index = match.group(1)

            if not info_hash:
                continue

            match = DATA_PATTERN.search(title_full)
            seeders = int(match.group(1)) if match and match.group(1) else None
            size = size_to_bytes(match.group(2)) if match and match.group(2) else None
            tracker = match.group(3) if match and match.group(3) else "KnightCrawler"

            torrents.append(
                {
                    "title": release_title,
                    "sourceTitle": title_full,
                    "resolvedFileName": resolved_filename,
                    "infoHash": info_hash.lower(),
                    "fileIndex": file_index,
                    "seeders": seeders,
                    "size": size,
                    "tracker": f"Torrentio|{tracker}",
                    "sources": torrent.get("sources", []),
                }
            )"""

    return replace_first_matching(
        content,
        (
            (target_parse_stream, replacement_parse_stream),
            (extraction_target_upstream, extraction_replacement_upstream),
            (extraction_target_8space, extraction_replacement_8space),
        ),
        error=(
            "Unable to apply managed Comet Torrentio scraper patch; upstream "
            "result extraction block has changed."
        ),
    )
