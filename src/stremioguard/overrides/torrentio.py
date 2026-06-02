from __future__ import annotations

from pathlib import Path


def render_torrentio_override(repo_dir: Path) -> str:
    # Keep the scraper patch focused on one job: preserve enough upstream
    # evidence from resolved/native-style Torrentio results for the rest of the
    # pipeline to reason about them. We do not try to fully reimplement
    # Torrentio here; we only normalize the result into the fields Comet
    # expects, with extra support for resolved URL / filename-derived data.
    #
    # Important: native Torrentio often returns a rich display title on the
    # first line and a concrete resolved filename on a later line. Comet needs
    # both:
    # - the rich first line for RTN parsing/ranking (resolution, HDR, codec...)
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
    quality_needles = (
        '"hdr", "dolby vision", " dv ", "[dv", "web-dl", "webrip", '
        '"bluray", "bdrip", "hdtv", "remux"'
    )
    replacement_lines = [
        f'{indent}info_hash = torrent.get("infoHash")',
        f'{indent}file_index = torrent.get("fileIdx", None)',
        f'{indent}behavior_hints = torrent.get("behaviorHints", {{}}) or {{}}',
        f"{indent}title_lines = [line.strip() for line in title_full.splitlines() if line.strip()]",
        f'{indent}resolved_filename = behavior_hints.get("filename")',
        f"{indent}metadata_lines = [",
        f"{inner}line for line in title_lines",
        f'{inner}if "💾" not in line and "👤" not in line and "⚙️" not in line and "🇬" not in line',
        f"{indent}]",
        f"{indent}def _line_score(line: str) -> tuple[int, int]:",
        f"{inner}normalized = line.lower()",
        f"{inner}score = 0",
        f'{inner}for needle in ("2160p", "1080p", "720p", "576p", "480p", "360p", "240p", "4k"):',
        f"{inner2}if needle in normalized:",
        f"{inner2}    score += 8",
        f"{inner}for needle in ({quality_needles}):",
        f"{inner2}if needle in normalized:",
        f"{inner2}    score += 4",
        f'{inner}for needle in ("x265", "x264", "hevc", "avc", "xvid", "ddp", "dts", "aac"):',
        f"{inner2}if needle in normalized:",
        f"{inner2}    score += 2",
        f'{inner}if "s01e01" in normalized or "s01" in normalized or "1x01" in normalized:',
        f"{inner2}score += 2",
        f"{inner}return score, len(line)",
        f"{indent}display_title = title",
        f"{indent}if metadata_lines:",
        f"{inner}display_title = max(metadata_lines, key=_line_score)",
        f"{indent}elif title_lines:",
        f"{inner}display_title = title_lines[0]",
        f"{indent}if not resolved_filename and title_lines:",
        f"{inner}fallback_filename = title_lines[-1]",
        f"{inner}if fallback_filename != display_title:",
        f"{inner2}resolved_filename = fallback_filename",
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
        f'{inner2}"title": display_title,',
        f'{inner2}"sourceTitle": title_full,',
        f'{inner2}"resolvedFileName": resolved_filename,',
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
