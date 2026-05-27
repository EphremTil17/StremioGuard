"""Managed Comet runtime override generation."""

from __future__ import annotations

import json
import re
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

    if "def _strip_redundant_hdr_tokens(" not in rendered:
        helper_marker = "def format_video_info(data: ParsedData):\n"
        helper_block = """
def _normalize_video_token(token: str) -> str:
    normalized = token.strip()
    upper = normalized.upper()
    if upper == "HEVC":
        return "HEVC"
    return normalized


def _strip_redundant_hdr_tokens(info: str) -> str:
    if not info:
        return ""
    parts = [part.strip() for part in info.split("•")]
    filtered = []
    for part in parts:
        normalized = part.upper().strip()
        if normalized == "HDR":
            continue
        filtered.append(_normalize_video_token(part))
    return " • ".join(filtered)


"""
        if helper_marker not in rendered:
            raise RuntimeError(
                "Unable to apply managed Comet formatter patch; upstream "
                "video formatting helper has changed."
            )
        rendered = rendered.replace(helper_marker, helper_block + helper_marker, 1)

    original_video_return = '    return " • ".join(video_parts) if video_parts else ""\n'
    replacement_video_return = (
        '    info = " • ".join(video_parts) if video_parts else ""\n'
        "    return _strip_redundant_hdr_tokens(info)\n"
    )
    if replacement_video_return not in rendered:
        if original_video_return not in rendered:
            raise RuntimeError(
                "Unable to apply managed Comet formatter patch; upstream "
                "video info return block has changed."
            )
        rendered = rendered.replace(original_video_return, replacement_video_return, 1)

    replacements = {
        '    "title": "{}",': '    "title": "☰  {}",',
        '    "video": "{}",': '    "video": "📽 {}",',
        '    "audio": "{}",': '    "audio": "🕪  {}",',
        '    "quality": "{}",': '    "quality": "✦ {}",',
        '    "seeders": "Seeders: {}",': '    "seeders": "🗣 {}",',
        '    "size": "Size: {}",': '    "size": "⛃{}",',
        '    "tracker": "Source: {}",': '    "tracker": "🔍︎ {}",',
        '    "tracker_clean": "Source: Comet|{}",': '    "tracker_clean": "🔍︎ Comet|{}",',
        '    "languages": "Languages: {}",': '    "languages": "{}",',
    }
    for before, after in replacements.items():
        rendered = rendered.replace(before, after)

    replacement_format_title = """def format_title(components: dict):
    lines = []

    if "title" in components:
        lines.append(components["title"])

    if "video" in components:
        lines.append(components["video"])

    if "quality" in components:
        lines.append(components["quality"])

    if "audio" in components:
        lines.append(components["audio"])

    if "size" in components:
        lines.append(components["size"])

    if not lines:
        return "Empty result format configuration"

    return "\\n".join(lines)
"""
    if replacement_format_title not in rendered:
        original_format_title = re.compile(
            r"def format_title\(components: dict\):\n"
            r"(?:    .*\n|\n)+?"
            r'    return "\\n"\.join\(lines\)\n',
            re.MULTILINE,
        )
        if not original_format_title.search(rendered):
            raise RuntimeError(
                "Unable to apply managed Comet formatter patch; upstream "
                "title formatting block has changed."
            )
        rendered = original_format_title.sub(
            lambda _match: replacement_format_title, rendered, count=1
        )

    return rendered


def render_stream_override(repo_dir: Path) -> str:
    stream_file = repo_dir / "comet" / "api" / "endpoints" / "stream.py"
    if not stream_file.exists():
        raise RuntimeError(f"Comet stream endpoint file not found at {stream_file}.")
    content = stream_file.read_text(encoding="utf-8")
    helper_marker = "def _build_stream_name(\n"
    if "_display_resolution_label(" not in content:
        helper = """
def _forwarded_external_base(request) -> str:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host")
    forwarded_prefix = request.headers.get("x-forwarded-prefix", "")
    if forwarded_proto and forwarded_host:
        prefix = forwarded_prefix.rstrip("/")
        return f"{forwarded_proto}://{forwarded_host}{prefix}"
    return f"{request.url.scheme}://{request.url.netloc}"


def _hdr_badge(formatted_components: dict | None) -> str:
    if not formatted_components:
        return ""
    video_info = str(formatted_components.get("video", "") or "").upper()
    return "HDR" if "HDR" in video_info or "DV" in video_info else ""


def _series_pack_badge(media_type: str | None, pack_backed: bool) -> str:
    if media_type != "series" or not pack_backed:
        return ""
    return "P"


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


def _display_primary_label(resolution, formatted_components: dict | None = None) -> str:
    normalized = str(resolution).strip().upper()
    mapped = _display_resolution_label(resolution)
    if normalized and normalized != "UNKNOWN":
        return mapped

    if formatted_components:
        quality_info = str(formatted_components.get("quality", "") or "").strip()
        if quality_info:
            quality_value = quality_info.removeprefix("✦ ").strip()
            if quality_value:
                return quality_value

        video_info = str(formatted_components.get("video", "") or "").lower()
        if "xvid" in video_info:
            return "XviD"
        if "hevc" in video_info:
            return "HEVC"
        if "avc" in video_info or "h.264" in video_info:
            return "AVC"

    return mapped


"""
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream "
                "stream helper signature has changed."
            )
        content = content.replace(helper_marker, helper + helper_marker, 1)
    original_signature = """def _build_stream_name(
    kodi: bool,
    service: str,
    resolution,
    icon: str = "",
    formatted_components: dict | None = None,
    seeders: int | None = None,
    status: str = "",
):
"""
    replacement_signature = """def _build_stream_name(
    kodi: bool,
    service: str,
    resolution,
    icon: str = "",
    formatted_components: dict | None = None,
    seeders: int | None = None,
    status: str = "",
    media_type: str | None = None,
    pack_backed: bool = False,
):
"""
    if "pack_backed: bool = False" not in content:
        if original_signature not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream "
                "stream helper signature has changed."
            )
        content = content.replace(original_signature, replacement_signature, 1)
    original_base_url = """    base_playback_host = (
        settings.PUBLIC_BASE_URL
        if settings.PUBLIC_BASE_URL
        else f"{request.url.scheme}://{request.url.netloc}"
    )
"""
    replacement_base_url = """    base_playback_host = (
        settings.PUBLIC_BASE_URL
        if settings.PUBLIC_BASE_URL
        else _forwarded_external_base(request)
    )
"""
    if replacement_base_url not in content:
        if original_base_url not in content:
            raise RuntimeError(
                "Unable to apply managed Comet playback-base patch; upstream "
                "playback URL block has changed."
            )
        content = content.replace(original_base_url, replacement_base_url, 1)
    original = '        return f"[{service}{icon}] Comet {resolution}"'
    replacement = (
        "        primary = _display_primary_label(resolution, formatted_components)\n"
        "        hdr = _hdr_badge(formatted_components)\n"
        "        pack = _series_pack_badge(media_type, pack_backed)\n"
        "        parts = [primary]\n"
        "        if hdr:\n"
        "            parts.append(hdr)\n"
        "        if pack:\n"
        "            parts.append(pack)\n"
        '        return " | ".join(parts)'
    )
    if replacement not in content:
        if original not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream name format has changed."
            )
        content = content.replace(original, replacement, 1)
    call_replacements = {
        '                status="C" if is_cached else "U",\n': (
            '                status="C" if is_cached else "U",\n'
            "                media_type=media_type,\n"
            '                pack_backed=torrent.get("packBacked", False),\n'
        ),
        '                status="P2P",\n': (
            '                status="P2P",\n'
            "                media_type=media_type,\n"
            '                pack_backed=torrent.get("packBacked", False),\n'
        ),
    }
    for before, after in call_replacements.items():
        content = content.replace(before, after)

    helper_marker = "def _build_stream_name(\n"
    helper_block = """def _promote_pack_backed_within_resolution(
    streams: list[dict], *, media_type: str | None
):
    if media_type != \"series\" or len(streams) < 2:
        return streams

    ordered_buckets = []
    bucket_groups = {}
    for stream in streams:
        bucket = str(stream.get(\"_sg_resolution_bucket\", \"\") or \"\")
        if bucket not in bucket_groups:
            ordered_buckets.append(bucket)
            bucket_groups[bucket] = {\"packs\": [], \"others\": []}
        group = \"packs\" if stream.get(\"_sg_pack_backed\") else \"others\"
        bucket_groups[bucket][group].append(stream)

    reordered = []
    for bucket in ordered_buckets:
        reordered.extend(bucket_groups[bucket][\"packs\"])
        reordered.extend(bucket_groups[bucket][\"others\"])
    return reordered


"""
    if "def _promote_pack_backed_within_resolution(" not in content:
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream ordering patch; stream helper "
                "signature has changed."
            )
        content = content.replace(helper_marker, helper_block + helper_marker, 1)

    debrid_stream_block = """            the_stream = {
                "name": stream_name,
                "description": formatted_title,
                "behaviorHints": behavior_hints,
            }
"""
    debrid_stream_replacement = """            the_stream = {
                "name": stream_name,
                "description": formatted_title,
                "behaviorHints": behavior_hints,
            }
            the_stream["_sg_resolution_bucket"] = _display_primary_label(
                rtn_data.resolution, formatted_components
            )
            the_stream["_sg_pack_backed"] = torrent.get("packBacked", False)
"""
    if "_sg_resolution_bucket" not in content and debrid_stream_block in content:
        content = content.replace(debrid_stream_block, debrid_stream_replacement, 1)

    torrent_stream_block = """            the_stream = {
                "name": stream_name,
                "description": formatted_title,
                "behaviorHints": behavior_hints,
                "infoHash": info_hash,
            }
"""
    torrent_stream_replacement = """            the_stream = {
                "name": stream_name,
                "description": formatted_title,
                "behaviorHints": behavior_hints,
                "infoHash": info_hash,
            }
            the_stream["_sg_resolution_bucket"] = _display_primary_label(
                rtn_data.resolution, formatted_components
            )
            the_stream["_sg_pack_backed"] = torrent.get("packBacked", False)
"""
    if torrent_stream_replacement not in content and torrent_stream_block in content:
        content = content.replace(torrent_stream_block, torrent_stream_replacement, 1)

    final_streams_block = """    if sort_mixed:
        final_streams = cached_results
    else:
        final_streams = cached_results + non_cached_results

    has_results = len(final_streams) > 0
"""
    final_streams_replacement = """    if sort_mixed:
        final_streams = cached_results
    else:
        final_streams = cached_results + non_cached_results

    final_streams = _promote_pack_backed_within_resolution(
        final_streams,
        media_type=media_type,
    )
    for stream in final_streams:
        stream.pop("_sg_resolution_bucket", None)
        stream.pop("_sg_pack_backed", None)

    has_results = len(final_streams) > 0
"""
    if 'stream.pop("_sg_resolution_bucket"' not in content and final_streams_block in content:
        content = content.replace(final_streams_block, final_streams_replacement, 1)
    return content


def render_config_override(repo_dir: Path) -> str:
    config_file = repo_dir / "comet" / "api" / "endpoints" / "config.py"
    if not config_file.exists():
        raise RuntimeError(f"Comet config endpoint file not found at {config_file}.")
    content = config_file.read_text(encoding="utf-8")

    marker = "def _next_url(request: Request):\n"
    if "_forwarded_prefix(" not in content:
        helper = """
def _forwarded_prefix(request: Request) -> str:
    prefix = request.headers.get("x-forwarded-prefix", "").strip().rstrip("/")
    if not prefix:
        return ""
    return prefix if prefix.startswith("/") else f"/{prefix}"


def _prefixed_path(request: Request, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    prefix = _forwarded_prefix(request)
    if prefix and not normalized_path.startswith(f"{prefix}/") and normalized_path != prefix:
        return f"{prefix}{normalized_path}"
    return normalized_path


def _sanitize_next_url_for_request(request: Request, next_url: str | None):
    sanitized = _sanitize_next_url(next_url)
    if sanitized == "/configure":
        return _prefixed_path(request, "/configure")
    return sanitized


def _is_secure_request(request: Request) -> bool:
    return (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https"


"""
        if marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet config-prefix patch; upstream "
                "next-url helper has changed."
            )
        content = content.replace(marker, helper + marker, 1)

    original_next = """def _next_url(request: Request):
    return (
        f"{request.url.path}?{request.url.query}"
        if request.url.query
        else request.url.path
    )
"""
    replacement_next = """def _next_url(request: Request):
    path = _prefixed_path(request, request.url.path)
    return f"{path}?{request.url.query}" if request.url.query else path
"""
    if replacement_next not in content:
        if original_next not in content:
            raise RuntimeError(
                "Unable to apply managed Comet config-prefix patch; upstream "
                "next-url body has changed."
            )
        content = content.replace(original_next, replacement_next, 1)

    replacements = {
        '"form_action": "/configure/login",': (
            '"form_action": _prefixed_path(request, "/configure/login"),'
        ),
        '"next_url": _sanitize_next_url(next_url),': (
            '"next_url": _sanitize_next_url_for_request(request, next_url),'
        ),
        "return RedirectResponse(_sanitize_next_url(next_url), status_code=303)": (
            "return RedirectResponse("
            "_sanitize_next_url_for_request(request, next_url), status_code=303)"
        ),
        'next_url=_sanitize_next_url(next_url), error="Invalid password"': (
            'next_url=_sanitize_next_url_for_request(request, next_url), error="Invalid password"'
        ),
        "response = RedirectResponse(_sanitize_next_url(next_url), status_code=303)": (
            "response = RedirectResponse("
            "_sanitize_next_url_for_request(request, next_url), status_code=303)"
        ),
        'secure=request.url.scheme == "https",': "secure=_is_secure_request(request),",
        'return RedirectResponse("/configure", status_code=303)': (
            'return RedirectResponse(_prefixed_path(request, "/configure"), status_code=303)'
        ),
    }
    for before, after in replacements.items():
        content = content.replace(before, after)
    return content


def render_configure_template_override(
    repo_dir: Path,
    gateway_addon_base_url: str | None = None,
) -> str:
    template_file = repo_dir / "comet" / "templates" / "index.html"
    if not template_file.exists():
        raise RuntimeError(f"Comet configure template not found at {template_file}.")
    content = template_file.read_text(encoding="utf-8")

    prefix_marker = '          const stremioApiPrefix = {{ (stremioApiPrefix or "") | tojson }};\n'
    gateway_base_literal = json.dumps((gateway_addon_base_url or "").rstrip("/"))
    if "function getCometMountPath()" not in content:
        prefix_line = (
            '          const stremioApiPrefix = {{ (stremioApiPrefix or "") | tojson }};\n'
        )
        prefix_helper = (
            prefix_line
            + """          const cometConfiguredPublicBase = __GATEWAY_ADDON_BASE_URL__;

          function getCometMountPath() {
            const segments = window.location.pathname.split("/").filter(Boolean);
            const configureIndex = segments.lastIndexOf("configure");
            const cometIndex = segments.indexOf("comet");
            if (cometIndex < 0 || configureIndex < 0 || cometIndex >= configureIndex) {
              return "";
            }
            return "/" + segments.slice(0, cometIndex + 1).join("/");
          }

          function getCometPublicBase() {
            if (cometConfiguredPublicBase) {
              if (cometConfiguredPublicBase.startsWith("/")) {
                return `${window.location.origin}${cometConfiguredPublicBase}`;
              }
              return cometConfiguredPublicBase;
            }
            return `${window.location.origin}${getCometMountPath()}`;
          }

          function getCometInstallBase(host, cometMountPath) {
            if (!cometConfiguredPublicBase) {
              return `${host}${cometMountPath}`;
            }
            if (cometConfiguredPublicBase.startsWith("/")) {
              return `${host}${cometConfiguredPublicBase}`;
            }
            const url = new URL(cometConfiguredPublicBase);
            return `${url.host}${url.pathname.replace(/\\/$/, "")}`;
          }
"""
        )
        prefix_helper = prefix_helper.replace("__GATEWAY_ADDON_BASE_URL__", gateway_base_literal)
        if prefix_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet configure-template patch; upstream "
                "stremioApiPrefix marker has changed."
            )
        content = content.replace(prefix_marker, prefix_helper, 1)

    host_line = "            const host = window.location.host;"
    host_replacement = (
        "            const host = window.location.host;\n"
        "            const cometMountPath = getCometMountPath();\n"
        "            const cometPublicBase = getCometPublicBase();\n"
        "            const cometInstallBase = getCometInstallBase(host, cometMountPath);"
    )
    if host_replacement not in content:
        content = content.replace(host_line, host_replacement)
    content = content.replace(
        "`stremio://${host}${stremioApiPrefix}/manifest.json`",
        "`stremio://${cometInstallBase}${stremioApiPrefix}/manifest.json`",
    )
    content = content.replace(
        "`stremio://${host}${stremioApiPrefix}/${settingsString}/manifest.json`",
        "`stremio://${cometInstallBase}${stremioApiPrefix}/${settingsString}/manifest.json`",
    )
    content = content.replace(
        "`${window.location.origin}${stremioApiPrefix}/manifest.json`",
        "`${cometPublicBase}${stremioApiPrefix}/manifest.json`",
    )
    content = content.replace(
        "`${window.location.origin}${stremioApiPrefix}/${settingsString}/manifest.json`",
        "`${cometPublicBase}${stremioApiPrefix}/${settingsString}/manifest.json`",
    )
    return content


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

    def _is_pack_backed_candidate(
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
            '                "packBacked": self._is_pack_backed_candidate(\n'
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
            '                "packBacked": self._is_pack_backed_candidate(\n'
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
