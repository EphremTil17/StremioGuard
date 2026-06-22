from __future__ import annotations

from pathlib import Path


def render_stream_override(repo_dir: Path) -> str:
    stream_file = repo_dir / "comet" / "api" / "endpoints" / "stream.py"
    if not stream_file.exists():
        raise RuntimeError(f"Comet stream endpoint file not found at {stream_file}.")
    content = stream_file.read_text(encoding="utf-8")
    helper_marker = "def _build_stream_name(\n"
    if "_display_resolution_label(" not in content:
        helper = r"""
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
    if "HDR" in video_info or "DV" in video_info:
        return "HDR"
    title_info = str(formatted_components.get("title", "") or "").upper()
    import re
    if re.search(r"\b(HDR|DV|HDR10|HDR10\+|DV-HDR|DV\+HDR|DOLBY\s*VISION)\b", title_info):
        return "HDR"
    return ""


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
    media_type: str | None = None,
    pack_backed: bool = False,
):
"""
    if "pack_backed: bool = False" not in content:
        original_signature_raw = """def _build_stream_name(
    kodi: bool,
    service: str,
    resolution,
    icon: str = "",
    formatted_components: dict | None = None,
    seeders: int | None = None,
    status: str = "",
):
"""
        if original_signature_raw not in content:
            raise RuntimeError(
                "Unable to apply managed Comet stream-name patch; upstream "
                "stream helper signature has changed."
            )
        content = content.replace(original_signature_raw, original_signature, 1)
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

    # Stamp each torrent dict with its RTN rank so the per-stream formatter can
    # surface it. ranked_torrents maps info_hash -> RTN Torrent (carrying .rank);
    # torrents maps info_hash -> the dict consumed during stream building.
    rank_stamp_block = "    torrents = torrent_manager.torrents\n"
    rank_stamp_replacement = (
        "    torrents = torrent_manager.torrents\n"
        "    for _sg_info_hash, _sg_ranked in torrent_manager.ranked_torrents.items():\n"
        "        _sg_torrent = torrents.get(_sg_info_hash)\n"
        "        if _sg_torrent is not None:\n"
        '            _sg_torrent["_sg_rank"] = getattr(_sg_ranked, "rank", None)\n'
    )
    if "_sg_rank" not in content and rank_stamp_block in content:
        content = content.replace(rank_stamp_block, rank_stamp_replacement, 1)

    # Render technical metadata first, then the RTN rank, and finally the raw
    # release title. The title is intentionally last because Android TV may
    # truncate the bottom of a stream card; technical metadata and rank must
    # remain visible above it.
    size_rank_block = """        formatted_components = format_components(
            rtn_data,
            torrent_title,
            torrent["seeders"],
            torrent_size,
            torrent["tracker"],
            config["resultFormat"],
        )
        formatted_title = format_title_fn(formatted_components)
"""
    size_rank_replacement = """        formatted_components = format_components(
            rtn_data,
            torrent_title,
            torrent["seeders"],
            torrent_size,
            torrent["tracker"],
            config["resultFormat"],
        )
        _sg_rank = torrent.get("_sg_rank")
        _sg_display_components = dict(formatted_components)
        _sg_title = _sg_display_components.pop("title", None)
        _sg_size = _sg_display_components.get("size")
        if _sg_rank is not None and _sg_size:
            _sg_display_components["size"] = f"{_sg_size} • R:{_sg_rank}"
        formatted_title = format_title_fn(_sg_display_components)
        if _sg_rank is not None and not _sg_size:
            formatted_title = f"{formatted_title}\\n– R:{_sg_rank}"
        if _sg_title is not None:
            formatted_title = f"{formatted_title}\\n{_sg_title}"
"""
    rank_already_applied = size_rank_replacement in content
    if "_sg_rank" in content and not rank_already_applied and size_rank_block in content:
        content = content.replace(size_rank_block, size_rank_replacement, 1)
    return content
