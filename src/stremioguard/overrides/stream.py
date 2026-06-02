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

    helper_marker = "def _build_stream_name(\n"
    helper_block = """def _promote_pack_backed_within_resolution(
    streams: list[dict], *, media_type: str | None
):
    if media_type != "series" or len(streams) < 2:
        return streams

    ordered_buckets = []
    bucket_groups = {}
    for stream in streams:
        bucket = str(stream.get("_sg_resolution_bucket", "") or "")
        if bucket not in bucket_groups:
            ordered_buckets.append(bucket)
            bucket_groups[bucket] = {
                "hdr_packs": [], "hdr_others": [],
                "sdr_packs": [], "sdr_others": [],
            }
        is_pack = bool(stream.get("_sg_pack_backed"))
        is_hdr = bool(stream.get("_sg_hdr"))
        if is_hdr and is_pack:
            bucket_groups[bucket]["hdr_packs"].append(stream)
        elif is_hdr:
            bucket_groups[bucket]["hdr_others"].append(stream)
        elif is_pack:
            bucket_groups[bucket]["sdr_packs"].append(stream)
        else:
            bucket_groups[bucket]["sdr_others"].append(stream)

    reordered = []
    for bucket in ordered_buckets:
        grp = bucket_groups[bucket]
        reordered.extend(grp["hdr_packs"])
        reordered.extend(grp["hdr_others"])
        reordered.extend(grp["sdr_packs"])
        reordered.extend(grp["sdr_others"])
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
            the_stream["_sg_hdr"] = bool(_hdr_badge(formatted_components))
"""
    if debrid_stream_replacement not in content and debrid_stream_block in content:
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
            the_stream["_sg_hdr"] = bool(_hdr_badge(formatted_components))
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
        stream.pop("_sg_hdr", None)

    has_results = len(final_streams) > 0
"""
    if 'stream.pop("_sg_resolution_bucket"' not in content and final_streams_block in content:
        content = content.replace(final_streams_block, final_streams_replacement, 1)

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

    # Append the RTN rank next to the size component (dot-separated) before the
    # description is rendered from formatted_components.
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
        if _sg_rank is not None and "size" in formatted_components:
            formatted_components["size"] = f"{formatted_components['size']} • {_sg_rank}"
        formatted_title = format_title_fn(formatted_components)
"""
    rank_already_applied = size_rank_replacement in content
    if "_sg_rank" in content and not rank_already_applied and size_rank_block in content:
        content = content.replace(size_rank_block, size_rank_replacement, 1)
    return content
