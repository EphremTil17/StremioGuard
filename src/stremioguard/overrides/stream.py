from __future__ import annotations

import ast
from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching


def render_stream_override(repo_dir: Path) -> str:
    stream_file = repo_dir / "comet" / "api" / "endpoints" / "stream.py"
    if not stream_file.exists():
        raise RuntimeError(f"Comet stream endpoint file not found at {stream_file}.")
    content = stream_file.read_text(encoding="utf-8")
    if "    torrents = search_result.torrents\n" not in content:
        raise RuntimeError(
            "Unable to apply required RTN rank display patch; Comet no longer uses "
            "the supported MediaSearchResult stream architecture."
        )

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
        if after in content:
            continue
        if before not in content:
            continue
        content = replace_first_matching(
            content,
            ((before, after),),
            error=(
                "Unable to apply managed Comet stream-name patch; upstream "
                "stream call shape has changed."
            ),
        )

    # Comet now hands this endpoint a MediaSearchResult. Its scalar rank map
    # crosses the search boundary separately from the native ordered hashes.
    # This is deliberately required: accepting a partially patched stream file
    # silently removed the user-visible RTN score in the past.
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
        _sg_rank = search_result.rtn_ranks.get(info_hash)
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
    content = replace_first_matching(
        content,
        ((size_rank_block, size_rank_replacement),),
        error=(
            "Unable to apply required RTN rank display patch; Comet stream formatting has changed."
        ),
    )
    content = _mark_uncached_streams(_block_p2p_streams(content))
    _assert_p2p_blocked(content)
    return content


def _is_torrent_switch_test(test: ast.expr) -> bool:
    """Whether an `if` test is true only when `enable_torrent` is."""
    if isinstance(test, ast.Name):
        return test.id == "enable_torrent"
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_torrent_switch_test(value) for value in test.values)
    return False


def _assert_p2p_blocked(content: str) -> None:
    """Prove, from the rendered code itself, that no P2P stream can be emitted.

    The substitution above only shows that one line was rewritten. This
    checks the result: `enable_torrent` is assigned exactly once, to False,
    and every place that produces an `infoHash` (what makes Stremio treat an
    entry as a torrent) sits inside an `if enable_torrent` block. An upstream
    change that adds a second switch or a second emission path then fails
    the required patch instead of passing through unnoticed.

    Structural, not behavioral: it reads the code, it does not request a
    stream. A torrent entry built in another module would not be seen here.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError as error:
        raise RuntimeError(f"Unable to prove P2P streams are blocked: {error}") from error

    assigned: list[ast.expr | None] = []
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets, value = [node.target], node.value
        for target in targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name) and name.id == "enable_torrent":
                    assigned.append(value)
    if len(assigned) != 1 or not (
        isinstance(assigned[0], ast.Constant) and assigned[0].value is False
    ):
        raise RuntimeError(
            "Unable to prove P2P streams are blocked: expected exactly one "
            f"`enable_torrent = False`, found {len(assigned)} assignment(s)."
        )

    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def guarded(node: ast.AST) -> bool:
        child = node
        while child in parents:
            parent = parents[child]
            if (
                isinstance(parent, ast.If)
                and _is_torrent_switch_test(parent.test)
                and any(child is statement for statement in parent.body)
            ):
                return True
            child = parent
        return False

    for node in ast.walk(tree):
        emits = (
            (
                isinstance(node, ast.Dict)
                and any(isinstance(k, ast.Constant) and k.value == "infoHash" for k in node.keys)
            )
            or (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Store)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "infoHash"
            )
            or (isinstance(node, ast.keyword) and node.arg == "infoHash")
        )
        if emits and not guarded(node):
            raise RuntimeError(
                "Unable to prove P2P streams are blocked: an `infoHash` stream entry at "
                f"line {getattr(node, 'lineno', '?')} is not inside an `if enable_torrent` block."
            )


# Stremio cannot colour text, so an amber glyph is the nearest thing to an
# amber row. It replaces the media-type line's bullet, which every entry has,
# so cached entries stay exactly as they were and uncached ones cost no width.
UNCACHED_MARKER = "🔸"
_MARK_UNCACHED_HELPER = f"""\
def _mark_uncached(description: str, formatted_components: dict) -> str:
    for key in ("quality", "video", "size"):
        line = str(formatted_components.get(key) or "")
        if line and line in description:
            bare = line.removeprefix("– ").removeprefix("✦ ")
            return description.replace(line, f"{UNCACHED_MARKER} {{bare}}", 1)
    return f"{UNCACHED_MARKER} {{description}}"


"""


def _block_p2p_streams(content: str) -> str:
    """Never offer direct-torrent streams, whatever the addon config asks for.

    Stremio plays a P2P stream with the client device's own torrent engine,
    on its own connection, outside the VPN this stack exists to enforce.
    Required: a Comet update that moves this switch must not quietly
    reintroduce P2P.
    """
    return replace_first_matching(
        content,
        (
            (
                '    enable_torrent = config["_enableTorrent"]\n',
                "    # StremioGuard: P2P streams would torrent from the client, outside the VPN.\n"
                "    enable_torrent = False\n",
            ),
        ),
        error="Unable to block P2P streams; Comet's torrent stream switch has changed.",
    )


def _mark_uncached_streams(content: str) -> str:
    helper_marker = "def _build_stream_name(\n"
    if "def _mark_uncached(" not in content:
        if helper_marker not in content:
            raise RuntimeError("Unable to mark uncached streams; upstream stream helper has moved.")
        content = content.replace(helper_marker, _MARK_UNCACHED_HELPER + helper_marker, 1)
    # The debrid stream entry, the one place where `is_cached` is known for a
    # service. The P2P entry also carries an infoHash line, so this is unique.
    return replace_first_matching(
        content,
        (
            (
                '                "description": formatted_title,\n'
                '                "behaviorHints": behavior_hints,\n'
                "            }\n",
                '                "description": (\n'
                "                    formatted_title\n"
                "                    if is_cached\n"
                "                    else _mark_uncached(formatted_title, formatted_components)\n"
                "                ),\n"
                '                "behaviorHints": behavior_hints,\n'
                "            }\n",
            ),
        ),
        error="Unable to mark uncached streams; Comet's stream entry shape has changed.",
    )
