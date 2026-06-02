from __future__ import annotations

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
