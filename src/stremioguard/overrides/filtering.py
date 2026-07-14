from __future__ import annotations

from pathlib import Path


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
    if "_titles_compat_match(" not in content:
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


def _titles_compat_match(
    torrent: dict, torrent_title: str, title: str, parsed_title: str, aliases: dict
) -> bool:
    if title_match(title, parsed_title, aliases=aliases):
        return True
    # Newer Comet versions ship their own multi-title fallback
    # (alternate_title_match, added 2026-06); keep it in the chain when this
    # version has it, so the compat patch only ever widens the net.
    alternate = globals().get("alternate_title_match")
    if callable(alternate) and alternate(torrent_title, title, aliases):
        return True
    return _torrent_evidence_match(torrent, title, parsed_title, aliases)


"""
        if helper_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet filtering patch; upstream helper marker has changed."
            )
        content = content.replace(helper_marker, helper + helper_marker, 1)

    replacement_line = (
        "if not _titles_compat_match(torrent, torrent_title, title, parsed.parsed_title, aliases):"
    )
    # Known upstream call-site shapes, newest first. The 2026-06 image added
    # upstream's own alternate_title_match() fallback and reformatted the call
    # site; older images use the original single line. Both collapse to the
    # one compat call above — the injected helper keeps upstream's fallback in
    # the chain when this version defines it. Anchors are exact-match on
    # purpose: an unrecognized shape must fail closed, not patch blindly.
    anchors = (
        "if not title_match(\n"
        "                title, parsed.parsed_title, aliases=aliases\n"
        "            ) and not alternate_title_match(torrent_title, title, aliases):",
        "if not title_match(title, parsed.parsed_title, aliases=aliases):",
    )
    if replacement_line not in content:
        anchor = next((candidate for candidate in anchors if candidate in content), None)
        if anchor is None:
            raise RuntimeError(
                "Unable to apply managed Comet filtering patch; upstream "
                "title-match block has changed."
            )
        content = content.replace(anchor, replacement_line, 1)

    return content
