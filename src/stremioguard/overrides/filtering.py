from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

# Insertion points for the injected helpers, newest upstream shape first.
# 2026-07 moved title matching into a TitleMatcher class and renamed
# quick_alias_match to exact_alias_match; earlier images have neither.
_HELPER_MARKERS = (
    "class TitleMatcher:\n",
    "def quick_alias_match(text_normalized: str, ez_aliases_normalized: list[str]):\n",
)


def render_filtering_override(repo_dir: Path) -> str:
    # The filtering patch makes title matching more evidence-driven. If the
    # resolved filename or source title clearly contains the Stremio-requested
    # title phrase, we should not reject the result just because the outer
    # release title is branded, multilingual, or formatted differently.
    filtering_file = repo_dir / "comet" / "services" / "filtering.py"
    if not filtering_file.exists():
        raise RuntimeError(f"Comet filtering file not found at {filtering_file}.")
    content = filtering_file.read_text(encoding="utf-8")

    helper_marker = next((marker for marker in _HELPER_MARKERS if marker in content), None)
    if helper_marker is None:
        raise RuntimeError(
            "Unable to apply managed Comet filtering patch; upstream helper marker has changed."
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
    torrent: dict,
    torrent_title: str,
    title: str,
    parsed_title: str,
    aliases: dict,
    matcher=None,
) -> bool:
    # Upstream's own matchers always run first, so this patch can only ever
    # widen the net. 2026-07 consolidated them behind TitleMatcher; on that
    # shape the call site passes the live matcher and its whole chain
    # (exact-alias, title_match, alternate_title_match) is delegated to.
    if matcher is not None:
        if matcher.matches_title(torrent_title, parsed_title):
            return True
    else:
        if title_match(title, parsed_title, aliases=aliases):
            return True
        # 2026-06 added a multi-title fallback as a module-level function;
        # keep it in the chain when this version defines it.
        alternate = globals().get("alternate_title_match")
        if callable(alternate) and alternate(torrent_title, title, aliases):
            return True
    return _torrent_evidence_match(torrent, title, parsed_title, aliases)


"""
        content = content.replace(helper_marker, helper + helper_marker, 1)

    # Known upstream call-site shapes, newest first: 2026-07 delegates to a
    # TitleMatcher instance, 2026-06 chained a module-level
    # alternate_title_match, older images call title_match on one line. Each
    # collapses to a single compat call. Anchors are exact-match on purpose:
    # an unrecognized shape must fail closed, not patch blindly.
    compat = "_titles_compat_match(torrent, torrent_title, title, parsed.parsed_title, aliases"
    content = replace_first_matching(
        content,
        (
            (
                "if not matcher.matches_title(torrent_title, parsed.parsed_title):",
                f"if not {compat}, matcher):",
            ),
            (
                "if not title_match(\n"
                "                title, parsed.parsed_title, aliases=aliases\n"
                "            ) and not alternate_title_match(torrent_title, title, aliases):",
                f"if not {compat}):",
            ),
            (
                "if not title_match(title, parsed.parsed_title, aliases=aliases):",
                f"if not {compat}):",
            ),
        ),
        error=(
            "Unable to apply managed Comet filtering patch; upstream title-match block has changed."
        ),
    )

    return content
