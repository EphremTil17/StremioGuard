"""Fail-closed source-rewriting helpers shared by the override renderers.

Every renderer edits upstream Comet source by matching an exact anchor and
substituting a patched version. The hazard is `str.replace()`: when the
anchor is absent it returns the content unchanged and raises nothing, so an
upstream refactor silently produces a half-patched file that the bundle
still reports as applied. Renderers must therefore route every edit through
`replace_first_matching`, which fails closed instead.

Upstream reformats these call sites periodically, so each edit accepts
several known shapes (newest first) and applies the first that matches.
"""

from __future__ import annotations


def replace_first_matching(
    content: str,
    candidates: tuple[tuple[str, str], ...],
    *,
    error: str,
    expected: int | None = 1,
) -> str:
    """Apply the first `(anchor, replacement)` whose anchor is present.

    Returns `content` unchanged when a replacement is already present
    (idempotent re-render). Raises `RuntimeError(error)` when no candidate
    matches.

    `expected` is the number of sites the anchor must match: a different
    count means the code moved and the edit can no longer be trusted to land
    where it did. Pass `None` for edits whose intent is "every occurrence"
    (any count of one or more is valid), so that merging or adding a call
    site upstream is not misreported as drift.
    """
    for anchor, replacement in candidates:
        if replacement in content:
            return content
        if anchor not in content:
            continue
        found = content.count(anchor)
        if expected is not None and found != expected:
            raise RuntimeError(f"{error} (matched {found} sites, expected {expected})")
        return content.replace(anchor, replacement)
    raise RuntimeError(error)
