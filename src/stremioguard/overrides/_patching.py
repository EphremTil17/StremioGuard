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
    expected: int = 1,
) -> str:
    """Apply the first `(anchor, replacement)` whose anchor is present.

    Returns `content` unchanged when a replacement is already present
    (idempotent re-render). Raises `RuntimeError(error)` when no candidate
    matches, or when an anchor matches a different number of times than
    `expected` — a changed occurrence count means the code moved and the
    edit can no longer be trusted to land where it did.
    """
    for anchor, replacement in candidates:
        if replacement in content:
            return content
        if anchor not in content:
            continue
        found = content.count(anchor)
        if found != expected:
            raise RuntimeError(f"{error} (matched {found} sites, expected {expected})")
        return content.replace(anchor, replacement)
    raise RuntimeError(error)
