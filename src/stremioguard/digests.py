"""Canonical validation for Docker image digests (`sha256:<64 lowercase hex>`)."""

from __future__ import annotations

import re

IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def is_image_digest(value: object) -> bool:
    """Return True iff ``value`` is a ``sha256:`` digest with 64 lowercase hex chars."""
    return isinstance(value, str) and IMAGE_DIGEST_RE.fullmatch(value) is not None


def require_image_digest(value: object, *, source: str) -> str:
    """Validate ``value`` as an image digest or raise ``RuntimeError`` naming ``source``."""
    if is_image_digest(value):
        assert isinstance(value, str)
        return value
    preview = ascii(value)[:80]
    raise RuntimeError(
        f"Invalid image digest from {source}: {preview} "
        "(expected 'sha256:' followed by 64 lowercase hex characters)."
    )
