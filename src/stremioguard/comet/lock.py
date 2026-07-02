from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CometLock:
    upstream_url: str
    pinned_commit: str
    default_branch: str
    image: str
    tested_digest: str

    @classmethod
    def load(cls, path: Path) -> CometLock:
        if not path.exists():
            raise RuntimeError(f"Comet lock file missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        tested_digest = data.get("tested_digest")
        if not tested_digest:
            raise RuntimeError(
                f"Comet lock file at {path} is missing 'tested_digest'. "
                "This is the maintainer-validated fallback image digest StremioGuard "
                "uses when the newest upstream image is not yet compatible with the "
                "managed patches. Set it to a 'sha256:...' digest that has passed "
                "`./stremio comet install`'s compatibility check."
            )
        return cls(
            upstream_url=data["upstream_url"],
            pinned_commit=data["pinned_commit"],
            default_branch=data["default_branch"],
            image=data.get("image", "g0ldyy/comet"),
            tested_digest=tested_digest,
        )
