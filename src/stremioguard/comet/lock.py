from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CometLock:
    upstream_url: str
    pinned_commit: str
    default_branch: str

    @classmethod
    def load(cls, path: Path) -> CometLock:
        if not path.exists():
            raise RuntimeError(f"Comet lock file missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            upstream_url=data["upstream_url"],
            pinned_commit=data["pinned_commit"],
            default_branch=data["default_branch"],
        )
