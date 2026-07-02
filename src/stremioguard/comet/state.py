"""Local, machine-owned digest-promotion state for the Comet image.

Distinct from `comet.lock.py` (repo-owned: the last commit/digest the
maintainers validated). This tracks which digest THIS deployment is actually
running, so `./stremio` never renders a floating `:latest` tag once an
install has resolved a digest — see docs/implementation-plan.md Phase 4.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stremioguard.env import atomic_write_text

STATE_FILE_NAME = "state.json"


@dataclass(frozen=True)
class CandidateDigest:
    digest: str
    checked_at: str
    validation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "checked_at": self.checked_at,
            "validation": self.validation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> CandidateDigest | None:
        if not data:
            return None
        return cls(
            digest=data["digest"],
            checked_at=data.get("checked_at", ""),
            validation=data.get("validation"),
        )


@dataclass(frozen=True)
class CometState:
    active_digest: str | None = None
    previous_digest: str | None = None
    candidate: CandidateDigest | None = None
    last_remote_check: str | None = None

    @classmethod
    def load(cls, path: Path) -> CometState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls(
            active_digest=data.get("active_digest"),
            previous_digest=data.get("previous_digest"),
            candidate=CandidateDigest.from_dict(data.get("candidate")),
            last_remote_check=data.get("last_remote_check"),
        )

    def save(self, path: Path) -> None:
        payload = {
            "active_digest": self.active_digest,
            "previous_digest": self.previous_digest,
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "last_remote_check": self.last_remote_check,
        }
        atomic_write_text(path, json.dumps(payload, indent=2) + "\n", mode=0o600)
