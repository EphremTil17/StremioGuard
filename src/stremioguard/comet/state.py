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

from stremioguard.digests import is_image_digest, require_image_digest
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
        """Missing means "never bootstrapped"; unreadable is an error.

        Treating a corrupt file as empty would drop the digest pin, and the
        next start would quietly run (and promote) whatever `:latest` is.
        """
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Comet state at {path} is unreadable ({error}); restore it or remove it "
                "to re-bootstrap from the validated image."
            ) from error
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Comet state at {path} is not a JSON object; restore it or remove it "
                "to re-bootstrap from the validated image."
            )
        active_digest = data.get("active_digest")
        if active_digest is not None and not is_image_digest(active_digest):
            raise RuntimeError(
                f"Comet state at {path} has an invalid active_digest; restore it or remove it "
                "to re-bootstrap from the validated image."
            )
        previous_digest = data.get("previous_digest")
        if previous_digest is not None and not is_image_digest(previous_digest):
            raise RuntimeError(
                f"Comet state at {path} has an invalid previous_digest; restore it or remove it "
                "to re-bootstrap from the validated image."
            )
        last_remote_check = data.get("last_remote_check")
        if last_remote_check is not None and not isinstance(last_remote_check, str):
            raise RuntimeError(
                f"Comet state at {path} has an invalid last_remote_check; restore it or remove it "
                "to re-bootstrap from the validated image."
            )
        raw_candidate = data.get("candidate")
        candidate: CandidateDigest | None = None
        if raw_candidate is not None:
            if not isinstance(raw_candidate, dict):
                raise RuntimeError(
                    f"Comet state at {path} has an invalid candidate; restore it or remove it "
                    "to re-bootstrap from the validated image."
                )
            candidate_digest = raw_candidate.get("digest")
            if not is_image_digest(candidate_digest):
                raise RuntimeError(
                    f"Comet state at {path} has an invalid candidate.digest; restore it or "
                    "remove it to re-bootstrap from the validated image."
                )
            checked_at = raw_candidate.get("checked_at", "")
            if not isinstance(checked_at, str):
                raise RuntimeError(
                    f"Comet state at {path} has an invalid candidate.checked_at; restore it or "
                    "remove it to re-bootstrap from the validated image."
                )
            validation = raw_candidate.get("validation")
            if validation is not None and not isinstance(validation, dict):
                raise RuntimeError(
                    f"Comet state at {path} has an invalid candidate.validation; restore it or "
                    "remove it to re-bootstrap from the validated image."
                )
            assert isinstance(candidate_digest, str)
            candidate = CandidateDigest(
                digest=candidate_digest,
                checked_at=checked_at,
                validation=validation,
            )
        return cls(
            active_digest=active_digest,
            previous_digest=previous_digest,
            candidate=candidate,
            last_remote_check=last_remote_check,
        )

    def save(self, path: Path) -> None:
        if self.active_digest is not None:
            require_image_digest(self.active_digest, source="CometState.active_digest")
        if self.previous_digest is not None:
            require_image_digest(self.previous_digest, source="CometState.previous_digest")
        if self.candidate is not None:
            require_image_digest(self.candidate.digest, source="CometState.candidate.digest")
        payload = {
            "active_digest": self.active_digest,
            "previous_digest": self.previous_digest,
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "last_remote_check": self.last_remote_check,
        }
        atomic_write_text(path, json.dumps(payload, indent=2) + "\n", mode=0o600)
