from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from stremioguard.digests import require_image_digest


@dataclass(frozen=True)
class CometLock:
    image: str
    tested_digest: str

    @classmethod
    def load(cls, path: Path) -> CometLock:
        if not path.exists():
            raise RuntimeError(f"Comet lock file missing: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Comet lock file at {path} is unreadable ({error}).") from error
        if not isinstance(data, dict):
            raise RuntimeError(f"Comet lock file at {path} is not a JSON object.")
        tested_digest = data.get("tested_digest")
        if not tested_digest:
            raise RuntimeError(
                f"Comet lock file at {path} is missing 'tested_digest'. "
                "This is the maintainer-validated fallback image digest StremioGuard "
                "uses when the newest upstream image is not yet compatible with the "
                "managed patches. Set it to a 'sha256:...' digest that has passed "
                "`./stremio comet install`'s compatibility check."
            )
        validated_digest = require_image_digest(
            tested_digest, source=f"Comet lock file at {path} ('tested_digest')"
        )
        image = data.get("image", "g0ldyy/comet")
        if not isinstance(image, str) or not image:
            raise RuntimeError(f"Comet lock file at {path} has an invalid 'image' field.")
        return cls(
            image=image,
            tested_digest=validated_digest,
        )
