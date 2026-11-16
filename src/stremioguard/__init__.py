"""StremioGuard — Stremio behind a gluetun VPN container."""

from __future__ import annotations

import sys

from loguru import logger

# Replace loguru's default import-time stderr sink so frame locals are never
# rendered in tracebacks even before the CLI or orchestrator reconfigures logging.
logger.remove()
logger.add(sys.stderr, diagnose=False)
