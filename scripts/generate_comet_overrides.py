#!/usr/bin/env python3
"""Generate managed Comet runtime override files into a state directory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from stremioguard.overrides import write_override_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", required=True, help="Path to vendored Comet checkout")
    parser.add_argument("--state-dir", required=True, help="Path to write generated overrides")
    parser.add_argument(
        "--result-format-style",
        default="plain",
        choices=("emoji", "plain"),
        help="Formatter style to render",
    )
    parser.add_argument(
        "--patch-episode-pack-results",
        action="store_true",
        help="Generate the orchestration override that preserves more episode results from packs",
    )
    parser.add_argument(
        "--gateway-addon-base-url",
        default=None,
        help="Optional gated Comet addon base URL for generated configure/install links",
    )
    args = parser.parse_args()

    write_override_bundle(
        repo_dir=Path(args.repo_dir),
        state_dir=Path(args.state_dir),
        result_format_style=args.result_format_style,
        patch_episode_pack_results=args.patch_episode_pack_results,
        gateway_addon_base_url=args.gateway_addon_base_url,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
