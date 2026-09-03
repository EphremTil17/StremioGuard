"""Regression tests for series pack detection and scraper title preservation."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from stremioguard.overrides.orchestration import render_orchestration_override
from stremioguard.overrides.torrentio import render_torrentio_override

from .test_overrides_bundle import _ORCHESTRATION_FIXTURE_NEW


@dataclass
class DummyParsed:
    seasons: list[int]
    episodes: list[int]


ORCHESTRATION_SOURCE = _ORCHESTRATION_FIXTURE_NEW

TORRENTIO_SOURCE = """\
import re

DATA_PATTERN = re.compile(
    r"(?:👤 (\\d+) )?💾 ([\\d.]+ [KMGT]B)(?: ⚙️ (\\w+))?", re.IGNORECASE
)

class TorrentioScraper:
    async def scrape(self, request):
        results = {"streams": []}
        torrents = []
        for torrent in results["streams"]:
            title_full = torrent["title"]

            if "\\n💾" in title_full:
                title = title_full.split("\\n💾")[0].split("\\n")[-1]
            else:
                title = title_full.split("\\n")[0]

            match = DATA_PATTERN.search(title_full)

            seeders = int(match.group(1)) if match and match.group(1) else None
            size = (
                size_to_bytes(match.group(2)) if match and match.group(2) else None
            )
            tracker = (
                match.group(3) if match and match.group(3) else "KnightCrawler"
            )

            torrents.append(
                {
                    "title": title,
                    "infoHash": torrent["infoHash"].lower(),
                    "fileIndex": torrent.get("fileIdx", None),
                    "seeders": seeders,
                    "size": size,
                    "tracker": f"Torrentio|{tracker}",
                    "sources": torrent.get("sources", []),
                }
            )
"""


class PackDetectionTests(unittest.TestCase):
    def test_orchestration_renders_and_detects_packs(self) -> None:
        comet_mock = mock.MagicMock()
        comet_mock.metadata_service.get_season_episode_count = mock.AsyncMock(return_value=15)
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                "sys.modules",
                {
                    "comet": comet_mock,
                    "comet.utils": mock.MagicMock(),
                    "comet.utils.parsing": mock.MagicMock(),
                    "comet.utils.models": mock.MagicMock(),
                    "comet.metadata_service": comet_mock.metadata_service,
                },
            ),
            mock.patch(
                "stremioguard.metadata.get_season_episode_count", mock.AsyncMock(return_value=15)
            ),
        ):
            root = Path(directory)
            orch_file = root / "comet" / "services" / "orchestration.py"
            orch_file.parent.mkdir(parents=True)
            orch_file.write_text(ORCHESTRATION_SOURCE, encoding="utf-8")

            rendered = render_orchestration_override(root)
            namespace: dict[str, Any] = {"ParsedData": DummyParsed}
            exec(compile(rendered, "orchestration.py", "exec"), namespace)

            manager_cls: Any = namespace["TorrentManager"]
            manager: Any = manager_cls()
            manager.media_type = "series"
            manager.search_season = 1
            manager.search_episode = 1
            manager.media_id = "tt0491738"
            manager.pack_backed_hashes = set()
            manager._pack_backed_candidates = {}

            # 1. Whole season torrent (file_index is None, parsed.episodes is empty)
            p_whole = DummyParsed(seasons=[1], episodes=[])
            res_whole = asyncio.run(
                manager._is_pack_backed_candidate(p_whole, info_hash="hash_whole", file_index=None)
            )
            self.assertTrue(
                res_whole, "Whole-season release without file_index must be pack-backed"
            )

            # 2. Episode 1 of a pack (file_index = 0, parsed.episodes = [1])
            p_ep1 = DummyParsed(seasons=[1], episodes=[1])
            res_ep1 = asyncio.run(
                manager._is_pack_backed_candidate(p_ep1, info_hash="hash_ep1", file_index=0)
            )
            self.assertTrue(res_ep1, "Episode 1 (file_index=0) of season pack must be pack-backed")

            # 3. Episode 2 of a pack (file_index = 1, parsed.episodes = [2])
            p_ep2 = DummyParsed(seasons=[1], episodes=[2])
            res_ep2 = asyncio.run(
                manager._is_pack_backed_candidate(p_ep2, info_hash="hash_ep2", file_index=1)
            )
            self.assertTrue(res_ep2, "Episode 2 (file_index=1) of season pack must be pack-backed")

            # 4. Standalone single episode release (file_index is None, episodes = [1])
            p_single = DummyParsed(seasons=[1], episodes=[1])
            res_single = asyncio.run(
                manager._is_pack_backed_candidate(
                    p_single, info_hash="hash_single", file_index=None
                )
            )
            self.assertFalse(
                res_single,
                "Standalone episode release without pack evidence must not be pack-backed",
            )

            # 5. Cached season-pack row recording
            manager._record_pack_backed_candidate(
                "hash_cached_pack", episode=None, file_index=None, is_season_pack=True
            )
            res_cached = asyncio.run(
                manager._is_pack_backed_candidate(
                    p_single, info_hash="hash_cached_pack", file_index=None
                )
            )
            self.assertTrue(
                res_cached, "Recorded season pack hash must be recognized as pack-backed"
            )

            # 6. Multi-episode full season span with Cinemeta count (15 of 15 episodes)
            meta_mock = mock.AsyncMock(return_value=15)
            with mock.patch.object(
                comet_mock.metadata_service, "get_season_episode_count", meta_mock
            ):
                p_full_span = DummyParsed(seasons=[1], episodes=list(range(1, 16)))
                res_full = asyncio.run(
                    manager._is_pack_backed_candidate(p_full_span, info_hash="hash_full_span")
                )
                self.assertTrue(
                    res_full, "Multi-episode span >= total episodes must be pack-backed"
                )

            # 7. Multi-episode partial batch with Cinemeta count (3 of 15 episodes, no index)
            meta_mock_partial = mock.AsyncMock(return_value=15)
            with mock.patch.object(
                comet_mock.metadata_service, "get_season_episode_count", meta_mock_partial
            ):
                p_partial_span = DummyParsed(seasons=[1], episodes=[1, 2, 3])
                res_partial = asyncio.run(
                    manager._is_pack_backed_candidate(
                        p_partial_span, info_hash="hash_partial_span", file_index=None
                    )
                )
                self.assertFalse(
                    res_partial,
                    "Partial multi-episode batch < total episodes must not be pack-backed",
                )

            # 8. Multi-episode with Cinemeta outage / miss (returns None -> defaults safely to True)
            meta_mock_outage = mock.AsyncMock(return_value=None)
            with mock.patch.object(
                comet_mock.metadata_service, "get_season_episode_count", meta_mock_outage
            ):
                p_outage = DummyParsed(seasons=[1], episodes=[1, 2, 3])
                res_outage = asyncio.run(
                    manager._is_pack_backed_candidate(p_outage, info_hash="hash_outage")
                )
                self.assertTrue(
                    res_outage,
                    "Cinemeta outage should fallback safely to treating multi-episode as pack",
                )

            # 9. Multi-season complete series boxset (S01-S08 with file_index = 0)
            p_boxset = DummyParsed(seasons=list(range(1, 9)), episodes=[1])
            res_boxset = asyncio.run(
                manager._is_pack_backed_candidate(p_boxset, info_hash="hash_boxset", file_index=0)
            )
            self.assertTrue(
                res_boxset, "Multi-season boxset file must be recognized as pack-backed"
            )

            # 10. Double-episode file (S01E01-E02 with file_index = 0 inside season pack)
            p_double = DummyParsed(seasons=[1], episodes=[1, 2])
            res_double = asyncio.run(
                manager._is_pack_backed_candidate(p_double, info_hash="hash_double", file_index=0)
            )
            self.assertTrue(
                res_double, "Double-episode file inside pack must be recognized as pack-backed"
            )

            # 11. Deep subfolder file index (Specials / extras with high index like 121)
            p_deep = DummyParsed(seasons=[1], episodes=[1])
            res_deep = asyncio.run(
                manager._is_pack_backed_candidate(p_deep, info_hash="hash_deep", file_index=121)
            )
            self.assertTrue(
                res_deep, "Deep subfolder file index inside pack must be recognized as pack-backed"
            )

    def test_torrentio_scraper_preserves_release_title_and_resolved_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            t_file = root / "comet" / "scrapers" / "torrentio.py"
            t_file.parent.mkdir(parents=True)
            t_file.write_text(TORRENTIO_SOURCE, encoding="utf-8")

            rendered = render_torrentio_override(root)
            self.assertIn('"title": release_title,', rendered)
            self.assertIn('"sourceTitle": title_full,', rendered)
            self.assertIn('"resolvedFileName": resolved_filename,', rendered)
            self.assertIn('"fileIndex": file_index,', rendered)

            # Ensure syntax compiles clean
            compile(rendered, "torrentio.py", "exec")
