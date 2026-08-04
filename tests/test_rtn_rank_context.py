"""Regression tests for RTN score propagation in the current Comet architecture."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stremioguard.overrides.bundle import (
    _validate_rtn_rank_display_contract,
    write_override_bundle,
)
from stremioguard.overrides.media_search import render_media_search_override
from stremioguard.overrides.stream import render_stream_override

MEDIA_SEARCH_SOURCE = """\
from dataclasses import dataclass, field


class MediaSearchStatus:
    OK = "ok"


@dataclass
class MediaSearchResult:
    status: str
    torrents: dict = field(default_factory=dict)
    ranked_info_hashes: list[str] = field(default_factory=list)
    service_cache_status: dict = field(default_factory=dict)


def build_result(torrent_manager):
    return MediaSearchResult(
        MediaSearchStatus.OK,
        torrents=torrent_manager.torrents,
        ranked_info_hashes=list(torrent_manager.ranked_torrents),
        service_cache_status={},
    )
"""


STREAM_SOURCE = """\
def _build_stream_name(
    kodi: bool,
    service: str,
    resolution,
    icon: str = "",
    formatted_components: dict | None = None,
    seeders: int | None = None,
    status: str = "",
):
    if not kodi:
        return f"[{service}{icon}] Comet {resolution}"
    return "kodi"


async def stream(request):
    base_playback_host = (
        settings.PUBLIC_BASE_URL
        if settings.PUBLIC_BASE_URL
        else f"{request.url.scheme}://{request.url.netloc}"
    )
    torrents = search_result.torrents
    for info_hash in ranked_info_hashes:
        torrent = torrents[info_hash]
        rtn_data = torrent["parsed"]
        torrent_title = torrent["title"]
        torrent_size = torrent["size"]
        formatted_components = format_components(
            rtn_data,
            torrent_title,
            torrent["seeders"],
            torrent_size,
            torrent["tracker"],
            config["resultFormat"],
        )
        formatted_title = format_title_fn(formatted_components)
"""


class RankContextOverrideTests(unittest.TestCase):
    def _write_sources(self, root: Path, *, media: str = MEDIA_SEARCH_SOURCE) -> None:
        media_file = root / "comet" / "services" / "media_search.py"
        stream_file = root / "comet" / "api" / "endpoints" / "stream.py"
        media_file.parent.mkdir(parents=True)
        stream_file.parent.mkdir(parents=True)
        media_file.write_text(media, encoding="utf-8")
        stream_file.write_text(STREAM_SOURCE, encoding="utf-8")

    def test_rank_map_is_carried_without_recomputing_or_reordering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(root)
            rendered = render_media_search_override(root)
            namespace: dict[str, object] = {}
            exec(compile(rendered, "media_search.py", "exec"), namespace)

            ranked = {
                "best": type("Ranked", (), {"rank": 5850})(),
                "lower": type("Ranked", (), {"rank": 850})(),
            }
            manager = type("Manager", (), {"torrents": {}, "ranked_torrents": ranked})()
            result = namespace["build_result"](manager)  # type: ignore[operator]

            self.assertEqual(result.ranked_info_hashes, ["best", "lower"])
            self.assertEqual(result.rtn_ranks, {"best": 5850, "lower": 850})
            self.assertNotIn("sort(", rendered)
            self.assertNotIn("get_rank(", rendered)

    def test_stream_reads_rank_from_current_search_result_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(root)
            rendered = render_stream_override(root)

            self.assertIn("search_result.rtn_ranks.get(info_hash)", rendered)
            self.assertIn('f"{_sg_size} • R:{_sg_rank}"', rendered)
            self.assertIn('f"{formatted_title}\\n– R:{_sg_rank}"', rendered)
            self.assertNotIn("torrent_manager.ranked_torrents", rendered)
            compile(rendered, "stream.py", "exec")

    def test_old_endpoint_owned_architecture_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(root)
            stream_file = root / "comet" / "api" / "endpoints" / "stream.py"
            stream_file.write_text(
                STREAM_SOURCE.replace(
                    "    torrents = search_result.torrents\n",
                    "    torrents = torrent_manager.torrents\n",
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "MediaSearchResult stream architecture"):
                render_stream_override(root)

    def test_missing_rank_result_construction_anchor_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(
                root,
                media=MEDIA_SEARCH_SOURCE.replace(
                    "        ranked_info_hashes=list(torrent_manager.ranked_torrents),\n", ""
                ),
            )

            with self.assertRaisesRegex(RuntimeError, "result construction has changed"):
                render_media_search_override(root)

    def test_bundle_manifest_mounts_both_sides_of_rank_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            self._write_sources(root)
            write_override_bundle(
                repo_dir=root,
                state_dir=state,
                result_format_style="plain",
                patch_episode_pack_results=False,
                gateway_enabled=False,
            )

            manifest = json.loads((state / "bundle-manifest.json").read_text(encoding="utf-8"))
            self.assertIn("media_search", manifest["applied"])
            self.assertEqual(
                manifest["outputs"]["media_search.py"],
                "/app/comet/services/media_search.py",
            )
            self.assertEqual(
                (state / "stream.py").stat().st_mode & 0o777,
                0o644,
            )

    def test_cross_file_contract_rejects_partial_score_display(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(root)
            media = render_media_search_override(root)
            stream = render_stream_override(root).replace(
                'f"{_sg_size} • R:{_sg_rank}"', 'f"{_sg_size}"'
            )
            (root / "media_search.py").write_text(media, encoding="utf-8")
            (root / "stream.py").write_text(stream, encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "RTN rank display contract is incomplete"):
                _validate_rtn_rank_display_contract(root)

    def test_stream_reuses_native_metadata_call_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_sources(root)
            stream_file = root / "comet" / "api" / "endpoints" / "stream.py"
            native_calls = """\\
        if True:
            cached_name = _build_stream_name(
                kodi,
                "debrid",
                "2160p",
                status="C" if is_cached else "U",
                media_type=media_type,
                pack_backed=torrent.get("packBacked", False),
            )
            p2p_name = _build_stream_name(
                kodi,
                "torrent",
                "1080p",
                status="P2P",
                media_type=media_type,
                pack_backed=torrent.get("packBacked", False),
            )
"""
            stream_file.write_text(STREAM_SOURCE + native_calls, encoding="utf-8")

            rendered = render_stream_override(root)

            self.assertEqual(rendered.count("media_type=media_type"), 2)
            self.assertEqual(rendered.count('pack_backed=torrent.get("packBacked", False)'), 2)
            compile(rendered, "stream.py", "exec")
