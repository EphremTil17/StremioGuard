import json
import sys
import unittest
from unittest import mock

# Mock aiohttp in sys.modules to satisfy import requirements during collection
mock_aiohttp = mock.MagicMock()
sys.modules["aiohttp"] = mock_aiohttp

from stremioguard import metadata  # noqa: E402


async def _chunk_stream(chunks: list[bytes], consumed: list[int] | None = None):
    for chunk in chunks:
        if consumed is not None:
            consumed.append(len(chunk))
        yield chunk


def _mock_aiohttp_response(
    status: int,
    chunks: list[bytes] | None = None,
    *,
    consumed: list[int] | None = None,
):
    mock_response = mock.MagicMock()
    mock_response.status = status
    mock_response.content = mock.MagicMock()
    mock_response.content.iter_chunked = mock.MagicMock(
        side_effect=lambda _size: _chunk_stream(list(chunks or ()), consumed)
    )

    mock_get_ctx = mock.MagicMock()
    mock_get_ctx.__aenter__ = mock.AsyncMock(return_value=mock_response)
    mock_get_ctx.__aexit__ = mock.AsyncMock(return_value=None)

    mock_session_inst = mock.MagicMock()
    mock_session_inst.get = mock.MagicMock(return_value=mock_get_ctx)

    mock_session_ctx = mock.MagicMock()
    mock_session_ctx.__aenter__ = mock.AsyncMock(return_value=mock_session_inst)
    mock_session_ctx.__aexit__ = mock.AsyncMock(return_value=None)
    return mock_session_ctx, mock_session_inst


class TestMetadataService(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Clear cache before each test
        metadata._EPISODE_COUNT_CACHE.clear()

    async def test_invalid_imdb_ids_and_seasons(self):
        self.assertIsNone(await metadata.get_season_episode_count("", 1))
        self.assertIsNone(await metadata.get_season_episode_count("1234567", 1))
        self.assertIsNone(await metadata.get_season_episode_count("invalid_id", 1))
        self.assertIsNone(await metadata.get_season_episode_count("tt123?foo=bar", 1))
        self.assertIsNone(await metadata.get_season_episode_count("tt../etc/passwd", 1))
        self.assertIsNone(await metadata.get_season_episode_count("tt1234567", -1))
        self.assertIsNone(await metadata.get_season_episode_count("tt1234567", True))

    @mock.patch("stremioguard.metadata.database")
    async def test_database_cache_hit(self, mock_database):
        # Mock connection and query
        mock_database.is_connected = True
        mock_database.fetch_val = mock.AsyncMock(return_value=12)

        count = await metadata.get_season_episode_count("tt1234567", 1)
        self.assertEqual(count, 12)
        mock_database.fetch_val.assert_called_once()

        # Verify in-memory cache hit on second lookup
        mock_database.fetch_val.reset_mock()
        count_cached = await metadata.get_season_episode_count("tt1234567", 1)
        self.assertEqual(count_cached, 12)
        mock_database.fetch_val.assert_not_called()

    @mock.patch("stremioguard.metadata.database")
    async def test_database_miss_and_cinemeta_multi_chunk_success(self, mock_database):
        mock_database.is_connected = True
        mock_database.fetch_val = mock.AsyncMock(return_value=None)

        body = json.dumps(
            {
                "meta": {
                    "videos": [
                        {"season": 1, "episode": 1},
                        {"season": 1, "episode": 10},
                        {"season": 2, "episode": 5},
                    ]
                }
            }
        ).encode("utf-8")
        # Deliver across multiple small chunks (matching real aiohttp StreamReader behavior).
        chunks = [body[i : i + 17] for i in range(0, len(body), 17)]
        self.assertGreater(len(chunks), 3)
        mock_session_ctx, mock_session_inst = _mock_aiohttp_response(200, chunks)

        with mock.patch.object(metadata.aiohttp, "ClientSession", return_value=mock_session_ctx):
            count = await metadata.get_season_episode_count("tt1234567", 1)
            self.assertEqual(count, 10)
            self.assertEqual(mock_session_inst.get.call_args.kwargs["allow_redirects"], False)

            # Verify cached count on second lookup
            count_cached = await metadata.get_season_episode_count("tt1234567", 1)
            self.assertEqual(count_cached, 10)

    @mock.patch("stremioguard.metadata.database")
    async def test_cinemeta_non_200_and_oversized_chunked_response_rejected(self, mock_database):
        mock_database.is_connected = False

        mock_session_ctx, _ = _mock_aiohttp_response(404)
        with mock.patch.object(metadata.aiohttp, "ClientSession", return_value=mock_session_ctx):
            self.assertIsNone(await metadata.get_season_episode_count("tt1234567", 1))

        # Stop reading once cumulative bytes exceed _MAX_CINEMETA_RESPONSE_BYTES.
        chunk_size = 65536
        total_chunks = (metadata._MAX_CINEMETA_RESPONSE_BYTES // chunk_size) + 5
        oversized_chunks = [b"x" * chunk_size] * total_chunks
        consumed: list[int] = []
        mock_session_ctx, _ = _mock_aiohttp_response(200, oversized_chunks, consumed=consumed)
        with mock.patch.object(metadata.aiohttp, "ClientSession", return_value=mock_session_ctx):
            self.assertIsNone(await metadata.get_season_episode_count("tt7654321", 1))
        self.assertLess(len(consumed), total_chunks)

    @mock.patch("stremioguard.metadata.database")
    async def test_cache_is_bounded_and_evicts_oldest(self, mock_database):
        mock_database.is_connected = True
        mock_database.fetch_val = mock.AsyncMock(return_value=8)
        with mock.patch.object(metadata, "_MAX_CACHE_ENTRIES", 2):
            await metadata.get_season_episode_count("tt0000001", 1)
            await metadata.get_season_episode_count("tt0000002", 1)
            # Touch tt0000001 so tt0000002 becomes oldest.
            await metadata.get_season_episode_count("tt0000001", 1)
            await metadata.get_season_episode_count("tt0000003", 1)
            self.assertEqual(len(metadata._EPISODE_COUNT_CACHE), 2)
            self.assertIn(("tt0000001", 1), metadata._EPISODE_COUNT_CACHE)
            self.assertNotIn(("tt0000002", 1), metadata._EPISODE_COUNT_CACHE)
            self.assertIn(("tt0000003", 1), metadata._EPISODE_COUNT_CACHE)
