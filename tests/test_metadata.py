import sys
import unittest
from unittest import mock

# Mock aiohttp in sys.modules to satisfy import requirements during collection
mock_aiohttp = mock.MagicMock()
sys.modules["aiohttp"] = mock_aiohttp

from stremioguard import metadata  # noqa: E402


class TestMetadataService(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Clear cache before each test
        metadata._EPISODE_COUNT_CACHE.clear()

    async def test_invalid_imdb_ids(self):
        self.assertIsNone(await metadata.get_season_episode_count("", 1))
        self.assertIsNone(await metadata.get_season_episode_count("1234567", 1))
        self.assertIsNone(await metadata.get_season_episode_count("invalid_id", 1))

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
    async def test_database_miss_and_cinemeta_success(self, mock_database):
        mock_database.is_connected = True
        mock_database.fetch_val = mock.AsyncMock(return_value=None)

        # Mock aiohttp response
        mock_response = mock.MagicMock()
        mock_response.status = 200
        mock_response.json = mock.AsyncMock(
            return_value={
                "meta": {
                    "videos": [
                        {"season": 1, "episode": 1},
                        {"season": 1, "episode": 10},
                        {"season": 2, "episode": 5},
                    ]
                }
            }
        )

        # Mock session.get context manager yielding mock_response
        mock_get_ctx = mock.MagicMock()
        mock_get_ctx.__aenter__ = mock.AsyncMock(return_value=mock_response)
        mock_get_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        # Mock session instance
        mock_session_inst = mock.MagicMock()
        mock_session_inst.get = mock.MagicMock(return_value=mock_get_ctx)

        # Mock ClientSession context manager yielding mock_session_inst
        mock_session_ctx = mock.MagicMock()
        mock_session_ctx.__aenter__ = mock.AsyncMock(return_value=mock_session_inst)
        mock_session_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        with mock.patch.object(metadata.aiohttp, "ClientSession", return_value=mock_session_ctx):
            count = await metadata.get_season_episode_count("tt1234567", 1)
            self.assertEqual(count, 10)

            # Verify cached count on second lookup
            count_cached = await metadata.get_season_episode_count("tt1234567", 1)
            self.assertEqual(count_cached, 10)

    @mock.patch("stremioguard.metadata.database")
    async def test_cinemeta_non_200_and_failure(self, mock_database):
        mock_database.is_connected = False  # Simulates local database disconnected

        # Mock aiohttp response yielding 404
        mock_response = mock.MagicMock()
        mock_response.status = 404

        # Mock session.get context manager yielding mock_response
        mock_get_ctx = mock.MagicMock()
        mock_get_ctx.__aenter__ = mock.AsyncMock(return_value=mock_response)
        mock_get_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        # Mock session instance
        mock_session_inst = mock.MagicMock()
        mock_session_inst.get = mock.MagicMock(return_value=mock_get_ctx)

        # Mock ClientSession context manager yielding mock_session_inst
        mock_session_ctx = mock.MagicMock()
        mock_session_ctx.__aenter__ = mock.AsyncMock(return_value=mock_session_inst)
        mock_session_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        with mock.patch.object(metadata.aiohttp, "ClientSession", return_value=mock_session_ctx):
            count = await metadata.get_season_episode_count("tt1234567", 1)
            self.assertIsNone(count)
