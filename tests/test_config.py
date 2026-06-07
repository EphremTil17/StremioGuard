"""Tests for Config class and environment loading validation."""

from __future__ import annotations

import unittest
from unittest import mock

from stremioguard.config import Config


class TestConfig(unittest.TestCase):
    def test_from_env_both_disabled_raises_runtime_error(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return False
            if key == "COMET_ENABLED":
                return False
            return default

        with (
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
            self.assertRaises(RuntimeError) as ctx,
        ):
            Config.from_env()

        self.assertIn("both STREMIO_ENABLED and COMET_ENABLED are set to 0", str(ctx.exception))

    def test_from_env_stremio_enabled_only(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return True
            if key == "COMET_ENABLED":
                return False
            return default

        with mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled):
            config = Config.from_env()
        self.assertTrue(config.stremio_enabled)

    def test_from_env_comet_enabled_only(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return False
            if key == "COMET_ENABLED":
                return True
            return default

        with mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled):
            config = Config.from_env()
        self.assertFalse(config.stremio_enabled)


if __name__ == "__main__":
    unittest.main()
