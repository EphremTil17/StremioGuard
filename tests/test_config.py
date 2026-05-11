"""Tests for Config class and environment loading validation."""

from __future__ import annotations

import unittest
from unittest import mock

from stremioguard.config import Config


class TestConfig(unittest.TestCase):
    def test_from_env_both_disabled_raises_runtime_error(self) -> None:
        def mock_env_file_value(env_file: object, key: str) -> str:
            if key == "STREMIO_ENABLED":
                return "0"
            if key == "COMET_ENABLED":
                return "0"
            return ""

        with (
            mock.patch("stremioguard.config.env_file_value", side_effect=mock_env_file_value),
            self.assertRaises(RuntimeError) as ctx,
        ):
            Config.from_env()

        self.assertIn("both STREMIO_ENABLED and COMET_ENABLED are set to 0", str(ctx.exception))

    def test_from_env_stremio_enabled_only(self) -> None:
        def mock_env_file_value(env_file: object, key: str) -> str:
            if key == "STREMIO_ENABLED":
                return "1"
            if key == "COMET_ENABLED":
                return "0"
            return ""

        with mock.patch("stremioguard.config.env_file_value", side_effect=mock_env_file_value):
            config = Config.from_env()
        self.assertTrue(config.stremio_enabled)

    def test_from_env_comet_enabled_only(self) -> None:
        def mock_env_file_value(env_file: object, key: str) -> str:
            if key == "STREMIO_ENABLED":
                return "0"
            if key == "COMET_ENABLED":
                return "1"
            return ""

        with mock.patch("stremioguard.config.env_file_value", side_effect=mock_env_file_value):
            config = Config.from_env()
        self.assertFalse(config.stremio_enabled)


if __name__ == "__main__":
    unittest.main()
