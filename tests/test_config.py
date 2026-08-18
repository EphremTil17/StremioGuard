"""Tests for Config class and environment loading validation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.config import Config, _tunable_int


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

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
        ):
            # Explicit root: from_env() defaults to the repo, whose .env is
            # root-owned on a hardened install and live on any install.
            config = Config.from_env(Path(directory))
        self.assertTrue(config.stremio_enabled)

    def test_from_env_comet_enabled_only(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return False
            if key == "COMET_ENABLED":
                return True
            return default

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
        ):
            # Explicit root: from_env() defaults to the repo, whose .env is
            # root-owned on a hardened install and live on any install.
            config = Config.from_env(Path(directory))
        self.assertFalse(config.stremio_enabled)

    def test_from_env_parses_recovery_and_failover_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / ".env"
            env_file.write_text(
                "SERVER_COUNTRIES=United States\n"
                "SERVER_REGIONS=North America\n"
                "SERVER_CITIES=Seattle\n"
                "SERVER_HOSTNAMES=us123.nordvpn.com\n"
                "SERVER_CATEGORIES=P2P\n"
                "VPN_RECOVERY_BUDGET_SECONDS=400\n"
                "VPN_RESTART_CADENCE_SECONDS=60\n",
                encoding="utf-8",
            )
            config = Config.from_env(root)
            self.assertEqual(config.server_countries, "United States")
            self.assertEqual(config.server_regions, "North America")
            self.assertEqual(config.server_cities, "Seattle")
            self.assertEqual(config.server_hostnames, "us123.nordvpn.com")
            self.assertEqual(config.server_categories, "P2P")
            self.assertEqual(config.vpn_recovery_budget_seconds, 400)
            self.assertEqual(config.vpn_restart_cadence_seconds, 60)
            self.assertEqual(config.vpn_lockout_file, root / ".stremio" / "vpn-lockout")


if __name__ == "__main__":
    unittest.main()


class TestTunableInt(unittest.TestCase):
    def test_env_var_wins_over_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("PUBLIC_IP_FAILURE_THRESHOLD=9\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "5"}):
                self.assertEqual(_tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3), 5)

    def test_prefixed_name_wins_over_bare(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            with mock.patch.dict(
                os.environ,
                {
                    "STREMIO_IP_CROSSCHECK_INTERVAL_SECONDS": "60",
                    "IP_CROSSCHECK_INTERVAL_SECONDS": "120",
                },
            ):
                self.assertEqual(_tunable_int(env_file, "IP_CROSSCHECK_INTERVAL_SECONDS", 300), 60)

    def test_reads_env_file_and_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("IP_CROSSCHECK_INTERVAL_SECONDS=45\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("IP_CROSSCHECK_INTERVAL_SECONDS", None)
                os.environ.pop("STREMIO_IP_CROSSCHECK_INTERVAL_SECONDS", None)
                self.assertEqual(_tunable_int(env_file, "IP_CROSSCHECK_INTERVAL_SECONDS", 300), 45)
                self.assertEqual(_tunable_int(env_file, "MISSING_KEY", 300), 300)

    def test_rejects_invalid_and_below_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            with (
                mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "nope"}),
                self.assertRaisesRegex(RuntimeError, "Invalid PUBLIC_IP_FAILURE_THRESHOLD"),
            ):
                _tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3)
            with (
                mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "0"}),
                self.assertRaisesRegex(RuntimeError, "expected >= 1"),
            ):
                _tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3)
