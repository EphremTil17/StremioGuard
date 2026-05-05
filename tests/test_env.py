"""Tests for stremioguard.env — dotenv read/write utilities."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stremioguard import env


class EnvUtilTests(unittest.TestCase):
    def test_env_file_value_reads_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("STREMIO_SKIP_HW_PROBE=0\n", encoding="utf-8")
            self.assertEqual(env.env_file_value(path, "STREMIO_SKIP_HW_PROBE"), "0")

    def test_env_flag_enabled_uses_default_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            self.assertTrue(env.env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=path))
            self.assertFalse(env.env_flag_enabled("STREMIO_APPLY_PATCHES", False, env_path=path))

    def test_env_flag_enabled_reads_falsey_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("STREMIO_APPLY_PATCHES=0\n", encoding="utf-8")
            self.assertFalse(env.env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=path))

    def test_env_needs_init_when_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(env.env_needs_init(Path(directory) / ".env"))

    def test_env_needs_init_when_placeholder_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            self.assertTrue(env.env_needs_init(path))

    def test_env_needs_init_when_value_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("WIREGUARD_PRIVATE_KEY=\n", encoding="utf-8")
            self.assertTrue(env.env_needs_init(path))

    def test_env_needs_init_when_nordvpn_openvpn_credentials_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "VPN_TYPE=openvpn\n"
                "OPENVPN_USER=<paste-service-username-here>\n"
                "OPENVPN_PASSWORD=<paste-service-password-here>\n",
                encoding="utf-8",
            )
            self.assertTrue(env.env_needs_init(path))

    def test_env_needs_init_false_when_key_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("WIREGUARD_PRIVATE_KEY=aGVsbG8td29ybGQ=\n", encoding="utf-8")
            self.assertFalse(env.env_needs_init(path))

    def test_env_needs_init_false_when_nordvpn_openvpn_credentials_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=openvpn\n"
                "OPENVPN_USER=svc-user\nOPENVPN_PASSWORD=svc-pass\n",
                encoding="utf-8",
            )
            self.assertFalse(env.env_needs_init(path))

    def test_write_env_setting_replaces_existing_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("STREMIO_APPLY_PATCHES=1\nTZ=America/Chicago\n", encoding="utf-8")
            env.write_env_setting(path, "STREMIO_APPLY_PATCHES", "0")
            content = path.read_text(encoding="utf-8")
            self.assertIn("STREMIO_APPLY_PATCHES=0", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_write_wireguard_key_replaces_line_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "TZ=America/Chicago\n",
                encoding="utf-8",
            )
            env.write_wireguard_key(path, "secret-key")
            content = path.read_text(encoding="utf-8")
            self.assertIn("WIREGUARD_PRIVATE_KEY=secret-key", content)
            self.assertNotIn("<paste-key-here>", content)
            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_write_wireguard_key_appends_when_line_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            env.write_wireguard_key(path, "fallback-key")
            content = path.read_text(encoding="utf-8")
            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("WIREGUARD_PRIVATE_KEY=fallback-key", content)

    def test_write_openvpn_credentials_replaces_both_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "OPENVPN_USER=<paste-service-username-here>\n"
                "OPENVPN_PASSWORD=<paste-service-password-here>\n",
                encoding="utf-8",
            )
            env.write_openvpn_credentials(path, "svc-user", "svc-pass")
            content = path.read_text(encoding="utf-8")
            self.assertIn("OPENVPN_USER=svc-user", content)
            self.assertIn("OPENVPN_PASSWORD=svc-pass", content)


if __name__ == "__main__":
    unittest.main()
