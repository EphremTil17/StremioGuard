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

    def test_env_needs_init_when_wireguard_key_is_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("WIREGUARD_PRIVATE_KEY=not-a-key\n", encoding="utf-8")
            self.assertTrue(env.env_needs_init(path))

    def test_env_needs_init_false_when_key_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "WIREGUARD_PRIVATE_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                encoding="utf-8",
            )
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

    def test_env_int_value_returns_default_when_missing_or_blank(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("COMET_HOST_PORT=\n", encoding="utf-8")
            self.assertEqual(env.env_int_value(path, "COMET_HOST_PORT", 18000), 18000)
            self.assertEqual(env.env_int_value(path, "MISSING_KEY", 42), 42)

    def test_env_int_value_parses_and_range_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("PORT=9000\nLEN=2\n", encoding="utf-8")
            self.assertEqual(env.env_int_value(path, "PORT", 1, minimum=1, maximum=65535), 9000)
            with self.assertRaisesRegex(RuntimeError, "Invalid LEN value: '2'; expected 4-32"):
                env.env_int_value(path, "LEN", 8, minimum=4, maximum=32)

    def test_env_int_value_rejects_non_integer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("PORT=nope\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Invalid PORT value: 'nope'"):
                env.env_int_value(path, "PORT", 1, minimum=1, maximum=65535)

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
            env.write_env_setting(path, "WIREGUARD_PRIVATE_KEY", "secret-key")
            content = path.read_text(encoding="utf-8")
            self.assertIn("WIREGUARD_PRIVATE_KEY=secret-key", content)
            self.assertNotIn("<paste-key-here>", content)
            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_write_wireguard_key_appends_when_line_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            env.write_env_setting(path, "WIREGUARD_PRIVATE_KEY", "fallback-key")
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
            env.write_env_settings(
                path, {"OPENVPN_USER": "svc-user", "OPENVPN_PASSWORD": "svc-pass"}
            )
            content = path.read_text(encoding="utf-8")
            self.assertIn("OPENVPN_USER=svc-user", content)
            self.assertIn("OPENVPN_PASSWORD=svc-pass", content)


if __name__ == "__main__":
    unittest.main()


def test_env_values_are_written_literally(tmp_path) -> None:
    from stremioguard.env import env_file_value, write_env_setting

    env = tmp_path / ".env"
    env.write_text("OPENVPN_PASSWORD=old\n", encoding="utf-8")
    for value in (r"a\1b", r"x\ny", "back\\\\slash"):
        write_env_setting(env, "OPENVPN_PASSWORD", value)
        assert env_file_value(env, "OPENVPN_PASSWORD") == value
    assert env.read_text(encoding="utf-8").count("\n") == 1


def test_env_values_reject_line_breaks(tmp_path) -> None:
    import pytest

    from stremioguard.env import write_env_setting

    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        write_env_setting(env, "OPENVPN_PASSWORD", "x\nINJECTED=1")
