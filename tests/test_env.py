"""Tests for stremioguard.env — dotenv read/write utilities."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pytest

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


# --- One dotenv grammar -----------------------------------------------------
# Each case below is a line the old `^KEY=(.*)$` regex read differently from
# Docker Compose: the reader and the container disagreed about a setting.


def _dotenv(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


def test_quoted_zero_disables_a_flag(tmp_path: Path) -> None:
    # The old reader saw the four characters `"0"`, which is not in the falsey
    # set, so a Comet the operator disabled was treated as enabled.
    from stremioguard.config import CometConfig

    path = _dotenv(tmp_path, 'COMET_ENABLED="0"\n')
    assert env.env_file_value(path, "COMET_ENABLED") == "0"
    assert env.env_flag_enabled("COMET_ENABLED", True, env_path=path) is False
    assert CometConfig.from_env(tmp_path).enabled is False
    _dotenv(tmp_path, "COMET_ENABLED='0'\n")
    assert env.env_flag_enabled("COMET_ENABLED", True, env_path=path) is False


def test_parse_dotenv_grammar() -> None:
    parsed = env.parse_dotenv(
        "\n".join(
            [
                "# a comment line",
                "",
                'DOUBLE="quoted value"',
                "SINGLE='single quoted'",
                "INLINE=value # trailing comment",
                "HASH_NO_SPACE=val#ue",
                "QUOTED_HASH='a # b' # comment after the quote",
                "export EXPORTED=yes",
                "  export   SPACED = padded value  ",
                "DOLLAR=$HOME",
                'DOLLAR_DQ="a$b${c}"',
                "DOLLAR_SQ='$x'",
                r'ESCAPES="say \"hi\" \\ \n end"',
                r"SQ_BACKSLASH='C:\new'",
                "EMPTY=",
                "EMPTY_QUOTED=''",
                "INHERIT_ONLY",
                "DUP=first",
                "DUP=second",
            ]
        )
    )
    assert parsed == {
        "DOUBLE": "quoted value",
        "SINGLE": "single quoted",
        "INLINE": "value",
        "HASH_NO_SPACE": "val#ue",
        "QUOTED_HASH": "a # b",
        "EXPORTED": "yes",
        "SPACED": "padded value",
        "DOLLAR": "$HOME",
        "DOLLAR_DQ": "a$b${c}",
        "DOLLAR_SQ": "$x",
        "ESCAPES": 'say "hi" \\ \n end',
        "SQ_BACKSLASH": "C:\\new",
        "EMPTY": "",
        "EMPTY_QUOTED": "",
        # The LAST assignment wins, as it does for Compose.
        "DUP": "second",
    }


def test_env_file_value_last_assignment_wins_and_export_is_read(tmp_path: Path) -> None:
    path = _dotenv(
        tmp_path,
        "VPN_SERVICE_PROVIDER=mullvad\nexport VPN_SERVICE_PROVIDER='NordVPN'\n",
    )
    assert env.env_file_value(path, "VPN_SERVICE_PROVIDER") == "NordVPN"
    assert env.read_env_provider(path) == "nordvpn"


@pytest.mark.parametrize(
    "text",
    ['KEY="never closed\n', "KEY='never closed\n", 'OK=1\nKEY="a\\"\n'],
)
def test_unterminated_quote_raises_with_its_line(text: str, tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match=r"line \d+: unterminated"):
        env.parse_dotenv(text)
    # Every reader goes through the same parser, so none can silently
    # disagree with the others about such a file.
    path = _dotenv(tmp_path, text)
    with pytest.raises(RuntimeError, match="unterminated"):
        env.env_file_value(path, "OK")


AWKWARD_VALUES = [
    "plain",
    "with spaces",
    "a # not a comment",
    "#leading-hash",
    "trailing #",
    "$HOME and ${PATH}",
    "it's",
    'say "hi"',
    "both ' and \"",
    "trailing backslash\\",
    "back\\slash",
    "\\'",
    "",
    "  padded  ",
    "tab\there",
    "=equals=",
    '"starts with a quote"',
    "'single-wrapped'",
]


@pytest.mark.parametrize("value", AWKWARD_VALUES)
def test_render_dotenv_round_trips(value: str) -> None:
    rendered = env.render_dotenv({"KEY": value, "NEXT": "after"})
    assert env.parse_dotenv(rendered) == {"KEY": value, "NEXT": "after"}
    line = rendered.splitlines()[0]
    # Fully quoted; double quotes only when single quotes cannot carry it.
    needs_double = "'" in value or value.endswith("\\")
    assert line.startswith('KEY="' if needs_double else "KEY='")


def test_format_env_value_quoting_rules() -> None:
    assert env.format_env_value("p$ss word") == "'p$ss word'"
    assert env.format_env_value("it's") == '"it\'s"'
    # Inside double quotes `$` is escaped so Compose cannot expand it.
    assert env.format_env_value("it's $HOME") == '"it\'s \\$HOME"'
    assert env.format_env_value("end\\") == '"end\\\\"'
    with pytest.raises(ValueError):
        env.format_env_value("two\nlines")


def test_render_dotenv_header_and_order() -> None:
    rendered = env.render_dotenv({"B": "2", "A": "1"}, header="# generated")
    assert rendered == "# generated\nB='2'\nA='1'\n"


@pytest.mark.parametrize("value", AWKWARD_VALUES)
def test_write_env_settings_round_trips(value: str, tmp_path: Path) -> None:
    path = _dotenv(tmp_path, "KEY=old\nOTHER=kept\n")
    env.write_env_settings(path, {"KEY": value})
    assert env.read_env_file(path) == {"KEY": value, "OTHER": "kept"}


def test_write_env_settings_replaces_the_last_assignment_and_keeps_export(
    tmp_path: Path,
) -> None:
    path = _dotenv(
        tmp_path,
        "# KEY=commented out\nKEY=first\nMIDDLE=1\n  export KEY=effective\nTAIL=2\n",
    )
    env.write_env_settings(path, {"KEY": "new value", "ADDED": "a # b"})
    assert path.read_text(encoding="utf-8").splitlines() == [
        "# KEY=commented out",
        "KEY=first",
        "MIDDLE=1",
        # The effective line is replaced in place, `export ` kept, and a
        # plain-safe value left unquoted.
        "export KEY=new value",
        "TAIL=2",
        # A value that would read back differently unquoted is quoted.
        "ADDED='a # b'",
    ]
    assert env.env_file_value(path, "KEY") == "new value"
    assert env.env_file_value(path, "ADDED") == "a # b"
    assert path.stat().st_mode & 0o777 == 0o600
