"""Tests for stremioguard CLI, init prompts, and NordVPN helpers."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

from stremioguard import cli as cli_mod
from stremioguard import init as init_mod
from stremioguard import nordvpn as nordvpn_mod
from stremioguard.env import env_file_value


class NordVpnTests(unittest.TestCase):
    def test_vpn_setup_checklist_includes_general_linux_requirements(self) -> None:
        checklist = nordvpn_mod.vpn_setup_checklist()
        self.assertIn("Docker with the Compose plugin", checklist)
        self.assertIn("/dev/net/tun", checklist)
        self.assertIn("VPN provider account", checklist)
        self.assertNotIn("nordvpn CLI", checklist)

    def test_vpn_setup_checklist_includes_nordvpn_specific_requirements(self) -> None:
        checklist = nordvpn_mod.vpn_setup_checklist("nordvpn")
        self.assertIn("nordvpn CLI", checklist)
        self.assertIn("nordvpn login", checklist)
        self.assertIn("wireguard-tools", checklist)

    def test_missing_nordvpn_dependencies_lists_all_missing_tools(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            missing = nordvpn_mod.missing_nordvpn_dependencies()
        self.assertEqual(len(missing), 2)
        self.assertIn("nordvpn CLI", missing[0])
        self.assertIn("wireguard-tools", missing[1])

    def test_preflight_nordvpn_setup_fails_with_single_aggregated_message(self) -> None:
        with (
            mock.patch.object(
                nordvpn_mod,
                "missing_nordvpn_dependencies",
                return_value=["- nordvpn CLI", "- wireguard-tools"],
            ),
            self.assertRaises(typer.Exit) as ctx,
        ):
            nordvpn_mod.preflight_nordvpn_setup()
        self.assertEqual(ctx.exception.exit_code, 1)

    def test_get_nordvpn_wireguard_key_manual_path_skips_host_extraction(self) -> None:
        with (
            mock.patch.object(nordvpn_mod, "_prompt_nordvpn_key_setup_mode", return_value="manual"),
            mock.patch.object(
                nordvpn_mod, "_prompt_manual_wireguard_key", return_value="manual-key"
            ),
            mock.patch.object(nordvpn_mod, "preflight_nordvpn_setup") as preflight,
        ):
            key = nordvpn_mod.get_nordvpn_wireguard_key()
        self.assertEqual(key, "manual-key")
        preflight.assert_not_called()

    def test_get_nordvpn_wireguard_key_auto_path_checks_prerequisites(self) -> None:
        with (
            mock.patch.object(nordvpn_mod, "_prompt_nordvpn_key_setup_mode", return_value="auto"),
            mock.patch.object(typer, "confirm", return_value=True),
            mock.patch.object(nordvpn_mod, "preflight_nordvpn_setup") as preflight,
            mock.patch.object(nordvpn_mod, "_extract_wireguard_key", return_value="auto-key"),
            mock.patch.object(nordvpn_mod, "logger"),
        ):
            key = nordvpn_mod.get_nordvpn_wireguard_key()
        self.assertEqual(key, "auto-key")
        preflight.assert_called_once()

    def test_configure_nordvpn_openvpn_writes_credentials_and_clears_wireguard_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_TYPE=wireguard\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "OPENVPN_USER=\nOPENVPN_PASSWORD=\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(nordvpn_mod, "_prompt_nordvpn_protocol", return_value="openvpn"),
                mock.patch.object(
                    nordvpn_mod,
                    "_prompt_openvpn_credentials",
                    return_value=("svc-user", "svc-pass"),
                ),
                mock.patch.object(nordvpn_mod, "logger"),
            ):
                nordvpn_mod.configure_nordvpn(env)
            self.assertEqual(env_file_value(env, "VPN_TYPE"), "openvpn")
            self.assertEqual(env_file_value(env, "OPENVPN_USER"), "svc-user")
            self.assertEqual(env_file_value(env, "OPENVPN_PASSWORD"), "svc-pass")
            self.assertEqual(env_file_value(env, "WIREGUARD_PRIVATE_KEY"), "")

    def test_configure_nordvpn_wireguard_writes_key_and_clears_openvpn_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_TYPE=openvpn\nWIREGUARD_PRIVATE_KEY=\n"
                "OPENVPN_USER=svc-user\nOPENVPN_PASSWORD=svc-pass\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    nordvpn_mod, "_prompt_nordvpn_protocol", return_value="wireguard"
                ),
                mock.patch.object(nordvpn_mod, "get_nordvpn_wireguard_key", return_value="wg-key"),
                mock.patch.object(nordvpn_mod, "logger"),
            ):
                nordvpn_mod.configure_nordvpn(env)
            self.assertEqual(env_file_value(env, "VPN_TYPE"), "wireguard")
            self.assertEqual(env_file_value(env, "WIREGUARD_PRIVATE_KEY"), "wg-key")
            self.assertEqual(env_file_value(env, "OPENVPN_USER"), "")
            self.assertEqual(env_file_value(env, "OPENVPN_PASSWORD"), "")


class InitPromptTests(unittest.TestCase):
    def test_configure_external_access_tier_one_writes_lan_bind_and_clears_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "EXTERNAL_BASE_URL=https://old.example\nSTREMIO_BIND_ADDRS=127.0.0.1\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(typer, "prompt", side_effect=["1", "1", "10.0.0.5"]),
                mock.patch.object(typer, "echo"),
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env)
            self.assertEqual(env_file_value(env, "EXTERNAL_BASE_URL"), "")
            self.assertEqual(env_file_value(env, "STREMIO_BIND_ADDRS"), "10.0.0.5")
            self.assertEqual(env_file_value(env, "STREMIO_HOST_PORT"), "11470")

    def test_configure_external_access_tier_two_writes_domain_and_lan_bind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            with (
                mock.patch.object(
                    typer, "prompt", side_effect=["2", "1", "10.0.0.5", "stremio.example.com"]
                ),
                mock.patch.object(typer, "echo"),
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env)
            self.assertEqual(
                env_file_value(env, "EXTERNAL_BASE_URL"), "https://stremio.example.com"
            )
            self.assertEqual(env_file_value(env, "STREMIO_BIND_ADDRS"), "10.0.0.5")

    def test_configure_external_access_warns_docker_proxy_on_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            with (
                mock.patch.object(
                    typer,
                    "prompt",
                    side_effect=["2", "1", "127.0.0.1", "y", "stremio.example.com"],
                ),
                mock.patch.object(typer, "echo"),
                mock.patch.object(init_mod, "logger") as log,
            ):
                init_mod.configure_external_access(env)
            log_messages = [call.args[0] for call in log.info.call_args_list if call.args]
            self.assertTrue(
                any(
                    "loopback upstream only works for a host-native proxy" in m
                    for m in log_messages
                )
            )

    def test_configure_external_access_uses_configured_host_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_HOST_PORT=12470\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(typer, "prompt", side_effect=["1", "1", "10.0.0.5"]),
                mock.patch.object(typer, "echo") as echo,
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env)
            echo_msgs = [call.args[0] for call in echo.call_args_list if call.args]
            self.assertIn(
                "How many host addresses should publish Stremio's streaming port (12470)?",
                echo_msgs,
            )

    def test_prompt_bind_addresses_accepts_multiple_addresses(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["2", "10.168.77.10", "100.125.26.36"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_bind_addresses(), ["10.168.77.10", "100.125.26.36"])

    def test_prompt_bind_addresses_accepts_zero_addresses(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="0"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_bind_addresses(), [])

    def test_prompt_lan_bind_addr_accepts_lan_ip(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="10.168.77.10"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_lan_bind_addr(), "10.168.77.10")

    def test_prompt_lan_bind_addr_accepts_all_interfaces(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="0.0.0.0"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_lan_bind_addr(), "0.0.0.0")

    def test_prompt_lan_bind_addr_rejects_invalid_then_accepts_valid(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["not-an-ip", "192.168.1.50"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_lan_bind_addr(), "192.168.1.50")

    def test_prompt_lan_bind_addr_warns_on_loopback_and_re_prompts_when_declined(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["127.0.0.1", "n", "10.0.0.5"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_lan_bind_addr(), "10.0.0.5")

    def test_prompt_lan_bind_addr_accepts_loopback_after_explicit_confirmation(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["127.0.0.1", "y"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_lan_bind_addr(), "127.0.0.1")

    def test_prompt_public_domain_strips_trailing_slash(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="stremio.example.com/"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_public_domain(), "stremio.example.com")

    def test_prompt_public_domain_rejects_scheme_then_accepts_bare_host(self) -> None:
        with (
            mock.patch.object(
                typer,
                "prompt",
                side_effect=["https://stremio.example.com", "stremio.example.com"],
            ),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_public_domain(), "stremio.example.com")


class UnifiedCliTests(unittest.TestCase):
    def test_start_auto_manages_comet_when_enabled(self) -> None:
        fake_manager = mock.Mock()
        with (
            mock.patch.object(cli_mod, "_warn_for_optional_stremio_settings"),
            mock.patch.object(cli_mod, "_comet_enabled", return_value=True),
            mock.patch.object(cli_mod, "_comet_manager", return_value=fake_manager),
            mock.patch.object(cli_mod, "RunContext") as context_cls,
            mock.patch.object(cli_mod, "run_guard") as run_guard,
            mock.patch.object(cli_mod, "_start_watchdog") as start_watchdog,
        ):
            context = context_cls.create.return_value
            cli_mod.start()
        fake_manager.prepare_runtime.assert_called_once()
        fake_manager.start.assert_called_once()
        run_guard.assert_called_once_with("start", context=context)
        start_watchdog.assert_called_once_with(context)

    def test_stop_stops_comet_when_enabled(self) -> None:
        fake_manager = mock.Mock()
        with (
            mock.patch.object(cli_mod, "_stop_watchdog"),
            mock.patch.object(cli_mod, "_comet_enabled", return_value=True),
            mock.patch.object(cli_mod, "_comet_manager", return_value=fake_manager),
            mock.patch.object(cli_mod, "run_guard") as run_guard,
        ):
            cli_mod.stop()
        fake_manager.stop.assert_called_once()
        run_guard.assert_called_once_with("stop", file_logging=False)

    def test_prompt_public_domain_rejects_path_and_whitespace(self) -> None:
        with (
            mock.patch.object(
                typer, "prompt", side_effect=["foo bar", "no-tld", "stremio.example.com"]
            ),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_public_domain(), "stremio.example.com")


class CliCommandTests(unittest.TestCase):
    def test_run_guard_exits_cleanly_when_guard_subprocess_fails(self) -> None:
        with (
            mock.patch.object(
                cli_mod.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, ["uv", "run"]),
            ),
            self.assertRaises(typer.Exit) as ctx,
        ):
            cli_mod.run_guard("start", file_logging=False)
        self.assertEqual(ctx.exception.exit_code, 1)

    def test_init_manual_nordvpn_path_collects_optional_settings_before_key_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )

            call_order: list[str] = []

            def record_external_access(_: Path) -> None:
                call_order.append("access")

            def record_optional_settings(_: Path) -> None:
                call_order.append("optional")

            def record_protocol_setup(_: Path) -> None:
                call_order.append("key")
                raise typer.Exit(1)

            with (
                mock.patch.object(cli_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(cli_mod, "ENV_FILE", env_file),
                mock.patch.object(cli_mod, "is_interactive", return_value=True),
                mock.patch.object(cli_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(cli_mod, "run_guard"),
                mock.patch.object(
                    cli_mod, "configure_external_access", side_effect=record_external_access
                ),
                mock.patch.object(cli_mod, "configure_nordvpn", side_effect=record_protocol_setup),
                mock.patch.object(
                    cli_mod,
                    "configure_optional_stremio_settings",
                    side_effect=record_optional_settings,
                ),
                mock.patch.object(cli_mod, "logger"),
                self.assertRaises(typer.Exit),
            ):
                cli_mod.init()

            self.assertEqual(call_order, ["access", "optional", "key"])

    def test_init_always_prompts_credentials_even_when_already_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            env_file.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=bad-key\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(cli_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(cli_mod, "ENV_FILE", env_file),
                mock.patch.object(cli_mod, "is_interactive", return_value=True),
                mock.patch.object(cli_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(cli_mod, "configure_external_access"),
                mock.patch.object(cli_mod, "configure_optional_stremio_settings"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(cli_mod, "run_guard"),
                mock.patch.object(cli_mod, "configure_nordvpn") as cfg_nordvpn,
                mock.patch.object(cli_mod, "restart") as restart,
                mock.patch.object(cli_mod, "logger"),
            ):
                cli_mod.init()

            cfg_nordvpn.assert_called_once()
            restart.assert_called_once()

    def test_init_prompts_provider_even_when_env_is_not_template_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=wireguard\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            env_file.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=wireguard\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\nEXTERNAL_BASE_URL=\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(cli_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(cli_mod, "ENV_FILE", env_file),
                mock.patch.object(cli_mod, "is_interactive", return_value=True),
                mock.patch.object(cli_mod, "prompt_provider", return_value="other") as prompt,
                mock.patch.object(cli_mod, "configure_external_access"),
                mock.patch.object(cli_mod, "configure_optional_stremio_settings"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(cli_mod, "run_guard"),
                mock.patch.object(cli_mod, "configure_nordvpn") as cfg_nordvpn,
                mock.patch.object(cli_mod, "print_manual_setup_pointer") as manual_pointer,
                mock.patch.object(cli_mod, "logger"),
            ):
                cli_mod.init()

            prompt.assert_called_once_with("nordvpn")
            cfg_nordvpn.assert_not_called()
            manual_pointer.assert_called_once()

    def test_init_disables_existing_comet_when_declined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            env_file.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=wg-key\nCOMET_ENABLED=1\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(cli_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(cli_mod, "ENV_FILE", env_file),
                mock.patch.object(cli_mod, "ROOT_DIR", temp_root),
                mock.patch.object(cli_mod, "is_interactive", return_value=True),
                mock.patch.object(cli_mod, "prompt_provider", return_value="other"),
                mock.patch.object(cli_mod, "configure_external_access"),
                mock.patch.object(cli_mod, "configure_optional_stremio_settings"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(cli_mod, "run_guard"),
                mock.patch.object(cli_mod, "configure_nordvpn"),
                mock.patch.object(cli_mod, "print_manual_setup_pointer"),
                mock.patch.object(cli_mod, "logger"),
            ):
                cli_mod.init()

            self.assertEqual(env_file_value(env_file, "COMET_ENABLED"), "0")


if __name__ == "__main__":
    unittest.main()
