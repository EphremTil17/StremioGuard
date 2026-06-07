"""Tests for stremioguard CLI, init prompts, and NordVPN helpers."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

from stremioguard import init as init_mod
from stremioguard import nordvpn as nordvpn_mod
from stremioguard.cli import context as context_mod
from stremioguard.cli import watchdog as watchdog_mod
from stremioguard.cli.commands import general as general_cmd_mod
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
                mock.patch.object(typer, "prompt", side_effect=["1", "10.0.0.5"]),
                mock.patch.object(typer, "echo"),
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env, is_proxied=False)
            self.assertEqual(env_file_value(env, "EXTERNAL_BASE_URL"), "")
            self.assertEqual(env_file_value(env, "STREMIO_BIND_ADDRS"), "10.0.0.5")
            self.assertEqual(env_file_value(env, "STREMIO_HOST_PORT"), "11470")

    def test_configure_external_access_tier_two_writes_domain_and_lan_bind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            with (
                mock.patch.object(
                    typer, "prompt", side_effect=["1", "10.0.0.5", "stremio.example.com"]
                ),
                mock.patch.object(typer, "echo"),
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env, is_proxied=True)
            self.assertEqual(
                env_file_value(env, "EXTERNAL_BASE_URL"), "https://stremio.example.com"
            )
            self.assertEqual(env_file_value(env, "STREMIO_BIND_ADDRS"), "10.0.0.5")

    def test_configure_external_access_proxy_loopback_confirms_host_native(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\n", encoding="utf-8")
            with (
                mock.patch.object(
                    typer,
                    "prompt",
                    side_effect=["127.0.0.1", "y", "stremio.example.com"],
                ),
                mock.patch.object(typer, "echo") as echo,
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env, is_proxied=True)
            echo_msgs = [call.args[0] for call in echo.call_args_list if call.args]
            self.assertTrue(
                any("not in Docker" in m for m in echo_msgs),
            )

    def test_configure_external_access_uses_configured_host_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "EXTERNAL_BASE_URL=\nSTREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_HOST_PORT=12470\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(typer, "prompt", side_effect=["1", "10.0.0.5"]),
                mock.patch.object(typer, "echo") as echo,
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_external_access(env, is_proxied=False)
            echo_msgs = [call.args[0] for call in echo.call_args_list if call.args]
            self.assertTrue(
                any("12470" in m for m in echo_msgs),
            )

    def test_direct_bind_accepts_multiple_addresses(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["2", "10.168.77.10", "100.125.26.36"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(
                init_mod._prompt_direct_bind_addresses(),
                ["10.168.77.10", "100.125.26.36"],
            )

    def test_direct_bind_accepts_zero_addresses(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="0"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_direct_bind_addresses(), [])

    def test_proxy_bind_accepts_lan_ip(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="10.168.77.10"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_proxy_bind_address(), ["10.168.77.10"])

    def test_proxy_bind_accepts_all_interfaces(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="0.0.0.0"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_proxy_bind_address(), ["0.0.0.0"])

    def test_single_bind_rejects_invalid_then_accepts_valid(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["not-an-ip", "192.168.1.50"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_single_bind_addr(), "192.168.1.50")

    def test_single_bind_warns_on_loopback_and_re_prompts_when_declined(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["127.0.0.1", "n", "10.0.0.5"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_single_bind_addr(), "10.0.0.5")

    def test_proxy_bind_warns_on_loopback_confirms_host_native(self) -> None:
        with (
            mock.patch.object(typer, "prompt", side_effect=["127.0.0.1", "y"]),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(init_mod._prompt_proxy_bind_address(), ["127.0.0.1"])

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


class WatchdogCliTests(unittest.TestCase):
    def test_pid_is_our_watchdog_matches_current_orchestrator_cmdline(self) -> None:
        cmdline = (
            b"uv\x00--cache-dir\x00/tmp/.uv-cache\x00run\x00python\x00-m\x00"
            b"stremioguard.orchestrator\x00watchdog\x00"
        )
        with mock.patch.object(Path, "read_bytes", return_value=cmdline):
            self.assertTrue(watchdog_mod._pid_is_our_watchdog(123))

    def test_watchdog_pids_finds_orphaned_watchdog_without_pid_file(self) -> None:
        proc_entries = [Path("/proc/111"), Path("/proc/222"), Path("/proc/sys")]
        with (
            mock.patch.object(watchdog_mod, "PID_FILE", Path("/tmp/nonexistent-watchdog.pid")),
            mock.patch.object(Path("/proc").__class__, "iterdir", return_value=proc_entries),
            mock.patch.object(
                watchdog_mod, "_pid_is_our_watchdog", side_effect=lambda pid: pid == 222
            ),
        ):
            self.assertEqual(watchdog_mod._watchdog_pids(), [222])

    def test_start_watchdog_recovers_pid_file_for_orphaned_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "watchdog.pid"
            log_file = Path(directory) / "watchdog.log"
            context = context_mod.RunContext(run_id="test-run", log_file=log_file)
            with (
                mock.patch.object(watchdog_mod, "PID_FILE", pid_file),
                mock.patch.object(watchdog_mod, "STATE_DIR", Path(directory)),
                mock.patch.object(watchdog_mod, "LOG_DIR", Path(directory)),
                mock.patch.object(watchdog_mod, "_require_uv"),
                mock.patch.object(watchdog_mod, "_watchdog_pids", return_value=[4321]),
                mock.patch.object(watchdog_mod.subprocess, "Popen") as popen,
                mock.patch.object(watchdog_mod, "logger"),
            ):
                watchdog_mod._start_watchdog(context)
            self.assertEqual(pid_file.read_text(encoding="utf-8").strip(), "4321")
            popen.assert_not_called()

    def test_stop_watchdog_terminates_orphaned_watchdog_without_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "watchdog.pid"
            with (
                mock.patch.object(watchdog_mod, "PID_FILE", pid_file),
                mock.patch.object(watchdog_mod, "_watchdog_pids", return_value=[4321]),
                mock.patch.object(watchdog_mod, "_wait_for_exit", return_value=True),
                mock.patch.object(watchdog_mod.os, "kill") as kill,
                mock.patch.object(watchdog_mod, "logger"),
            ):
                watchdog_mod._stop_watchdog()
            kill.assert_called_once_with(4321, watchdog_mod.signal.SIGTERM)
            self.assertFalse(pid_file.exists())


class UnifiedCliTests(unittest.TestCase):
    def test_start_calls_run_guard_and_starts_watchdog(self) -> None:
        with (
            mock.patch.object(general_cmd_mod, "_warn_for_optional_stremio_settings"),
            mock.patch.object(general_cmd_mod, "RunContext") as context_cls,
            mock.patch.object(general_cmd_mod, "run_guard") as run_guard,
            mock.patch.object(general_cmd_mod, "_start_watchdog") as start_watchdog,
        ):
            context = context_cls.create.return_value
            general_cmd_mod.start()
        run_guard.assert_called_once_with("start", context=context)
        start_watchdog.assert_called_once_with(context)

    def test_stop_calls_run_guard_and_stops_watchdog(self) -> None:
        with (
            mock.patch.object(general_cmd_mod, "_stop_watchdog") as stop_watchdog,
            mock.patch.object(general_cmd_mod, "run_guard") as run_guard,
        ):
            general_cmd_mod.stop()
        stop_watchdog.assert_called_once()
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
                watchdog_mod.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, ["uv", "run"]),
            ),
            self.assertRaises(typer.Exit) as ctx,
        ):
            watchdog_mod.run_guard("start", file_logging=False)
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

            def record_external_access(*args: object, **kwargs: object) -> None:
                call_order.append("access")

            def record_optional_settings(_: Path) -> None:
                call_order.append("optional")

            def record_protocol_setup(_: Path) -> None:
                call_order.append("key")
                raise typer.Exit(1)

            with (
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "prompt", return_value="1"),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(
                    general_cmd_mod, "configure_external_access", side_effect=record_external_access
                ),
                mock.patch.object(
                    general_cmd_mod, "configure_nordvpn", side_effect=record_protocol_setup
                ),
                mock.patch.object(
                    general_cmd_mod,
                    "configure_optional_stremio_settings",
                    side_effect=record_optional_settings,
                ),
                mock.patch.object(general_cmd_mod, "logger"),
                self.assertRaises(typer.Exit),
            ):
                general_cmd_mod.init()

            self.assertEqual(call_order, ["optional", "access", "key"])

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
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "prompt", return_value="1"),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(general_cmd_mod, "configure_external_access"),
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn") as cfg_nordvpn,
                mock.patch.object(general_cmd_mod, "restart") as restart,
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

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
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "prompt", return_value="1"),
                mock.patch.object(
                    general_cmd_mod, "prompt_provider", return_value="other"
                ) as prompt,
                mock.patch.object(general_cmd_mod, "configure_external_access"),
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn") as cfg_nordvpn,
                mock.patch.object(general_cmd_mod, "print_manual_setup_pointer") as manual_pointer,
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

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
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "ROOT_DIR", temp_root),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "prompt", return_value="3"),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="other"),
                mock.patch.object(general_cmd_mod, "configure_external_access"),
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn"),
                mock.patch.object(general_cmd_mod, "print_manual_setup_pointer"),
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

            self.assertEqual(env_file_value(env_file, "COMET_ENABLED"), "0")

    def test_init_invalid_profile_choice_reprompts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "ROOT_DIR", temp_root),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "prompt", side_effect=["invalid", "2", "1", "nordvpn"]),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(general_cmd_mod, "configure_external_access") as ext,
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings") as opt,
                mock.patch.object(general_cmd_mod, "prompt_comet_setup") as comet,
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn"),
                mock.patch.object(general_cmd_mod, "restart"),
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

            self.assertEqual(env_file_value(env_file, "STREMIO_ENABLED"), "0")
            self.assertEqual(env_file_value(env_file, "COMET_ENABLED"), "1")
            ext.assert_called_once()
            opt.assert_not_called()
            comet.assert_called_once()


if __name__ == "__main__":
    unittest.main()
