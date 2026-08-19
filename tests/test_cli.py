"""Tests for stremioguard CLI, init prompts, and NordVPN helpers."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import typer

from stremioguard import init as init_mod
from stremioguard import nordvpn as nordvpn_mod
from stremioguard.cli import context as context_mod
from stremioguard.cli import watchdog as watchdog_mod
from stremioguard.cli.commands import general as general_cmd_mod
from stremioguard.config import MANAGED_STACK_ENV
from stremioguard.env import env_file_value

general_mod = general_cmd_mod


class NordVpnTests(unittest.TestCase):
    def test_fetch_nordvpn_credentials_from_token_success(self) -> None:
        token = "test-token-12345"
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        payload = json.dumps(
            {
                "nordlynx_private_key": key,
                "username": "svc-user",
                "password": "svc-password",
            }
        ).encode("utf-8")

        mock_response = mock.MagicMock()
        mock_response.read.return_value = payload
        mock_response.__enter__.return_value = mock_response

        with mock.patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            result_key, user, password = nordvpn_mod.fetch_nordvpn_credentials_from_token(token)

        self.assertEqual(result_key, key)
        self.assertEqual(user, "svc-user")
        self.assertEqual(password, "svc-password")
        req = mock_urlopen.call_args[0][0]
        self.assertIn("Authorization", req.headers)
        self.assertTrue(req.headers["Authorization"].startswith("Basic "))

    def test_fetch_nordvpn_wireguard_key_from_token_empty_token_fails(self) -> None:
        with self.assertRaises(typer.Exit):
            nordvpn_mod.fetch_nordvpn_wireguard_key_from_token("   ")

    def test_fetch_nordvpn_wireguard_key_from_token_http_401_fails(self) -> None:
        http_error = urllib.error.HTTPError(
            url="https://api.nordvpn.com",
            code=401,
            msg="Unauthorized",
            hdrs=mock.MagicMock(),
            fp=None,
        )
        with (
            mock.patch("urllib.request.urlopen", side_effect=http_error),
            self.assertRaises(typer.Exit),
        ):
            nordvpn_mod.fetch_nordvpn_wireguard_key_from_token("invalid-token")

    def test_fetch_nordvpn_wireguard_key_from_token_url_error_fails(self) -> None:
        url_error = urllib.error.URLError("Connection refused")
        with (
            mock.patch("urllib.request.urlopen", side_effect=url_error),
            self.assertRaises(typer.Exit),
        ):
            nordvpn_mod.fetch_nordvpn_wireguard_key_from_token("token")

    def test_fetch_nordvpn_wireguard_key_from_token_missing_key_fails(self) -> None:
        payload = json.dumps({"user_id": 123}).encode("utf-8")
        mock_response = mock.MagicMock()
        mock_response.read.return_value = payload
        mock_response.__enter__.return_value = mock_response

        with (
            mock.patch("urllib.request.urlopen", return_value=mock_response),
            self.assertRaises(typer.Exit),
        ):
            nordvpn_mod.fetch_nordvpn_wireguard_key_from_token("token")

    def test_fetch_nordvpn_wireguard_key_from_token_invalid_key_format_fails(self) -> None:
        payload = json.dumps({"nordlynx_private_key": "not-a-valid-wireguard-key"}).encode("utf-8")
        mock_response = mock.MagicMock()
        mock_response.read.return_value = payload
        mock_response.__enter__.return_value = mock_response

        with (
            mock.patch("urllib.request.urlopen", return_value=mock_response),
            self.assertRaises(typer.Exit),
        ):
            nordvpn_mod.fetch_nordvpn_wireguard_key_from_token("token")

    def test_prompt_manual_wireguard_key_success(self) -> None:
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        with mock.patch.object(typer, "prompt", return_value=key):
            result = nordvpn_mod._prompt_manual_wireguard_key()
        self.assertEqual(result, key)

    def test_configure_nordvpn_openvpn_manual_writes_credentials(self) -> None:
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
                    nordvpn_mod, "_prompt_nordvpn_openvpn_setup_mode", return_value="manual"
                ),
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

    def test_configure_nordvpn_openvpn_token_writes_credentials(self) -> None:
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
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
                    nordvpn_mod, "_prompt_nordvpn_openvpn_setup_mode", return_value="token"
                ),
                mock.patch.object(typer, "prompt", return_value="token-123"),
                mock.patch.object(
                    nordvpn_mod,
                    "fetch_nordvpn_credentials_from_token",
                    return_value=(key, "svc-user", "svc-pass"),
                ),
                mock.patch.object(nordvpn_mod, "logger"),
            ):
                nordvpn_mod.configure_nordvpn(env)
            self.assertEqual(env_file_value(env, "VPN_TYPE"), "openvpn")
            self.assertEqual(env_file_value(env, "OPENVPN_USER"), "svc-user")
            self.assertEqual(env_file_value(env, "OPENVPN_PASSWORD"), "svc-pass")
            self.assertEqual(env_file_value(env, "WIREGUARD_PRIVATE_KEY"), key)

    def test_configure_nordvpn_wireguard_token_writes_key_and_credentials(self) -> None:
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_TYPE=openvpn\nWIREGUARD_PRIVATE_KEY=\n"
                "OPENVPN_USER=old-user\nOPENVPN_PASSWORD=old-pass\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    nordvpn_mod, "_prompt_nordvpn_protocol", return_value="wireguard"
                ),
                mock.patch.object(
                    nordvpn_mod, "_prompt_nordvpn_key_setup_mode", return_value="token"
                ),
                mock.patch.object(typer, "prompt", return_value="token-123"),
                mock.patch.object(
                    nordvpn_mod,
                    "fetch_nordvpn_credentials_from_token",
                    return_value=(key, "new-user", "new-pass"),
                ),
                mock.patch.object(nordvpn_mod, "logger"),
            ):
                nordvpn_mod.configure_nordvpn(env)
            self.assertEqual(env_file_value(env, "VPN_TYPE"), "wireguard")
            self.assertEqual(env_file_value(env, "WIREGUARD_PRIVATE_KEY"), key)
            self.assertEqual(env_file_value(env, "WIREGUARD_ADDRESSES"), "10.5.0.2/32")
            self.assertEqual(env_file_value(env, "OPENVPN_USER"), "new-user")
            self.assertEqual(env_file_value(env, "OPENVPN_PASSWORD"), "new-pass")

    def test_configure_nordvpn_wireguard_manual_writes_key_and_clears_openvpn(self) -> None:
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
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
                mock.patch.object(
                    nordvpn_mod, "_prompt_nordvpn_key_setup_mode", return_value="manual"
                ),
                mock.patch.object(nordvpn_mod, "_prompt_manual_wireguard_key", return_value=key),
                mock.patch.object(nordvpn_mod, "logger"),
            ):
                nordvpn_mod.configure_nordvpn(env)
            self.assertEqual(env_file_value(env, "VPN_TYPE"), "wireguard")
            self.assertEqual(env_file_value(env, "WIREGUARD_PRIVATE_KEY"), key)
            self.assertEqual(env_file_value(env, "WIREGUARD_ADDRESSES"), "10.5.0.2/32")
            self.assertEqual(env_file_value(env, "OPENVPN_USER"), "")
            self.assertEqual(env_file_value(env, "OPENVPN_PASSWORD"), "")


class InitPromptTests(unittest.TestCase):
    def test_existing_setup_summary_is_env_derived_and_redacts_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "STREMIO_ENABLED=0\nCOMET_ENABLED=1\n"
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=openvpn\n"
                "OPENVPN_USER=private-user\nOPENVPN_PASSWORD=private-password\n"
                "STREMIO_BIND_ADDRS=10.0.0.5,100.64.0.2\n"
                "COMET_GATEWAY_PUBLIC_BASE_URL=https://public-user:public-password@comet.example.test\n"
                "SERVER_COUNTRIES=United States\nSERVER_CITIES=Seattle\n",
                encoding="utf-8",
            )

            summary = "\n".join(init_mod.existing_setup_summary(env))

        self.assertIn("Comet-only", summary)
        self.assertIn("nordvpn / openvpn (configured)", summary)
        self.assertIn("countries=United States", summary)
        self.assertIn("cities=Seattle", summary)
        self.assertIn("<credentials-redacted>@comet.example.test", summary)
        self.assertNotIn("private-user", summary)
        self.assertNotIn("private-password", summary)
        self.assertNotIn("public-user", summary)
        self.assertNotIn("public-password", summary)

    def test_public_url_summary_fails_closed_for_sensitive_or_malformed_values(self) -> None:
        self.assertEqual(
            init_mod._redacted_public_url("https://comet.example.test/configure?token=private"),
            "https://comet.example.test",
        )
        self.assertEqual(
            init_mod._redacted_public_url("https://comet.example.test:not-a-port"),
            "configured (redacted)",
        )

    def test_existing_setup_defaults_preserve_profile_access_and_bind_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "STREMIO_ENABLED=0\nCOMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n"
                "COMET_GATEWAY_PUBLIC_BASE_URL=https://comet.example.test\n"
                "STREMIO_BIND_ADDRS=10.0.0.5,100.64.0.2\n",
                encoding="utf-8",
            )
            self.assertEqual(init_mod.configured_profile_choice(env), "2")
            self.assertEqual(init_mod.configured_access_choice(env, comet_only=True), "2")
            with (
                mock.patch.object(
                    typer, "prompt", side_effect=["2", "10.0.0.5", "100.64.0.2"]
                ) as prompt,
                mock.patch.object(typer, "echo"),
            ):
                addresses = init_mod._prompt_direct_bind_addresses(
                    default_addresses=["10.0.0.5", "100.64.0.2"]
                )

        self.assertEqual(addresses, ["10.0.0.5", "100.64.0.2"])
        self.assertEqual(prompt.call_args_list[0].kwargs["default"], "2")
        self.assertEqual(prompt.call_args_list[1].kwargs["default"], "10.0.0.5")
        self.assertEqual(prompt.call_args_list[2].kwargs["default"], "100.64.0.2")

    def test_optional_stremio_prompts_default_to_existing_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("STREMIO_APPLY_PATCHES=0\nSTREMIO_SKIP_HW_PROBE=0\n", encoding="utf-8")
            with (
                mock.patch.object(typer, "confirm", side_effect=[False, False]) as confirm,
                mock.patch.object(init_mod, "logger"),
            ):
                init_mod.configure_optional_stremio_settings(env)

        self.assertFalse(confirm.call_args_list[0].kwargs["default"])
        self.assertFalse(confirm.call_args_list[1].kwargs["default"])

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
        with (
            mock.patch.object(Path, "read_bytes", return_value=cmdline),
            mock.patch.object(watchdog_mod.os, "readlink", return_value=str(watchdog_mod.ROOT_DIR)),
        ):
            self.assertTrue(watchdog_mod._pid_is_our_watchdog(123))

    def test_pid_is_our_watchdog_rejects_process_outside_repo(self) -> None:
        cmdline = (
            b"uv\x00--cache-dir\x00/tmp/.uv-cache\x00run\x00python\x00-m\x00"
            b"stremioguard.orchestrator\x00watchdog\x00"
        )
        with (
            mock.patch.object(Path, "read_bytes", return_value=cmdline),
            mock.patch.object(watchdog_mod.os, "readlink", return_value="/some/other/dir"),
        ):
            self.assertFalse(watchdog_mod._pid_is_our_watchdog(123))

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
    def test_status_runs_guard_status_and_comet_status(self) -> None:
        with (
            mock.patch.object(general_cmd_mod, "run_guard") as run_guard,
            mock.patch.object(general_cmd_mod, "_comet_enabled", return_value=False),
        ):
            general_cmd_mod.status()
        run_guard.assert_called_once_with("status", file_logging=False)

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

    def test_init_resumes_valid_existing_setup_without_mutating_or_prompting_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            original = (
                "STREMIO_ENABLED=1\nCOMET_ENABLED=1\n"
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=openvpn\n"
                "OPENVPN_USER=private-user\nOPENVPN_PASSWORD=private-password\n"
            )
            env_file.write_text(original, encoding="utf-8")

            with (
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "confirm", return_value=True) as confirm,
                mock.patch.object(typer, "prompt") as prompt,
                mock.patch.object(general_cmd_mod, "configure_nordvpn") as configure_nordvpn,
                mock.patch.object(general_cmd_mod, "run_guard") as run_guard,
                mock.patch.object(general_cmd_mod, "restart") as restart,
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

            self.assertEqual(env_file.read_text(encoding="utf-8"), original)
            confirm.assert_called_once_with(
                "Reuse this setup and restart without changing it?", default=True
            )
            prompt.assert_not_called()
            configure_nordvpn.assert_not_called()
            run_guard.assert_called_once_with("pull", file_logging=False)
            restart.assert_called_once()

    def test_init_editing_valid_setup_keeps_nordvpn_credentials_when_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            original = (
                "STREMIO_ENABLED=1\nCOMET_ENABLED=1\n"
                "VPN_SERVICE_PROVIDER=nordvpn\nVPN_TYPE=openvpn\n"
                "OPENVPN_USER=private-user\nOPENVPN_PASSWORD=private-password\n"
            )
            env_file.write_text(original, encoding="utf-8")

            with (
                mock.patch.object(general_cmd_mod, "ENV_EXAMPLE", env_example),
                mock.patch.object(general_cmd_mod, "ENV_FILE", env_file),
                mock.patch.object(general_cmd_mod, "ROOT_DIR", temp_root),
                mock.patch.object(general_cmd_mod, "is_interactive", return_value=True),
                mock.patch.object(typer, "confirm", side_effect=[False, True]),
                mock.patch.object(typer, "prompt", side_effect=["1", "1"]),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(general_cmd_mod, "configure_external_access"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn") as configure_nordvpn,
                mock.patch.object(general_cmd_mod, "run_guard"),
                mock.patch.object(general_cmd_mod, "restart"),
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

            self.assertEqual(env_file.read_text(encoding="utf-8"), original)
            configure_nordvpn.assert_not_called()

    def test_init_configures_nordvpn_and_restarts(self) -> None:
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
                mock.patch.object(typer, "prompt", return_value="1"),
                mock.patch.object(typer, "confirm", return_value=False),
                mock.patch.object(general_cmd_mod, "prompt_provider", return_value="nordvpn"),
                mock.patch.object(general_cmd_mod, "configure_optional_stremio_settings"),
                mock.patch.object(general_cmd_mod, "prompt_comet_setup"),
                mock.patch.object(general_cmd_mod, "configure_external_access"),
                mock.patch.object(general_cmd_mod, "configure_nordvpn") as cfg_nordvpn,
                mock.patch.object(general_cmd_mod, "run_guard") as run_guard,
                mock.patch.object(general_cmd_mod, "restart") as restart,
                mock.patch.object(general_cmd_mod, "logger"),
            ):
                general_cmd_mod.init()

            cfg_nordvpn.assert_called_once()
            run_guard.assert_called_once_with("pull", file_logging=False)
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


class PostgresDataDirectoryTests(unittest.TestCase):
    """Postgres must find its real data directory no matter how the stack is
    started, including a plain `docker compose up` with no override.

    This used to be enforced by a `${VAR:?}` tripwire that made Compose refuse
    to run at all without the generated override. That guarded the right thing
    the wrong way: Compose interpolates before every command, so `logs` and
    `ps` were rejected too. Putting the fixed path in the base file removes the
    failure mode instead of detecting it."""

    def _compose_file(self) -> str:
        root = Path(__file__).resolve().parent.parent
        return (root / "docker-compose.yml").read_text(encoding="utf-8")

    def test_base_compose_mounts_the_data_directory(self) -> None:
        compose = self._compose_file()
        self.assertIn(".stremio/comet/postgres-data:/var/lib/postgresql/", compose)

    def test_base_compose_supplies_the_credentials_file(self) -> None:
        compose = self._compose_file()
        self.assertIn(".stremio/comet/postgres.env", compose)
        # Optional, so every Compose command still works on a fresh clone
        # before `./stremio init` has generated it.
        self.assertIn("required: false", compose)

    def test_no_interpolation_tripwire_remains(self) -> None:
        # A required-variable interpolation on a live line breaks read-only
        # commands too. Comments are exempt: one of them explains the removal.
        live = [
            line for line in self._compose_file().splitlines() if not line.lstrip().startswith("#")
        ]
        self.assertNotIn(":?", "\n".join(live))


class ComposeUpGateTests(unittest.TestCase):
    """`docker compose up` on its own yields a stack with no published ports,
    an unconfigured Comet, no leak check and no watchdog. A gate service says
    so, and only `up` runs containers, so read-only commands stay usable."""

    def _compose_file(self) -> str:
        root = Path(__file__).resolve().parent.parent
        return (root / "docker-compose.yml").read_text(encoding="utf-8")

    def test_gate_service_name_carries_the_instruction(self) -> None:
        # For `up -d`, Compose shows only `service "<name>" didn't complete
        # successfully`, so the name is the sole text that reaches the operator.
        compose = self._compose_file()
        self.assertIn("use-stremio-start-instead:", compose)

    def test_everything_is_gated_through_gluetun(self) -> None:
        # Every other service hangs off gluetun, so gating gluetun is enough.
        compose = self._compose_file()
        gluetun = compose.split("\n  gluetun:", 1)[1].split("\n  stremio:", 1)[0]
        self.assertIn("use-stremio-start-instead", gluetun)
        self.assertIn("service_completed_successfully", gluetun)

    def test_gate_reads_the_marker_at_runtime_not_interpolation(self) -> None:
        # `${VAR:-0}` resolves for every command but only *matters* when the
        # container runs; `${VAR:?}` would abort `logs` and `ps` as well.
        compose = self._compose_file()
        self.assertIn(f"${{{MANAGED_STACK_ENV}:-0}}", compose)

    def test_cli_import_sets_the_marker(self) -> None:
        import stremioguard.cli  # noqa: F401  (import is the behavior under test)

        self.assertEqual(os.environ.get(MANAGED_STACK_ENV), "1")

    def test_watchdog_environment_carries_the_marker(self) -> None:
        # The watchdog runs compose too, from a copied environment.
        with tempfile.TemporaryDirectory() as directory:
            context = context_mod.RunContext(run_id="test", log_file=Path(directory) / "log")
            self.assertEqual(context.env(background=True).get(MANAGED_STACK_ENV), "1")


class ToolchainPathTests(unittest.TestCase):
    """The wrapper hands the invoking user's cache down via UV_CACHE_DIR;
    child processes must honour it instead of re-deriving the repo path."""

    def test_cache_dir_honours_the_wrapper_override(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"UV_CACHE_DIR": directory}),
        ):
            self.assertEqual(context_mod.toolchain_cache_dir(), Path(directory))

    def test_cache_dir_falls_back_to_the_checkout(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "UV_CACHE_DIR"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(context_mod.toolchain_cache_dir(), context_mod.ROOT_DIR / ".uv-cache")

    def test_watchdog_spawns_uv_with_that_cache(self) -> None:
        # Regression: this call site passed a hardcoded repo-relative cache,
        # so a sudo run left a root-owned .uv-cache in the checkout and broke
        # `uv run` for the repo owner.
        command = watchdog_mod._uv_command("python", "-c", "pass")
        self.assertEqual(command[:2], ["uv", "--cache-dir"])
        self.assertEqual(command[2], str(watchdog_mod.UV_CACHE))


class UnlockCommandTests(unittest.TestCase):
    def test_cli_unlock_when_no_lockout_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch("stremioguard.cli.commands.general.ROOT_DIR", root),
                mock.patch("stremioguard.cli.commands.general.logger") as mock_logger,
            ):
                general_mod.unlock()
                mock_logger.info.assert_called_with("No VPN lockout is active.")

    def test_cli_unlock_confirmed_clears_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lockout_file = root / ".stremio" / "vpn-lockout.json"
            lockout_file.parent.mkdir(parents=True, exist_ok=True)
            lockout_file.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-20T00:00:00Z",
                        "reason": "auth_rejected",
                        "outage_duration_seconds": 12.0,
                        "remediation": "Run ./stremio init",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch("stremioguard.cli.commands.general.ROOT_DIR", root),
                mock.patch("stremioguard.cli.commands.general.typer.confirm", return_value=True),
                mock.patch("stremioguard.cli.commands.general.logger") as mock_logger,
            ):
                general_mod.unlock()
                self.assertFalse(lockout_file.exists())
                mock_logger.success.assert_called_once()

    def test_cli_unlock_declined_retains_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lockout_file = root / ".stremio" / "vpn-lockout.json"
            lockout_file.parent.mkdir(parents=True, exist_ok=True)
            lockout_file.write_text('{"reason": "auth_rejected"}\n', encoding="utf-8")
            with (
                mock.patch("stremioguard.cli.commands.general.ROOT_DIR", root),
                mock.patch("stremioguard.cli.commands.general.typer.confirm", return_value=False),
                mock.patch("stremioguard.cli.commands.general.logger") as mock_logger,
            ):
                general_mod.unlock()
                self.assertTrue(lockout_file.exists())
                mock_logger.info.assert_called_with("Lockout marker retained.")


if __name__ == "__main__":
    unittest.main()
