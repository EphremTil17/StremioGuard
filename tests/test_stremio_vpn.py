from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

MODULE_PATH = Path(__file__).resolve().parents[1] / "bin" / "stremio-vpn"
LOADER = importlib.machinery.SourceFileLoader("stremio_vpn", str(MODULE_PATH))
SPEC = importlib.util.spec_from_loader("stremio_vpn", LOADER)
if SPEC is None:
    raise RuntimeError(f"Could not load module spec for {MODULE_PATH}")
stremio_vpn = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules["stremio_vpn"] = stremio_vpn
SPEC.loader.exec_module(stremio_vpn)

STREMIO_PATH = Path(__file__).resolve().parents[1] / "stremio.py"
STREMIO_LOADER = importlib.machinery.SourceFileLoader("stremio_app", str(STREMIO_PATH))
STREMIO_SPEC = importlib.util.spec_from_loader("stremio_app", STREMIO_LOADER)
if STREMIO_SPEC is None:
    raise RuntimeError(f"Could not load module spec for {STREMIO_PATH}")
stremio_app = importlib.util.module_from_spec(STREMIO_SPEC)
assert STREMIO_SPEC.loader
sys.modules["stremio_app"] = stremio_app
STREMIO_SPEC.loader.exec_module(stremio_app)


GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    "{{.State.Health.Status}}",
    "gluetun",
)


class FakeRunner:
    def __init__(
        self,
        responses: dict[
            tuple[str, ...],
            list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
        ],
    ) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []

    def run(
        self,
        args: list[str],
        *,
        check: bool = False,
        capture: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        key = tuple(args)
        response = self.responses.get(key)
        if isinstance(response, list):
            result = response.pop(0)
        elif response is not None:
            result = response
        else:
            result = subprocess.CompletedProcess(args, 0, "", "")

        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, args, result.stdout, result.stderr
            )
        return result


def completed(
    args: list[str],
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


def make_config(tmp_path: Path, **overrides):
    state_dir = tmp_path / ".stremio"
    state_dir.mkdir(parents=True, exist_ok=True)
    values = {
        "root_dir": tmp_path,
        "compose_file": tmp_path / "docker-compose.yml",
        "service_name": "stremio",
        "container_name": "stremio-server",
        "gluetun_container_name": "gluetun",
        "gluetun_healthy_timeout_seconds": 1,
        "watch_interval_seconds": 1,
        "watchdog_log_interval_seconds": 300,
        "public_ip_timeout_seconds": 1,
        "home_ip_file": state_dir / "home-ip",
        "expected_vpn_ip": None,
        "ip_check_urls": ("https://example.test/ip",),
        "install_missing": False,
        "run_id": "test-run",
        "log_file": None,
        "log_session": True,
    }
    values.update(overrides)
    return stremio_vpn.Config(**values)


class GluetunGuardTests(unittest.TestCase):
    def test_docker_permission_help_detects_socket_permission_error(self) -> None:
        help_text = stremio_vpn.docker_permission_help(
            "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock"
        )

        self.assertIsNotNone(help_text)
        self.assertIn("permission error", help_text.lower())
        self.assertIn("docker ps", help_text)
        self.assertIn("sudo ./stremio", help_text)

    def test_require_commands_reports_docker_socket_permission_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed(
                        ["docker", "ps", "--format", "{{.ID}}"],
                        "",
                        "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n",
                        returncode=1,
                    ),
                }
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with self.assertRaises(RuntimeError) as ctx:
                guard.require_commands()

            self.assertIn("not authorized to run it", str(ctx.exception))

    def test_docker_daemon_help_reuses_socket_permission_guidance(self) -> None:
        runner = FakeRunner(
            {
                ("docker", "ps", "--format", "{{.ID}}"): completed(
                    ["docker", "ps", "--format", "{{.ID}}"],
                    "",
                    "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n",
                    returncode=1,
                )
            }
        )

        help_text = stremio_vpn.docker_daemon_help(runner)

        self.assertIsNotNone(help_text)
        self.assertIn("`docker` group", help_text)

    def test_public_ip_safe_rejects_saved_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = stremio_vpn.GluetunGuard(cfg, FakeRunner({}))

            with mock.patch.object(guard, "public_ip_via_gluetun", return_value="198.51.100.10"):
                self.assertFalse(guard.public_ip_safe())

    def test_public_ip_safe_accepts_non_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = stremio_vpn.GluetunGuard(cfg, FakeRunner({}))

            with mock.patch.object(guard, "public_ip_via_gluetun", return_value="203.0.113.20"):
                self.assertTrue(guard.public_ip_safe())

    def test_setup_resets_builds_and_starts_compose_instance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                }
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
            ):
                guard.setup_stremio(reset=True)

            compose_prefix = ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml")]
            self.assertIn([*compose_prefix, "down", "--remove-orphans"], runner.calls)
            self.assertIn([*compose_prefix, "build", "stremio"], runner.calls)
            self.assertIn([*compose_prefix, "up", "-d", "stremio"], runner.calls)

    def test_start_runs_setup_when_no_compose_instance_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            ps_args = (
                "docker",
                "compose",
                "-f",
                str(tmp_path / "docker-compose.yml"),
                "ps",
                "-a",
                "-q",
                "stremio",
            )
            runner = FakeRunner({ps_args: completed(list(ps_args), "")})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "require_commands", return_value=None),
                mock.patch.object(guard, "preflight", return_value=None),
            ):
                guard.start_stremio()

            compose_prefix = ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml")]
            self.assertIn([*compose_prefix, "build", "stremio"], runner.calls)
            self.assertIn([*compose_prefix, "up", "-d", "stremio"], runner.calls)
            self.assertNotIn([*compose_prefix, "down", "--remove-orphans"], runner.calls)

    def test_parse_public_ip_accepts_valid_addresses(self) -> None:
        self.assertEqual(stremio_vpn.parse_public_ip("203.0.113.20\n"), "203.0.113.20")
        self.assertEqual(stremio_vpn.parse_public_ip("  198.51.100.10 "), "198.51.100.10")
        self.assertEqual(stremio_vpn.parse_public_ip("2001:db8::1"), "2001:db8::1")

    def test_parse_public_ip_rejects_garbage(self) -> None:
        self.assertIsNone(stremio_vpn.parse_public_ip(""))
        self.assertIsNone(stremio_vpn.parse_public_ip("not.an.ip"))
        self.assertIsNone(stremio_vpn.parse_public_ip("999.999.999.999"))
        self.assertIsNone(stremio_vpn.parse_public_ip("::::"))
        self.assertIsNone(stremio_vpn.parse_public_ip("203.0.113.20 extra"))

    def test_gluetun_healthy_returns_true_when_inspect_shows_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "healthy\n")}
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)
            self.assertTrue(guard.gluetun_healthy())

    def test_gluetun_healthy_returns_false_when_inspect_shows_starting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())

    def test_gluetun_healthy_returns_false_when_container_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT),
                        "",
                        "Error: No such object: gluetun\n",
                        returncode=1,
                    )
                }
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)
            self.assertFalse(guard.gluetun_healthy())

    def test_watch_once_stops_stremio_when_gluetun_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with mock.patch.object(guard, "gluetun_healthy", return_value=False):
                guard.watch_once(auto_start=True)

            compose_prefix = ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml")]
            self.assertIn([*compose_prefix, "stop", "stremio"], runner.calls)
            self.assertNotIn([*compose_prefix, "up", "-d", "stremio"], runner.calls)
            self.assertEqual(guard.vpn_drop_count, 1)

    def test_watch_once_stops_stremio_when_ip_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(guard, "public_ip_safe", return_value=False),
            ):
                guard.watch_once(auto_start=True)

            compose_prefix = ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml")]
            self.assertIn([*compose_prefix, "stop", "stremio"], runner.calls)
            self.assertNotIn([*compose_prefix, "up", "-d", "stremio"], runner.calls)

    def test_watch_once_auto_starts_stremio_when_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
                mock.patch.object(guard, "container_running", return_value=False),
            ):
                guard.watch_once(auto_start=True)

            compose_prefix = ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml")]
            self.assertIn([*compose_prefix, "up", "-d", "stremio"], runner.calls)

    def test_watch_once_does_not_log_healthy_tick_before_summary_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "log") as log_mock,
            ):
                guard.watch_once(auto_start=True)

            log_messages = [call.args[0] for call in log_mock.call_args_list]
            self.assertFalse(any("Watchdog summary" in message for message in log_messages))

    def test_watch_once_logs_summary_after_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner({})
            guard = stremio_vpn.GluetunGuard(
                make_config(tmp_path, watchdog_log_interval_seconds=5),
                runner,
            )
            guard.last_public_ip = "203.0.113.20"
            guard.summary_started_at = 10.0

            with (
                mock.patch.object(stremio_vpn.time, "monotonic", return_value=16.0),
                mock.patch.object(guard, "gluetun_healthy", return_value=True),
                mock.patch.object(guard, "public_ip_safe", return_value=True),
                mock.patch.object(guard, "container_running", return_value=True),
                mock.patch.object(guard, "log") as log_mock,
            ):
                guard.watch_once(auto_start=True)

            log_messages = [call.args[0] for call in log_mock.call_args_list]
            self.assertTrue(any("Watchdog summary" in message for message in log_messages))
            self.assertEqual(guard.checks_since_summary, 0)
            self.assertEqual(guard.summary_started_at, 16.0)

    def test_wait_for_gluetun_healthy_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "starting\n")}
            )
            guard = stremio_vpn.GluetunGuard(
                make_config(tmp_path, gluetun_healthy_timeout_seconds=0), runner
            )

            with (
                mock.patch.object(stremio_vpn.time, "sleep", return_value=None),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.wait_for_gluetun_healthy()

            self.assertIn("did not become healthy", str(ctx.exception))

    def test_public_ip_via_gluetun_uses_docker_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            exec_call = (
                "docker",
                "exec",
                "gluetun",
                "wget",
                "-qO-",
                "--timeout",
                "1",
                "https://example.test/ip",
            )
            runner = FakeRunner({exec_call: completed(list(exec_call), "203.0.113.20\n")})
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            self.assertEqual(guard.public_ip_via_gluetun(), "203.0.113.20")
            self.assertIn(list(exec_call), runner.calls)

    def test_record_home_ip_refuses_when_gluetun_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {GLUETUN_HEALTH_INSPECT: completed(list(GLUETUN_HEALTH_INSPECT), "healthy\n")}
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "public_ip", return_value="203.0.113.20"),
                self.assertRaises(RuntimeError) as ctx,
            ):
                guard.record_home_ip()

            self.assertIn("healthy", str(ctx.exception).lower())
            self.assertFalse(guard.config.home_ip_file.exists())

    def test_record_home_ip_writes_when_gluetun_not_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    GLUETUN_HEALTH_INSPECT: completed(
                        list(GLUETUN_HEALTH_INSPECT),
                        "",
                        "Error: No such object: gluetun\n",
                        returncode=1,
                    )
                }
            )
            guard = stremio_vpn.GluetunGuard(make_config(tmp_path), runner)

            with mock.patch.object(guard, "public_ip", return_value="198.51.100.10"):
                guard.record_home_ip()

            self.assertEqual(
                guard.config.home_ip_file.read_text(encoding="utf-8").strip(),
                "198.51.100.10",
            )


class StremioInitHelpersTests(unittest.TestCase):
    def test_run_guard_exits_cleanly_when_guard_subprocess_fails(self) -> None:
        with (
            mock.patch.object(
                stremio_app.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(1, ["uv", "run"]),
            ),
            self.assertRaises(typer.Exit) as ctx,
        ):
            stremio_app.run_guard("start", file_logging=False)

        self.assertEqual(ctx.exception.exit_code, 1)

    def test_vpn_setup_checklist_includes_general_linux_requirements(self) -> None:
        checklist = stremio_app._vpn_setup_checklist()

        self.assertIn("Docker with the Compose plugin", checklist)
        self.assertIn("/dev/net/tun", checklist)
        self.assertIn("VPN provider account", checklist)
        self.assertNotIn("nordvpn CLI", checklist)

    def test_vpn_setup_checklist_includes_nordvpn_specific_requirements(self) -> None:
        checklist = stremio_app._vpn_setup_checklist("nordvpn")

        self.assertIn("nordvpn CLI", checklist)
        self.assertIn("nordvpn login", checklist)
        self.assertIn("wireguard-tools", checklist)

    def test_missing_nordvpn_dependencies_lists_all_missing_tools(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            missing = stremio_app._missing_nordvpn_dependencies()

        self.assertEqual(len(missing), 2)
        self.assertIn("nordvpn CLI", missing[0])
        self.assertIn("wireguard-tools", missing[1])

    def test_preflight_nordvpn_setup_fails_with_single_aggregated_message(self) -> None:
        with (
            mock.patch.object(
                stremio_app,
                "_missing_nordvpn_dependencies",
                return_value=["- nordvpn CLI", "- wireguard-tools"],
            ),
            self.assertRaises(typer.Exit) as ctx,
        ):
            stremio_app._preflight_nordvpn_setup()

        self.assertEqual(ctx.exception.exit_code, 1)

    def test_configure_external_access_tier_one_writes_lan_bind_and_clears_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "EXTERNAL_BASE_URL=https://old.example\nHOST_BIND_ADDR=127.0.0.1\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    stremio_app.typer,
                    "prompt",
                    side_effect=["1", "10.0.0.5"],
                ),
                mock.patch.object(stremio_app.typer, "echo"),
                mock.patch.object(stremio_app, "logger"),
            ):
                stremio_app._configure_external_access(env)

            self.assertEqual(stremio_app.env_file_value(env, "EXTERNAL_BASE_URL"), "")
            self.assertEqual(stremio_app.env_file_value(env, "HOST_BIND_ADDR"), "10.0.0.5")

    def test_configure_external_access_tier_two_writes_domain_and_lan_bind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "EXTERNAL_BASE_URL=\nHOST_BIND_ADDR=127.0.0.1\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    stremio_app.typer,
                    "prompt",
                    side_effect=["2", "10.0.0.5", "stremio.example.com"],
                ),
                mock.patch.object(stremio_app.typer, "echo"),
                mock.patch.object(stremio_app, "logger"),
            ):
                stremio_app._configure_external_access(env)

            self.assertEqual(
                stremio_app.env_file_value(env, "EXTERNAL_BASE_URL"),
                "https://stremio.example.com",
            )
            self.assertEqual(stremio_app.env_file_value(env, "HOST_BIND_ADDR"), "10.0.0.5")

    def test_prompt_lan_bind_addr_accepts_lan_ip(self) -> None:
        with (
            mock.patch.object(stremio_app.typer, "prompt", return_value="10.168.77.10"),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_lan_bind_addr(), "10.168.77.10")

    def test_prompt_lan_bind_addr_accepts_all_interfaces(self) -> None:
        with (
            mock.patch.object(stremio_app.typer, "prompt", return_value="0.0.0.0"),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_lan_bind_addr(), "0.0.0.0")

    def test_prompt_lan_bind_addr_rejects_invalid_then_accepts_valid(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                side_effect=["not-an-ip", "192.168.1.50"],
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_lan_bind_addr(), "192.168.1.50")

    def test_prompt_lan_bind_addr_warns_on_loopback_and_re_prompts_when_declined(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                side_effect=["127.0.0.1", "n", "10.0.0.5"],
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_lan_bind_addr(), "10.0.0.5")

    def test_prompt_lan_bind_addr_accepts_loopback_after_explicit_confirmation(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                side_effect=["127.0.0.1", "y"],
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_lan_bind_addr(), "127.0.0.1")

    def test_prompt_public_domain_strips_trailing_slash(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                return_value="stremio.example.com/",
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_public_domain(), "stremio.example.com")

    def test_prompt_public_domain_rejects_scheme_then_accepts_bare_host(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                side_effect=["https://stremio.example.com", "stremio.example.com"],
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_public_domain(), "stremio.example.com")

    def test_prompt_public_domain_rejects_path_and_whitespace(self) -> None:
        with (
            mock.patch.object(
                stremio_app.typer,
                "prompt",
                side_effect=["foo bar", "no-tld", "stremio.example.com"],
            ),
            mock.patch.object(stremio_app.typer, "echo"),
        ):
            self.assertEqual(stremio_app._prompt_public_domain(), "stremio.example.com")

    def test_get_nordvpn_wireguard_key_manual_path_skips_host_extraction(self) -> None:
        with (
            mock.patch.object(
                stremio_app,
                "_prompt_nordvpn_key_setup_mode",
                return_value="manual",
            ),
            mock.patch.object(
                stremio_app,
                "_prompt_manual_wireguard_key",
                return_value="manual-key",
            ),
            mock.patch.object(stremio_app, "_preflight_nordvpn_setup") as preflight,
        ):
            key = stremio_app._get_nordvpn_wireguard_key()

        self.assertEqual(key, "manual-key")
        preflight.assert_not_called()

    def test_get_nordvpn_wireguard_key_auto_path_checks_prerequisites(self) -> None:
        with (
            mock.patch.object(stremio_app, "_prompt_nordvpn_key_setup_mode", return_value="auto"),
            mock.patch.object(stremio_app, "_prompt_yes_no", return_value=True),
            mock.patch.object(stremio_app, "_preflight_nordvpn_setup") as preflight,
            mock.patch.object(stremio_app, "_extract_wireguard_key", return_value="auto-key"),
            mock.patch.object(stremio_app, "logger"),
        ):
            key = stremio_app._get_nordvpn_wireguard_key()

        self.assertEqual(key, "auto-key")
        preflight.assert_called_once()

    def test_configure_nordvpn_openvpn_writes_credentials_and_clears_wireguard_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_TYPE=wireguard\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "OPENVPN_USER=\n"
                "OPENVPN_PASSWORD=\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(stremio_app, "_prompt_nordvpn_protocol", return_value="openvpn"),
                mock.patch.object(
                    stremio_app,
                    "_prompt_openvpn_credentials",
                    return_value=("svc-user", "svc-pass"),
                ),
                mock.patch.object(stremio_app, "logger"),
            ):
                stremio_app._configure_nordvpn(env)

            self.assertEqual(stremio_app.env_file_value(env, "VPN_TYPE"), "openvpn")
            self.assertEqual(stremio_app.env_file_value(env, "OPENVPN_USER"), "svc-user")
            self.assertEqual(stremio_app.env_file_value(env, "OPENVPN_PASSWORD"), "svc-pass")
            self.assertEqual(stremio_app.env_file_value(env, "WIREGUARD_PRIVATE_KEY"), "")

    def test_configure_nordvpn_wireguard_writes_key_and_clears_openvpn_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_TYPE=openvpn\n"
                "WIREGUARD_PRIVATE_KEY=\n"
                "OPENVPN_USER=svc-user\n"
                "OPENVPN_PASSWORD=svc-pass\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    stremio_app,
                    "_prompt_nordvpn_protocol",
                    return_value="wireguard",
                ),
                mock.patch.object(stremio_app, "_get_nordvpn_wireguard_key", return_value="wg-key"),
                mock.patch.object(stremio_app, "logger"),
            ):
                stremio_app._configure_nordvpn(env)

            self.assertEqual(stremio_app.env_file_value(env, "VPN_TYPE"), "wireguard")
            self.assertEqual(stremio_app.env_file_value(env, "WIREGUARD_PRIVATE_KEY"), "wg-key")
            self.assertEqual(stremio_app.env_file_value(env, "OPENVPN_USER"), "")
            self.assertEqual(stremio_app.env_file_value(env, "OPENVPN_PASSWORD"), "")

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
                mock.patch.object(stremio_app, "ENV_EXAMPLE", env_example),
                mock.patch.object(stremio_app, "ENV_FILE", env_file),
                mock.patch.object(stremio_app, "is_interactive", return_value=True),
                mock.patch.object(stremio_app, "_prompt_provider", return_value="nordvpn"),
                mock.patch.object(
                    stremio_app,
                    "_configure_external_access",
                    side_effect=record_external_access,
                ),
                mock.patch.object(
                    stremio_app,
                    "_configure_nordvpn",
                    side_effect=record_protocol_setup,
                ),
                mock.patch.object(
                    stremio_app,
                    "_configure_optional_stremio_settings",
                    side_effect=record_optional_settings,
                ),
                mock.patch.object(stremio_app, "logger"),
                self.assertRaises(typer.Exit),
            ):
                stremio_app.init()

            self.assertEqual(call_order, ["access", "optional", "key"])

    def test_init_prompts_provider_even_when_env_is_not_template_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_example = temp_root / ".env.example"
            env_file = temp_root / ".env"
            env_example.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "VPN_TYPE=wireguard\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            env_file.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "VPN_TYPE=wireguard\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "EXTERNAL_BASE_URL=\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(stremio_app, "ENV_EXAMPLE", env_example),
                mock.patch.object(stremio_app, "ENV_FILE", env_file),
                mock.patch.object(stremio_app, "is_interactive", return_value=True),
                mock.patch.object(stremio_app, "_prompt_provider", return_value="other") as prompt,
                mock.patch.object(stremio_app, "_configure_nordvpn") as configure_nordvpn,
                mock.patch.object(stremio_app, "_print_manual_setup_pointer") as manual_pointer,
                mock.patch.object(stremio_app, "logger"),
            ):
                stremio_app.init()

            prompt.assert_called_once_with("nordvpn")
            configure_nordvpn.assert_not_called()
            manual_pointer.assert_called_once()

    def test_env_needs_init_when_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(stremio_app.env_needs_init(Path(directory) / ".env"))

    def test_env_needs_init_when_placeholder_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            self.assertTrue(stremio_app.env_needs_init(env))

    def test_env_needs_init_when_value_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("WIREGUARD_PRIVATE_KEY=\n", encoding="utf-8")
            self.assertTrue(stremio_app.env_needs_init(env))

    def test_env_needs_init_when_nordvpn_openvpn_credentials_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "VPN_TYPE=openvpn\n"
                "OPENVPN_USER=<paste-service-username-here>\n"
                "OPENVPN_PASSWORD=<paste-service-password-here>\n",
                encoding="utf-8",
            )
            self.assertTrue(stremio_app.env_needs_init(env))

    def test_env_needs_init_false_when_key_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "WIREGUARD_PRIVATE_KEY=aGVsbG8td29ybGQ=\n",
                encoding="utf-8",
            )
            self.assertFalse(stremio_app.env_needs_init(env))

    def test_env_needs_init_false_when_nordvpn_openvpn_credentials_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "VPN_TYPE=openvpn\n"
                "OPENVPN_USER=svc-user\n"
                "OPENVPN_PASSWORD=svc-pass\n",
                encoding="utf-8",
            )
            self.assertFalse(stremio_app.env_needs_init(env))

    def test_write_wireguard_key_replaces_line_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "TZ=America/Chicago\n",
                encoding="utf-8",
            )
            stremio_app.write_wireguard_key(env, "secret-key")
            content = env.read_text(encoding="utf-8")

            self.assertIn("WIREGUARD_PRIVATE_KEY=secret-key", content)
            self.assertNotIn("<paste-key-here>", content)
            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_write_wireguard_key_appends_when_line_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            stremio_app.write_wireguard_key(env, "fallback-key")
            content = env.read_text(encoding="utf-8")

            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("WIREGUARD_PRIVATE_KEY=fallback-key", content)

    def test_write_openvpn_credentials_replaces_both_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "OPENVPN_USER=<paste-service-username-here>\n"
                "OPENVPN_PASSWORD=<paste-service-password-here>\n",
                encoding="utf-8",
            )

            stremio_app.write_openvpn_credentials(env, "svc-user", "svc-pass")

            content = env.read_text(encoding="utf-8")
            self.assertIn("OPENVPN_USER=svc-user", content)
            self.assertIn("OPENVPN_PASSWORD=svc-pass", content)

    def test_write_env_setting_replaces_existing_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("STREMIO_APPLY_PATCHES=1\nTZ=America/Chicago\n", encoding="utf-8")

            stremio_app.write_env_setting(env, "STREMIO_APPLY_PATCHES", "0")

            content = env.read_text(encoding="utf-8")
            self.assertIn("STREMIO_APPLY_PATCHES=0", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_env_file_value_reads_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("STREMIO_SKIP_HW_PROBE=0\n", encoding="utf-8")

            self.assertEqual(stremio_app.env_file_value(env, "STREMIO_SKIP_HW_PROBE"), "0")

    def test_env_flag_enabled_uses_default_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"

            self.assertTrue(
                stremio_app.env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=env)
            )
            self.assertFalse(
                stremio_app.env_flag_enabled("STREMIO_APPLY_PATCHES", False, env_path=env)
            )

    def test_env_flag_enabled_reads_falsey_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("STREMIO_APPLY_PATCHES=0\n", encoding="utf-8")

            self.assertFalse(
                stremio_app.env_flag_enabled("STREMIO_APPLY_PATCHES", True, env_path=env)
            )


if __name__ == "__main__":
    unittest.main()
