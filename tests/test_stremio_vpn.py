from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "bin" / "stremio-vpn"
LOADER = importlib.machinery.SourceFileLoader("stremio_vpn", str(MODULE_PATH))
SPEC = importlib.util.spec_from_loader("stremio_vpn", LOADER)
if SPEC is None:
    raise RuntimeError(f"Could not load module spec for {MODULE_PATH}")
stremio_vpn = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules["stremio_vpn"] = stremio_vpn
SPEC.loader.exec_module(stremio_vpn)

STREAMIO_PATH = Path(__file__).resolve().parents[1] / "streamio.py"
STREAMIO_LOADER = importlib.machinery.SourceFileLoader("streamio_app", str(STREAMIO_PATH))
STREAMIO_SPEC = importlib.util.spec_from_loader("streamio_app", STREAMIO_LOADER)
if STREAMIO_SPEC is None:
    raise RuntimeError(f"Could not load module spec for {STREAMIO_PATH}")
streamio = importlib.util.module_from_spec(STREAMIO_SPEC)
assert STREAMIO_SPEC.loader
sys.modules["streamio_app"] = streamio
STREAMIO_SPEC.loader.exec_module(streamio)


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
    state_dir = tmp_path / ".streamio"
    state_dir.mkdir(parents=True, exist_ok=True)
    values = {
        "root_dir": tmp_path,
        "compose_file": tmp_path / "docker-compose.yml",
        "service_name": "stremio",
        "container_name": "stremio-server",
        "gluetun_container_name": "gluetun",
        "gluetun_healthy_timeout_seconds": 1,
        "watch_interval_seconds": 1,
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


class StreamioInitHelpersTests(unittest.TestCase):
    def test_env_needs_init_when_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(streamio.env_needs_init(Path(directory) / ".env"))

    def test_env_needs_init_when_placeholder_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n",
                encoding="utf-8",
            )
            self.assertTrue(streamio.env_needs_init(env))

    def test_env_needs_init_when_value_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("WIREGUARD_PRIVATE_KEY=\n", encoding="utf-8")
            self.assertTrue(streamio.env_needs_init(env))

    def test_env_needs_init_false_when_key_populated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "WIREGUARD_PRIVATE_KEY=aGVsbG8td29ybGQ=\n",
                encoding="utf-8",
            )
            self.assertFalse(streamio.env_needs_init(env))

    def test_write_wireguard_key_replaces_line_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text(
                "VPN_SERVICE_PROVIDER=nordvpn\n"
                "WIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
                "TZ=America/Chicago\n",
                encoding="utf-8",
            )
            streamio.write_wireguard_key(env, "secret-key")
            content = env.read_text(encoding="utf-8")

            self.assertIn("WIREGUARD_PRIVATE_KEY=secret-key", content)
            self.assertNotIn("<paste-key-here>", content)
            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("TZ=America/Chicago", content)

    def test_write_wireguard_key_appends_when_line_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
            streamio.write_wireguard_key(env, "fallback-key")
            content = env.read_text(encoding="utf-8")

            self.assertIn("VPN_SERVICE_PROVIDER=nordvpn", content)
            self.assertIn("WIREGUARD_PRIVATE_KEY=fallback-key", content)


if __name__ == "__main__":
    unittest.main()
