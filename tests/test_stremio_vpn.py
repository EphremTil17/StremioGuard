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
stremio_vpn = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["stremio_vpn"] = stremio_vpn
SPEC.loader.exec_module(stremio_vpn)


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
    values = {
        "root_dir": tmp_path,
        "compose_file": tmp_path / "docker-compose.yml",
        "service_name": "stremio",
        "container_name": "stremio-server",
        "nordvpn_group": "p2p",
        "nordvpn_country": "united_states",
        "vpn_wait_seconds": 1,
        "watch_interval_seconds": 1,
        "public_ip_timeout_seconds": 1,
        "home_ip_file": tmp_path / ".vpn-guard.home-ip",
        "expected_vpn_ip": None,
        "ip_check_urls": ("https://example.test/ip",),
    }
    values.update(overrides)
    return stremio_vpn.Config(**values)


class VpnGuardTests(unittest.TestCase):
    def test_public_ip_safe_rejects_saved_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = stremio_vpn.VpnGuard(cfg, FakeRunner({}))

            with mock.patch.object(guard, "public_ip", return_value="198.51.100.10"):
                self.assertFalse(guard.public_ip_safe())

    def test_public_ip_safe_accepts_non_home_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_config(tmp_path)
            cfg.home_ip_file.write_text("198.51.100.10\n", encoding="utf-8")
            guard = stremio_vpn.VpnGuard(cfg, FakeRunner({}))

            with mock.patch.object(guard, "public_ip", return_value="203.0.113.20"):
                self.assertTrue(guard.public_ip_safe())

    def test_connect_vpn_attempts_configured_p2p_country_when_disconnected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    ("nordvpn", "status"): [
                        completed(["nordvpn", "status"], "Status: Disconnected\n"),
                        completed(["nordvpn", "status"], "Status: Connected\n"),
                    ],
                    ("nordvpn", "connect", "--group", "p2p", "united_states"): completed(
                        ["nordvpn", "connect", "--group", "p2p", "united_states"],
                        "Connecting...\n",
                    ),
                }
            )
            guard = stremio_vpn.VpnGuard(make_config(tmp_path), runner)

            with mock.patch.object(stremio_vpn.time, "sleep", return_value=None):
                guard.connect_vpn()

            self.assertIn(["nordvpn", "connect", "--group", "p2p", "united_states"], runner.calls)

    def test_watch_once_stops_container_before_reconnect_when_vpn_drops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            runner = FakeRunner(
                {
                    ("nordvpn", "status"): [
                        completed(["nordvpn", "status"], "Status: Disconnected\n"),
                        completed(["nordvpn", "status"], "Status: Disconnected\n"),
                        completed(["nordvpn", "status"], "Status: Connected\n"),
                        completed(["nordvpn", "status"], "Status: Connected\n"),
                    ],
                    ("nordvpn", "connect", "--group", "p2p", "united_states"): completed(
                        ["nordvpn", "connect", "--group", "p2p", "united_states"]
                    ),
                    ("docker", "inspect", "-f", "{{.State.Running}}", "stremio-server"): completed(
                        ["docker", "inspect", "-f", "{{.State.Running}}", "stremio-server"],
                        "true\n",
                    ),
                }
            )
            guard = stremio_vpn.VpnGuard(make_config(tmp_path), runner)

            with (
                mock.patch.object(guard, "public_ip_safe", return_value=True),
                mock.patch.object(stremio_vpn.time, "sleep", return_value=None),
            ):
                guard.watch_once()

            stop_call = [
                "docker",
                "compose",
                "-f",
                str(tmp_path / "docker-compose.yml"),
                "stop",
                "stremio",
            ]
            connect_call = ["nordvpn", "connect", "--group", "p2p", "united_states"]
            self.assertIn(stop_call, runner.calls)
            self.assertIn(connect_call, runner.calls)
            self.assertLess(runner.calls.index(stop_call), runner.calls.index(connect_call))


if __name__ == "__main__":
    unittest.main()
