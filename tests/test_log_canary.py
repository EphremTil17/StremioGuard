"""Log canary: a token-shaped request path must reach no log sink."""

from __future__ import annotations

import gzip
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.comet import log_canary as canary_mod
from stremioguard.comet.log_canary import (
    EXPECTED_PROBE_STATUSES,
    DockerLogSink,
    FileGlobSink,
    Probe,
    SinkResult,
    SinkStatus,
    fingerprint,
    new_canary,
    public_probes,
    run_log_canary,
    wget_status,
)
from stremioguard.comet.manager import CometManager

from .conftest import FakeRunner, completed, make_comet_config, make_comet_gateway_config


def _no_sleep(_seconds: float) -> None:
    return None


class FileGlobSinkTests(unittest.TestCase):
    def test_counts_hits_across_plain_and_gzip_rotations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            (logs / "proxy-host-1_access.log").write_text("GET /comet/CANARY/probe\nok\n")
            with gzip.open(logs / "proxy-host-1_access.log.1.gz", "wt") as handle:
                handle.write("GET /comet/CANARY/probe\n")
            result = FileGlobSink("npm", str(logs / "proxy-host-1_*")).count("CANARY")
        self.assertEqual((result.status, result.hits), (SinkStatus.FAIL, 2))

    def test_clean_files_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "a.log").write_text('"GET /comet/*** HTTP/1.1" 403\n')
            result = FileGlobSink("npm", f"{directory}/*.log").count("CANARY")
        self.assertEqual(result.status, SinkStatus.PASS)

    def test_no_matching_files_is_unverified_not_pass(self) -> None:
        # A typo'd glob must not silently read as "clean".
        with tempfile.TemporaryDirectory() as directory:
            result = FileGlobSink("npm", f"{directory}/missing-*.log").count("CANARY")
        self.assertEqual(result.status, SinkStatus.UNVERIFIED)

    def test_unreadable_file_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "root-only.log"
            path.write_text("x\n")
            with mock.patch("builtins.open", side_effect=PermissionError(13, "Permission denied")):
                result = FileGlobSink("npm", str(path)).count("CANARY")
        self.assertEqual(result.status, SinkStatus.UNVERIFIED)
        self.assertIn("Permission denied", result.detail)

    def test_modified_since_skips_stale_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "old.log").write_text("CANARY\n")
            sink = FileGlobSink("run", f"{directory}/*.log", modified_since=time.time() + 60)
            result = sink.count("CANARY")
        self.assertEqual(result.status, SinkStatus.PASS)


class DockerLogSinkTests(unittest.TestCase):
    def test_hit_in_stderr_fails(self) -> None:
        args = ["docker", "logs", "--since", "100", "gw"]
        runner = FakeRunner({tuple(args): completed(args, "", "GET /comet/CANARY/probe\n")})
        result = DockerLogSink("gateway", "gw", runner, "100").count("CANARY")
        self.assertEqual((result.status, result.hits), (SinkStatus.FAIL, 1))

    def test_docker_failure_or_missing_container_is_unverified(self) -> None:
        args = ["docker", "logs", "--since", "100", "gw"]
        runner = FakeRunner({tuple(args): completed(args, returncode=1)})
        self.assertEqual(
            DockerLogSink("gateway", "gw", runner, "100").count("CANARY").status,
            SinkStatus.UNVERIFIED,
        )
        self.assertEqual(
            DockerLogSink("gateway", None, runner, "100").count("CANARY").status,
            SinkStatus.UNVERIFIED,
        )


class ProbeTests(unittest.TestCase):
    def test_https_base_also_probes_plain_http_twin(self) -> None:
        # A proxy's server-level HTTP->HTTPS redirect logs outside its locations.
        sent: list[str] = []
        with mock.patch.object(canary_mod, "http_status", side_effect=lambda u: sent.append(u)):
            probes = public_probes("https://comet.example.com/", "CANARY")
            for probe in probes:
                probe.send()
        self.assertEqual(
            sent,
            [
                "https://comet.example.com/comet/CANARY/probe",
                "http://comet.example.com/comet/CANARY/probe",
            ],
        )
        self.assertEqual([p.required for p in probes], [True, False])

    def test_wget_status_parses_gnu_error(self) -> None:
        url = "http://127.0.0.1:8000/x"
        args = ["docker", "exec", "g", "wget", "-O", "/dev/null", "--timeout", "10", url]
        gnu = "HTTP request sent, awaiting response... 404 Not Found\nERROR 404: Not Found.\n"
        runner = FakeRunner({tuple(args): completed(args, "", gnu, 8)})
        self.assertEqual(wget_status(runner, "g", url), 404)

    def test_wget_status_parses_busybox_error(self) -> None:
        url = "http://127.0.0.1:8000/x"
        args = ["docker", "exec", "g", "wget", "-O", "/dev/null", "--timeout", "10", url]
        runner = FakeRunner(
            {
                tuple(args): completed(
                    args, "", "wget: server returned error: HTTP/1.1 404 Not Found\n", 1
                )
            }
        )
        self.assertEqual(wget_status(runner, "g", url), 404)
        self.assertIsNone(wget_status(runner, None, url))

    def test_canary_matches_gateway_token_shape(self) -> None:
        canary = new_canary(8)
        self.assertRegex(canary, r"^[A-Za-z0-9]{8}$")
        self.assertNotEqual(canary, new_canary(8))


class RunLogCanaryTests(unittest.TestCase):
    def _sink(self, status: SinkStatus):
        sink = mock.Mock()
        sink.count.return_value = SinkResult("s", status)
        return sink

    def test_passes_only_when_probes_reach_and_every_sink_passes(self) -> None:
        reached = [Probe("public https", lambda: 403, EXPECTED_PROBE_STATUSES)]
        report = run_log_canary("C", reached, [self._sink(SinkStatus.PASS)], sleep=_no_sleep)
        self.assertTrue(report.passed)
        self.assertEqual(report.canary_fingerprint, fingerprint("C"))

        for status in (SinkStatus.FAIL, SinkStatus.UNVERIFIED):
            report = run_log_canary("C", reached, [self._sink(status)], sleep=_no_sleep)
            self.assertFalse(report.passed)

    def test_unreached_probe_cannot_pass(self) -> None:
        # A 502 or network error means the hops were never exercised.
        for code in (None, 502, 200):
            report = run_log_canary(
                "C",
                [Probe("public https", lambda code=code: code, EXPECTED_PROBE_STATUSES)],
                [self._sink(SinkStatus.PASS)],
                sleep=_no_sleep,
            )
            self.assertFalse(report.passed, code)

    def test_optional_probe_may_find_its_hop_closed(self) -> None:
        https = Probe("public https", lambda: 403, EXPECTED_PROBE_STATUSES)
        closed = Probe("public http", lambda: None, EXPECTED_PROBE_STATUSES, required=False)
        wrong = Probe("public http", lambda: 200, EXPECTED_PROBE_STATUSES, required=False)
        sinks = [self._sink(SinkStatus.PASS)]
        self.assertTrue(run_log_canary("C", [https, closed], sinks, sleep=_no_sleep).passed)
        # An answer outside the expected set is never acceptable, optional or not.
        self.assertFalse(run_log_canary("C", [https, wrong], sinks, sleep=_no_sleep).passed)
        # Optional probes alone prove no hop was exercised.
        self.assertFalse(run_log_canary("C", [closed], sinks, sleep=_no_sleep).passed)

    def test_empty_sink_list_cannot_pass(self) -> None:
        report = run_log_canary(
            "C", [Probe("p", lambda: 403, EXPECTED_PROBE_STATUSES)], [], sleep=_no_sleep
        )
        self.assertFalse(report.passed)


class CometManagerLogCanaryTests(unittest.TestCase):
    """End to end through the manager with a simulated path-logging reverse proxy."""

    def _manager(self, tmp_path: Path, npm_logs: Path):
        cfg = make_comet_config(tmp_path, log_canary_globs=(str(npm_logs / "proxy-host-1_*.log"),))
        runner = FakeRunner({})
        manager = CometManager(cfg, runner)
        gateway = make_comet_gateway_config(tmp_path, public_base_url="https://comet.example.com")
        return manager, runner, gateway

    def _run(self, tmp_path: Path, *, proxy_logs_path: bool):
        npm_logs = tmp_path / "npm"
        npm_logs.mkdir()
        access_log = npm_logs / "proxy-host-1_access.log"
        access_log.write_text("")
        manager, runner, gateway = self._manager(tmp_path, npm_logs)
        seen_urls: list[str] = []

        def fake_proxy(url: str, **_kwargs: object) -> int:
            seen_urls.append(url)
            if proxy_logs_path:  # what NPM did before the fix
                with access_log.open("a") as handle:
                    handle.write(f'"GET {url.split("//", 1)[1].split("/", 1)[1]}" 403\n')
            return 301 if url.startswith("http://") else 403

        def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[:2] == ["docker", "exec"]:
                return completed(args, "", "wget: server returned error: HTTP/1.1 404\n", 1)
            if args[:2] == ["docker", "logs"]:
                return completed(args, '"GET /comet/*** HTTP/1.1" 403\n')
            return completed(args)

        logged: list[str] = []
        with (
            mock.patch.object(manager, "gateway_config", return_value=gateway),
            mock.patch.object(manager, "gluetun_container_id", return_value="gluetun"),
            mock.patch.object(manager, "service_container_id", return_value="comet"),
            mock.patch.object(manager, "gateway_manager") as gateway_manager,
            mock.patch.object(canary_mod, "http_status", side_effect=fake_proxy),
            mock.patch.object(runner, "run", side_effect=fake_run),
            mock.patch("stremioguard.comet.log_canary.time.sleep"),
            mock.patch.object(manager, "log", side_effect=logged.append),
            mock.patch.object(manager, "warn", side_effect=logged.append),
            mock.patch.object(manager, "success", side_effect=logged.append),
        ):
            gateway_manager.return_value.service_container_id.return_value = "gw"
            report = manager.log_canary()
        canary = seen_urls[0].split("/comet/", 1)[1].split("/", 1)[0]
        return report, canary, seen_urls, logged

    def test_path_logging_proxy_fails_its_sink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, canary, urls, logged = self._run(Path(directory), proxy_logs_path=True)

        self.assertFalse(report.passed)
        npm = next(sink for sink in report.sinks if "proxy-host-1" in sink.name)
        self.assertEqual((npm.status, npm.hits), (SinkStatus.FAIL, 2))  # https + http
        self.assertEqual([u.split("://")[0] for u in urls], ["https", "http"])
        # The canary itself never reaches our own output, only its fingerprint.
        self.assertFalse(any(canary in line for line in logged))
        self.assertTrue(any(fingerprint(canary) in line for line in logged))

    def test_clean_stack_passes_every_sink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _, _ = self._run(Path(directory), proxy_logs_path=False)

        self.assertTrue(report.passed, report)
        self.assertEqual(
            [probe.name for probe in report.probes], ["public https", "public http", "comet direct"]
        )
        self.assertTrue(all(sink.status == SinkStatus.PASS for sink in report.sinks))

    def test_disabled_gateway_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            manager = CometManager(make_comet_config(tmp_path), FakeRunner({}))
            with (
                mock.patch.object(
                    manager,
                    "gateway_config",
                    return_value=make_comet_gateway_config(tmp_path, enabled=False),
                ),
                self.assertRaisesRegex(RuntimeError, "needs the Comet gateway"),
            ):
                manager.log_canary()


if __name__ == "__main__":
    unittest.main()
