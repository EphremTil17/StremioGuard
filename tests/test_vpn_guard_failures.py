"""Acceptance tests AC-2 through AC-16 for handoff 0007."""

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
import typer

from stremioguard import env as env_mod
from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard.cli import supervisor
from stremioguard.cli.commands import general as general_cmd_mod
from stremioguard.config import (
    DOCKER_QUERY_TIMEOUT_SECONDS,
    TEARDOWN_MUTATION_TIMEOUT_SECONDS,
    SubprocessRunner,
    compose_command,
)
from stremioguard.guard import GluetunGuard, LockoutActiveError, PublicIPAssessment
from stremioguard.orchestrator import Orchestrator
from tests.conftest import (
    ACTIVE_STATUS_ARGS,
    PUBLIC_IPV4_ALT,
    PUBLIC_IPV4_EGRESS,
    PUBLIC_IPV4_HOST,
    PUBLIC_IPV6_EGRESS,
    PUBLIC_IPV6_HOST,
    FakeRunner,
    completed,
    compose_args_prefix,
    make_config,
)

GLUETUN_HEALTH_INSPECT = (
    "docker",
    "inspect",
    "--format",
    guard_mod.GLUETUN_STATE_FORMAT,
    "gluetun",
)


# ---------------------------------------------------------------------------
# AC-2 (INV-1): Host probe bounded against stall, trickle, bad UTF-8, garbage
# ---------------------------------------------------------------------------


def _start_tcp_server(handler) -> tuple[str, threading.Event, threading.Thread]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.1)
    port = srv.getsockname()[1]
    stop = threading.Event()
    conns: list[socket.socket] = []

    def _serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            conns.append(conn)
            t = threading.Thread(target=handler, args=(conn, stop), daemon=True)
            t.start()
        for c in conns:
            with contextlib.suppress(OSError):
                c.close()
        with contextlib.suppress(OSError):
            srv.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}/", stop, thread


def test_ac2_host_probe_bounds_stall_trickle_non_utf8_and_non_address(tmp_path: Path) -> None:
    """AC-2 (INV-1): bad URLs are each skipped within 3s and good server wins."""

    def stall_handler(conn: socket.socket, stop: threading.Event) -> None:
        try:
            conn.recv(1024)
            stop.wait(10.0)
        except OSError:
            pass

    def trickle_handler(conn: socket.socket, stop: threading.Event) -> None:
        try:
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
            for _ in range(30):
                if stop.wait(0.5):
                    break
                conn.sendall(b"x")
        except OSError:
            pass

    def non_utf8_handler(conn: socket.socket, _stop: threading.Event) -> None:
        try:
            conn.recv(1024)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\xff\xfe\x80\x81"
            )
        except OSError:
            pass

    def non_addr_handler(conn: socket.socket, _stop: threading.Event) -> None:
        try:
            conn.recv(1024)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world"
            )
        except OSError:
            pass

    def good_handler(conn: socket.socket, _stop: threading.Event) -> None:
        try:
            conn.recv(1024)
            body = f"{PUBLIC_IPV4_HOST}\n".encode()
            head = (
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            conn.sendall(head + body)
        except OSError:
            pass

    servers = [
        _start_tcp_server(h)
        for h in (stall_handler, trickle_handler, non_utf8_handler, non_addr_handler, good_handler)
    ]
    try:
        urls = [s[0] for s in servers]
        stall_url, trickle_url, non_utf8_url, non_addr_url, good_url = urls

        # Each bad URL individually skips within 3s.
        for bad_url in (stall_url, trickle_url, non_utf8_url, non_addr_url):
            g = GluetunGuard(
                make_config(tmp_path, public_ip_timeout_seconds=2, ip_check_urls=(bad_url,)),
                FakeRunner({}),
            )
            t0 = time.monotonic()
            assert g.public_ip() is None
            elapsed = time.monotonic() - t0
            assert elapsed < 3.0, f"{bad_url} took {elapsed:.2f}s >= 3.0s"

        # Combined sequence returns the good server's address.
        g_good = GluetunGuard(
            make_config(tmp_path, public_ip_timeout_seconds=2, ip_check_urls=tuple(urls)),
            FakeRunner({}),
        )
        t0 = time.monotonic()
        assert g_good.public_ip() == PUBLIC_IPV4_HOST
        assert time.monotonic() - t0 < 8.0

        # Only bad URLs -> None.
        g_bad = GluetunGuard(
            make_config(
                tmp_path,
                public_ip_timeout_seconds=2,
                ip_check_urls=(stall_url, trickle_url, non_utf8_url, non_addr_url),
            ),
            FakeRunner({}),
        )
        assert g_bad.public_ip() is None
    finally:
        for _, stop, thread in servers:
            stop.set()
            thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# AC-3 (INV-1, INV-6): Real SubprocessRunner with undecodable bytes
# ---------------------------------------------------------------------------


def test_ac3_subprocess_runner_handles_non_utf8_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-3 (INV-1, INV-6): real SubprocessRunner decodes \\xff\\xfe without UnicodeDecodeError."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_docker = bin_dir / "docker"
    fake_docker.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if 'ps' in args and '-q' in args:\n"
        "    sys.stdout.buffer.write(b'gluetun-cid\\n')\n"
        "    sys.exit(0)\n"
        "if 'ps' in args and '--status' in args:\n"
        "    sys.stdout.buffer.write(b'\\xff\\xfe\\n')\n"
        "    sys.exit(1)\n"
        "if 'logs' in args:\n"
        "    sys.stdout.buffer.write(b'line1 \\xff\\xfe line2\\n')\n"
        "    sys.exit(0)\n"
        "if 'exec' in args:\n"
        "    sys.stdout.buffer.write(b'\\xff\\xfe\\n')\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

    guard = GluetunGuard(make_config(tmp_path), SubprocessRunner())
    assert guard.public_ip_via_gluetun() is None
    logs_text = guard.gluetun_recent_logs()
    assert "line1" in logs_text and "\ufffd" in logs_text
    assert guard.running_services(["stremio"]) is None


# ---------------------------------------------------------------------------
# AC-4 (INV-2, INV-3, INV-12): H1 end state over 360 ticks + recovery
# ---------------------------------------------------------------------------


def test_ac4_hour_long_probe_timeout_outage_does_not_lock_out_and_recovers(
    tmp_path: Path,
) -> None:
    """AC-4 (INV-2, INV-3, INV-12): 360 TimeoutExpired ticks never lock out; egress warns <= 13x."""
    cfg = make_config(tmp_path, public_ip_failure_threshold=3)
    prefix = compose_args_prefix(tmp_path)
    ps_gluetun = (*prefix, "ps", "-q", "gluetun")
    ps_stremio = (*prefix, "ps", "-q", "stremio")
    status_stremio = (*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio")
    stop_stremio = (*prefix, "stop", "stremio")
    up_stremio = (*prefix, "up", "-d", "--no-deps", "--build", "stremio")
    exec_probe = [
        "docker",
        "exec",
        "gluetun",
        "timeout",
        "-s",
        "KILL",
        "1",
        "wget",
        "--tries=1",
        "--timeout=1",
        *(f"--header={k}: {v}" for k, v in guard_mod.PROBE_REQUEST_HEADERS),
        "-qO-",
        "https://example.test/ip",
    ]

    probe_recovered = {"ok": False}
    services_running = {"stremio": True}

    class _TimeoutThenRecoverRunner(FakeRunner):
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            self.calls.append(args)
            self.envs.append(env)
            self.timeouts.append(timeout)
            self.inputs.append(input)
            if args == exec_probe:
                if not probe_recovered["ok"]:
                    raise subprocess.TimeoutExpired(args, timeout or 3)
                return completed(args, f"{PUBLIC_IPV4_EGRESS}\n")
            if args == list(status_stremio):
                out = "stremio\n" if services_running["stremio"] else ""
                return completed(args, out)
            if args == list(stop_stremio):
                services_running["stremio"] = False
                return completed(args)
            if args == list(up_stremio):
                services_running["stremio"] = True
                return completed(args)
            if tuple(args) in self.responses:
                resp = self.responses[tuple(args)]
                assert isinstance(resp, subprocess.CompletedProcess)
                return resp
            return completed(args, "")

    runner = _TimeoutThenRecoverRunner(
        {
            ps_gluetun: completed(list(ps_gluetun), "gluetun\n"),
            ps_stremio: completed(list(ps_stremio), "stremio\n"),
            GLUETUN_HEALTH_INSPECT: completed(
                list(GLUETUN_HEALTH_INSPECT), "healthy|2026-11-11T10:00:00Z\n"
            ),
            (
                "docker",
                "inspect",
                "--format",
                "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}|{{.HostConfig.NetworkMode}}",
                "stremio",
            ): completed([], "stremio|true|2026-11-11T10:00:05Z|container:gluetun\n"),
            (
                "docker",
                "exec",
                "gluetun",
                "timeout",
                "-s",
                "KILL",
                "1",
                "wget",
                "--tries=1",
                "--timeout=1",
                "-O-",
                "http://127.0.0.1:18080/v1/publicip/ip",
            ): completed([], "", returncode=1),
            ("docker", "exec", "gluetun", "iptables", "-S", "OUTPUT"): completed(
                [], f"-P OUTPUT DROP\n{guard_mod.DNS_BLOCK_RULE}\n-A OUTPUT -o lo -j ACCEPT\n"
            ),
        }
    )

    clock = {"now": 1000.0}
    warnings: list[str] = []
    heartbeats: list[str] = []

    with (
        mock.patch.object(guard_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod, "notify", side_effect=heartbeats.append),
    ):
        guard = GluetunGuard(cfg, runner)
        orig_warn = guard.warn

        def capture_warn(msg: str) -> None:
            warnings.append(msg)
            orig_warn(msg)

        guard.warn = capture_warn  # type: ignore[method-assign]
        orch = Orchestrator(guard)

        with mock.patch.object(guard, "public_ip", return_value=None):
            for i in range(360):
                assert orch._tick() is True
                assert orch.consecutive_loop_errors == 0
                if i < 2:
                    assert services_running["stremio"] is True
                else:
                    assert services_running["stremio"] is False
                clock["now"] += 10.0

        assert len(heartbeats) == 360
        assert all(hb == "WATCHDOG=1" for hb in heartbeats)
        assert not cfg.vpn_lockout_file.exists()
        egress_warnings = [w for w in warnings if "tunnel egress IP via gluetun" in w]
        assert 1 <= len(egress_warnings) <= 13

        # URL 1 recovers -> starts on first SAFE tick.
        probe_recovered["ok"] = True
        with mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST):
            assert orch._tick() is True
        assert services_running["stremio"] is True
        assert list(up_stremio) in runner.calls


# ---------------------------------------------------------------------------
# AC-5 (INV-2, D6): Recovery budget counts only unhealthy ticks
# ---------------------------------------------------------------------------


def test_ac5_recovery_budget_ignores_healthy_unknown_time(tmp_path: Path) -> None:
    """AC-5 (INV-2, D6): 3600s of healthy+UNKNOWN does not exhaust the VPN recovery budget."""
    cfg = make_config(tmp_path, vpn_recovery_budget_seconds=300, vpn_restart_cadence_seconds=45)
    guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(guard)

    clock = {"now": 1000.0}
    healthy = {"value": False}
    assessment = {"value": PublicIPAssessment.UNKNOWN}

    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod.time, "time", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "gluetun_healthy", side_effect=lambda: healthy["value"]),
        mock.patch.object(
            guard, "public_ip_assessment", side_effect=lambda **_: assessment["value"]
        ),
        mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
        mock.patch.object(guard, "stop_active_services", return_value=True),
        mock.patch.object(guard, "services_confirmed_stopped", return_value=True),
        mock.patch.object(guard, "restart_gluetun", return_value=True) as restart_gluetun,
        mock.patch.object(guard, "stop_gluetun"),
    ):
        # 1 tick unhealthy -> enters outage, restarts once.
        orch.watch_once()
        assert restart_gluetun.call_count == 1
        assert orch.outage_started_at == 1000.0

        # Healthy with UNKNOWN for 3600 simulated seconds (360 ticks).
        healthy["value"] = True
        for _ in range(360):
            clock["now"] += 10.0
            orch.watch_once()
        assert not cfg.vpn_lockout_file.exists()
        assert orch.outage_started_at is not None

        # Unhealthy again for 1 tick -> NO lockout, restarts at normal cadence.
        healthy["value"] = False
        clock["now"] += 10.0
        orch.watch_once()
        assert not cfg.vpn_lockout_file.exists()
        assert restart_gluetun.call_count == 2

        # Accumulate unhealthy time until budget (300s) is reached -> exit 78.
        with pytest.raises(typer.Exit) as excinfo:
            for _ in range(40):
                clock["now"] += 10.0
                orch.watch_once()
        assert excinfo.value.exit_code == 78
        marker = json.loads(cfg.vpn_lockout_file.read_text(encoding="utf-8"))
        assert marker["reason"] == "recovery_budget_exhausted"


def test_ac5_regression_continuous_unhealthy_budget_exhausted(tmp_path: Path) -> None:
    """AC-5 regression: continuous unhealthiness for budget locks out with exit 78."""
    cfg = make_config(tmp_path, vpn_recovery_budget_seconds=300, vpn_restart_cadence_seconds=45)
    guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(guard)
    clock = {"now": 1000.0}
    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod.time, "time", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "gluetun_healthy", return_value=False),
        mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
        mock.patch.object(guard, "stop_active_services", return_value=True),
        mock.patch.object(guard, "services_confirmed_stopped", return_value=True),
        mock.patch.object(guard, "restart_gluetun", return_value=True),
        mock.patch.object(guard, "stop_gluetun"),
    ):
        orch.watch_once()
        clock["now"] = 1300.0
        with pytest.raises(typer.Exit) as excinfo:
            orch.watch_once()
    assert excinfo.value.exit_code == 78
    marker = json.loads(cfg.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "recovery_budget_exhausted"


# ---------------------------------------------------------------------------
# AC-6 (INV-4): Leak matrix through real public_ip_assessment()
# ---------------------------------------------------------------------------


def test_ac6_leak_matrix_same_family_and_ipv4_mapped_normalization(tmp_path: Path) -> None:
    """AC-6 (INV-4): same-family evidence and ::ffff: IPv4-mapped normalization."""
    home = PUBLIC_IPV4_HOST
    vpn_v4 = PUBLIC_IPV4_EGRESS

    def assess(
        *,
        egress: str | None,
        host: str | None,
        home_file_content: str | None = f"{home}\n",
        expected_vpn_ip: str | None = None,
    ) -> tuple[PublicIPAssessment, list[str]]:
        cfg = make_config(tmp_path, expected_vpn_ip=expected_vpn_ip)
        if home_file_content is not None:
            cfg.home_ip_file.write_text(home_file_content, encoding="utf-8")
        elif cfg.home_ip_file.exists():
            cfg.home_ip_file.unlink()
        guard = GluetunGuard(cfg, FakeRunner({}))
        warnings: list[str] = []
        with (
            mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
            mock.patch.object(guard, "public_ip_via_control_server", return_value=None),
            mock.patch.object(guard, "public_ip_via_gluetun", return_value=egress),
            mock.patch.object(guard, "public_ip", return_value=host),
            mock.patch.object(guard, "warn", side_effect=warnings.append),
        ):
            return guard.public_ip_assessment(force_probe=True), warnings

    # 1. ::ffff:H egress with home H and host probe failing -> UNSAFE_DEFINITIVE
    v1, _ = assess(egress=f"::ffff:{home}", host=None)
    assert v1 == PublicIPAssessment.UNSAFE_DEFINITIVE

    # 2. ::ffff:H egress with host probe answering H -> UNSAFE_DEFINITIVE
    v2, _ = assess(egress=f"::ffff:{home}", host=home, home_file_content=None)
    assert v2 == PublicIPAssessment.UNSAFE_DEFINITIVE

    # 3. IPv6 egress with IPv6 host probe failing and only IPv4 home -> UNKNOWN with reason
    v3, w3 = assess(egress=PUBLIC_IPV6_EGRESS, host=None)
    assert v3 == PublicIPAssessment.UNKNOWN
    assert any("family" in w.lower() for w in w3)

    # 4. IPv6 egress with different IPv6 host answer -> SAFE
    v4, _ = assess(egress=PUBLIC_IPV6_EGRESS, host=PUBLIC_IPV6_HOST, home_file_content=None)
    assert v4 == PublicIPAssessment.SAFE

    # 5. IPv4 egress != home with host probe failing -> SAFE (regression)
    v5, _ = assess(egress=vpn_v4, host=None)
    assert v5 == PublicIPAssessment.SAFE

    # 6. EXPECTED_VPN_IP=E with egress ::ffff:E -> not flagged (SAFE)
    v6, _ = assess(egress=f"::ffff:{vpn_v4}", host=home, expected_vpn_ip=vpn_v4)
    assert v6 == PublicIPAssessment.SAFE


# ---------------------------------------------------------------------------
# AC-7 (INV-5): Intermittent leaks lock out within 24h window
# ---------------------------------------------------------------------------


def test_ac7_intermittent_leaks_24h_window(tmp_path: Path) -> None:
    """AC-7 (INV-5): 420s intermittent, 23h apart, 25h apart, and consecutive leaks."""

    def run_sequence(steps: list[tuple[float, PublicIPAssessment]]) -> tuple[bool, int, Path]:
        sub = tmp_path / f"case-{len(steps)}-{steps[-1][0]}"
        sub.mkdir()
        cfg = make_config(sub)
        guard = GluetunGuard(cfg, FakeRunner({}))
        orch = Orchestrator(guard)
        clock = {"now": 10_000.0}
        verdict = {"val": PublicIPAssessment.SAFE}
        running = {"stremio": True}
        locked_out = False

        def do_stop(**_kwargs: object) -> bool:
            running["stremio"] = False
            return True

        def do_start(*_args: object, **_kwargs: object) -> bool:
            running["stremio"] = True
            return True

        with (
            mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
            mock.patch.object(guard, "gluetun_healthy", return_value=True),
            mock.patch.object(
                guard, "public_ip_assessment", side_effect=lambda **_: verdict["val"]
            ),
            mock.patch.object(guard, "stop_active_services", side_effect=do_stop) as stop,
            mock.patch.object(guard, "stop_gluetun"),
            mock.patch.object(
                guard, "container_running", side_effect=lambda **_: running["stremio"]
            ),
            mock.patch.object(guard, "start_services", side_effect=do_start),
        ):
            for t_offset, v in steps:
                clock["now"] = 10_000.0 + t_offset
                verdict["val"] = v
                try:
                    orch.watch_once()
                except typer.Exit as exc:
                    assert exc.exit_code == 78
                    locked_out = True
                    break
            stop_count = stop.call_count
        return locked_out, stop_count, cfg.vpn_lockout_file

    # (a) Leak every 420s with SAFE between for 3 hours -> locks out on 2nd leak.
    seq_a: list[tuple[float, PublicIPAssessment]] = []
    for t in range(0, 3 * 3600 + 1, 10):
        verdict_val = (
            PublicIPAssessment.UNSAFE_DEFINITIVE if t % 420 == 0 else PublicIPAssessment.SAFE
        )
        seq_a.append((float(t), verdict_val))
    locked_a, _, marker_a = run_sequence(seq_a)
    assert locked_a is True
    assert json.loads(marker_a.read_text(encoding="utf-8"))["reason"] == "egress_leak"

    # (b) Two leaks 23h apart with SAFE between -> locks out on 2nd leak.
    locked_b, _, marker_b = run_sequence(
        [
            (0.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
            (10.0, PublicIPAssessment.SAFE),
            (23 * 3600.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
        ]
    )
    assert locked_b is True
    assert json.loads(marker_b.read_text(encoding="utf-8"))["reason"] == "egress_leak"

    # (c) Two leaks 25h apart -> does NOT lock out, services stopped on each verdict.
    locked_c, stops_c, marker_c = run_sequence(
        [
            (0.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
            (10.0, PublicIPAssessment.SAFE),
            (25 * 3600.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
        ]
    )
    assert locked_c is False
    assert stops_c == 2
    assert not marker_c.exists()

    # (d) Two in a row -> locks out (regression).
    locked_d, _, marker_d = run_sequence(
        [
            (0.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
            (10.0, PublicIPAssessment.UNSAFE_DEFINITIVE),
        ]
    )
    assert locked_d is True
    assert json.loads(marker_d.read_text(encoding="utf-8"))["reason"] == "egress_leak"


# ---------------------------------------------------------------------------
# AC-8 (INV-6): Unknown running state
# ---------------------------------------------------------------------------


def test_ac8_unknown_running_state_stops_all_and_never_auto_starts(tmp_path: Path) -> None:
    """AC-8 (INV-6): compose ps timeout/error stops all on stop, never starts on watch."""
    cfg = make_config(tmp_path, max_auto_starts_per_hour=3)
    prefix = compose_args_prefix(tmp_path)
    status_cmd = [*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"]
    stop_cmd = [*prefix, "stop", "stremio"]
    ps_q_cmd = [*prefix, "ps", "-q", "stremio"]
    docker_stop_cmd = ["docker", "stop", "-t", "5", "stremio-cid"]

    # (a) stop_active_services with compose ps raising TimeoutExpired
    confirm_result = {"ok": False}

    class _PsTimeoutRunner(FakeRunner):
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            self.calls.append(args)
            self.envs.append(env)
            self.timeouts.append(timeout)
            self.inputs.append(input)
            if args == status_cmd:
                if confirm_result["ok"]:
                    return completed(args, "")
                raise subprocess.TimeoutExpired(args, timeout or 30)
            if args == stop_cmd:
                return completed(args)
            if args == ps_q_cmd:
                return completed(args, "stremio-cid\n")
            if args == docker_stop_cmd:
                return completed(args)
            return completed(args, "")

    runner_a = _PsTimeoutRunner({})
    guard_a = GluetunGuard(cfg, runner_a)
    assert guard_a.stop_active_services(["stremio"]) is False
    assert stop_cmd in runner_a.calls
    assert docker_stop_cmd in runner_a.calls

    # When later confirm query succeeds with empty, returns True.
    class _LaterConfirmRunner(_PsTimeoutRunner):
        def __init__(self) -> None:
            super().__init__({})
            self.status_calls = 0

        def run(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if args == status_cmd:
                self.status_calls += 1
                self.calls.append(args)
                if self.status_calls < 3:
                    raise subprocess.TimeoutExpired(args, 30)
                return completed(args, "")
            return super().run(args, **kwargs)  # type: ignore[arg-type]

    guard_a2 = GluetunGuard(cfg, _LaterConfirmRunner())
    assert guard_a2.stop_active_services(["stremio"]) is True

    # (b) Watchdog in steady state, SAFE, compose ps timing out then non-zero for 20 ticks
    ps_mode = {"mode": "timeout"}  # "timeout" | "fail" | "empty"
    up_cmd = [*prefix, "up", "-d", "--no-deps", "--build", "stremio"]
    running_cmd = [*prefix, "ps", "--status", "running", "--services", "stremio"]

    class _WatchRunner(FakeRunner):
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            self.calls.append(args)
            self.envs.append(env)
            self.timeouts.append(timeout)
            self.inputs.append(input)
            # Health checks ask for running containers, stop paths for any active one.
            if args in (status_cmd, running_cmd):
                if ps_mode["mode"] == "timeout":
                    raise subprocess.TimeoutExpired(args, timeout or 30)
                if ps_mode["mode"] == "fail":
                    return completed(args, "", "daemon error", returncode=1)
                return completed(args, "")
            return completed(args, "")

    runner_b = _WatchRunner({})
    guard_b = GluetunGuard(cfg, runner_b)
    orch = Orchestrator(guard_b)
    clock = {"now": 1000.0}
    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(guard_b, "gluetun_healthy", return_value=True),
        mock.patch.object(guard_b, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
    ):
        for i in range(20):
            ps_mode["mode"] = "timeout" if i < 10 else "fail"
            clock["now"] += 10.0
            orch.watch_once()

        assert up_cmd not in runner_b.calls
        assert len(orch.auto_start_times) == 0
        assert not cfg.vpn_lockout_file.exists()

        # (c) compose ps recovers and reports nothing running -> starts on that tick
        ps_mode["mode"] = "empty"
        clock["now"] += 10.0
        orch.watch_once()
        assert up_cmd in runner_b.calls
        assert len(orch.auto_start_times) == 1


# ---------------------------------------------------------------------------
# AC-9 (D14): Auth scan omits --tail when --since is given
# ---------------------------------------------------------------------------


def test_ac9_auth_scan_finds_auth_failed_followed_by_999_lines_without_tail(
    tmp_path: Path,
) -> None:
    """AC-9 (D14): AUTH_FAILED followed by 999 lines inside --since window is found."""
    cfg = make_config(tmp_path)
    log_body = (
        "2026-11-15T10:00:00Z ERROR [openvpn] AUTH: Received control message: AUTH_FAILED\n"
        + "".join(f"2026-11-15T10:01:{i % 60:02d}Z INFO line {i}\n" for i in range(999))
    )
    logs_cmd = ["docker", "logs", "--since", "1700000000", "gluetun-cid"]
    runner = FakeRunner(
        {
            tuple(compose_command(tmp_path, "ps", "-q", "gluetun")): completed([], "gluetun-cid\n"),
            tuple(logs_cmd): completed(logs_cmd, stdout=log_body),
        }
    )
    guard = GluetunGuard(cfg, runner)
    evidence = guard.gluetun_auth_evidence(lines=200, since_epoch=1700000000.0)
    assert evidence is not None and "AUTH_FAILED" in evidence
    log_calls = [c for c in runner.calls if c[:2] == ["docker", "logs"]]
    assert log_calls == [logs_cmd]
    assert "--tail" not in log_calls[0]


# ---------------------------------------------------------------------------
# AC-10 (INV-7): Bounded teardown & TimeoutStartSec margin
# ---------------------------------------------------------------------------


def test_ac10_bounded_teardown_and_failsafe_unit_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-10 (INV-7): fail_safe() and stop have finite timeouts and fit TimeoutStartSec."""
    # Check both single-service and worst-case 5-service stacks.
    (tmp_path / ".env").write_text(
        "STREMIO_ENABLED=1\nCOMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n"
        "COMET_DEFAULT_DEBRID_APIKEY=key\n",
        encoding="utf-8",
    )
    (tmp_path / ".stremio").mkdir(exist_ok=True)
    (tmp_path / ".stremio" / "docker-compose.bindings.yml").touch()

    unit_text = supervisor.render_failsafe_unit()
    match = re.search(r"^TimeoutStartSec=(\d+)$", unit_text, re.MULTILINE)
    assert match is not None, unit_text
    timeout_start_sec = int(match.group(1))

    def run_all_timeouts(action_fn, *, teardown: bool, deployed: bool) -> float:
        sim_clock = {"now": 0.0}

        class _ClockTimeoutRunner:
            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                assert timeout is not None, f"Unbounded Docker call (timeout=None): {args}"
                sim_clock["now"] += timeout
                raise subprocess.TimeoutExpired(args, timeout)

        monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: tmp_path)
        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: _ClockTimeoutRunner())

        with pytest.raises((RuntimeError, typer.Exit)):
            orchestrator_mod._run_command(
                action_fn, teardown=teardown, deployed=deployed, lock=None
            )
        return sim_clock["now"]

    # 1. Model (1): every call raises TimeoutExpired after advancing clock by timeout
    failsafe_timeout_case = run_all_timeouts(lambda o: o.fail_safe(), teardown=True, deployed=True)
    assert failsafe_timeout_case > 0
    assert failsafe_timeout_case < timeout_start_sec * (2 / 3), (
        f"model1={failsafe_timeout_case}s not < 2/3 of TimeoutStartSec={timeout_start_sec}s"
    )

    # 2. Model (2): slow success — every call advances clock by full timeout then answers
    model2_root = tmp_path / "model2"
    model2_root.mkdir()
    (model2_root / ".env").write_text(
        "STREMIO_ENABLED=1\nCOMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=1\n"
        "COMET_DEFAULT_DEBRID_APIKEY=key\n",
        encoding="utf-8",
    )
    (model2_root / ".stremio").mkdir(exist_ok=True)
    (model2_root / ".stremio" / "docker-compose.bindings.yml").touch()
    all_five = ("stremio", "comet-gateway", "comet", "stremthru", "comet-postgres")
    slow_clock = {"now": 0.0, "calls": 0}

    class _SlowSuccessRunner:
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            assert timeout is not None, f"Unbounded Docker call (timeout=None): {args}"
            slow_clock["now"] += timeout
            slow_clock["calls"] += 1
            if args == ["docker", "info", "--format", "{{.ID}}"]:
                return completed(args, "daemon-a\n")
            if args[:2] == ["docker", "compose"] and "config" in args and "--services" in args:
                return completed(args, "\n".join(["gluetun", *all_five]) + "\n")
            if args[:2] == ["docker", "compose"] and "--status" in args and "running" in args:
                return completed(args, "\n".join(all_five) + "\n")
            if args[:2] == ["docker", "compose"] and "stop" in args:
                return completed(args, "", "compose stop failed\n", returncode=1)
            if args[:2] == ["docker", "compose"] and "-q" in args:
                svc = args[-1]
                return completed(args, f"{svc}-cid\n")
            if args[:2] == ["docker", "stop"]:
                return completed(args)
            return completed(args)

    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: model2_root)
    monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: _SlowSuccessRunner())
    with pytest.raises(typer.Exit) as excinfo:
        orchestrator_mod._run_command(
            lambda o: o.fail_safe(), teardown=True, deployed=True, lock=None
        )
    assert excinfo.value.exit_code != 0
    slow_success_total = slow_clock["now"] + orchestrator_mod.TEARDOWN_LOCK_WAIT_SECONDS
    assert slow_success_total < timeout_start_sec * (2 / 3), (
        f"model2={slow_success_total}s not < 2/3 of TimeoutStartSec={timeout_start_sec}s"
    )
    print(
        f"AC-10 worst-case fail_safe() simulated times: "
        f"model1(all-timeout)={failsafe_timeout_case:.1f}s, "
        f"model2(slow-success+60s_lock)={slow_success_total:.1f}s "
        f"({slow_clock['calls']} calls, TimeoutStartSec={timeout_start_sec}s, "
        f"2/3 limit={timeout_start_sec * 2 / 3:.1f}s)"
    )

    # 3. stop action with all Docker calls timing out
    monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: tmp_path)

    def _stop_action(o: Orchestrator) -> None:
        o.guard.require_commands()
        if not o.guard.stop_active_services():
            raise RuntimeError("Protected services could not be confirmed stopped.")

    stop_worst_case = run_all_timeouts(_stop_action, teardown=True, deployed=False)
    assert stop_worst_case == float(DOCKER_QUERY_TIMEOUT_SECONDS)

    # Verify teardown guard uses TEARDOWN_MUTATION_TIMEOUT_SECONDS for compose stop
    seen_timeouts: list[float | None] = []

    class _RecordRunner(FakeRunner):
        def run(
            self,
            args: list[str],
            *,
            check: bool = False,
            capture: bool = True,
            timeout: float | None = None,
            env: dict[str, str] | None = None,
            input: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
            seen_timeouts.append(timeout)
            return super().run(
                args, check=check, capture=capture, timeout=timeout, env=env, input=input
            )

    prefix = compose_args_prefix(tmp_path)
    rec = _RecordRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
            (*prefix, "config", "--services"): completed([], "stremio\n"),
            (*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                completed([], "stremio\n"),
                completed([], ""),
            ],
            (*prefix, "stop", "stremio"): completed([]),
        }
    )
    teardown_guard = GluetunGuard(make_config(tmp_path), rec, teardown=True)
    teardown_guard.require_commands()
    assert teardown_guard.stop_active_services() is True
    stop_idx = rec.calls.index([*prefix, "stop", "stremio"])
    assert seen_timeouts[stop_idx] == TEARDOWN_MUTATION_TIMEOUT_SECONDS
    assert all(t is not None for t in seen_timeouts)


# ---------------------------------------------------------------------------
# AC-11 (INV-8): Marker cannot be written, CLI start/restart/status
# ---------------------------------------------------------------------------


def test_ac11_unwritable_state_dir_and_cli_failsafe_gating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-11 (INV-8): 0500 .stremio/ fail-safe exits non-zero; CLI refuses failed/activating."""
    # (a) .stremio/ mode 0500 -> stop runs, fail_safe() raises, _run_command exits non-zero
    state_dir = tmp_path / ".stremio"
    state_dir.mkdir(exist_ok=True)
    (tmp_path / ".env").write_text(
        "STREMIO_ENABLED=1\nSTREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
        encoding="utf-8",
    )
    (state_dir / "docker-compose.bindings.yml").touch()
    (state_dir / "daemon-id").write_text("daemon-a\n", encoding="utf-8")
    prefix = compose_args_prefix(tmp_path)
    runner_a = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
            (*prefix, "config", "--services"): completed([], "stremio\n"),
            (*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"): [
                completed([], "stremio\n"),
                completed([], ""),
            ],
            (*prefix, "stop", "stremio"): completed([]),
        }
    )
    state_dir.chmod(0o500)
    try:
        # Simulate a non-owner / read-only 0500 state dir where fchmod cannot
        # restore write bits, matching root-owned .stremio/ on a hardened host.
        monkeypatch.setattr(orchestrator_mod, "_deployment_root", lambda: tmp_path)
        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda: runner_a)
        with (
            mock.patch.object(
                env_mod.os,
                "fchmod",
                side_effect=PermissionError("read-only state dir"),
            ),
            pytest.raises(typer.Exit) as excinfo,
        ):
            orchestrator_mod._run_command(
                lambda o: o.fail_safe(), teardown=True, deployed=True, lock="preferred"
            )
        assert excinfo.value.exit_code != 0
        assert [*prefix, "stop", "stremio"] in runner_a.calls
    finally:
        state_dir.chmod(0o700)

    # (b)-(d) CLI start(), restart(), status_lines() with fake systemctl
    fs_state = {"active": "failed", "sub": "failed", "result": "exit-code"}
    systemctl_calls: list[tuple[str, ...]] = []

    def fake_systemctl(*args: str) -> subprocess.CompletedProcess[str]:
        systemctl_calls.append(args)
        if args == ("show", "--property=Version", "--value"):
            return subprocess.CompletedProcess(args, 0, "255\n", "")
        if len(args) > 1 and args[0] == "show" and args[1] == supervisor.FAILSAFE_UNIT:
            return subprocess.CompletedProcess(
                args,
                0,
                f"LoadState=loaded\nActiveState={fs_state['active']}\n"
                f"SubState={fs_state['sub']}\nMainPID=0\nNRestarts=0\n"
                f"Result={fs_state['result']}\nUnitFileState=static\n"
                f"FragmentPath={supervisor.unit_dir() / supervisor.FAILSAFE_UNIT}\n",
                "",
            )
        if len(args) > 1 and args[0] == "show":
            unit = args[1]
            return subprocess.CompletedProcess(
                args,
                0,
                f"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n"
                f"NRestarts=0\nResult=success\nUnitFileState=disabled\n"
                f"FragmentPath={supervisor.unit_dir() / unit}\n",
                "",
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    linger_dir = tmp_path / "linger"
    linger_dir.mkdir()
    monkeypatch.setattr(supervisor, "_systemctl", fake_systemctl)
    monkeypatch.setattr(supervisor.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(supervisor.shutil, "which", lambda name: f"/usr/bin/{name}")
    orig_exists = Path.exists

    def fake_exists(p: Path) -> bool:
        if str(p).startswith("/var/lib/systemd/linger/"):
            return True
        return orig_exists(p)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(general_cmd_mod, "_warn_for_optional_stremio_settings", lambda: None)

    compose_calls: list[tuple[object, ...]] = []

    def fake_run_guard(*args: str, **kwargs: object) -> None:
        compose_calls.append(args)

    monkeypatch.setattr(general_cmd_mod, "run_guard", fake_run_guard)
    monkeypatch.setattr(supervisor, "start_watchdog", lambda *a, **k: None)

    # (b) failed -> exit 78 before any docker compose call, names unit and recovery
    errors: list[str] = []
    with (
        mock.patch.object(supervisor.logger, "error", side_effect=errors.append),
        pytest.raises(typer.Exit) as excinfo,
    ):
        general_cmd_mod.start()
    assert excinfo.value.exit_code == 78
    assert compose_calls == []
    assert any(supervisor.FAILSAFE_UNIT in e and "restart" in e for e in errors)

    # (b) activating -> exit 78 before any docker compose call
    fs_state.update({"active": "activating", "sub": "auto-restart", "result": "exit-code"})
    errors.clear()
    with (
        mock.patch.object(supervisor.logger, "error", side_effect=errors.append),
        pytest.raises(typer.Exit) as excinfo,
    ):
        general_cmd_mod.start()
    assert excinfo.value.exit_code == 78
    assert compose_calls == []
    assert any(supervisor.FAILSAFE_UNIT in e and "restart" in e for e in errors)

    # (c) restart() with fail-safe failed -> proceeds
    fs_state.update({"active": "failed", "sub": "failed", "result": "exit-code"})
    monkeypatch.setattr(supervisor, "stop_watchdog", lambda: True)
    general_cmd_mod.restart()
    assert compose_calls == [("reset",)]

    # (b) inactive/success -> start() proceeds
    compose_calls.clear()
    fs_state.update({"active": "inactive", "sub": "dead", "result": "success"})
    general_cmd_mod.start()
    assert compose_calls == [("start",)]

    # (d) status_lines prints fail-safe line with state and last result
    fs_state.update({"active": "failed", "sub": "failed", "result": "exit-code"})
    lines = supervisor.status_lines()
    assert any(
        supervisor.FAILSAFE_UNIT in line
        and "failed/failed" in line
        and "last result=exit-code" in line
        for line in lines
    )


# ---------------------------------------------------------------------------
# AC-12 (INV-8, mock-only): atomic_write_text fsyncs parent directory
# ---------------------------------------------------------------------------


def test_ac12_atomic_write_text_fsyncs_parent_directory(tmp_path: Path) -> None:
    """AC-12 (INV-8, mock-only): after rename, parent dir is opened and fsynced."""
    target = tmp_path / ".stremio" / "vpn-lockout"
    events: list[str] = []
    real_replace = Path.replace
    real_open = os.open
    real_fsync = os.fsync
    real_close = os.close

    def tracked_replace(self: Path, dst: Path) -> Path:
        events.append("replace")
        return real_replace(self, dst)

    def tracked_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if Path(str(path)) == target.parent:
            events.append(f"open_dir:{fd}")
        return fd

    def tracked_fsync(fd: int) -> None:
        events.append(f"fsync:{fd}")
        real_fsync(fd)

    def tracked_close(fd: int) -> None:
        events.append(f"close:{fd}")
        real_close(fd)

    with (
        mock.patch.object(Path, "replace", tracked_replace),
        mock.patch.object(env_mod.os, "open", side_effect=tracked_open),
        mock.patch.object(env_mod.os, "fsync", side_effect=tracked_fsync),
        mock.patch.object(env_mod.os, "close", side_effect=tracked_close),
    ):
        env_mod.atomic_write_text(target, '{"ok": true}\n', mode=0o600)

    replace_idx = events.index("replace")
    dir_events = events[replace_idx + 1 :]
    open_ev = next(e for e in dir_events if e.startswith("open_dir:"))
    dir_fd = open_ev.split(":", 1)[1]
    assert f"fsync:{dir_fd}" in dir_events
    assert dir_events.index(f"fsync:{dir_fd}") < dir_events.index(f"close:{dir_fd}")


# ---------------------------------------------------------------------------
# AC-13 (INV-9): Start or restart without SAFE stops running services
# ---------------------------------------------------------------------------


def test_ac13_start_and_restart_without_safe_stops_services_and_confirms(tmp_path: Path) -> None:
    """AC-13 (INV-9): start/reset on preflight=False stops all protected services and confirms."""
    (tmp_path / ".env").write_text(
        "STREMIO_ENABLED=1\nSTREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
        encoding="utf-8",
    )
    prefix = compose_args_prefix(tmp_path)
    ps_stremio_all = (*prefix, "ps", "-a", "-q", "stremio")
    cfg_services = (*prefix, "config", "--services")
    ps_running = (*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio")
    stop_stremio = (*prefix, "stop", "stremio")
    down_cmd = (*prefix, "down", "--remove-orphans", "--timeout", "10")

    for _cause in ("unsafe", "unknown", "unavailable"):
        running = {"stremio": True}
        events: list[str] = []

        class _StartFailRunner(FakeRunner):
            def __init__(self, state: dict[str, bool]) -> None:
                super().__init__({})
                self._state = state

            def run(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.calls.append(args)
                if args == list(ps_stremio_all):
                    return completed(args, "stremio-cid\n")
                if args == list(cfg_services):
                    return completed(args, "use-stremio-start-instead\ngluetun\nstremio\n")
                if args == list(ps_running):
                    return completed(args, "stremio\n" if self._state["stremio"] else "")
                if args == list(stop_stremio):
                    self._state["stremio"] = False
                    return completed(args)
                return completed(args)

        guard = GluetunGuard(make_config(tmp_path), _StartFailRunner(running))
        orig_log, orig_warn, orig_success = guard.log, guard.warn, guard.success

        def _rec(prefix_tag: str, orig, msg: str, _events: list[str] = events) -> None:
            _events.append(f"{prefix_tag}:{msg}")
            orig(msg)

        guard.log = lambda m, o=orig_log: _rec("INFO", o, m)  # type: ignore[method-assign]
        guard.warn = lambda m, o=orig_warn: _rec("WARN", o, m)  # type: ignore[method-assign]
        guard.success = lambda m, o=orig_success: _rec("OK", o, m)  # type: ignore[method-assign]
        orch = Orchestrator(guard)

        with mock.patch.object(guard, "preflight", return_value=False):
            orch.start_active_services()

        assert running["stremio"] is False
        assert list(stop_stremio) in guard.runner.calls  # type: ignore[attr-defined]
        assert "OK:Active services are stopped." in events
        confirm_idx = events.index("OK:Active services are stopped.")
        for earlier in events[:confirm_idx]:
            assert "remain stopped" not in earlier.lower()
            assert "are stopped" not in earlier.lower()

    # Also verify real preflight() warnings do not say "remain stopped"
    guard_real = GluetunGuard(make_config(tmp_path), FakeRunner({}))
    preflight_warnings: list[str] = []
    with (
        mock.patch.object(guard_real, "require_commands"),
        mock.patch.object(guard_real, "check_vpn_lockout"),
        mock.patch.object(guard_real, "check_bind_addresses"),
        mock.patch.object(guard_real, "write_compose_override"),
        mock.patch.object(guard_real, "refresh_gluetun_image"),
        mock.patch.object(guard_real, "compose_fresh"),
        mock.patch.object(
            guard_real,
            "wait_for_gluetun_healthy",
            side_effect=guard_mod.GluetunUnavailableError("down"),
        ),
        mock.patch.object(guard_real, "warn", side_effect=preflight_warnings.append),
    ):
        assert guard_real.preflight(defer_vpn_recovery=True) is False
    with (
        mock.patch.object(guard_real, "require_commands"),
        mock.patch.object(guard_real, "check_vpn_lockout"),
        mock.patch.object(guard_real, "check_bind_addresses"),
        mock.patch.object(guard_real, "write_compose_override"),
        mock.patch.object(guard_real, "refresh_gluetun_image"),
        mock.patch.object(guard_real, "compose_fresh"),
        mock.patch.object(guard_real, "wait_for_gluetun_healthy"),
        mock.patch.object(guard_real, "public_ip_safe", return_value=False),
        mock.patch.object(guard_real, "warn", side_effect=preflight_warnings.append),
    ):
        assert guard_real.preflight(defer_vpn_recovery=True) is False
    assert len(preflight_warnings) == 2
    assert all("remain stopped" not in w.lower() for w in preflight_warnings)

    # setup_active_services(reset=True) with preflight() False
    runner_reset = FakeRunner(
        {
            down_cmd: completed(list(down_cmd)),
            cfg_services: completed(list(cfg_services), "gluetun\nstremio\n"),
            ps_running: [completed(list(ps_running), "stremio\n"), completed(list(ps_running), "")],
            stop_stremio: completed(list(stop_stremio)),
        }
    )
    guard_reset = GluetunGuard(make_config(tmp_path), runner_reset)
    with (
        mock.patch.object(guard_reset, "preflight", return_value=False),
        mock.patch.object(orchestrator_mod.time, "sleep"),
    ):
        Orchestrator(guard_reset).setup_active_services(reset=True)
    assert list(stop_stremio) in runner_reset.calls

    # Unconfirmed stop raises RuntimeError -> exit 1 in _run_command
    guard_fail = GluetunGuard(make_config(tmp_path), FakeRunner({}))
    orch_fail = Orchestrator(guard_fail)
    with (
        mock.patch.object(guard_fail, "compose_instance_exists", return_value=True),
        mock.patch.object(guard_fail, "preflight", return_value=False),
        mock.patch.object(guard_fail, "stop_active_services", return_value=False),
        pytest.raises(RuntimeError, match="could not be confirmed stopped"),
    ):
        orch_fail.start_active_services()


# ---------------------------------------------------------------------------
# AC-14 (INV-10): Marker forms block starts and are left untouched by fail_safe
# ---------------------------------------------------------------------------


def test_ac14_all_marker_forms_block_and_survive_failsafe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-14 (INV-10): dangling/valid symlinks, dir, 0-byte, 0000 file, 0600 parent."""
    monkeypatch.setattr(supervisor, "STATE_DIR", tmp_path / ".stremio")
    monkeypatch.setattr(supervisor, "watchdog_running", lambda: True)

    # Regression: no marker passes check_vpn_lockout
    cfg = make_config(tmp_path)
    guard = GluetunGuard(cfg, FakeRunner({}))
    guard.check_vpn_lockout(allow_recovery=False)

    marker = cfg.vpn_lockout_file
    target_missing = tmp_path / "missing-target"
    target_valid = tmp_path / "valid-target"
    target_valid.write_text('{"reason": "auth_rejected"}\n', encoding="utf-8")

    forms = (
        "dangling_symlink",
        "valid_symlink",
        "directory",
        "zero_byte",
        "mode_0000",
        "parent_0600",
    )

    for form in forms:
        # Clean up any previous form
        marker.parent.chmod(0o700)
        if os.path.lexists(marker):
            if marker.is_dir() and not marker.is_symlink():
                marker.rmdir()
            else:
                marker.chmod(0o600) if not marker.is_symlink() else None
                marker.unlink()

        if form == "dangling_symlink":
            marker.symlink_to(target_missing)
        elif form == "valid_symlink":
            marker.symlink_to(target_valid)
        elif form == "directory":
            marker.mkdir()
        elif form == "zero_byte":
            marker.write_bytes(b"")
        elif form == "mode_0000":
            marker.write_bytes(b"locked")
            marker.chmod(0o000)
        elif form == "parent_0600":
            marker.write_bytes(b"secret")
            marker.parent.chmod(0o600)

        try:
            with pytest.raises(LockoutActiveError):
                guard.check_vpn_lockout(allow_recovery=False)

            with pytest.raises(typer.Exit):
                supervisor.require_supervised_stack()

            orch = Orchestrator(guard)
            with (
                mock.patch.object(guard, "require_commands"),
                mock.patch.object(guard, "stop_active_services", return_value=True),
            ):
                if form == "valid_symlink":
                    orch.fail_safe()
                else:
                    # Unparseable/unreadable marker still keeps marker intact and raises.
                    with pytest.raises(RuntimeError):
                        orch.fail_safe()

            # Verify fail_safe left each form untouched
            if form == "dangling_symlink":
                assert marker.is_symlink()
                assert not target_missing.exists()
            elif form == "valid_symlink":
                assert marker.is_symlink()
                assert target_valid.read_text(encoding="utf-8") == '{"reason": "auth_rejected"}\n'
            elif form == "directory":
                assert marker.is_dir() and not marker.is_symlink()
            elif form == "zero_byte":
                assert marker.read_bytes() == b""
            elif form == "mode_0000":
                marker.chmod(0o400)
                assert marker.read_bytes() == b"locked"
            elif form == "parent_0600":
                marker.parent.chmod(0o700)
                assert marker.read_bytes() == b"secret"
        finally:
            marker.parent.chmod(0o700)
            if os.path.lexists(marker):
                if marker.is_dir() and not marker.is_symlink():
                    marker.rmdir()
                else:
                    if not marker.is_symlink():
                        marker.chmod(0o600)
                    marker.unlink()


# ---------------------------------------------------------------------------
# AC-15 (INV-10): Running watchdog detects a new marker on next tick
# ---------------------------------------------------------------------------


def test_ac15_running_watchdog_stops_and_exits_78_on_new_marker(tmp_path: Path) -> None:
    """AC-15 (INV-10): marker written between ticks stops services & gluetun and exits 78."""
    cfg = make_config(tmp_path)
    guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(guard)

    with (
        mock.patch.object(orchestrator_mod, "notify"),
        mock.patch.object(guard, "gluetun_healthy", return_value=True),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.SAFE),
        mock.patch.object(guard, "container_running", return_value=True),
    ):
        assert orch._tick() is True

    marker_bytes = b'{"reason": "operator_test"}\n'
    cfg.vpn_lockout_file.write_bytes(marker_bytes)

    with (
        mock.patch.object(orchestrator_mod, "notify"),
        mock.patch.object(guard, "start_services") as start_mock,
        mock.patch.object(guard, "stop_active_services", return_value=True) as stop_services,
        mock.patch.object(guard, "stop_gluetun") as stop_gluetun,
        pytest.raises(typer.Exit) as excinfo,
    ):
        orch._tick()

    assert excinfo.value.exit_code == 78
    start_mock.assert_not_called()
    stop_services.assert_called_once_with()
    stop_gluetun.assert_called_once_with()
    assert cfg.vpn_lockout_file.read_bytes() == marker_bytes


# ---------------------------------------------------------------------------
# AC-16 (INV-11): Fail-safe daemon check failure still attempts stop
# ---------------------------------------------------------------------------


def test_ac16_failsafe_still_attempts_stop_when_daemon_check_fails(tmp_path: Path) -> None:
    """AC-16 (INV-11): unreadable daemon-id or daemon mismatch still attempts compose stop."""
    (tmp_path / ".env").write_text(
        "STREMIO_ENABLED=1\nSTREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
        encoding="utf-8",
    )
    prefix = compose_args_prefix(tmp_path)
    cfg_cmd = (*prefix, "config", "--services")
    ps_running = (*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio")
    stop_cmd = (*prefix, "stop", "stremio")
    daemon_record = tmp_path / ".stremio" / "daemon-id"
    daemon_record.parent.mkdir(parents=True, exist_ok=True)

    # Case 1: .stremio/daemon-id unreadable (mode 0000)
    daemon_record.write_text("daemon-a\n", encoding="utf-8")
    daemon_record.chmod(0o000)
    try:
        runner1 = FakeRunner(
            {
                ("docker", "compose", "version"): completed([]),
                ("docker", "ps", "--format", "{{.ID}}"): completed([]),
                ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-a\n"),
                cfg_cmd: completed(list(cfg_cmd), "gluetun\nstremio\n"),
                ps_running: [
                    completed(list(ps_running), "stremio\n"),
                    completed(list(ps_running), ""),
                ],
                stop_cmd: completed(list(stop_cmd)),
            }
        )
        guard1 = GluetunGuard(make_config(tmp_path), runner1, teardown=True)
        with pytest.raises(PermissionError):
            Orchestrator(guard1).fail_safe()
        assert list(stop_cmd) in runner1.calls
    finally:
        daemon_record.chmod(0o600)

    # Case 2: daemon ID mismatch
    daemon_record.write_text("daemon-a\n", encoding="utf-8")
    runner2 = FakeRunner(
        {
            ("docker", "compose", "version"): completed([]),
            ("docker", "ps", "--format", "{{.ID}}"): completed([]),
            ("docker", "info", "--format", "{{.ID}}"): completed([], "daemon-b\n"),
            cfg_cmd: completed(list(cfg_cmd), "gluetun\nstremio\n"),
            ps_running: [completed(list(ps_running), "stremio\n"), completed(list(ps_running), "")],
            stop_cmd: completed(list(stop_cmd)),
        }
    )
    guard2 = GluetunGuard(make_config(tmp_path), runner2, teardown=True)
    with pytest.raises(RuntimeError, match="different Docker daemon"):
        Orchestrator(guard2).fail_safe()
    assert list(stop_cmd) in runner2.calls


# ---------------------------------------------------------------------------
# AC-19 (INV-3, INV-1): Host probe cancels socket & leaks no threads/fds
# ---------------------------------------------------------------------------


def _create_localhost_cert(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a short-lived self-signed cert valid for localhost and 127.0.0.1."""
    cert_file = tmp_path / "localhost-cert.pem"
    key_file = tmp_path / "localhost-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return cert_file, key_file


def _spawn_trickle_server(
    mode: str,
    *,
    cert_file: Path | None = None,
    key_file: Path | None = None,
    trickle_interval: float = 0.2,
) -> tuple[str, subprocess.Popen[str]]:
    """Run an HTTP or HTTPS stall/trickle server in a child process."""
    server_code = """
import socket, ssl, sys, threading, time

mode = sys.argv[1]
trickle_interval = float(sys.argv[2])
cert_file = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
key_file = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None

tls_ctx = None
if mode in {"https_ok", "https_status_line", "https_headers", "https_body"}:
    assert cert_file and key_file
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(64)
print(srv.getsockname()[1], flush=True)


def handle(raw_conn):
    conn = raw_conn
    try:
        if tls_ctx is not None:
            conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
        if mode == "https_tls_handshake":
            conn.recv(4096)
            conn.sendall(b"\\x16\\x03\\x03\\x40\\x00")
            while True:
                time.sleep(trickle_interval)
                conn.sendall(b"\\x00")
        elif mode == "http_stall":
            conn.recv(1024)
            time.sleep(120)
        elif mode == "https_ok":
            buf = b""
            while b"\\r\\n\\r\\n" not in buf:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                buf += chunk
            body = b"1.1.1.1"
            hdrs = (
                f"HTTP/1.1 200 OK\\r\\nContent-Length: {len(body)}\\r\\n"
                "Connection: close\\r\\n\\r\\n"
            )
            conn.sendall(hdrs.encode() + body)
        else:
            buf = b""
            while b"\\r\\n\\r\\n" not in buf:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if mode.startswith("http_") and b"\\r\\n" in buf:
                    break
            if mode.endswith("_headers"):
                conn.sendall(b"HTTP/1.1 200 OK\\r\\n")
                byte = b"X"
            elif mode.endswith("_body"):
                conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\n")
                byte = b"1"
            else:
                byte = b"H"
            while True:
                time.sleep(trickle_interval)
                conn.sendall(byte)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
"""
    cmd = [
        sys.executable,
        "-c",
        server_code,
        mode,
        str(trickle_interval),
        str(cert_file or ""),
        str(key_file or ""),
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    port = int(proc.stdout.readline().strip())
    scheme = "https" if mode.startswith("https_") else "http"
    return f"{scheme}://127.0.0.1:{port}/", proc


def test_ac19_host_probe_leaves_no_threads_or_fds_across_all_trickle_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-19 (INV-3, INV-1): HTTP & HTTPS stall/trickle phases leak zero threads or fds."""
    cert_file, key_file = _create_localhost_cert(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_file))

    ok_url, ok_proc = _spawn_trickle_server("https_ok", cert_file=cert_file, key_file=key_file)
    try:
        ok_guard = GluetunGuard(
            make_config(tmp_path, public_ip_timeout_seconds=1, ip_check_urls=(ok_url,)),
            FakeRunner({}),
        )
        assert ok_guard.public_ip() == PUBLIC_IPV4_HOST
    finally:
        ok_proc.kill()
        ok_proc.wait(timeout=5)

    modes = (
        "http_stall",
        "http_status_line",
        "http_headers",
        "http_body",
        "https_tls_handshake",
        "https_status_line",
        "https_headers",
        "https_body",
    )
    for mode in modes:
        url, proc = _spawn_trickle_server(
            mode,
            cert_file=cert_file,
            key_file=key_file,
            trickle_interval=0.2,
        )
        try:
            guard = GluetunGuard(
                make_config(tmp_path, public_ip_timeout_seconds=1, ip_check_urls=(url,)),
                FakeRunner({}),
            )
            baseline_fds = len(os.listdir("/proc/self/fd"))
            for i in range(3):
                t0 = time.monotonic()
                assert guard.public_ip() is None
                elapsed = time.monotonic() - t0
                assert 0.8 <= elapsed < 2.0, (
                    f"{mode} call {i} elapsed {elapsed:.2f}s outside [0.8s, 2.0s)"
                )

            settle_deadline = time.monotonic() + 1.0
            time.sleep(0.25)
            alive_probes: list[threading.Thread] = []
            after_fds = baseline_fds
            while True:
                alive_probes = [
                    t
                    for t in threading.enumerate()
                    if t.name == "stremioguard-ip-probe" and t.is_alive()
                ]
                after_fds = len(os.listdir("/proc/self/fd"))
                if (not alive_probes and after_fds <= baseline_fds) or (
                    time.monotonic() >= settle_deadline
                ):
                    break
                time.sleep(0.05)

            assert alive_probes == [], f"{mode} leaked probe threads: {alive_probes}"
            assert after_fds <= baseline_fds, (
                f"{mode} leaked fds: baseline={baseline_fds}, after={after_fds}"
            )
        finally:
            proc.kill()
            proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# AC-20 (D6, R1-2): Recovery budget locks out under alternating flapping
# ---------------------------------------------------------------------------


def test_ac20_recovery_budget_exhausts_under_alternating_healthy_unhealthy_ticks(
    tmp_path: Path,
) -> None:
    """AC-20 (D6): alternating unhealthy/healthy+UNKNOWN ticks lock out by 32nd unhealthy tick."""
    cfg = make_config(
        tmp_path,
        watch_interval_seconds=10,
        vpn_recovery_budget_seconds=300,
        vpn_restart_cadence_seconds=45,
    )
    guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(guard)
    clock = {"now": 1000.0}
    healthy_seq = {"tick": 0}
    unhealthy_ticks = 0

    def is_healthy() -> bool:
        # Tick 0 (unhealthy #1), Tick 1 (healthy), Tick 2 (unhealthy #2), ...
        val = (healthy_seq["tick"] % 2) == 1
        healthy_seq["tick"] += 1
        return val

    with (
        mock.patch.object(orchestrator_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(orchestrator_mod.time, "time", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "gluetun_healthy", side_effect=is_healthy),
        mock.patch.object(guard, "public_ip_assessment", return_value=PublicIPAssessment.UNKNOWN),
        mock.patch.object(guard, "gluetun_auth_evidence", return_value=None),
        mock.patch.object(guard, "stop_active_services", return_value=True),
        mock.patch.object(guard, "services_confirmed_stopped", return_value=True),
        mock.patch.object(guard, "restart_gluetun", return_value=True),
        mock.patch.object(guard, "stop_gluetun"),
    ):
        locked_out = False
        for tick in range(80):
            if tick % 2 == 0:
                unhealthy_ticks += 1
            try:
                orch.watch_once()
            except typer.Exit as exc:
                assert exc.exit_code == 78
                locked_out = True
                break
            clock["now"] += 10.0

    assert locked_out is True
    assert unhealthy_ticks <= 32, f"Took {unhealthy_ticks} unhealthy ticks (> 32)"
    marker = json.loads(cfg.vpn_lockout_file.read_text(encoding="utf-8"))
    assert marker["reason"] == "recovery_budget_exhausted"


# ---------------------------------------------------------------------------
# AC-21 (INV-1, R1-4): Control-server probe faults never escape assessment
# ---------------------------------------------------------------------------


def test_ac21_control_server_probe_faults_do_not_escape_assessment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-21 (INV-1): TimeoutExpired, OSError, non-UTF-8 on control route leave egress intact."""
    cfg = make_config(tmp_path)
    prefix = compose_args_prefix(tmp_path)
    ps_gluetun = (*prefix, "ps", "-q", "gluetun")
    control_cmd = [
        "docker",
        "exec",
        "gluetun-cid",
        "timeout",
        "-s",
        "KILL",
        "1",
        "wget",
        "--tries=1",
        "--timeout=1",
        "-O-",
        "http://127.0.0.1:18080/v1/publicip/ip",
    ]
    egress_cmd = [
        "docker",
        "exec",
        "gluetun-cid",
        "timeout",
        "-s",
        "KILL",
        "1",
        "wget",
        "--tries=1",
        "--timeout=1",
        *(f"--header={k}: {v}" for k, v in guard_mod.PROBE_REQUEST_HEADERS),
        "-qO-",
        "https://example.test/ip",
    ]

    for fault in (
        subprocess.TimeoutExpired(control_cmd, 3),
        OSError("exec pipe broken"),
    ):

        class _FaultRunner(FakeRunner):
            def __init__(self, exc: BaseException) -> None:
                super().__init__(
                    {
                        ps_gluetun: completed(list(ps_gluetun), "gluetun-cid\n"),
                        ("docker", "exec", "gluetun-cid", "iptables", "-S", "OUTPUT"): completed(
                            [], f"-P OUTPUT DROP\n{guard_mod.DNS_BLOCK_RULE}\n"
                        ),
                    }
                )
                self._exc = exc

            def run(
                self,
                args: list[str],
                *,
                check: bool = False,
                capture: bool = True,
                timeout: float | None = None,
                env: dict[str, str] | None = None,
                input: str | None = None,
            ) -> subprocess.CompletedProcess[str]:
                if args == control_cmd:
                    self.calls.append(args)
                    raise self._exc
                if args == egress_cmd:
                    self.calls.append(args)
                    return completed(args, f"{PUBLIC_IPV4_EGRESS}\n")
                return super().run(
                    args, check=check, capture=capture, timeout=timeout, env=env, input=input
                )

        runner = _FaultRunner(fault)
        guard = GluetunGuard(cfg, runner)
        with mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST):
            assert guard.public_ip_assessment(force_probe=True) == PublicIPAssessment.SAFE
        assert control_cmd in runner.calls
        assert egress_cmd in runner.calls

    # Real SubprocessRunner with fake `docker` on PATH emitting undecodable bytes on control route
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_docker = bin_dir / "docker"
    fake_docker.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if 'ps' in args and '-q' in args:\n"
        "    sys.stdout.buffer.write(b'gluetun-cid\\n')\n"
        "    sys.exit(0)\n"
        "if 'exec' in args and any('18080' in a for a in args):\n"
        "    sys.stdout.buffer.write(b'\\xff\\xfe\\n')\n"
        "    sys.exit(0)\n"
        "if 'exec' in args and 'iptables' in args:\n"
        f"    sys.stdout.buffer.write(b'-P OUTPUT DROP\\n{guard_mod.DNS_BLOCK_RULE}\\n')\n"
        "    sys.exit(0)\n"
        "if 'exec' in args:\n"
        f"    sys.stdout.buffer.write(b'{PUBLIC_IPV4_EGRESS}\\n')\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")

    guard_real = GluetunGuard(cfg, SubprocessRunner())
    with mock.patch.object(guard_real, "public_ip", return_value=PUBLIC_IPV4_EGRESS):
        assert (
            guard_real.public_ip_assessment(force_probe=True)
            == PublicIPAssessment.UNSAFE_DEFINITIVE
        )


@pytest.mark.parametrize(
    ("expected_vpn_ip", "egress", "verdict"),
    [
        # A different tunnel exit than the one pinned is a definitive failure.
        (PUBLIC_IPV4_ALT, PUBLIC_IPV4_EGRESS, PublicIPAssessment.UNSAFE_DEFINITIVE),
        (PUBLIC_IPV4_EGRESS, PUBLIC_IPV4_EGRESS, PublicIPAssessment.SAFE),
        # The pin is compared in canonical form, so another spelling of the
        # same address is not a mismatch.
        (PUBLIC_IPV6_EGRESS.upper(), PUBLIC_IPV6_EGRESS, PublicIPAssessment.SAFE),
        (
            "2001:4860:4860:0:0:0:0:8888",
            PUBLIC_IPV6_EGRESS,
            PublicIPAssessment.SAFE,
        ),
        # A pin that is not a public address can never match: fail closed.
        ("10.0.0.1", PUBLIC_IPV4_EGRESS, PublicIPAssessment.UNSAFE_DEFINITIVE),
    ],
    ids=["mismatch", "match", "ipv6-uppercase", "ipv6-uncompressed", "non-public-pin"],
)
def test_expected_vpn_ip_pins_the_tunnel_exit(
    tmp_path: Path, expected_vpn_ip: str, egress: str, verdict: PublicIPAssessment
) -> None:
    cfg = make_config(tmp_path, expected_vpn_ip=expected_vpn_ip)
    guard = GluetunGuard(cfg, FakeRunner({}))
    host = PUBLIC_IPV6_HOST if ":" in egress else PUBLIC_IPV4_HOST
    warnings: list[str] = []
    with (
        mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
        mock.patch.object(guard, "public_ip_via_control_server", return_value=None),
        mock.patch.object(guard, "public_ip_via_gluetun", return_value=egress),
        mock.patch.object(guard, "public_ip", return_value=host),
        mock.patch.object(guard, "warn", side_effect=warnings.append),
    ):
        assert guard.public_ip_assessment(force_probe=True) == verdict
    mismatch = [w for w in warnings if "EXPECTED_VPN_IP" in w]
    assert bool(mismatch) == (verdict == PublicIPAssessment.UNSAFE_DEFINITIVE)
