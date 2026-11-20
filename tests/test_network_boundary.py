"""Default-suite tests for network boundary compose pins and DNS block verification.

Covers AC-2 (default), AC-4 (default), AC-6, AC-7, AC-8.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from stremioguard import guard as guard_mod
from stremioguard import orchestrator as orchestrator_mod
from stremioguard.config import SubprocessRunner
from stremioguard.guard import DNS_BLOCK_RULE, GluetunGuard, GluetunState, PublicIPAssessment
from stremioguard.orchestrator import Orchestrator
from tests.conftest import (
    PUBLIC_IPV4_EGRESS,
    PUBLIC_IPV4_HOST,
    FakeRunner,
    completed,
    compose_args_prefix,
    make_config,
)

PREFIX = "sgfix8-"
REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_POST_RULES = "iptables -I OUTPUT -d 127.0.0.11/32 -j DROP\n"
PINNED_CONFIG_SHA256 = {
    "gluetun-post-rules-v2": "c501fbbb465742056a341e5ec3dc7e7b0ce1e8b79d71ca4bd5a9388645943a47",
    "comet-postgres-hba-v1": "172afd075c77dedf26b58490ad5fa77c1269c6cfa5c5abde731495b686a9fe50",
}


def _compose_config_json(root_dir: Path, *extra: str) -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            f"{PREFIX}config",
            "-f",
            str(root_dir / "docker-compose.yml"),
            "config",
            "--format",
            "json",
            *extra,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
    return data


def test_ac2_compose_pins_gluetun_dns_and_firewall_over_env_file(tmp_path: Path) -> None:
    """AC-2 (default suite, INV-4): Compose environment pins override .stremio/gluetun.env."""
    shutil.copy2(REPO_ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    stremio_dir = tmp_path / ".stremio"
    stremio_dir.mkdir()
    (stremio_dir / "gluetun.env").write_text(
        "DNS_KEEP_NAMESERVER=on\nFIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=off\n",
        encoding="utf-8",
    )

    resolved = _compose_config_json(tmp_path)
    services = resolved["services"]
    assert isinstance(services, dict)
    gluetun = services["gluetun"]
    assert isinstance(gluetun, dict)
    env = gluetun["environment"]
    assert isinstance(env, dict)
    assert env["DNS_KEEP_NAMESERVER"] == "off"
    assert env["FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT"] == "on"


def test_ac4_compose_drops_net_raw_on_namespace_services_only() -> None:
    """AC-4 (default suite, INV-2): namespace services drop ALL (NET_RAW is not effective)."""
    resolved = _compose_config_json(REPO_ROOT, "--no-env-resolution")
    services = resolved["services"]
    assert isinstance(services, dict)
    for name in ("stremio", "comet-gateway", "comet-postgres", "stremthru", "comet"):
        service = services[name]
        assert isinstance(service, dict)
        assert service.get("cap_drop") == ["ALL"], name
        assert "NET_RAW" not in (service.get("cap_add") or []), name

    gluetun = services["gluetun"]
    assert isinstance(gluetun, dict)
    assert gluetun.get("cap_add") == ["NET_ADMIN"]
    assert gluetun.get("cap_drop") is None


def test_ac8_compose_configs_pin_sha256_and_match_dns_block_rule() -> None:
    """AC-8 (D5): SHA-256 of each compose config is pinned and post-rules matches DNS_BLOCK_RULE."""
    resolved = _compose_config_json(REPO_ROOT, "--no-env-resolution")
    configs = resolved.get("configs")
    assert isinstance(configs, dict)
    assert set(configs) == set(PINNED_CONFIG_SHA256), (
        f"Compose configs changed ({sorted(configs)} vs {sorted(PINNED_CONFIG_SHA256)}); "
        "remember to bump the -vN suffix when changing config content because Compose does not "
        "recreate containers on content-only edits."
    )
    for name, expected_digest in PINNED_CONFIG_SHA256.items():
        entry = configs[name]
        assert isinstance(entry, dict)
        content = entry.get("content")
        assert isinstance(content, str)
        actual_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert actual_digest == expected_digest, (
            f"Compose config {name!r} content changed (got {actual_digest}, expected "
            f"{expected_digest}). Bump the -vN config name suffix because Compose does not "
            "recreate a container when only the config content changes."
        )

    post_rules = configs["gluetun-post-rules-v2"]
    assert isinstance(post_rules, dict)
    assert post_rules["content"] == EXPECTED_POST_RULES
    line = post_rules["content"].strip()
    assert line.startswith("iptables -I OUTPUT ")
    assert " -d 127.0.0.11/32 " in line
    assert line.endswith(" -j DROP")
    # REJECT emits `reject-with icmp-port-unreachable`, which breaks gluetun's
    # Go iptables chain parser when removing outdated VPN rules on reconnect.
    assert " -j REJECT" not in line
    assert " -d 127.0.0.11/32 " in DNS_BLOCK_RULE
    assert " -j DROP" in DNS_BLOCK_RULE


def test_ac6_dns_block_matrix_and_warning_rate_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-6 (INV-3, D4): public_ip_assessment() gates on namespace_dns_block_active()."""
    cfg = make_config(tmp_path)
    prefix = compose_args_prefix(tmp_path)
    ps_gluetun = (*prefix, "ps", "-q", "gluetun")
    iptables_cmd = ("docker", "exec", "gluetun-cid", "iptables", "-S", "OUTPUT")

    def run_case(
        iptables_response: subprocess.CompletedProcess[str] | BaseException | None,
        *,
        with_container_id: bool = True,
    ) -> tuple[PublicIPAssessment, list[str], int, GluetunGuard]:
        responses: dict[
            tuple[str, ...],
            list[subprocess.CompletedProcess[str]] | subprocess.CompletedProcess[str],
        ] = {}
        if with_container_id:
            responses[ps_gluetun] = completed(list(ps_gluetun), "gluetun-cid\n")
        else:
            responses[ps_gluetun] = completed(list(ps_gluetun), "\n")

        class _CaseRunner(FakeRunner):
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
                if tuple(args) == iptables_cmd:
                    self.calls.append(args)
                    self.envs.append(env)
                    self.timeouts.append(timeout)
                    self.inputs.append(input)
                    if isinstance(iptables_response, BaseException):
                        raise iptables_response
                    assert iptables_response is not None
                    return iptables_response
                return super().run(
                    args, check=check, capture=capture, timeout=timeout, env=env, input=input
                )

        guard = GluetunGuard(cfg, _CaseRunner(responses))
        guard._verified_egress_ip = PUBLIC_IPV4_EGRESS
        guard._last_egress_probe_time = 1e12
        warnings: list[str] = []
        with (
            mock.patch.object(guard, "public_ip_via_control_server", return_value=None),
            mock.patch.object(
                guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS
            ) as ep,
            mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST),
            mock.patch.object(guard, "warn", side_effect=warnings.append),
        ):
            verdict = guard.public_ip_assessment(force_probe=True)
        return verdict, warnings, ep.call_count, guard

    # (a) rule first -> proceeds to egress probe
    verdict_a, warnings_a, probes_a, _ = run_case(
        completed(
            list(iptables_cmd),
            f"-P OUTPUT DROP\n{DNS_BLOCK_RULE}\n-A OUTPUT -o lo -j ACCEPT\n",
        )
    )
    assert verdict_a == PublicIPAssessment.SAFE
    assert probes_a == 1
    assert warnings_a == []

    # (b) no rule -> UNKNOWN, no egress probe, _verified_egress_ip cleared
    verdict_b, warnings_b, probes_b, guard_b = run_case(
        completed(list(iptables_cmd), "-P OUTPUT DROP\n-A OUTPUT -o lo -j ACCEPT\n")
    )
    assert verdict_b == PublicIPAssessment.UNKNOWN
    assert probes_b == 0
    assert guard_b._verified_egress_ip is None
    assert len(warnings_b) == 1
    assert "gluetun-post-rules-v2" in warnings_b[0]
    assert "/iptables/post-rules.txt" in warnings_b[0]

    # (c) rule after -A OUTPUT -o lo -j ACCEPT -> UNKNOWN
    verdict_c, _, probes_c, guard_c = run_case(
        completed(
            list(iptables_cmd),
            f"-P OUTPUT DROP\n-A OUTPUT -o lo -j ACCEPT\n{DNS_BLOCK_RULE}\n",
        )
    )
    assert verdict_c == PublicIPAssessment.UNKNOWN
    assert probes_c == 0
    assert guard_c._verified_egress_ip is None

    # (d) legacy -j REJECT instead -> UNKNOWN (breaks gluetun's iptables parser on reconnect)
    verdict_d, _, probes_d, guard_d = run_case(
        completed(
            list(iptables_cmd),
            "-P OUTPUT DROP\n"
            "-A OUTPUT -d 127.0.0.11/32 -j REJECT --reject-with icmp-port-unreachable\n",
        )
    )
    assert verdict_d == PublicIPAssessment.UNKNOWN
    assert probes_d == 0
    assert guard_d._verified_egress_ip is None

    # (e) docker exec non-zero, TimeoutExpired, OSError -> UNKNOWN with different warning from (b)
    verdict_e1, warnings_e1, probes_e1, guard_e1 = run_case(
        completed(list(iptables_cmd), "", "iptables failed", returncode=1)
    )
    verdict_e2, warnings_e2, probes_e2, guard_e2 = run_case(
        subprocess.TimeoutExpired(list(iptables_cmd), 5)
    )
    verdict_e3, warnings_e3, probes_e3, guard_e3 = run_case(OSError("exec pipe broken"))
    for verdict, warnings, probes, g in (
        (verdict_e1, warnings_e1, probes_e1, guard_e1),
        (verdict_e2, warnings_e2, probes_e2, guard_e2),
        (verdict_e3, warnings_e3, probes_e3, guard_e3),
    ):
        assert verdict == PublicIPAssessment.UNKNOWN
        assert probes == 0
        assert g._verified_egress_ip is None
        assert len(warnings) == 1
        assert warnings[0] != warnings_b[0]

    # (e) undecodable bytes through real SubprocessRunner and fake docker on PATH
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
        "if 'exec' in args and 'iptables' in args:\n"
        "    sys.stdout.buffer.write(b'\\xff\\xfe-A OUTPUT\\n')\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")
    real_guard = GluetunGuard(cfg, SubprocessRunner())
    real_guard._verified_egress_ip = PUBLIC_IPV4_EGRESS
    with (
        mock.patch.object(real_guard, "public_ip_via_control_server", return_value=None),
        mock.patch.object(real_guard, "public_ip_via_gluetun") as real_ep,
    ):
        assert real_guard.public_ip_assessment(force_probe=True) == PublicIPAssessment.UNKNOWN
        assert real_ep.call_count == 0
        assert real_guard._verified_egress_ip is None

    # (f) no gluetun container ID -> UNKNOWN
    verdict_f, warnings_f, probes_f, guard_f = run_case(None, with_container_id=False)
    assert verdict_f == PublicIPAssessment.UNKNOWN
    assert probes_f == 0
    assert guard_f._verified_egress_ip is None
    assert len(warnings_f) == 1

    # 100 calls with (b) -> warning appears once
    loop_warnings: list[str] = []
    with (
        mock.patch.object(guard_b, "public_ip_via_control_server", return_value=None),
        mock.patch.object(guard_b, "public_ip_via_gluetun") as loop_ep,
        mock.patch.object(guard_b, "warn", side_effect=loop_warnings.append),
        mock.patch.object(guard_mod.time, "monotonic", return_value=1000.0),
    ):
        guard_b._dns_block_warned_at = None
        for _ in range(100):
            assert guard_b.public_ip_assessment() == PublicIPAssessment.UNKNOWN
        assert loop_ep.call_count == 0
        assert len(loop_warnings) == 1


def test_ac7_dns_block_identity_caching_orchestrator_and_preflight(tmp_path: Path) -> None:
    """AC-7 (INV-3, D4): identity caching, StartedAt change, None state, Orchestrator, preflight."""
    cfg = make_config(
        tmp_path,
        egress_probe_interval_seconds=300,
        public_ip_failure_threshold=3,
        watch_interval_seconds=10,
    )
    clock = {"now": 1000.0}

    # (a) 10 calls with block present, same identity, egress not due -> check runs once
    guard = GluetunGuard(cfg, FakeRunner({}))
    guard.last_gluetun_state = GluetunState("cid-1", "healthy", "2026-11-16T00:00:00Z")
    with (
        mock.patch.object(guard_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "namespace_dns_block_active", return_value=True) as dns_check,
        mock.patch.object(guard, "public_ip_via_control_server", return_value=PUBLIC_IPV4_EGRESS),
        mock.patch.object(guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS),
        mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST),
    ):
        for _ in range(10):
            assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
            clock["now"] += 1.0
        assert dns_check.call_count == 1

        # (b) same container ID, new StartedAt while egress cache is fresh -> runs before SAFE
        guard.last_gluetun_state = GluetunState("cid-1", "healthy", "2026-11-16T00:01:00Z")
        assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
        assert dns_check.call_count == 2

        # (d) egress is due -> runs again even with same identity
        clock["now"] += 300.0
        assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
        assert dns_check.call_count == 3

        # (c) last_gluetun_state is None -> runs on every call
        guard.last_gluetun_state = None
        for _ in range(4):
            assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
        assert dns_check.call_count == 7

    # (e) Real Orchestrator: steady SAFE -> identity changes, no block for 5 ticks, then block
    (tmp_path / ".env").write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  gluetun: {}\n  stremio: {}\n")
    orch_clock = {"now": 2000.0}
    orch_guard = GluetunGuard(cfg, FakeRunner({}))
    orch = Orchestrator(orch_guard)

    state_holder = {"state": GluetunState("cid-1", "healthy", "2026-11-16T00:00:00Z")}
    dns_holder = {"active": True}
    services_up = {"running": True}
    up_calls: list[list[str]] = []

    def fake_gluetun_healthy() -> bool:
        orch_guard.last_gluetun_state = state_holder["state"]
        return True

    def fake_start_services(services: list[str], **_: object) -> None:
        up_calls.append(list(services))
        services_up["running"] = True

    def fake_stop_services(**_: object) -> bool:
        services_up["running"] = False
        return True

    with (
        mock.patch.object(guard_mod.time, "monotonic", side_effect=lambda: orch_clock["now"]),
        mock.patch.object(
            orchestrator_mod.time, "monotonic", side_effect=lambda: orch_clock["now"]
        ),
        mock.patch.object(orch_guard, "gluetun_healthy", side_effect=fake_gluetun_healthy),
        mock.patch.object(
            orch_guard, "namespace_dns_block_active", side_effect=lambda: dns_holder["active"]
        ),
        mock.patch.object(
            orch_guard, "public_ip_via_control_server", return_value=PUBLIC_IPV4_EGRESS
        ),
        mock.patch.object(orch_guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS),
        mock.patch.object(orch_guard, "public_ip", return_value=PUBLIC_IPV4_HOST),
        mock.patch.object(orch_guard, "stale_namespace_services", return_value=[]),
        mock.patch.object(
            orch_guard, "container_running", side_effect=lambda **_: services_up["running"]
        ),
        mock.patch.object(orch_guard, "start_services", side_effect=fake_start_services),
        mock.patch.object(orch_guard, "stop_active_services", side_effect=fake_stop_services),
    ):
        # Initial steady-state SAFE tick
        orch.watch_once()
        assert services_up["running"] is True
        assert up_calls == []

        # Gluetun identity changes and block is missing for 5 ticks
        state_holder["state"] = GluetunState("cid-2", "healthy", "2026-11-16T00:05:00Z")
        dns_holder["active"] = False
        for tick in range(1, 6):
            orch_clock["now"] += 10.0
            orch.watch_once()
            assert not cfg.vpn_lockout_file.exists()
            assert up_calls == []
            if tick < 3:
                assert services_up["running"] is True
            else:
                assert services_up["running"] is False

        # Tick 6: block appears -> services start
        dns_holder["active"] = True
        orch_clock["now"] += 10.0
        orch.watch_once()
        assert services_up["running"] is True
        assert len(up_calls) == 1

    # (f) preflight(defer_vpn_recovery=True) and preflight(defer_vpn_recovery=False)
    pre_cfg = make_config(tmp_path / "preflight")
    (pre_cfg.root_dir / ".env").write_text(
        "VPN_SERVICE_PROVIDER=nordvpn\nSTREMIO_ENABLED=1\nCOMET_ENABLED=0\n"
        "STREMIO_USERNAME=sg\nSTREMIO_PASSWORD=sg-test-password\n",
        encoding="utf-8",
    )
    pre_guard = GluetunGuard(pre_cfg, FakeRunner({}))
    with (
        mock.patch.object(pre_guard, "require_commands"),
        mock.patch.object(pre_guard, "check_vpn_lockout"),
        mock.patch.object(pre_guard, "check_bind_addresses"),
        mock.patch.object(pre_guard, "write_compose_override"),
        mock.patch.object(pre_guard, "refresh_gluetun_image"),
        mock.patch.object(pre_guard, "running_gluetun_endpoint_env", return_value={}),
        mock.patch.object(pre_guard, "compose_fresh"),
        mock.patch.object(pre_guard, "wait_for_gluetun_healthy"),
        mock.patch.object(pre_guard, "namespace_dns_block_active", return_value=False),
        mock.patch.object(pre_guard, "public_ip_via_control_server", return_value=None),
        mock.patch.object(pre_guard, "public_ip_via_gluetun") as pre_ep,
        mock.patch.object(pre_guard, "start_services") as pre_start,
    ):
        assert pre_guard.preflight(defer_vpn_recovery=True) is False
        pre_start.assert_not_called()
        pre_ep.assert_not_called()

        with pytest.raises(RuntimeError, match="Public IP check failed"):
            pre_guard.preflight(defer_vpn_recovery=False)
        pre_start.assert_not_called()
        pre_ep.assert_not_called()


def test_ac18_compose_config_postgres_hba_and_listen_addresses() -> None:
    """AC-18 (D7): comet-postgres appends hba_file and listen_addresses and mounts config."""
    resolved = _compose_config_json(REPO_ROOT, "--no-env-resolution")
    services = resolved["services"]
    assert isinstance(services, dict)
    pg = services["comet-postgres"]
    assert isinstance(pg, dict)

    cmd = pg["command"]
    assert isinstance(cmd, list)
    expected_tail = [
        "-c",
        "hba_file=/etc/postgresql/pg_hba.conf",
        "-c",
        "listen_addresses=127.0.0.1",
    ]
    assert cmd[-4:] == expected_tail, cmd
    assert cmd.count("hba_file=/etc/postgresql/pg_hba.conf") == 1
    assert cmd.count("listen_addresses=127.0.0.1") == 1
    assert "max_connections=100" in cmd[:-4]

    mounts = pg.get("configs")
    assert isinstance(mounts, list)
    assert any(
        isinstance(m, dict)
        and m.get("source") == "comet-postgres-hba-v1"
        and m.get("target") == "/etc/postgresql/pg_hba.conf"
        for m in mounts
    ), mounts


@pytest.mark.parametrize(
    "state",
    [None, GluetunState(None, None, None), GluetunState("cid-1", "healthy", None)],
    ids=["no-observation", "no-container", "no-start-time"],
)
def test_unknown_gluetun_identity_never_reuses_a_cached_safe_verdict(
    tmp_path: Path, state: GluetunState | None
) -> None:
    """A SAFE probed while gluetun's identity was unknown proves nothing for the next tick.

    The cached verdict is tied to the gluetun container it was probed in
    (F-5). With no identity there is nothing to tie it to, so every call
    probes the tunnel again instead of trusting an identity-less cache.
    """
    cfg = make_config(tmp_path, egress_probe_interval_seconds=300)
    clock = {"now": 1000.0}
    guard = GluetunGuard(cfg, FakeRunner({}))
    guard.last_gluetun_state = state
    with (
        mock.patch.object(guard_mod.time, "monotonic", side_effect=lambda: clock["now"]),
        mock.patch.object(guard, "namespace_dns_block_active", return_value=True),
        mock.patch.object(guard, "public_ip_via_control_server", return_value=PUBLIC_IPV4_EGRESS),
        mock.patch.object(
            guard, "public_ip_via_gluetun", return_value=PUBLIC_IPV4_EGRESS
        ) as egress_probe,
        mock.patch.object(guard, "public_ip", return_value=PUBLIC_IPV4_HOST),
    ):
        for _ in range(3):
            assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
            clock["now"] += 1.0  # well inside the 300 s cache window
        assert egress_probe.call_count == 3

        # Once the identity is known, the next SAFE is cached for that container.
        guard.last_gluetun_state = GluetunState("cid-1", "healthy", "2026-11-16T00:00:00Z")
        for _ in range(3):
            assert guard.public_ip_assessment() == PublicIPAssessment.SAFE
            clock["now"] += 1.0
        assert egress_probe.call_count == 4
