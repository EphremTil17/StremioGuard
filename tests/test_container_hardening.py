"""Default-suite tests for container hardening, gluetun pins, and gateway liveness."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from loguru import logger

from stremioguard.comet_gateway import CometGatewayManager
from stremioguard.config import (
    COMET_GATEWAY_HEALTH_PORT,
    GLUETUN_ENV_FILE,
    NAMESPACE_PORTS,
    PUBLISHED_ENV_FILE,
)
from stremioguard.env import parse_dotenv, render_dotenv
from stremioguard.guard import GluetunGuard
from stremioguard.publishing import (
    GENERATED_ENV_HEADER,
    GLUETUN_PINNED_ENV,
    StackPublisher,
    render_gluetun_env,
)
from tests.conftest import FakeRunner, make_comet_gateway_config, make_config

REPO_ROOT = Path(__file__).resolve().parent.parent
PREFIX = os.environ.get("STREMIOGUARD_DOCKER_TEST_PREFIX", "sgfix12-")

EXPECTED_D1_PINS: dict[str, str] = {
    "DNS_KEEP_NAMESERVER": "off",
    "FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT": "on",
    "HTTP_CONTROL_SERVER_ADDRESS": "127.0.0.1:18080",
    "HTTPPROXY": "off",
    "SHADOWSOCKS": "off",
    "PPROF_ENABLED": "no",
    "HEALTH_SERVER_ADDRESS": "127.0.0.1:9999",
    "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH": "/gluetun/auth/config.toml",
    "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE": "{}",
    "FIREWALL_INPUT_PORTS": "",
    "FIREWALL_VPN_INPUT_PORTS": "",
    "FIREWALL_OUTBOUND_SUBNETS": "",
    "VPN_PORT_FORWARDING": "off",
    "VPN_INTERFACE": "tun0",
}


def _compose_config_json(*extra: str) -> dict[str, object]:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-p",
            f"{PREFIX}config",
            "-f",
            str(REPO_ROOT / "docker-compose.yml"),
            "config",
            "--format",
            "json",
            "--no-env-resolution",
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


def test_ac1_gluetun_compose_pins_match_python_and_d1_table() -> None:
    """AC-1 (INV-3): Compose gluetun literal pins equal GLUETUN_PINNED_ENV and D1."""
    resolved = _compose_config_json("--no-interpolate")
    services = resolved["services"]
    assert isinstance(services, dict)
    gluetun = services["gluetun"]
    assert isinstance(gluetun, dict)
    env = gluetun["environment"]
    assert isinstance(env, dict)

    literal_env = {
        str(k): str(v) if v is not None else ""
        for k, v in env.items()
        if not (isinstance(v, str) and v.startswith("${"))
    }
    missing = sorted(set(GLUETUN_PINNED_ENV) - set(literal_env))
    extra = sorted(set(literal_env) - set(GLUETUN_PINNED_ENV))
    assert not missing and not extra, f"Gluetun pin drift: missing={missing}, extra={extra}"
    mismatched = {
        k: (literal_env[k], GLUETUN_PINNED_ENV[k])
        for k in GLUETUN_PINNED_ENV
        if literal_env[k] != GLUETUN_PINNED_ENV[k]
    }
    assert not mismatched, f"Gluetun pin value mismatch (compose vs Python): {mismatched}"
    assert list(GLUETUN_PINNED_ENV.items()) == list(EXPECTED_D1_PINS.items())


def test_ac2_render_gluetun_env_strips_all_pinned_keys() -> None:
    """AC-2 (INV-2): render_gluetun_env drops every pinned key, bare or exported."""
    all_pinned_lines = "\n".join(
        f"{key}=non-pin-{idx}" for idx, key in enumerate(GLUETUN_PINNED_ENV)
    )
    rendered_plain = render_gluetun_env(all_pinned_lines)
    for key in GLUETUN_PINNED_ENV:
        assert key not in rendered_plain
    assert rendered_plain == render_dotenv({}, header=GENERATED_ENV_HEADER)

    exported_lines = "\n".join(
        f"  export   {key}=non-pin-{idx}" for idx, key in enumerate(GLUETUN_PINNED_ENV)
    )
    rendered_exported = render_gluetun_env(exported_lines)
    for key in GLUETUN_PINNED_ENV:
        assert key not in rendered_exported
    assert rendered_exported == render_dotenv({}, header=GENERATED_ENV_HEADER)

    mixed_env = "\n".join(
        [
            "VPN_SERVICE_PROVIDER=custom",
            *(f"{key}=override-{idx}" for idx, key in enumerate(GLUETUN_PINNED_ENV)),
            "SERVER_COUNTRIES=Netherlands",
            "CUSTOM_GLUETUN_OPTION=keep-me",
        ]
    )
    rendered_mixed = render_gluetun_env(mixed_env)
    for key in GLUETUN_PINNED_ENV:
        assert key not in rendered_mixed
    expected_mixed = render_dotenv(
        {
            "VPN_SERVICE_PROVIDER": "custom",
            "SERVER_COUNTRIES": "Netherlands",
            "CUSTOM_GLUETUN_OPTION": "keep-me",
        },
        header=GENERATED_ENV_HEADER,
    )
    assert rendered_mixed == expected_mixed


def test_ac3_publish_warns_for_overridden_pins_without_leaking_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-3 (INV-2, wiring): deploying publish warns per differing pin without leaking values."""
    sentinel = "SG12_UNIQUE_AUTH_SENTINEL_9f8e7d6c"
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "COMET_ENABLED=0",
                "HTTPPROXY=on",
                "FIREWALL_OUTBOUND_SUBNETS=192.168.1.0/24",
                f'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={{"auth":"basic","username":"u","password":"{sentinel}"}}',
                "DNS_KEEP_NAMESERVER=off",
                "VPN_SERVICE_PROVIDER=custom",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def run_and_capture(fn: object) -> tuple[list[tuple[str, str]], str]:
        records: list[tuple[str, str]] = []
        sink_id = logger.add(lambda msg: records.append((msg.record["level"].name, str(msg))))
        capsys.readouterr()
        try:
            assert callable(fn)
            fn()
        finally:
            logger.remove(sink_id)
        captured = capsys.readouterr()
        all_output = "".join(text for _, text in records) + captured.out + captured.err
        return records, all_output

    def assert_expected_warnings(records: list[tuple[str, str]], all_output: str) -> None:
        warnings = [text for level, text in records if level == "WARNING"]
        assert len(warnings) == 3, warnings
        assert "HTTPPROXY" in warnings[0] and "`off`" in warnings[0]
        assert "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE" in warnings[1] and "`{}`" in warnings[1]
        assert (
            "FIREWALL_OUTBOUND_SUBNETS" in warnings[2]
            and '`""`' in warnings[2]
            and "LAN access" in warnings[2]
        )
        for w in warnings:
            assert "DNS_KEEP_NAMESERVER" not in w
        assert sentinel not in all_output
        assert "192.168.1.0/24" not in all_output
        assert "HTTPPROXY=on" not in all_output and "`on`" not in all_output

        gluetun_env = parse_dotenv((tmp_path / GLUETUN_ENV_FILE).read_text(encoding="utf-8"))
        assert "HTTPPROXY" not in gluetun_env
        assert "FIREWALL_OUTBOUND_SUBNETS" not in gluetun_env
        assert "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE" not in gluetun_env
        assert "DNS_KEEP_NAMESERVER" not in gluetun_env
        assert gluetun_env["VPN_SERVICE_PROVIDER"] == "custom"

    # (a) StackPublisher(root).publish()
    records_a1, out_a1 = run_and_capture(lambda: StackPublisher(tmp_path).publish())
    assert_expected_warnings(records_a1, out_a1)

    # (b) GluetunGuard.write_compose_override()
    guard = GluetunGuard(make_config(tmp_path), FakeRunner({}))
    records_b, out_b = run_and_capture(guard.write_compose_override)
    assert_expected_warnings(records_b, out_b)

    # (c) StackPublisher(root, env_file=<published snapshot>).publish() -> no warning
    records_c, _ = run_and_capture(
        lambda: StackPublisher(tmp_path, env_file=tmp_path / PUBLISHED_ENV_FILE).publish()
    )
    assert [text for level, text in records_c if level == "WARNING"] == []

    # Second deploying publish warns again (no persisted suppression)
    records_a2, out_a2 = run_and_capture(lambda: StackPublisher(tmp_path).publish())
    assert_expected_warnings(records_a2, out_a2)

    # Removing the overridden lines silences warnings
    env_path.write_text(
        "COMET_ENABLED=0\nDNS_KEEP_NAMESERVER=off\nVPN_SERVICE_PROVIDER=custom\n",
        encoding="utf-8",
    )
    records_clean, _ = run_and_capture(lambda: StackPublisher(tmp_path).publish())
    assert [text for level, text in records_clean if level == "WARNING"] == []


EXPECTED_D3_HARDENING: dict[str, dict[str, object]] = {
    "comet": {
        "cap_drop": ["ALL"],
        "cap_add": set(),
        "read_only": True,
        "tmpfs": {"/tmp"},
    },
    "stremthru": {
        "cap_drop": ["ALL"],
        "cap_add": set(),
        "read_only": True,
        "tmpfs": {"/tmp"},
    },
    "comet-gateway": {
        "cap_drop": ["ALL"],
        "cap_add": {"CHOWN", "SETGID", "SETUID"},
        "read_only": True,
        "tmpfs": {"/tmp", "/var/cache/nginx"},
    },
    "comet-postgres": {
        "cap_drop": ["ALL"],
        "cap_add": {"CHOWN", "DAC_READ_SEARCH", "SETGID", "SETUID"},
        "read_only": False,
        "tmpfs": set(),
    },
    "stremio": {
        "cap_drop": ["ALL"],
        "cap_add": {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"},
        "read_only": False,
        "tmpfs": set(),
    },
    "use-stremio-start-instead": {
        "cap_drop": ["ALL"],
        "cap_add": set(),
        "read_only": False,
        "tmpfs": set(),
    },
    "gluetun": {
        "cap_drop": None,
        "cap_add": {"NET_ADMIN"},
        "read_only": False,
        "tmpfs": set(),
    },
}


def test_ac4_compose_hardening_matches_d3_table() -> None:
    """AC-4 (INV-4): Compose services match D3 capabilities, no-new-privileges, read_only, tmpfs."""
    resolved = _compose_config_json()
    services = resolved["services"]
    assert isinstance(services, dict)
    assert set(services) == set(EXPECTED_D3_HARDENING)

    for name, expected in EXPECTED_D3_HARDENING.items():
        svc = services[name]
        assert isinstance(svc, dict), name
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("cap_drop") == expected["cap_drop"], name

        raw_cap_add = svc.get("cap_add") or []
        assert isinstance(raw_cap_add, list), name
        assert len(raw_cap_add) == len(set(raw_cap_add)), f"{name}: duplicate cap_add {raw_cap_add}"
        assert set(raw_cap_add) == expected["cap_add"], name
        assert "NET_RAW" not in raw_cap_add, name

        assert bool(svc.get("read_only")) is expected["read_only"], name

        raw_tmpfs = svc.get("tmpfs") or []
        assert isinstance(raw_tmpfs, list), name
        tmpfs_targets = {
            entry["target"] if isinstance(entry, dict) else str(entry).split(":", 1)[0]
            for entry in raw_tmpfs
        }
        assert tmpfs_targets == expected["tmpfs"], name

    assert services["gluetun"].get("cap_add") == ["NET_ADMIN"]  # type: ignore[union-attr]
    assert services["gluetun"].get("cap_drop") is None  # type: ignore[union-attr]
    for ns_svc in ("comet", "stremthru", "comet-gateway", "comet-postgres", "stremio"):
        assert "ALL" in (services[ns_svc].get("cap_drop") or []), ns_svc  # type: ignore[union-attr]


def test_ac5_only_gluetun_on_bridge_and_no_gateway_dependents() -> None:
    """AC-5 (INV-8, INV-7): Only gluetun has networks; no service depends on comet-gateway."""
    resolved = _compose_config_json()
    services = resolved["services"]
    assert isinstance(services, dict)

    for name, svc in services.items():
        assert isinstance(svc, dict), name
        depends_on = svc.get("depends_on") or {}
        assert "comet-gateway" not in depends_on, name
        if name == "gluetun":
            assert svc.get("network_mode") is None
            assert svc.get("networks")
        elif name == "use-stremio-start-instead":
            assert svc.get("network_mode") == "none"
            assert not svc.get("networks")
        else:
            assert svc.get("network_mode") == "service:gluetun", name
            assert not svc.get("networks"), name


def test_ac6_gateway_liveness_config_port_and_healthcheck(tmp_path: Path) -> None:
    """AC-6 (INV-6, D4): nginx health server block, NAMESPACE_PORTS, and compose healthcheck."""
    assert COMET_GATEWAY_HEALTH_PORT == 8099
    assert NAMESPACE_PORTS["comet-gateway health (loopback)"] == 8099
    assert list(NAMESPACE_PORTS.values()).count(8099) == 1
    assert len(set(NAMESPACE_PORTS.values())) == len(NAMESPACE_PORTS)

    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    public_marker = "    server {\n"
    first_idx = conf.index(public_marker)
    second_idx = conf.index(public_marker, first_idx + len(public_marker))
    public_block = conf[first_idx:second_idx]
    health_block = conf[second_idx:]

    assert "8099" not in public_block
    assert "__sg_alive" not in public_block

    assert "listen 127.0.0.1:8099;" in health_block
    assert "access_log off;" in health_block
    assert "location = /__sg_alive" in health_block and "return 204;" in health_block
    assert "location /" in health_block and "return 404;" in health_block
    for forbidden in ("proxy_pass", "limit_req", "$gateway_token", "$token_valid"):
        assert forbidden not in health_block

    resolved = _compose_config_json()
    gateway = resolved["services"]["comet-gateway"]  # type: ignore[index]
    healthcheck = gateway["healthcheck"]
    expected_cmd = [
        "CMD",
        "curl",
        "-fsS",
        "-o",
        "/dev/null",
        "--max-time",
        "3",
        "http://127.0.0.1:8099/__sg_alive",
    ]
    assert healthcheck["test"] == expected_cmd
    assert all("nginx" not in part for part in healthcheck["test"])


def test_ac16_test_compose_helpers_never_read_env_or_secret_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-16 (R1-1, INV-9): Compose helpers pass --env-file /dev/null --no-env-resolution."""
    from tests import test_container_hardening as hardening_mod
    from tests import test_container_hardening_docker as docker_hardening_mod

    shutil.copy2(REPO_ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    sentinels = {
        ".env": ("SERVER_COUNTRIES=SG12_SENTINEL_ENV_A\n", "SG12_SENTINEL_ENV_A"),
        ".stremio/gluetun.env": (
            "OPENVPN_PASSWORD=SG12_SENTINEL_GLUETUN_B\n",
            "SG12_SENTINEL_GLUETUN_B",
        ),
        ".stremio/comet/postgres.env": (
            "POSTGRES_PASSWORD=SG12_SENTINEL_PG_C\n",
            "SG12_SENTINEL_PG_C",
        ),
        ".stremio/stremthru/stremthru.env": (
            "STREMTHRU_AUTH=user:SG12_SENTINEL_ST_D\n",
            "SG12_SENTINEL_ST_D",
        ),
    }
    for rel, (body, _) in sentinels.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    captured: list[tuple[list[str], str]] = []
    real_run = subprocess.run

    def spy_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        res = real_run(args, **kwargs)  # type: ignore[call-overload]
        captured.append((list(args), str(res.stdout)))
        return res

    monkeypatch.setattr(hardening_mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(docker_hardening_mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(hardening_mod.subprocess, "run", spy_run)
    monkeypatch.setattr(docker_hardening_mod.subprocess, "run", spy_run)

    hardening_mod._compose_config_json("--no-interpolate")
    docker_hardening_mod._resolved_repo_compose()

    assert len(captured) == 2
    for idx, (argv, raw_stdout) in enumerate(captured):
        env_idx = argv.index("--env-file")
        assert argv[env_idx + 1] == "/dev/null", argv
        assert "--no-env-resolution" in argv, argv
        if idx == 0:
            assert "--no-interpolate" in argv, argv
        for _, sentinel in sentinels.values():
            assert sentinel not in raw_stdout


def test_ac17_gateway_listen_directives_loopback_and_public_only(tmp_path: Path) -> None:
    """AC-17 (R1-2, INV-6): Public has only listen 8090; health has only 127.0.0.1:8099."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    blocks = re.findall(r"(?m)^    server \{\n(.*?)^    \}", conf, flags=re.DOTALL)
    assert len(blocks) == 2, f"Expected 2 server blocks, got {len(blocks)}"

    public_listens = [
        " ".join(line.strip().split())
        for line in re.findall(r"^\s*listen\s+[^;]+;", blocks[0], flags=re.MULTILINE)
    ]
    health_listens = [
        " ".join(line.strip().split())
        for line in re.findall(r"^\s*listen\s+[^;]+;", blocks[1], flags=re.MULTILINE)
    ]
    assert public_listens == ["listen 8090;"], public_listens
    assert health_listens == ["listen 127.0.0.1:8099;"], health_listens


def test_ac17_mutation_guards_catch_wildcard_listen_directives(tmp_path: Path) -> None:
    """AC-17 (R1-2): Verify the listen-directive check fails on added or non-loopback listen."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()

    def extract_health_listens(text: str) -> list[str]:
        blocks = re.findall(r"(?m)^    server \{\n(.*?)^    \}", text, flags=re.DOTALL)
        assert len(blocks) == 2
        return [
            " ".join(line.strip().split())
            for line in re.findall(r"^\s*listen\s+[^;]+;", blocks[1], flags=re.MULTILINE)
        ]

    added_wildcard = conf.replace(
        "listen 127.0.0.1:8099;", "listen 127.0.0.1:8099;\n        listen 8099;"
    )
    assert extract_health_listens(added_wildcard) != ["listen 127.0.0.1:8099;"]

    replaced_wildcard = conf.replace("listen 127.0.0.1:8099;", "listen 8099;")
    assert extract_health_listens(replaced_wildcard) != ["listen 127.0.0.1:8099;"]
