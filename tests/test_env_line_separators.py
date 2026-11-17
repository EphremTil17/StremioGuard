"""Tests for env line-separator refusal, writer invariants, NordVPN/URL/image input boundaries."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import secrets
import stat
import subprocess
import threading
import time
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest
import typer
from loguru import logger

from stremioguard import env, nordvpn, orchestrator, publishing, resolver
from stremioguard.cli import supervisor
from stremioguard.cli.commands import general as general_cmd
from stremioguard.comet.manager import CometManager
from stremioguard.config import (
    GENERATED_COMPOSE_FILE,
    GLUETUN_ENV_FILE,
    PUBLISHED_COMPOSE_FILE,
    PUBLISHED_ENV_FILE,
    CometConfig,
)
from stremioguard.publishing import StackPublisher
from tests.conftest import (
    ACTIVE_STATUS_ARGS,
    PUBLIC_IPV4_STATION,
    FakeRunner,
    completed,
    make_comet_config,
    write_minimal_bundle_manifest,
)

GOLDENS_PATH = Path(__file__).resolve().parent / "data" / "env_rendering_goldens.json"

ALL_D1_CHARS = tuple(sorted(env.FORBIDDEN_ENV_CHARS, key=ord))
NON_LF_D1_CHARS = tuple(c for c in ALL_D1_CHARS if c != "\n")


# --- AC-1: Parser matrix ----------------------------------------------------


@pytest.mark.parametrize("char", NON_LF_D1_CHARS, ids=lambda c: f"U+{ord(c):04X}")
@pytest.mark.parametrize("quoting", ["unquoted", "single", "double"])
def test_ac1_parser_refuses_all_forbidden_chars_and_quoting_forms(
    tmp_path: Path, char: str, quoting: str
) -> None:
    """AC-1: every non-LF D1 char in unquoted, single-quoted, or double-quoted form raises."""
    payload = f"SGCANARY{char}FIREWALL_OUTBOUND_SUBNETS=0.0.0.0/0"
    if quoting == "unquoted":
        line = f"OPENVPN_PASSWORD={payload}\n"
    elif quoting == "single":
        line = f"OPENVPN_PASSWORD='{payload}'\n"
    else:
        line = f'OPENVPN_PASSWORD="{payload}"\n'

    env_path = tmp_path / ".env"
    env_path.write_bytes(line.encode("utf-8"))

    with pytest.raises(RuntimeError) as exc_info:
        env.read_env_file(env_path)

    message = str(exc_info.value)
    assert str(env_path) in message
    assert "line 1" in message
    assert f"U+{ord(char):04X}" in message
    assert "OPENVPN_PASSWORD" in message
    assert "SGCANARY" not in message
    assert "FIREWALL_OUTBOUND_SUBNETS" not in message


@pytest.mark.parametrize(
    ("escape", "codepoint"),
    [(r"\n", "U+000A"), (r"\r", "U+000D")],
)
def test_ac1_parser_refuses_double_quote_line_break_escapes(
    tmp_path: Path, escape: str, codepoint: str
) -> None:
    """AC-1: double-quote escapes producing \\n or \\r are refused without returning extra keys."""
    env_path = tmp_path / ".env"
    env_path.write_text(f'OPENVPN_PASSWORD="SGCANARY{escape}X=1"\n', encoding="utf-8")

    with pytest.raises(RuntimeError) as exc_info:
        env.read_env_file(env_path)

    message = str(exc_info.value)
    assert str(env_path) in message
    assert "line 1" in message
    assert codepoint in message
    assert "OPENVPN_PASSWORD" in message
    assert "SGCANARY" not in message
    assert "X=1" not in message


def test_ac1_parser_refuses_non_assignment_line_with_forbidden_char(tmp_path: Path) -> None:
    """AC-1 / D2: non-comment lines without `=` carrying a D1 char are also refused."""
    env_path = tmp_path / ".env"
    env_path.write_text("OK=1\nINHERIT_ONLY\u2028X=1\n", encoding="utf-8")

    with pytest.raises(RuntimeError) as exc_info:
        env.read_env_file(env_path)

    message = str(exc_info.value)
    assert str(env_path) in message
    assert "line 2" in message
    assert "U+2028" in message
    assert "INHERIT_ONLY" not in message


# --- AC-2: Grammar ----------------------------------------------------------


def test_ac2_crlf_parses_identically_to_lf_and_counts_lf_lines() -> None:
    """AC-2: CRLF matches LF twin, comments/U+2028 lines skipped, line count uses \\n."""
    lf_text = "# header\nA=one\nB='two'\nC=\"three\"\nexport D=four # inline\n"
    crlf_text = lf_text.replace("\n", "\r\n")
    assert env.parse_dotenv(crlf_text) == env.parse_dotenv(lf_text)

    comment_lines = [f"# comment {c} INJ=1" for c in NON_LF_D1_CHARS]
    text_with_comments = "\n".join(
        [
            "FIRST=1",
            *comment_lines,
            "\u2028",
            "SECOND=2",
        ]
    )
    assert env.parse_dotenv(text_with_comments) == {"FIRST": "1", "SECOND": "2"}

    # Error line numbers count only \n-separated lines.
    error_text = "LINE1=ok\r\n# line 2 \u2028 skipped\n\u2028\nLINE4=bad\u2028canary\n"
    with pytest.raises(RuntimeError) as exc_info:
        env.parse_dotenv(error_text, source="test.env")
    message = str(exc_info.value)
    assert "test.env" in message
    assert "line 4" in message
    assert "LINE4" in message
    assert "U+2028" in message
    assert "canary" not in message


# --- AC-3: Writer matrix and D1 set completeness ----------------------------


def test_ac3_forbidden_set_matches_unicode_splitlines_plus_nul() -> None:
    """AC-3 / D1: FORBIDDEN_ENV_CHARS equals every char str.splitlines() splits on plus NUL."""
    expected = {c for c in map(chr, range(0x110000)) if len(f"a{c}b".splitlines()) > 1} | {"\x00"}
    assert expected == env.FORBIDDEN_ENV_CHARS


@pytest.mark.parametrize("char", ALL_D1_CHARS, ids=lambda c: f"U+{ord(c):04X}")
def test_ac3_all_writers_refuse_every_forbidden_char(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, char: str
) -> None:
    """AC-3: every D3 writer refuses every D1 character with ValueError, never echoing the value."""
    bad = f"SGCANARY{char}end"
    codepoint = f"U+{ord(char):04X}"

    env_path = tmp_path / ".env"
    original_bytes = b"OPENVPN_PASSWORD=existing\nOTHER=kept\n"
    env_path.write_bytes(original_bytes)

    with pytest.raises(ValueError) as exc_write_many:
        env.write_env_settings(env_path, {"OPENVPN_PASSWORD": bad})
    assert "OPENVPN_PASSWORD" in str(exc_write_many.value)
    assert codepoint in str(exc_write_many.value)
    assert "SGCANARY" not in str(exc_write_many.value)
    assert env_path.read_bytes() == original_bytes

    with pytest.raises(ValueError) as exc_write_one:
        env.write_env_setting(env_path, "OPENVPN_PASSWORD", bad)
    assert "OPENVPN_PASSWORD" in str(exc_write_one.value)
    assert codepoint in str(exc_write_one.value)
    assert "SGCANARY" not in str(exc_write_one.value)
    assert env_path.read_bytes() == original_bytes

    for fn in (env.format_env_value, env.render_env_value, env.render_strict_env_value):
        with pytest.raises(ValueError) as exc_fn:
            fn(bad)
        assert codepoint in str(exc_fn.value)
        assert "SGCANARY" not in str(exc_fn.value)

    with pytest.raises(ValueError) as exc_dotenv:
        env.render_dotenv({"OPENVPN_PASSWORD": bad})
    assert "OPENVPN_PASSWORD" in str(exc_dotenv.value)
    assert codepoint in str(exc_dotenv.value)
    assert "SGCANARY" not in str(exc_dotenv.value)

    manager = CometManager(make_comet_config(tmp_path), FakeRunner({}))
    monkeypatch.setattr(secrets, "token_urlsafe", lambda _n=24: bad)
    with pytest.raises(ValueError) as exc_stremthru:
        manager._write_stremthru_env()
    assert "STREMTHRU_AUTH" in str(exc_stremthru.value)
    assert codepoint in str(exc_stremthru.value)
    assert "SGCANARY" not in str(exc_stremthru.value)
    assert not manager.stremthru_env_file().exists()

    with pytest.raises(ValueError) as exc_env_line:
        supervisor._env_line("EXPECTED_VPN_IP", bad)
    assert "EXPECTED_VPN_IP" in str(exc_env_line.value)
    assert codepoint in str(exc_env_line.value)
    assert "SGCANARY" not in str(exc_env_line.value)

    with pytest.raises(ValueError) as exc_unit:
        supervisor._unit_value(bad)
    assert "unit value" in str(exc_unit.value).lower()
    assert codepoint in str(exc_unit.value)
    assert "SGCANARY" not in str(exc_unit.value)


# --- AC-5: Byte-identical rendering against 2de2bc7 goldens -----------------


def test_ac5_clean_rendering_matches_2de2bc7_goldens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-5: clean values render byte-for-byte identically to commit 2de2bc7."""
    goldens = json.loads(GOLDENS_PATH.read_text(encoding="utf-8"))

    for item in goldens["corpus"]:
        key = item["key"]
        value = item["value"]
        assert env.format_env_value(value) == item["format_env_value"]
        assert env.render_env_value(value) == item["render_env_value"]
        assert env.render_strict_env_value(value) == item["render_strict_env_value"]
        assert env.render_dotenv({key: value}, header="# hdr") == item["render_dotenv"]
        assert supervisor._env_line(key, value) == item["_env_line"]

    all_values = {item["key"]: item["value"] for item in goldens["corpus"]}
    assert env.render_dotenv(all_values, header="# corpus") == goldens["render_dotenv_all"]

    env_path = tmp_path / ".env"
    env_path.write_bytes(goldens["write_env_settings_initial"].encode("utf-8"))
    env.write_env_settings(env_path, {"DUP": "a # b", "PLAIN_REPLACE": "simple"})
    env.write_env_settings(env_path, {"ADDED": "it's $HOME", "KEEP": "updated"})
    assert env_path.read_bytes() == goldens["write_env_settings_after"].encode("utf-8")

    (tmp_path / ".env").write_text("COMET_ENABLED=1\n", encoding="utf-8")
    manager = CometManager(CometConfig.from_env(tmp_path), FakeRunner({}))
    monkeypatch.setattr(secrets, "token_urlsafe", lambda _n=24: goldens["stremthru_fixed_token"])
    manager._write_stremthru_env()
    actual_stremthru = manager.stremthru_env_file().read_bytes()
    assert actual_stremthru == goldens["stremthru_env"].encode()
    expected_line = f"STREMTHRU_AUTH=stremioguard:{goldens['stremthru_fixed_token']}\n".encode()
    assert expected_line in actual_stremthru


# --- AC-6: Repetition and untouched CRLF/raw lines --------------------------


@pytest.mark.parametrize(
    "initial_bytes",
    [
        b"KEY=old\nOTHER=kept\n",
        b"KEY=old\nOTHER=kept",
        b"OTHER=kept\r\nKEY=old\r\n",
    ],
    ids=["trailing_lf", "no_trailing_lf", "crlf"],
)
def test_ac6_repeated_write_env_settings_is_idempotent_and_preserves_untouched_crlf(
    tmp_path: Path, initial_bytes: bytes
) -> None:
    """AC-6 / D4: 100 consecutive writes do not grow the file and preserve untouched CRLF lines."""
    env_path = tmp_path / ".env"
    env_path.write_bytes(initial_bytes)

    env.write_env_settings(env_path, {"KEY": "stable"})
    after_first = env_path.read_bytes()
    if b"OTHER=kept\r\n" in initial_bytes:
        assert b"OTHER=kept\r\n" in after_first

    for _ in range(99):
        env.write_env_settings(env_path, {"KEY": "stable"})
        assert env_path.read_bytes() == after_first


def test_ac6_write_env_settings_keeps_untouched_forbidden_line_verbatim(tmp_path: Path) -> None:
    """D4: write_env_settings does not refuse because of another line and keeps it byte-for-byte."""
    env_path = tmp_path / ".env"
    env_path.write_bytes("BROKEN=a\u2028b\r\nKEY=old\n".encode("utf-8"))
    env.write_env_settings(env_path, {"KEY": "new"})
    assert env_path.read_bytes() == "BROKEN=a\u2028b\r\nKEY=new\n".encode("utf-8")


# --- AC-7: Refused publish leaves generation byte-identical -----------------


def _file_hashes(root: Path) -> dict[str, str]:
    targets = [
        root / GLUETUN_ENV_FILE,
        root / PUBLISHED_ENV_FILE,
        root / PUBLISHED_COMPOSE_FILE,
        root / GENERATED_COMPOSE_FILE,
    ]
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in targets}


def test_ac7_refused_publish_leaves_all_published_files_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-7 / AC-20 / D5: failed publish leaves gluetun.env, snapshot, base, override intact."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  gluetun:\n    image: qmcgaw/gluetun\n", encoding="utf-8"
    )
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\nOPENVPN_PASSWORD=good\n",
        encoding="utf-8",
    )
    write_minimal_bundle_manifest(make_comet_config(tmp_path))
    StackPublisher(tmp_path).publish()
    before_hashes = _file_hashes(tmp_path)

    # (a) Raw U+2028 in a gluetun key, with a changed non-gluetun key too.
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n"
        "COMET_TORBOX_API_KEY=changed\nOPENVPN_PASSWORD=pw\u2028X=1\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="U\\+2028"):
        StackPublisher(tmp_path).publish()
    assert _file_hashes(tmp_path) == before_hashes

    # (b) Raw U+2028 in a COMET_ key, with a changed gluetun key too.
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n"
        "OPENVPN_PASSWORD=changed\nCOMET_TORBOX_API_KEY=tok\u2028X=1\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="U\\+2028"):
        StackPublisher(tmp_path).publish()
    assert _file_hashes(tmp_path) == before_hashes

    # (c) Clean .env differing in both gluetun and non-gluetun keys, with parse_dotenv
    # patched inside publishing to leak COMET_X with U+2028.
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n"
        "OPENVPN_PASSWORD=changed\nCOMET_TORBOX_API_KEY=changed\n",
        encoding="utf-8",
    )
    real_parse_dotenv = env.parse_dotenv

    def leaky_parse_dotenv(text: str, *, source: str = ".env") -> dict[str, str]:
        parsed = real_parse_dotenv(text, source=source)
        parsed["COMET_X"] = "bad\u2028val"
        return parsed

    monkeypatch.setattr(publishing, "parse_dotenv", leaky_parse_dotenv)
    with pytest.raises(ValueError, match="COMET_X"):
        StackPublisher(tmp_path).publish()
    assert _file_hashes(tmp_path) == before_hashes


# --- AC-8: Teardown with a refused .env -------------------------------------


@pytest.mark.parametrize("with_snapshot", [False, True])
def test_ac8_teardown_and_failsafe_stop_services_despite_refused_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_snapshot: bool
) -> None:
    """AC-8 / INV-6: fail_safe() and stop attempt compose stop even when .env is refused."""
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  gluetun:\n    image: x\n", encoding="utf-8"
    )
    (tmp_path / ".stremio").mkdir(exist_ok=True)
    if with_snapshot:
        (tmp_path / PUBLISHED_ENV_FILE).write_text("STREMIO_ENABLED=1\n", encoding="utf-8")
        (tmp_path / PUBLISHED_COMPOSE_FILE).write_text(
            "services:\n  gluetun:\n    image: x\n", encoding="utf-8"
        )
        (tmp_path / GENERATED_COMPOSE_FILE).write_text("services: {}\n", encoding="utf-8")

    (tmp_path / ".env").write_text(
        "OPENVPN_PASSWORD=pw\u2028FIREWALL_OUTBOUND_SUBNETS=0.0.0.0/0\n",
        encoding="utf-8",
    )

    from stremioguard import config as config_mod
    from stremioguard.config import compose_command

    def _stop(o: orchestrator.Orchestrator) -> None:
        o.guard.require_commands()
        if not o.guard.stop_active_services():
            raise RuntimeError("Protected services could not be confirmed stopped.")

    for action_name, action in (
        ("stop", _stop),
        ("fail_safe", lambda o: o.fail_safe()),
    ):
        prefix = compose_command(tmp_path)
        responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]] = {
            ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
            ("docker", "ps", "--format", "{{.ID}}"): completed(
                ["docker", "ps", "--format", "{{.ID}}"]
            ),
            tuple([*prefix, "config", "--services"]): completed(
                [*prefix, "config", "--services"], "gluetun\nstremio\n"
            ),
            tuple([*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"]): completed(
                [*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"],
                "stremio\n",
            ),
            tuple([*prefix, "ps", "-q", "gluetun"]): completed(
                [*prefix, "ps", "-q", "gluetun"], ""
            ),
            tuple([*prefix, "stop", "stremio"]): completed([*prefix, "stop", "stremio"]),
        }
        # Second status query after stop reports services stopped.
        status_key = tuple([*prefix, "ps", *ACTIVE_STATUS_ARGS, "--services", "stremio"])
        runner = FakeRunner(
            {
                **responses,
                status_key: [
                    completed(list(status_key), "stremio\n"),
                    completed(list(status_key), ""),
                ],
            }
        )
        monkeypatch.setattr(orchestrator, "_deployment_root", lambda: tmp_path)
        monkeypatch.setattr(orchestrator, "configure_file_logging", lambda _cfg: None)
        monkeypatch.setattr(config_mod, "SubprocessRunner", lambda r=runner: r)
        monkeypatch.setattr(orchestrator, "SubprocessRunner", lambda r=runner: r, raising=False)
        from stremioguard import guard as guard_mod

        monkeypatch.setattr(guard_mod, "SubprocessRunner", lambda r=runner: r)

        orchestrator._run_command(action, teardown=True, deployed=(action_name == "fail_safe"))
        assert any(call[-2:] == ["stop", "stremio"] for call in runner.calls), action_name


# --- AC-9: Forwarded values and NordVPN endpoint station --------------------


@pytest.mark.parametrize("bad_char", ["\u2028", "\r", "\n"])
@pytest.mark.parametrize("cmd_name", ["start", "restart"])
def test_ac9a_start_and_restart_refuse_bad_forwarded_env_before_side_effects(
    monkeypatch: pytest.MonkeyPatch, bad_char: str, cmd_name: str
) -> None:
    """AC-9(a) / D6: start() and restart() refuse bad forwarded env before any side effect."""
    monkeypatch.setenv("IP_CHECK_URLS", f"https://example.test/ip{bad_char}EVIL=1")
    sink = StringIO()
    handler_id = logger.add(sink, format="{message}")
    try:
        with (
            mock.patch.object(general_cmd, "_warn_for_optional_stremio_settings"),
            mock.patch.object(supervisor, "prepare_supervision", return_value=False),
            mock.patch.object(supervisor, "stop_watchdog") as stop_watchdog,
            mock.patch.object(general_cmd, "run_guard") as run_guard,
            mock.patch.object(supervisor, "start_watchdog") as start_watchdog,
            pytest.raises(typer.Exit) as exc_info,
        ):
            getattr(general_cmd, cmd_name)()
    finally:
        logger.remove(handler_id)

    assert exc_info.value.exit_code == 1
    stop_watchdog.assert_not_called()
    run_guard.assert_not_called()
    start_watchdog.assert_not_called()
    log_output = sink.getvalue()
    assert "IP_CHECK_URLS" in log_output
    assert f"U+{ord(bad_char):04X}" in log_output
    assert "EVIL" not in log_output


@pytest.mark.parametrize(
    "bad_station",
    [
        "192.0.2.1\u2028X=1",
        "host.example",
        "",
        None,
        ["192.0.2.1"],
        " 192.0.2.1",
    ],
)
def test_ac9b_resolver_rejects_malformed_station_from_api_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_station: object
) -> None:
    """AC-9(b) / D7: malformed stations from API or cache never produce endpoint keys."""
    env_path = tmp_path / ".env"
    env_path.write_text("VPN_SERVICE_PROVIDER=nordvpn\nSERVER_COUNTRIES=Canada\n", encoding="utf-8")
    cache_path = tmp_path / "cache.json"

    # 1. From stub API response (no cache)
    payload = [
        {
            "hostname": "ca1.nordvpn.com",
            "station": bad_station,
            "status": "online",
            "load": 10,
            "locations": [{"country": {"name": "Canada", "city": {"name": "Toronto"}}}],
        }
    ]
    monkeypatch.setattr(resolver, "_fetch_nordvpn_recommendations", lambda **_kw: payload)
    assert resolver.nordvpn_endpoint_env(env_path, cache_path) == {}
    assert not cache_path.exists()

    # 2. From fresh cache (API returns empty)
    cache_path.write_text(
        json.dumps(
            {
                "country": "Canada",
                "city": None,
                "hostname": "ca1.nordvpn.com",
                "ip": bad_station,
                "timestamp": time.time(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(resolver, "_fetch_nordvpn_recommendations", lambda **_kw: [])
    assert resolver.nordvpn_endpoint_env(env_path, cache_path) == {}

    # 3. From stale cache when API fails
    cache_path.write_text(
        json.dumps(
            {
                "country": "Canada",
                "city": None,
                "hostname": "ca1.nordvpn.com",
                "ip": bad_station,
                "timestamp": time.time() - 100000,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        resolver,
        "_fetch_nordvpn_recommendations",
        mock.Mock(side_effect=OSError("offline")),
    )
    assert resolver.nordvpn_endpoint_env(env_path, cache_path) == {}


def test_ac9b_resolver_accepts_valid_station_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-9(b) / D7: valid public station IP sets both endpoint keys."""
    env_path = tmp_path / ".env"
    env_path.write_text("VPN_SERVICE_PROVIDER=nordvpn\nSERVER_COUNTRIES=Canada\n", encoding="utf-8")
    cache_path = tmp_path / "cache.json"
    payload = [
        {
            "hostname": "ca1.nordvpn.com",
            "station": PUBLIC_IPV4_STATION,
            "status": "online",
            "load": 10,
            "locations": [{"country": {"name": "Canada", "city": {"name": "Toronto"}}}],
        }
    ]
    monkeypatch.setattr(resolver, "_fetch_nordvpn_recommendations", lambda **_kw: payload)
    assert resolver.nordvpn_endpoint_env(env_path, cache_path) == {
        "OPENVPN_ENDPOINT_IP": PUBLIC_IPV4_STATION,
        "WIREGUARD_ENDPOINT_IP": PUBLIC_IPV4_STATION,
    }


def test_ac9c_clean_env_proceeds_for_start_and_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-9(c): regression for clean environment through start() and restart()."""
    monkeypatch.setenv("IP_CHECK_URLS", "https://example.test/ip")
    calls: list[str] = []
    with (
        mock.patch.object(general_cmd, "_warn_for_optional_stremio_settings"),
        mock.patch.object(supervisor, "prepare_supervision", return_value=False),
        mock.patch.object(
            supervisor, "stop_watchdog", side_effect=lambda: calls.append("stop") or True
        ),
        mock.patch.object(
            general_cmd, "run_guard", side_effect=lambda action, **_k: calls.append(action)
        ),
        mock.patch.object(
            supervisor, "start_watchdog", side_effect=lambda *_a, **_k: calls.append("watch")
        ),
    ):
        general_cmd.start()
        general_cmd.restart()
    assert calls == ["start", "watch", "stop", "reset", "watch"]


# --- AC-13: COMET_IMAGE grammar (unit part) ---------------------------------


@pytest.mark.parametrize(
    "valid_image",
    [
        "g0ldyy/comet",
        "ghcr.io/g0ldyy/comet",
        "localhost/comet",
        "localhost:5000/comet",
        "registry.local:5000/mirror/comet",
        "Registry.Example.com/team/comet",
        "my_org/comet__x",
        "a/b--c",
        "a/" + "b" * 253,
    ],
)
def test_ac13_accepts_valid_comet_image_repositories(tmp_path: Path, valid_image: str) -> None:
    """AC-13 / D10: valid Docker repository names are accepted."""
    assert len(valid_image) <= 255
    (tmp_path / ".env").write_text(
        f"COMET_ENABLED=1\nCOMET_IMAGE={valid_image}\n", encoding="utf-8"
    )
    cfg = CometConfig.from_env(tmp_path)
    assert cfg.image == valid_image


@pytest.mark.parametrize(
    "invalid_image",
    [
        "g0ldyy/comet #x",
        "g0ldyy/comet\tx",
        "-oProxyCommand=id",
        "$HOME/comet",
        '"g0ldyy/comet"',
        "g0ldyy//comet",
        "g0ldyy/comet_",
        "g0ldyy/_comet",
        "g0ldyy/comet.",
        "G0ldyy/comet",
        "a:b/c",
        "a/" + "b" * 254,
    ],
)
def test_ac13_rejects_invalid_comet_image_repositories(tmp_path: Path, invalid_image: str) -> None:
    """AC-13 / D10: invalid Docker repository names raise RuntimeError naming COMET_IMAGE."""
    (tmp_path / ".env").write_text(
        f"COMET_ENABLED=1\nCOMET_IMAGE='{invalid_image}'\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError) as exc_info:
        CometConfig.from_env(tmp_path)
    message = str(exc_info.value)
    assert "COMET_IMAGE" in message
    assert ascii(invalid_image) in message


@pytest.mark.parametrize("tagged", ["g0ldyy/comet:latest", "g0ldyy/comet@sha256:" + "a" * 64])
def test_ac13_rejects_tag_or_digest_with_existing_message(tmp_path: Path, tagged: str) -> None:
    """AC-13 / D10: tag or digest keeps the existing 'without a tag or digest' message."""
    (tmp_path / ".env").write_text(f"COMET_ENABLED=1\nCOMET_IMAGE={tagged}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="without a tag or digest"):
        CometConfig.from_env(tmp_path)


def test_ac13_rejects_dotenv_comment_injection_and_newline_escape(tmp_path: Path) -> None:
    """AC-13: single-quoted #x refused by D10; double-quoted \\n refused at parse by D2."""
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\nCOMET_IMAGE='g0ldyy/comet #x'\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="COMET_IMAGE"):
        CometConfig.from_env(tmp_path)

    (tmp_path / ".env").write_text(
        'COMET_ENABLED=1\nCOMET_IMAGE="g0ldyy/comet\\n    privileged: true"\n',
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="U\\+000A"):
        CometConfig.from_env(tmp_path)


# --- AC-14: Public URL errors -----------------------------------------------


@pytest.mark.parametrize("key", ["COMET_PUBLIC_BASE_URL", "COMET_GATEWAY_PUBLIC_BASE_URL"])
@pytest.mark.parametrize(
    "bad_url",
    [
        "ftp://user:SGC1@host/SGC2?t=SGC3#SGC4",
        "host.example/SGC5",
    ],
)
def test_ac14_public_url_errors_redact_value_and_name_key(
    tmp_path: Path, key: str, bad_url: str
) -> None:
    """AC-14 / D11: invalid public URL error names key and reason without leaking URL parts."""
    (tmp_path / ".env").write_text(f"COMET_ENABLED=1\n{key}={bad_url}\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as exc_info:
        CometConfig.from_env(tmp_path)
    message = str(exc_info.value)
    assert key in message
    assert "SGC" not in message


def test_ac14_valid_public_url_accepted(tmp_path: Path) -> None:
    """AC-14 regression: https://host.example/path is accepted."""
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=1\n"
        "COMET_PUBLIC_BASE_URL=https://host.example/path\n"
        "COMET_GATEWAY_PUBLIC_BASE_URL=https://host.example/path\n",
        encoding="utf-8",
    )
    cfg = CometConfig.from_env(tmp_path)
    assert cfg.public_base_url == "https://host.example/path"
    assert cfg.gateway_public_base_url == "https://host.example/path"


# --- AC-15: NordVPN credentials boundary ------------------------------------


def _bind_stub_server(
    handler_cls: type[http.server.BaseHTTPRequestHandler],
) -> tuple[http.server.ThreadingHTTPServer, int]:
    for port in range(19000, 19050):
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
            return server, port
        except OSError:
            continue
    raise AssertionError("No free port in 127.0.0.1:19000-19049")


def test_ac15_nordvpn_credentials_validation_with_stub_http_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-15 / D12: bounded read, strict UTF-8, string types, and D1 checks on NordVPN response."""
    valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    env_path = tmp_path / ".env"
    initial_env = b"VPN_TYPE=wireguard\nOPENVPN_USER=old\nOPENVPN_PASSWORD=old\n"
    env_path.write_bytes(initial_env)

    state: dict[str, object] = {"body": b"{}", "bytes_sent": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = state["body"]
            assert isinstance(body, bytes)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            sent = 0
            chunk_size = 16384
            try:
                for offset in range(0, len(body), chunk_size):
                    chunk = body[offset : offset + chunk_size]
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    sent += len(chunk)
            except OSError:
                pass
            state["bytes_sent"] = sent

        def log_message(self, format: str, *args: object) -> None:
            return

    server, port = _bind_stub_server(Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    secret_token = "SGC_SECRET_TOKEN_XYZ"
    monkeypatch.setattr(
        nordvpn,
        "NORDVPN_CREDENTIALS_API_URL",
        f"http://127.0.0.1:{port}/v1/users/services/credentials",
    )

    bad_payloads: list[tuple[str, bytes]] = [
        (
            "username_u2028",
            json.dumps(
                {
                    "nordlynx_private_key": valid_key,
                    "username": "usr\u2028INJECTED=SGC",
                    "password": "ok",
                }
            ).encode("utf-8"),
        ),
        (
            "password_vt",
            json.dumps(
                {
                    "nordlynx_private_key": valid_key,
                    "username": "ok",
                    "password": "pw\vSGC",
                }
            ).encode("utf-8"),
        ),
        (
            "username_list",
            json.dumps(
                {"nordlynx_private_key": valid_key, "username": ["SGC"], "password": "ok"}
            ).encode("utf-8"),
        ),
        (
            "username_dict",
            json.dumps(
                {"nordlynx_private_key": valid_key, "username": {"a": "SGC"}, "password": "ok"}
            ).encode("utf-8"),
        ),
        (
            "username_int",
            json.dumps(
                {"nordlynx_private_key": valid_key, "username": 12345, "password": "ok"}
            ).encode("utf-8"),
        ),
        (
            "5mib_body",
            b'{"nordlynx_private_key":"'
            + valid_key.encode("ascii")
            + b'","pad":"'
            + b"S" * (5 * 1024 * 1024)
            + b'"}',
        ),
        ("non_utf8", b"\xff" + b"SGC" * 10),
    ]

    try:
        for case_name, payload in bad_payloads:
            state["body"] = payload
            state["bytes_sent"] = 0
            log_sink = StringIO()
            handler_id = logger.add(log_sink, format="{message}")
            try:
                with (
                    mock.patch.object(
                        nordvpn, "_prompt_nordvpn_protocol", return_value="wireguard"
                    ),
                    mock.patch.object(
                        nordvpn, "_prompt_nordvpn_key_setup_mode", return_value="token"
                    ),
                    mock.patch.object(
                        nordvpn, "_prompt_nordvpn_access_token", return_value=secret_token
                    ),
                    pytest.raises(typer.Exit) as exc_info,
                ):
                    nordvpn.configure_nordvpn(env_path)
            finally:
                logger.remove(handler_id)

            assert exc_info.value.exit_code == 1, case_name
            assert env_path.read_bytes() == initial_env, case_name
            captured = capsys.readouterr()
            combined = captured.out + captured.err + log_sink.getvalue()
            assert "Traceback" not in combined, case_name
            assert "SGC" not in combined, case_name
            assert secret_token not in combined, case_name
            if case_name == "username_u2028":
                assert (
                    "NordVPN API returned a username containing U+2028, "
                    "which cannot be stored in .env."
                ) in combined
            if case_name == "5mib_body":
                # Client closes after reading 65537 bytes instead of draining 5 MiB.
                assert int(state["bytes_sent"]) < 5 * 1024 * 1024

        # (f) Valid response writes keys as before.
        state["body"] = json.dumps(
            {
                "nordlynx_private_key": valid_key,
                "username": "svc-user",
                "password": "svc-password",
            }
        ).encode("utf-8")
        with (
            mock.patch.object(nordvpn, "_prompt_nordvpn_protocol", return_value="wireguard"),
            mock.patch.object(nordvpn, "_prompt_nordvpn_key_setup_mode", return_value="token"),
            mock.patch.object(nordvpn, "_prompt_nordvpn_access_token", return_value=secret_token),
        ):
            nordvpn.configure_nordvpn(env_path)
        assert env.env_file_value(env_path, "WIREGUARD_PRIVATE_KEY") == valid_key
        assert env.env_file_value(env_path, "OPENVPN_USER") == "svc-user"
        assert env.env_file_value(env_path, "OPENVPN_PASSWORD") == "svc-password"
    finally:
        server.shutdown()
        server.server_close()


# --- AC-16: Fresh reads (no _ENV_CACHE) -------------------------------------


def test_ac16_read_env_file_is_never_stale_and_fails_on_unreadable(tmp_path: Path) -> None:
    """AC-16 / D13: same-size rewrite with preserved mtime returns new value; chmod 000 raises."""
    env_path = tmp_path / ".env"
    env_path.write_text("KEY=aaaa\n", encoding="utf-8")
    stat_before = env_path.stat()
    assert env.read_env_file(env_path) == {"KEY": "aaaa"}

    # Same size, different value, same mtime/atime.
    env_path.write_text("KEY=bbbb\n", encoding="utf-8")
    os.utime(env_path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    assert env.read_env_file(env_path) == {"KEY": "bbbb"}

    env_path.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            env.read_env_file(env_path)
    finally:
        env_path.chmod(0o600)


# --- AC-17: Private .env creation on init -----------------------------------


def test_ac17_init_creates_env_with_mode_0600_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-17 / D14: init creates .env with mode 0600 under umask 0022 via atomic_write_text."""
    env_example = tmp_path / ".env.example"
    env_file = tmp_path / ".env"
    example_text = "VPN_SERVICE_PROVIDER=nordvpn\nWIREGUARD_PRIVATE_KEY=<paste-key-here>\n"
    env_example.write_text(example_text, encoding="utf-8")

    seen_calls: list[tuple[Path, str, int]] = []
    real_atomic = env.atomic_write_text

    def spy_atomic(path: Path, content: str, *, mode: int = 0o644) -> None:
        seen_calls.append((path, content, mode))
        real_atomic(path, content, mode=mode)

    old_umask = os.umask(0o022)
    try:
        monkeypatch.setattr(general_cmd, "ENV_EXAMPLE", env_example)
        monkeypatch.setattr(general_cmd, "ENV_FILE", env_file)
        monkeypatch.setattr(general_cmd, "atomic_write_text", spy_atomic)
        monkeypatch.setattr(general_cmd, "is_interactive", lambda: True)
        monkeypatch.setattr(typer, "prompt", lambda *_a, **_k: "3")
        monkeypatch.setattr(general_cmd, "configure_optional_stremio_settings", lambda _p: None)
        monkeypatch.setattr(general_cmd, "configure_external_access", lambda *_a, **_k: None)
        monkeypatch.setattr(general_cmd, "run_guard", lambda *_a, **_k: None)
        monkeypatch.setattr(general_cmd, "prompt_provider", lambda _p: "custom")
        monkeypatch.setattr(general_cmd, "print_manual_setup_pointer", lambda: None)

        general_cmd.init()
    finally:
        os.umask(old_umask)

    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert seen_calls[0] == (env_file, example_text, 0o600)
    # Note: write_env_setting afterwards updates STREMIO_ENABLED / COMET_ENABLED,
    # keeping mode 0600 from initial creation via atomic_write_text(..., mode=0o600).
