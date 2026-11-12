"""Tests for Config class and environment loading validation."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.config import Config, _tunable_int


class TestConfig(unittest.TestCase):
    def test_from_env_both_disabled_raises_runtime_error(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return False
            if key == "COMET_ENABLED":
                return False
            return default

        with (
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
            self.assertRaises(RuntimeError) as ctx,
        ):
            Config.from_env()

        self.assertIn("both STREMIO_ENABLED and COMET_ENABLED are set to 0", str(ctx.exception))

    def test_from_env_stremio_enabled_only(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return True
            if key == "COMET_ENABLED":
                return False
            return default

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
        ):
            # Explicit root: from_env() defaults to the repo, whose .env is
            # root-owned on a hardened install and live on any install.
            config = Config.from_env(Path(directory))
        self.assertTrue(config.stremio_enabled)

    def test_from_env_comet_enabled_only(self) -> None:
        def mock_env_flag_enabled(key: str, default: bool, env_path: object) -> bool:
            if key == "STREMIO_ENABLED":
                return False
            if key == "COMET_ENABLED":
                return True
            return default

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("stremioguard.config.env_flag_enabled", side_effect=mock_env_flag_enabled),
        ):
            # Explicit root: from_env() defaults to the repo, whose .env is
            # root-owned on a hardened install and live on any install.
            config = Config.from_env(Path(directory))
        self.assertFalse(config.stremio_enabled)

    def test_from_env_parses_recovery_and_failover_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env_file = root / ".env"
            env_file.write_text(
                "SERVER_COUNTRIES=United States\n"
                "SERVER_REGIONS=North America\n"
                "SERVER_CITIES=Denver\n"
                "SERVER_HOSTNAMES=us123.nordvpn.com\n"
                "SERVER_CATEGORIES=P2P\n"
                "VPN_RECOVERY_BUDGET_SECONDS=400\n"
                "VPN_RESTART_CADENCE_SECONDS=60\n",
                encoding="utf-8",
            )
            config = Config.from_env(root)
            self.assertEqual(config.server_countries, "United States")
            self.assertEqual(config.server_regions, "North America")
            self.assertEqual(config.server_cities, "Denver")
            self.assertEqual(config.server_hostnames, "us123.nordvpn.com")
            self.assertEqual(config.server_categories, "P2P")
            self.assertEqual(config.vpn_recovery_budget_seconds, 400)
            self.assertEqual(config.vpn_restart_cadence_seconds, 60)
            self.assertEqual(config.vpn_lockout_file, root / ".stremio" / "vpn-lockout")


if __name__ == "__main__":
    unittest.main()


class TestTunableInt(unittest.TestCase):
    def test_env_var_wins_over_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("PUBLIC_IP_FAILURE_THRESHOLD=9\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "5"}):
                self.assertEqual(_tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3), 5)

    def test_prefixed_name_wins_over_bare(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            with mock.patch.dict(
                os.environ,
                {
                    "STREMIO_EGRESS_PROBE_INTERVAL_SECONDS": "60",
                    "EGRESS_PROBE_INTERVAL_SECONDS": "120",
                },
            ):
                self.assertEqual(_tunable_int(env_file, "EGRESS_PROBE_INTERVAL_SECONDS", 300), 60)

    def test_reads_env_file_and_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("EGRESS_PROBE_INTERVAL_SECONDS=45\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("EGRESS_PROBE_INTERVAL_SECONDS", None)
                os.environ.pop("STREMIO_EGRESS_PROBE_INTERVAL_SECONDS", None)
                self.assertEqual(_tunable_int(env_file, "EGRESS_PROBE_INTERVAL_SECONDS", 300), 45)
                self.assertEqual(_tunable_int(env_file, "MISSING_KEY", 300), 300)

    def test_rejects_invalid_and_below_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            with (
                mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "nope"}),
                self.assertRaisesRegex(RuntimeError, "Invalid PUBLIC_IP_FAILURE_THRESHOLD"),
            ):
                _tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3)
            with (
                mock.patch.dict(os.environ, {"PUBLIC_IP_FAILURE_THRESHOLD": "0"}),
                self.assertRaisesRegex(RuntimeError, "expected >= 1"),
            ):
                _tunable_int(env_file, "PUBLIC_IP_FAILURE_THRESHOLD", 3)


class TestProcessEnvRegistry(unittest.TestCase):
    """The supervised watchdog only sees forwarded keys; reads must be listed."""

    def test_every_process_env_read_in_config_is_registered(self) -> None:
        import re

        from stremioguard import config as config_mod

        source = Path(config_mod.__file__).read_text(encoding="utf-8")
        direct = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', source))
        tunables = set(re.findall(r'_tunable_int\(\s*env_file,\s*"([A-Z_]+)"', source))
        registered = set(config_mod.CONFIG_ENV_KEYS)
        self.assertLessEqual(direct, registered)
        self.assertLessEqual(tunables, set(config_mod.TUNABLE_KEYS))
        self.assertTrue(tunables)

    def test_watch_intervals_can_live_in_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "WATCH_INTERVAL_SECONDS=7\nWATCHDOG_LOG_INTERVAL_SECONDS=0\n", encoding="utf-8"
            )
            env = {
                k: v
                for k, v in os.environ.items()
                if "WATCH_INTERVAL" not in k and "WATCHDOG_LOG" not in k
            }
            with mock.patch.dict(os.environ, env, clear=True):
                config = Config.from_env(root)
        self.assertEqual(config.watch_interval_seconds, 7)
        self.assertEqual(config.watchdog_log_interval_seconds, 0)


def test_compose_command_ignores_an_exported_compose_file(tmp_path, monkeypatch) -> None:
    from stremioguard.config import compose_command

    monkeypatch.setenv("COMPOSE_FILE", "/elsewhere/docker-compose.yml")
    assert compose_command(tmp_path, "ps") == [
        "docker",
        "compose",
        "-f",
        str(tmp_path / "docker-compose.yml"),
        "ps",
    ]
    (tmp_path / ".stremio").mkdir()
    (tmp_path / ".stremio" / "docker-compose.bindings.yml").touch()
    assert "-f" in compose_command(tmp_path, "ps")[4:]


def test_bind_addresses_have_one_parser_with_every_rule(tmp_path) -> None:
    import pytest

    from stremioguard.config import parse_bind_addresses

    env = tmp_path / ".env"
    env.write_text("")
    assert parse_bind_addresses(env) == ["127.0.0.1"]
    env.write_text("STREMIO_BIND_ADDRS=\n")
    assert parse_bind_addresses(env) == []
    env.write_text("STREMIO_BIND_ADDRS=10.0.0.1, 10.0.0.1 ,100.64.0.1\n")
    assert parse_bind_addresses(env) == ["10.0.0.1", "100.64.0.1"]
    for bad in ("0.0.0.0,10.0.0.1", "::1", "nope"):
        env.write_text(f"STREMIO_BIND_ADDRS={bad}\n")
        with pytest.raises(RuntimeError):
            parse_bind_addresses(env)


# --- docker-compose.yml against the namespace port registry ----------------------

_COMPOSE_FILE = Path(__file__).resolve().parent.parent / "docker-compose.yml"


def _compose_services() -> dict[str, str]:
    """Each top-level service's block of docker-compose.yml, by name.

    A structural split (two-space service keys under `services:`), not a YAML
    parse: PyYAML is not a dependency. Good enough to read single-line values.
    """
    import re

    text = _COMPOSE_FILE.read_text(encoding="utf-8")
    body = text.split("\nservices:\n", 1)[1] if not text.startswith("services:\n") else text
    parts = re.split(r"^  ([a-z0-9][a-z0-9_-]*):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_stremthru_listens_and_is_probed_on_the_registered_port() -> None:
    import re

    from stremioguard.config import NAMESPACE_PORTS, STREMTHRU_INTERNAL_URL, STREMTHRU_PORT

    stremthru = _compose_services()["stremthru"]
    listen = re.search(r"^\s+STREMTHRU_LISTEN_ADDR:\s*\"?127\.0\.0\.1:(\d+)\"?$", stremthru, re.M)
    assert listen, "STREMTHRU_LISTEN_ADDR not found in the stremthru service"
    assert int(listen.group(1)) == STREMTHRU_PORT
    health = re.search(r"^\s+test:.*http://127\.0\.0\.1:(\d+)/v0/health", stremthru, re.M)
    assert health, "stremthru healthcheck URL not found"
    assert int(health.group(1)) == STREMTHRU_PORT
    assert f"http://127.0.0.1:{STREMTHRU_PORT}" == STREMTHRU_INTERNAL_URL
    assert NAMESPACE_PORTS["stremthru"] == STREMTHRU_PORT
    # The collision this registry exists to prevent: Stremio's own nginx.
    assert NAMESPACE_PORTS["stremio web UI (image's nginx)"] != STREMTHRU_PORT


def test_namespace_ports_are_unique_and_match_the_compose_file() -> None:
    import re

    from stremioguard.comet_gateway import COMET_GATEWAY_CONTAINER_PORT
    from stremioguard.config import COMET_PORT, NAMESPACE_PORTS

    ports = list(NAMESPACE_PORTS.values())
    duplicates = {port for port in ports if ports.count(port) > 1}
    assert not duplicates, f"two namespace listeners share {sorted(duplicates)}"
    assert NAMESPACE_PORTS["comet"] == COMET_PORT
    assert NAMESPACE_PORTS["comet-gateway"] == COMET_GATEWAY_CONTAINER_PORT
    gluetun = _compose_services()["gluetun"]
    control = re.search(r"HTTP_CONTROL_SERVER_ADDRESS:\s*\"?127\.0\.0\.1:(\d+)", gluetun)
    assert control and int(control.group(1)) == NAMESPACE_PORTS["gluetun control server"]


def test_gluetun_image_is_digest_pinned() -> None:
    import re

    image = re.search(r"^\s+image:\s*(\S+)\s*$", _compose_services()["gluetun"], re.M)
    assert image, "gluetun has no image line"
    assert re.fullmatch(r"qmcgaw/gluetun(:[\w.-]+)?@sha256:[0-9a-f]{64}", image.group(1)), (
        image.group(1)
    )


# --- Deployed configuration ----------------------------------------------------------


def test_deployed_env_file_prefers_the_published_snapshot(tmp_path) -> None:
    from stremioguard.config import deployed_env_file

    assert deployed_env_file(tmp_path) == tmp_path / ".env"
    snapshot = tmp_path / ".stremio" / "env.snapshot"
    snapshot.parent.mkdir()
    snapshot.write_text("", encoding="utf-8")
    assert deployed_env_file(tmp_path) == snapshot


def test_config_reads_alert_url_and_auto_start_limit_from_its_env_file(
    tmp_path, monkeypatch
) -> None:
    import pytest

    for key in ("MAX_AUTO_STARTS_PER_HOUR", "STREMIO_MAX_AUTO_STARTS_PER_HOUR"):
        monkeypatch.delenv(key, raising=False)
    snapshot = tmp_path / "env.snapshot"
    snapshot.write_text(
        "STREMIO_ALERT_URL='https://ntfy.example.test/topic'\nMAX_AUTO_STARTS_PER_HOUR='0'\n",
        encoding="utf-8",
    )
    config = Config.from_env(tmp_path, env_file=snapshot)
    assert config.env_file == snapshot
    assert config.alert_url == "https://ntfy.example.test/topic"
    assert config.max_auto_starts_per_hour == 0
    # Defaults when unset.
    empty = tmp_path / "empty.env"
    empty.write_text("", encoding="utf-8")
    config = Config.from_env(tmp_path, env_file=empty)
    assert config.alert_url is None
    assert config.max_auto_starts_per_hour == 10
    # A malformed URL fails loudly instead of silently never alerting.
    empty.write_text("STREMIO_ALERT_URL=ntfy.example.test/topic\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="STREMIO_ALERT_URL"):
        Config.from_env(tmp_path, env_file=empty)
    empty.write_text("MAX_AUTO_STARTS_PER_HOUR=-1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="MAX_AUTO_STARTS_PER_HOUR"):
        Config.from_env(tmp_path, env_file=empty)
