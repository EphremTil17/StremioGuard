"""Regression tests for compose-override rendering across different profiles."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stremioguard.config import PUBLISHED_COMPOSE_FILE, PUBLISHED_ENV_FILE, compose_command
from stremioguard.env import parse_dotenv
from stremioguard.publishing import (
    StackPublisher,
    ensure_gluetun_auth_config,
    render_stack_compose_override,
)

from .conftest import (
    REQUIRED_PATCH_OUTPUTS,
    FakeRunner,
    make_comet_config,
    make_comet_gateway_config,
    make_config,
    record_test_digest,
    write_bundle,
    write_minimal_bundle_manifest,
)


class TestPublishingOverride(unittest.TestCase):
    def test_unified_profile_publishing(self) -> None:
        comet_cfg = make_comet_config(Path("/tmp"), enabled=True)
        gateway_cfg = make_comet_gateway_config(Path("/tmp"), enabled=True)
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=True,
            comet_config=comet_cfg,
            comet_gateway_config=gateway_cfg,
        )
        # Check both Stremio and Comet Gateway ports are published
        self.assertIn('"10.0.0.1:11470:11470"', content)
        self.assertIn('"10.0.0.1:18001:8090"', content)
        # Check raw Comet is localhost-only
        self.assertIn('"127.0.0.1:18000:8000"', content)
        self.assertIn("comet:", content)
        self.assertIn("comet-gateway:", content)

    def test_override_leaves_postgres_paths_to_the_base_file(self) -> None:
        # The data directory and credentials file are fixed paths, so they live
        # in docker-compose.yml where every way of starting the stack picks
        # them up. Emitting them here too would restore the split that let a
        # plain `docker compose up` hand Postgres an anonymous volume.
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=False,
            comet_config=make_comet_config(Path("/tmp"), enabled=True),
            comet_gateway_config=None,
        )
        self.assertIn("comet:", content)
        self.assertNotIn("postgres-data", content)
        self.assertNotIn("postgres.env", content)

    def test_stremio_only_profile_publishing(self) -> None:
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=True,
            comet_config=None,
            comet_gateway_config=None,
        )
        self.assertIn('"10.0.0.1:11470:11470"', content)
        self.assertNotIn("comet:", content)
        self.assertNotIn("comet-gateway:", content)
        self.assertNotIn("18001", content)
        self.assertNotIn("18000", content)

    def test_comet_only_profile_publishing(self) -> None:
        comet_cfg = make_comet_config(Path("/tmp"), enabled=True)
        gateway_cfg = make_comet_gateway_config(Path("/tmp"), enabled=True)
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            stremio_enabled=False,
            comet_config=comet_cfg,
            comet_gateway_config=gateway_cfg,
        )
        self.assertNotIn('"10.0.0.1:11470:11470"', content)
        self.assertIn('"10.0.0.1:18001:8090"', content)
        self.assertIn('"127.0.0.1:18000:8000"', content)
        self.assertIn("comet:", content)
        self.assertIn("comet-gateway:", content)


class TestGluetunAuthConfig(unittest.TestCase):
    def test_ensure_writes_managed_role_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = ensure_gluetun_auth_config(root)
            content = path.read_text(encoding="utf-8")
            self.assertEqual(path, root / ".stremio" / "gluetun-auth.toml")
            self.assertIn("[[roles]]", content)
            self.assertIn('routes = ["GET /v1/publicip/ip"]', content)
            self.assertIn('auth = "none"', content)

    def test_ensure_preserves_user_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".stremio" / "gluetun-auth.toml"
            path.parent.mkdir(parents=True)
            custom = '[[roles]]\nname = "mine"\nauth = "basic"\n'
            path.write_text(custom, encoding="utf-8")
            ensure_gluetun_auth_config(root)
            self.assertEqual(path.read_text(encoding="utf-8"), custom)

    def test_ensure_refreshes_drifted_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".stremio" / "gluetun-auth.toml"
            path.parent.mkdir(parents=True)
            path.write_text("# Generated by ./stremio; old contents\n", encoding="utf-8")
            ensure_gluetun_auth_config(root)
            self.assertIn('routes = ["GET /v1/publicip/ip"]', path.read_text(encoding="utf-8"))

    def test_override_mounts_auth_config_into_gluetun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_file = ensure_gluetun_auth_config(root)
            content = render_stack_compose_override(
                bind_addresses=["10.0.0.1"],
                stremio_host_port=11470,
                stremio_container_port=11470,
                stremio_enabled=True,
                comet_config=None,
                gluetun_auth_config_file=auth_file,
            )
            self.assertIn(f"- {auth_file}:/gluetun/auth/config.toml:ro", content)


class TestStackPublisher(unittest.TestCase):
    def test_stack_publisher_produces_identical_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Write a dummy .env
            env_path = root / ".env"
            env_path.write_text(
                "STREMIO_BIND_ADDRS=10.0.0.1\nSTREMIO_ENABLED=1\nSTREMIO_HOST_PORT=11470\nSTREMIO_CONTAINER_PORT=11470\n",
                encoding="utf-8",
            )

            # Run publisher
            pub = StackPublisher(root)
            # Mock CometConfig and CometGatewayConfig to be disabled
            comet_cfg = make_comet_config(root, enabled=False)
            gateway_cfg = make_comet_gateway_config(root, enabled=False)

            with (
                mock.patch("stremioguard.publishing.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.publishing.CometGatewayConfig.from_env", return_value=gateway_cfg
                ),
            ):
                pub.publish()

            override_content = pub.compose_override_file.read_text(encoding="utf-8")

            # Direct rendering
            auth_file = ensure_gluetun_auth_config(root)
            direct_content = render_stack_compose_override(
                bind_addresses=["10.0.0.1"],
                stremio_host_port=11470,
                stremio_container_port=11470,
                stremio_enabled=True,
                comet_config=None,
                comet_gateway_config=None,
                gluetun_auth_config_file=auth_file,
            )
            self.assertEqual(override_content, direct_content)

    def test_compose_read_only_versus_fresh_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Write a dummy .env
            env_path = root / ".env"
            env_path.write_text(
                "STREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_ENABLED=1\n", encoding="utf-8"
            )

            from unittest import mock

            from stremioguard.guard import GluetunGuard

            runner = FakeRunner({})

            # Create a mock config
            cfg = make_config(root)
            guard = GluetunGuard(cfg, runner)

            # Generate the first compose override
            guard.write_compose_override()
            mtime_before = (
                (guard.config.root_dir / ".stremio" / "docker-compose.bindings.yml").stat().st_mtime
            )

            # 1. Calling read-only compose does NOT rewrite the override file
            # (publish is not called)
            with mock.patch("stremioguard.publishing.StackPublisher.publish") as publish_mock:
                guard.compose("ps", check=False)
                publish_mock.assert_not_called()
            self.assertEqual(
                (guard.config.root_dir / ".stremio" / "docker-compose.bindings.yml")
                .stat()
                .st_mtime,
                mtime_before,
            )

            # 2. Calling compose_fresh DOES call StackPublisher.publish
            with mock.patch("stremioguard.publishing.StackPublisher.publish") as publish_mock:
                guard.compose_fresh("up", "-d", check=False)
                publish_mock.assert_called_once()


class TestPublisherFailClosed(unittest.TestCase):
    def _env(self, root: Path, *, gateway: bool) -> None:
        (root / ".env").write_text(
            f"COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED={'1' if gateway else '0'}\n",
            encoding="utf-8",
        )

    def test_publish_raises_when_comet_enabled_but_manifest_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=False)
            record_test_digest(root / ".stremio" / "comet")
            with self.assertRaisesRegex(RuntimeError, "no override bundle exists for image"):
                StackPublisher(root).publish()
            self.assertFalse((root / ".stremio" / "docker-compose.bindings.yml").exists())

    def test_publish_raises_when_gateway_requires_missing_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=True)
            comet_cfg = make_comet_config(root)
            record_test_digest(comet_cfg.state_dir)
            # Manifest lacking the gateway-required stream/config/template outputs.
            write_bundle(comet_cfg, outputs={"torrentio.py": "/app/comet/scrapers/torrentio.py"})
            with self.assertRaisesRegex(RuntimeError, "required by this deployment shape"):
                StackPublisher(root).publish()

    def test_publish_accepts_manifest_with_required_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=True)
            comet_cfg = make_comet_config(root)
            record_test_digest(comet_cfg.state_dir)
            outputs = {
                **REQUIRED_PATCH_OUTPUTS,
                "stream.py": "/app/comet/api/endpoints/stream.py",
                "config.py": "/app/comet/api/endpoints/config.py",
                "media_search.py": "/app/comet/services/media_search.py",
                "index.html": "/app/comet/templates/index.html",
            }
            bundle_dir = write_bundle(comet_cfg, outputs=outputs)
            self.assertEqual(bundle_dir, comet_cfg.state_dir / "bundles" / ("sha256-" + "a" * 64))
            StackPublisher(root).publish()
            content = (root / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            for output_name, container_path in outputs.items():
                self.assertIn(f"- {bundle_dir / output_name}:{container_path}:ro", content)
            # Never the retired flat layout directly under state_dir.
            self.assertNotIn(f"{comet_cfg.state_dir / 'app.py'}:", content)

    def test_publish_refuses_bundle_rendered_for_another_digest(self) -> None:
        # A promotion that stopped halfway: the active digest's directory
        # holds a manifest claiming another image. Mounting one image's
        # patches over another must be refused, and nothing published.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=False)
            comet_cfg = make_comet_config(root)
            record_test_digest(comet_cfg.state_dir)
            write_bundle(comet_cfg, manifest_digest="sha256:" + "b" * 64)
            with self.assertRaisesRegex(RuntimeError, "rendered for image sha256:b"):
                StackPublisher(root).publish()
            self.assertFalse((root / ".stremio" / "docker-compose.bindings.yml").exists())
            self.assertFalse((root / PUBLISHED_ENV_FILE).exists())

    def test_publish_refuses_manifest_without_active_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=False)
            comet_cfg = make_comet_config(root)
            record_test_digest(comet_cfg.state_dir)
            bundle_dir = write_bundle(comet_cfg)
            manifest_path = bundle_dir / "bundle-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            del manifest["active_digest"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "an unknown digest"):
                StackPublisher(root).publish()

    def test_publish_refuses_when_a_listed_output_is_missing_on_disk(self) -> None:
        # Docker would create a directory at the missing bind source and
        # Comet would import a directory instead of its patched module.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._env(root, gateway=False)
            comet_cfg = make_comet_config(root)
            record_test_digest(comet_cfg.state_dir)
            bundle_dir = write_bundle(comet_cfg)
            (bundle_dir / "logger.py").unlink()
            with self.assertRaisesRegex(RuntimeError, "missing on disk: logger.py"):
                StackPublisher(root).publish()
            self.assertFalse((root / ".stremio" / "docker-compose.bindings.yml").exists())

    def test_publish_skips_manifest_check_when_comet_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("COMET_ENABLED=0\n", encoding="utf-8")
            StackPublisher(root).publish()
            self.assertTrue((root / ".stremio" / "docker-compose.bindings.yml").exists())


class TestStackPublisherDigestPinning(unittest.TestCase):
    def test_publish_pins_image_to_active_digest_from_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8"
            )
            comet_cfg = make_comet_config(root)
            from stremioguard.comet.state import CometState

            digest = "sha256:" + "9" * 64
            CometState(active_digest=digest).save(comet_cfg.state_dir / "state.json")
            bundle_dir = write_bundle(comet_cfg, digest)

            StackPublisher(root).publish()
            content = (root / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn(f"image: g0ldyy/comet@{digest}", content)
            self.assertIn(f"- {bundle_dir / 'app.py'}:/app/comet/api/app.py:ro", content)

    def test_publish_refuses_a_floating_tag_when_no_digest_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8"
            )
            write_bundle(make_comet_config(root))
            # Never run an unvalidated `:latest`; prepare_runtime bootstraps
            # a validated digest before anything publishes.
            with self.assertRaisesRegex(RuntimeError, "No validated Comet image digest"):
                StackPublisher(root).publish()
            self.assertFalse((root / ".stremio" / "docker-compose.bindings.yml").exists())

    def test_explicit_image_override_wins_over_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8"
            )
            comet_cfg = make_comet_config(root)
            from stremioguard.comet.state import CometState

            CometState(active_digest="sha256:" + "9" * 64).save(comet_cfg.state_dir / "state.json")
            override_digest = "sha256:" + "7" * 64
            # The bundle must be the override image's own, not the state's.
            write_bundle(comet_cfg, "sha256:" + "9" * 64)
            with self.assertRaisesRegex(RuntimeError, "no override bundle exists"):
                StackPublisher(root).publish(image_override=f"g0ldyy/comet@{override_digest}")
            override_bundle = write_bundle(comet_cfg, override_digest)

            StackPublisher(root).publish(image_override=f"g0ldyy/comet@{override_digest}")
            content = (root / ".stremio" / "docker-compose.bindings.yml").read_text(
                encoding="utf-8"
            )
            self.assertIn(f"image: g0ldyy/comet@{override_digest}", content)
            self.assertIn(f"- {override_bundle / 'app.py'}:", content)

    def test_image_override_without_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "COMET_ENABLED=1\nCOMET_GATEWAY_ENABLED=0\n", encoding="utf-8"
            )
            write_minimal_bundle_manifest(make_comet_config(root))
            with self.assertRaisesRegex(RuntimeError, "without a digest"):
                StackPublisher(root).publish(image_override="g0ldyy/comet:latest")


class TestPublishedGeneration(unittest.TestCase):
    """publish() writes the whole generation the stack then runs from."""

    def test_publish_writes_snapshot_and_base_copy_and_compose_uses_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_text = "services:\n  gluetun:\n    image: qmcgaw/gluetun\n"
            (root / "docker-compose.yml").write_text(base_text, encoding="utf-8")
            (root / ".env").write_text(
                "COMET_ENABLED=0\n"
                "export VPN_TYPE=wireguard\n"
                'OPENVPN_PASSWORD="p$ss # word"\n'
                "TZ=UTC # inline comment\n"
                "TZ=Europe/Berlin\n",
                encoding="utf-8",
            )
            # Before any publish: the working tree's base file, no env file.
            self.assertEqual(
                compose_command(root, "ps"),
                ["docker", "compose", "-f", str(root / "docker-compose.yml"), "ps"],
            )

            StackPublisher(root).publish()

            snapshot = root / PUBLISHED_ENV_FILE
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
            snapshot_text = snapshot.read_text(encoding="utf-8")
            self.assertEqual(
                snapshot_text.splitlines()[1:],
                [
                    "COMET_ENABLED='0'",
                    "VPN_TYPE='wireguard'",
                    "OPENVPN_PASSWORD='p$ss # word'",
                    "TZ='Europe/Berlin'",
                ],
            )
            self.assertEqual(
                parse_dotenv(snapshot_text),
                {
                    "COMET_ENABLED": "0",
                    "VPN_TYPE": "wireguard",
                    "OPENVPN_PASSWORD": "p$ss # word",
                    "TZ": "Europe/Berlin",
                },
            )

            base_copy = root / PUBLISHED_COMPOSE_FILE
            self.assertTrue(base_copy.read_text(encoding="utf-8").endswith(base_text))

            override = root / ".stremio" / "docker-compose.bindings.yml"
            self.assertEqual(
                compose_command(root, "ps"),
                [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(root),
                    "--env-file",
                    str(snapshot),
                    "-f",
                    str(base_copy),
                    "-f",
                    str(override),
                    "ps",
                ],
            )

            # The published generation is frozen: a working-tree edit after
            # the publish does not reach the copy compose reads.
            (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            self.assertTrue(base_copy.read_text(encoding="utf-8").endswith(base_text))

    def test_publish_without_base_file_keeps_unpublished_compose_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("COMET_ENABLED=0\n", encoding="utf-8")
            StackPublisher(root).publish()
            self.assertFalse((root / PUBLISHED_COMPOSE_FILE).exists())
            self.assertTrue((root / PUBLISHED_ENV_FILE).exists())
            override = root / ".stremio" / "docker-compose.bindings.yml"
            # All three files are required before the published form is used.
            self.assertEqual(
                compose_command(root, "ps"),
                [
                    "docker",
                    "compose",
                    "-f",
                    str(root / "docker-compose.yml"),
                    "-f",
                    str(override),
                    "ps",
                ],
            )


def test_gluetun_gets_only_its_own_settings_normalized() -> None:
    from stremioguard.publishing import render_gluetun_env

    env = "\n".join(
        [
            "# comment",
            "",
            "VPN_SERVICE_PROVIDER=nordvpn",
            'OPENVPN_PASSWORD="p@ss word"',
            "WIREGUARD_PRIVATE_KEY=abc=",
            "TZ=America/Los_Angeles",
            "SERVER_COUNTRIES=United States",
            "FIREWALL_OUTBOUND_SUBNETS=192.168.1.0/24",
            "COMET_TORBOX_API_KEY=secret",
            "COMET_CONFIGURE_PAGE_PASSWORD=secret",
            "STREMIO_BIND_ADDRS=127.0.0.1",
            "WATCH_INTERVAL_SECONDS=5",
            "EXTERNAL_BASE_URL=https://x",
        ]
    )
    rendered = render_gluetun_env(env)
    lines = rendered.splitlines()
    assert lines[0].startswith("# Generated by ./stremio")
    assert lines[1:] == [
        "VPN_SERVICE_PROVIDER='nordvpn'",
        "OPENVPN_PASSWORD='p@ss word'",
        "WIREGUARD_PRIVATE_KEY='abc='",
        "TZ='America/Los_Angeles'",
        "SERVER_COUNTRIES='United States'",
    ]
    # What the VPN container reads back is exactly the parsed .env value.
    assert parse_dotenv(rendered) == {
        "VPN_SERVICE_PROVIDER": "nordvpn",
        "OPENVPN_PASSWORD": "p@ss word",
        "WIREGUARD_PRIVATE_KEY": "abc=",
        "TZ": "America/Los_Angeles",
        "SERVER_COUNTRIES": "United States",
    }


def test_gluetun_env_filters_exported_and_spaced_stremioguard_keys() -> None:
    # The old line filter split on "=" and saw the key "export COMET_...",
    # which matched no prefix, so the debrid key reached the VPN container.
    from stremioguard.publishing import render_gluetun_env

    rendered = render_gluetun_env(
        "export COMET_TORBOX_API_KEY=secret\n"
        "  export   COMET_DEFAULT_DEBRID_APIKEY = other-secret\n"
        "COMET_CONFIGURE_PAGE_PASSWORD='quoted-secret'\n"
        "export VPN_TYPE=wireguard\n"
        "export STREMIO_ALERT_URL=https://ntfy.example.test/secret-topic\n"
    )
    assert "secret" not in rendered
    assert "STREMIO_" not in rendered
    assert "COMET_" not in rendered
    assert parse_dotenv(rendered) == {"VPN_TYPE": "wireguard"}


def test_gluetun_env_is_private_and_compose_uses_it(tmp_path: Path) -> None:
    from stremioguard.publishing import write_gluetun_env

    (tmp_path / ".env").write_text("VPN_TYPE=wireguard\nCOMET_TORBOX_API_KEY=k\n")
    path = write_gluetun_env(tmp_path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert "COMET_" not in path.read_text()
    compose = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text()
    gluetun = compose.split("\n  gluetun:\n", 1)[1].split("\n  stremio:\n", 1)[0]
    assert "./.stremio/gluetun.env" in gluetun
    assert "env_file: .env" not in compose


def test_publishing_from_the_snapshot_rewrites_only_the_override(tmp_path: Path) -> None:
    # What `./stremio comet start|update apply|rollback` do: re-render the
    # override from the DEPLOYED configuration. Pending edits to .env and
    # docker-compose.yml must stay pending, in every published file.
    from stremioguard.config import GLUETUN_ENV_FILE, PUBLISHED_COMPOSE_FILE, PUBLISHED_ENV_FILE

    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "COMET_ENABLED=0\nSTREMIO_BIND_ADDRS=127.0.0.1\nTZ=UTC\n", encoding="utf-8"
    )
    StackPublisher(tmp_path).publish()
    published = [
        tmp_path / name for name in (GLUETUN_ENV_FILE, PUBLISHED_ENV_FILE, PUBLISHED_COMPOSE_FILE)
    ]
    before = {path: path.read_bytes() for path in published}
    override = tmp_path / ".stremio" / "docker-compose.bindings.yml"
    deployed_override = override.read_text(encoding="utf-8")
    assert '"127.0.0.1:11470:11470"' in deployed_override

    (tmp_path / ".env").write_text(
        "COMET_ENABLED=0\nSTREMIO_BIND_ADDRS=0.0.0.0\nTZ=Europe/Berlin\n", encoding="utf-8"
    )
    (tmp_path / "docker-compose.yml").write_text("services: {changed: {}}\n", encoding="utf-8")
    override.unlink()
    StackPublisher(tmp_path, env_file=tmp_path / PUBLISHED_ENV_FILE).publish()

    assert {path: path.read_bytes() for path in published} == before
    # Rendered again, from the snapshot: the pending bind change is not in it.
    assert override.read_text(encoding="utf-8") == deployed_override

    # A deploy picks all of it up.
    StackPublisher(tmp_path).publish()
    assert '"0.0.0.0:11470:11470"' in override.read_text(encoding="utf-8")
    assert "Europe/Berlin" in (tmp_path / PUBLISHED_ENV_FILE).read_text(encoding="utf-8")
    assert "changed" in (tmp_path / PUBLISHED_COMPOSE_FILE).read_text(encoding="utf-8")
