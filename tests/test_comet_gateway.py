"""Tests for the token-managed Comet gateway."""

from __future__ import annotations

from pathlib import Path

import pytest

from stremioguard.comet_gateway import (
    COMET_GATEWAY_CONTAINER_PORT,
    CometGatewayConfig,
    CometGatewayManager,
)
from stremioguard.publishing import render_stack_compose_override
from tests.conftest import make_comet_config, make_comet_gateway_config


class TestCometGatewayConfig:
    def test_defaults_to_enabled_loopback_gateway(self, tmp_path: Path) -> None:
        config = CometGatewayConfig.from_env(tmp_path)

        assert config.enabled is True
        assert config.host_port == 18001
        assert config.bind_addresses == ("127.0.0.1",)
        assert config.token_length == 8

    def test_reads_env_values(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "COMET_GATEWAY_ENABLED=1\n"
            "COMET_GATEWAY_HOST_PORT=19001\n"
            "COMET_GATEWAY_PUBLIC_BASE_URL=https://comet.example.test\n"
            "COMET_GATEWAY_TOKEN_LENGTH=12\n"
            "STREMIO_BIND_ADDRS=10.0.0.1,100.64.0.2\n",
            encoding="utf-8",
        )

        config = CometGatewayConfig.from_env(tmp_path)

        assert config.host_port == 19001
        assert config.public_base_url == "https://comet.example.test"
        assert config.token_length == 12
        assert config.bind_addresses == ("10.0.0.1", "100.64.0.2")

    def test_rejects_invalid_port(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("COMET_GATEWAY_HOST_PORT=nope\n", encoding="utf-8")

        with pytest.raises(RuntimeError, match="Invalid COMET_GATEWAY_HOST_PORT"):
            CometGatewayConfig.from_env(tmp_path)


class TestCometGatewayManager:
    def test_add_first_token_makes_it_default(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))

        token_id, token = manager.add_token("Shared Addon")

        assert manager.default_token_id() == token_id
        assert manager.default_token() == token
        assert manager.addon_base_url(token) == f"https://comet.example.com/comet/{token}"
        assert manager.config.tokens_file.stat().st_mode & 0o777 == 0o600

    def test_rotate_preserves_default_status(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        token_id, old_token = manager.add_token("Shared Addon")

        new_id, new_token = manager.rotate_token(token_id)

        assert new_id != token_id
        assert new_token != old_token
        assert manager.default_token_id() == new_id
        assert manager.default_token() == new_token

    def test_revoke_default_promotes_oldest_remaining_token(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        first_id, _ = manager.add_token("First")
        second_id, _ = manager.add_token("Second")

        manager.revoke_token(first_id)

        assert manager.default_token_id() == second_id

    def test_use_selects_default_token(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        first_id, _ = manager.add_token("First")
        second_id, _ = manager.add_token("Second")

        manager.use_token(second_id)

        assert manager.default_token_id() == second_id
        assert first_id != second_id

    def test_rewrite_manifest_url_strips_existing_gateway_prefix(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        token_id, token = manager.add_token("Shared Addon")

        rewritten = manager.rewrite_manifest_url(
            "https://old.example/comet/oldtoken/abc123/manifest.json",
            token_id,
        )

        assert rewritten == f"https://comet.example.com/comet/{token}/abc123/manifest.json"

    def test_render_nginx_allows_configure_and_blocks_direct_addon_paths(
        self,
        tmp_path: Path,
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Shared Addon")
        rendered = manager.render_nginx_conf()

        assert f"listen {COMET_GATEWAY_CONTAINER_PORT};" in rendered
        assert "location / {" in rendered
        assert "proxy_pass $comet_upstream$request_uri;" in rendered
        assert "return 403" in rendered
        assert "/comet/$gateway_token" in rendered
        assert "proxy_pass $comet_upstream$comet_uri$is_args$args;" in rendered

    def test_render_tokens_map_marks_known_tokens_valid(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        _, token = manager.add_token("Shared Addon")

        rendered = manager.render_tokens_map()

        assert f'"{token}" 1;' in rendered
        assert "default 0;" in rendered


class TestCometGatewayPublishing:
    def test_gateway_publishes_on_gluetun_and_raw_comet_is_loopback_only(
        self,
        tmp_path: Path,
    ) -> None:
        comet = make_comet_config(tmp_path, bind_addresses=("10.0.0.1", "100.64.0.1"))
        gateway = make_comet_gateway_config(
            tmp_path,
            bind_addresses=("10.0.0.1", "100.64.0.1"),
        )

        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1", "100.64.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=comet,
            comet_gateway_config=gateway,
            stremio_enabled=True,
        )

        assert '"127.0.0.1:18000:8000"' in content
        assert '"10.0.0.1:18001:8090"' in content
        assert '"100.64.0.1:18001:8090"' in content
        assert '"10.0.0.1:18000:8000"' not in content
        assert "comet-gateway:" in content
        assert str(gateway.nginx_conf_file) in content

    def test_gateway_disabled_keeps_direct_comet_publish(self, tmp_path: Path) -> None:
        comet = make_comet_config(tmp_path, bind_addresses=("10.0.0.1",))
        gateway = make_comet_gateway_config(tmp_path, enabled=False)

        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=comet,
            comet_gateway_config=gateway,
            stremio_enabled=True,
        )

        assert '"10.0.0.1:18000:8000"' in content
        assert "comet-gateway:" not in content
