"""Tests for the token-based authentication proxy module."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from stremioguard.auth import AUTH_CONTAINER_PORT, AuthConfig, AuthManager
from stremioguard.publishing import render_stack_compose_override
from tests.conftest import make_auth_config, make_comet_config

# ── AuthConfig ─────────────────────────────────────────────────────


class TestAuthConfig:
    def test_from_env_disabled_by_default(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("VPN_SERVICE_PROVIDER=nordvpn\n", encoding="utf-8")
        config = AuthConfig.from_env(tmp_path)
        assert config.enabled is False
        assert config.host_port == 11471
        assert config.token_length == 8

    def test_from_env_enabled(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "AUTH_ENABLED=1\nAUTH_HOST_PORT=9999\nAUTH_TOKEN_LENGTH=6\n"
            "AUTH_DOMAIN=my.domain.com\nSTREMIO_BIND_ADDRS=10.0.0.1\n",
            encoding="utf-8",
        )
        config = AuthConfig.from_env(tmp_path)
        assert config.enabled is True
        assert config.host_port == 9999
        assert config.token_length == 6
        assert config.domain == "my.domain.com"
        assert config.bind_addresses == ("10.0.0.1",)

    def test_from_env_infers_domain_from_external_base_url(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "AUTH_ENABLED=1\nEXTERNAL_BASE_URL=https://stremio.example.com\n",
            encoding="utf-8",
        )
        config = AuthConfig.from_env(tmp_path)
        assert config.domain == "stremio.example.com"

    def test_from_env_explicit_domain_overrides_external_url(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "AUTH_ENABLED=1\nAUTH_DOMAIN=custom.domain.com\n"
            "EXTERNAL_BASE_URL=https://other.domain.com\n",
            encoding="utf-8",
        )
        config = AuthConfig.from_env(tmp_path)
        assert config.domain == "custom.domain.com"

    def test_from_env_invalid_port_raises(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("AUTH_HOST_PORT=notaport\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="Invalid AUTH_HOST_PORT"):
            AuthConfig.from_env(tmp_path)

    def test_from_env_invalid_token_length_raises(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("AUTH_TOKEN_LENGTH=2\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="Invalid AUTH_TOKEN_LENGTH"):
            AuthConfig.from_env(tmp_path)


# ── Token CRUD ─────────────────────────────────────────────────────


class TestTokenCRUD:
    def test_add_token_creates_file(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        token_id, token_value = manager.add_token("Dad's TV")
        assert config.tokens_file.exists()
        assert len(token_id) == 6
        assert len(token_value) == config.token_length
        data = json.loads(config.tokens_file.read_text(encoding="utf-8"))
        assert token_id in data["tokens"]
        assert data["tokens"][token_id]["label"] == "Dad's TV"
        assert data["tokens"][token_id]["token"] == token_value

    def test_add_token_file_permissions(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        manager.add_token("test")
        mode = os.stat(config.tokens_file).st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_add_multiple_tokens_unique(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        id1, val1 = manager.add_token("Device A")
        id2, val2 = manager.add_token("Device B")
        assert id1 != id2
        assert val1 != val2
        assert len(manager.list_tokens()) == 2

    def test_revoke_token(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        token_id, _ = manager.add_token("Temp Device")
        label = manager.revoke_token(token_id)
        assert label == "Temp Device"
        assert len(manager.list_tokens()) == 0

    def test_revoke_nonexistent_raises(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        with pytest.raises(KeyError):
            manager.revoke_token("nonexistent")

    def test_rotate_token_preserves_label(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        old_id, old_val = manager.add_token("My Phone")
        new_id, new_val = manager.rotate_token(old_id)
        assert new_id != old_id
        assert new_val != old_val
        tokens = manager.list_tokens()
        assert len(tokens) == 1
        assert tokens[0]["label"] == "My Phone"
        assert tokens[0]["id"] == new_id

    def test_list_tokens_returns_all(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        manager.add_token("A")
        manager.add_token("B")
        manager.add_token("C")
        tokens = manager.list_tokens()
        assert len(tokens) == 3
        labels = {t["label"] for t in tokens}
        assert labels == {"A", "B", "C"}

    def test_list_tokens_empty(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        assert manager.list_tokens() == []


# ── Nginx config generation ────────────────────────────────────────


class TestNginxConfig:
    def test_render_tokens_map_with_tokens(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        manager.add_token("Device A")
        manager.add_token("Device B")
        rendered = manager.render_tokens_map()
        assert "map $token_from_uri $token_valid" in rendered
        assert "default 0;" in rendered
        assert rendered.count('" 1;') == 2

    def test_render_tokens_map_empty(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_tokens_map()
        assert "default 0;" in rendered
        assert '" 1;' not in rendered

    def test_render_nginx_conf_proxy_pass(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "$upstream http://gluetun:11470" in rendered
        assert "proxy_pass $upstream" in rendered
        assert "resolver 127.0.0.11" in rendered

    def test_render_nginx_conf_websocket_headers(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "proxy_set_header Upgrade" in rendered
        assert 'proxy_set_header Connection "upgrade"' in rendered

    def test_render_nginx_conf_forwards_token_prefix(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "proxy_set_header X-Forwarded-Prefix /$auth_token;" in rendered
        assert "proxy_set_header X-Forwarded-Host $host;" in rendered

    def test_render_nginx_conf_omits_client_ip_forwarding(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert 'proxy_set_header X-Real-IP "";' in rendered
        assert 'proxy_set_header X-Forwarded-For "";' in rendered

    def test_render_nginx_conf_rate_limiting(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "limit_req_zone" in rendered
        assert "limit_req zone=auth_fail" in rendered

    def test_render_nginx_conf_listen_port(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert f"listen {AUTH_CONTAINER_PORT};" in rendered

    def test_render_nginx_conf_token_length_in_regex(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path, token_length=6)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "{6,10}" in rendered

    def test_render_nginx_conf_403_for_invalid(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "return 403" in rendered

    def test_write_nginx_configs_creates_files(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        manager.write_nginx_configs()
        assert config.nginx_conf_file.exists()
        assert config.tokens_map_file.exists()

    def test_render_nginx_conf_no_trailing_slash_redirect(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        rendered = manager.render_nginx_conf()
        assert "return 301" in rendered


# ── URL display ────────────────────────────────────────────────────


class TestDisplayHelpers:
    def test_full_url_with_domain(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path, domain="streamio.example.com")
        manager = AuthManager(config)
        assert manager.full_url("abc123") == "https://streamio.example.com/abc123/"

    def test_full_url_without_domain(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path, domain=None)
        manager = AuthManager(config)
        url = manager.full_url("abc123")
        assert url == "http://127.0.0.1:11471/abc123/"

    def test_upstream_snippet_content(self, tmp_path: Path) -> None:
        config = make_auth_config(tmp_path)
        manager = AuthManager(config)
        snippet = manager.upstream_snippet()
        assert "11471" in snippet
        assert "11470" in snippet


# ── Compose override integration ───────────────────────────────────


class TestComposeOverride:
    def test_override_includes_auth_proxy_when_enabled(self, tmp_path: Path) -> None:
        auth_config = make_auth_config(tmp_path, bind_addresses=("10.0.0.1",))
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=None,
            auth_config=auth_config,
        )
        assert "auth-proxy:" in content
        assert f"10.0.0.1:11471:{AUTH_CONTAINER_PORT}" in content
        assert "nginx.conf:/etc/nginx/nginx.conf:ro" in content
        assert "tokens.map:/etc/nginx/tokens.map:ro" in content
        assert '"10.0.0.1:11470:11470"' not in content

    def test_override_omits_auth_proxy_when_none(self, tmp_path: Path) -> None:
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=None,
            auth_config=None,
        )
        assert "auth-proxy:" not in content

    def test_override_includes_both_auth_and_comet(self, tmp_path: Path) -> None:
        auth_config = make_auth_config(tmp_path, bind_addresses=("10.0.0.1",))
        comet_config = make_comet_config(tmp_path)
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=comet_config,
            auth_config=auth_config,
        )
        assert "auth-proxy:" in content
        assert "comet:" in content

    def test_override_auth_proxy_multiple_bind_addresses(self, tmp_path: Path) -> None:
        auth_config = make_auth_config(tmp_path, bind_addresses=("10.0.0.1", "100.64.0.1"))
        content = render_stack_compose_override(
            bind_addresses=["10.0.0.1", "100.64.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=None,
            auth_config=auth_config,
        )
        assert f"10.0.0.1:11471:{AUTH_CONTAINER_PORT}" in content
        assert f"100.64.0.1:11471:{AUTH_CONTAINER_PORT}" in content
        assert '"10.0.0.1:11470:11470"' not in content
        assert '"100.64.0.1:11470:11470"' not in content
