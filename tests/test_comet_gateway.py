"""Tests for the token-managed Comet gateway."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from unittest import mock

import pytest

from stremioguard import comet_gateway as gateway_mod
from stremioguard.comet_gateway import (
    COMET_GATEWAY_CONTAINER_PORT,
    CometGatewayConfig,
    CometGatewayManager,
)
from stremioguard.publishing import render_stack_compose_override
from tests.conftest import FakeRunner, completed, make_comet_config, make_comet_gateway_config


class TestCometGatewayConfig:
    def test_defaults_to_enabled_loopback_gateway(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("COMET_ENABLED=1\n", encoding="utf-8")
        config = CometGatewayConfig.from_env(tmp_path)

        assert config.enabled is True
        assert config.host_port == 18001
        assert config.bind_addresses == ("127.0.0.1",)
        assert config.token_length == 8

    def test_reads_env_values(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "COMET_ENABLED=1\n"
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
        (tmp_path / ".env").write_text(
            "COMET_ENABLED=1\nCOMET_GATEWAY_HOST_PORT=nope\n", encoding="utf-8"
        )

        with pytest.raises(RuntimeError, match="Invalid COMET_GATEWAY_HOST_PORT"):
            CometGatewayConfig.from_env(tmp_path)

    def test_rejects_short_token_length(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text(
            "COMET_ENABLED=1\nCOMET_GATEWAY_TOKEN_LENGTH=4\n", encoding="utf-8"
        )

        with pytest.raises(RuntimeError, match="COMET_GATEWAY_TOKEN_LENGTH"):
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
        assert "absolute_redirect off;" in rendered
        assert 'location ~ "^/(?:configure(?:/|$)|static/|health(?:/|$))" {' in rendered
        assert "admin" not in rendered.split('location ~ "^/(?:configure')[1].split("\n", 1)[0]
        assert "location = / {" in rendered
        assert "proxy_pass $comet_upstream$request_uri;" in rendered
        assert (
            "location / {\n"
            "            limit_req zone=gateway_fail burst=3 nodelay;\n"
            "            deny all;\n"
            "        }" in rendered
        )
        assert "/comet/$gateway_token" in rendered
        assert "proxy_pass $comet_upstream$raw_comet_path$is_args$args;" in rendered
        assert "return 302 /comet/$gateway_token/configure;" in rendered

    def test_render_tokens_map_marks_known_tokens_valid(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        _, token = manager.add_token("Shared Addon")

        rendered = manager.render_tokens_map()

        assert f'"~^{token}$" 1;' in rendered
        assert "default 0;" in rendered

    def test_render_nginx_rate_limits_auth_failures_not_valid_tokens(
        self,
        tmp_path: Path,
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Shared Addon")
        rendered = manager.render_nginx_conf()

        # Invalid tokens must NOT be rejected by a rewrite-phase `return 403`
        # (which would run before limit_req's preaccess phase and bypass the
        # limiter); they are rewritten into an internal location whose
        # access-phase `deny all` rejects AFTER limit_req has counted them.
        assert "limit_req_zone $binary_remote_addr zone=gateway_auth:1m rate=5r/s;" in rendered
        assert "limit_req_zone $binary_remote_addr zone=gateway_admin:1m rate=10r/s;" in rendered
        assert rendered.count("rewrite ^ /__sg_invalid_token last;") == 1
        assert "location = /__sg_invalid_token {" in rendered
        assert "limit_req zone=gateway_auth burst=10 nodelay;" in rendered
        assert "location = /__sg_forbidden {" in rendered
        assert "limit_req zone=gateway_fail burst=3 nodelay;" in rendered
        assert "deny all;" in rendered
        # Valid-token proxying must carry no limiter — playback seeking is bursty.
        token_location = rendered.split("location ^~ /comet/ {")[1].split("\n        }", 1)[0]
        assert "limit_req" not in token_location
        # No rewrite-phase return 403 remains in the token locations.
        assert "if ($token_valid = 0) {\n                return 403;" not in rendered
        # Configure/admin and root proxy get the human-paced admin limiter.
        assert rendered.count("limit_req zone=gateway_admin burst=20 nodelay;") == 2

    def test_render_nginx_masks_token_in_access_log(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        _, token = manager.add_token("Shared Addon")
        rendered = manager.render_nginx_conf()

        # The access log uses the masked request variable, never the raw one.
        assert 'log_format main \'$remote_addr [$time_local] "$request_masked"' in rendered
        assert '"$request" $status' not in rendered
        assert "map $request $request_masked {" in rendered
        # The concrete token value must never appear anywhere in the rendered conf.
        assert token not in rendered

    def test_render_nginx_keeps_request_lines_out_of_error_log(self, tmp_path: Path) -> None:
        # nginx appends the raw request line (token + base64 config) to every
        # request-context error entry; upstream failures log at [error].
        rendered = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()

        error_logs = [line for line in rendered.splitlines() if line.startswith("error_log")]
        assert error_logs == ["error_log /var/log/nginx/error.log crit;"]
        # Failure diagnostics move to the masked access log instead.
        assert "upstream=$upstream_status urt=$upstream_response_time rt=$request_time" in rendered

    def test_mask_regex_hides_token_and_config_blob(self, tmp_path: Path) -> None:
        # Plan 0.1: verify the mask against a real playback request line. It
        # carries the token AND the base64 config blob after it (which can
        # embed debrid API keys) — neither may survive into the access log.
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        _, token = manager.add_token("Shared Addon")
        rendered = manager.render_nginx_conf()

        mask_line = next(line for line in rendered.splitlines() if "***" in line)
        nginx_pattern = mask_line.strip().split(" ")[0].removeprefix("~")
        pattern = re.compile(nginx_pattern.replace("?<", "?P<"))

        blob = "eyJkZWJyaWRBcGlLZXkiOiJzZWNyZXQta2V5In0"
        line = f"GET /comet/{token}/{blob}/playback/tt1234/deadbeef HTTP/1.1"
        match = pattern.match(line)
        assert match is not None
        masked = match.group("mrh") + "***" + match.group("mrt")
        assert masked == "GET /comet/*** HTTP/1.1"
        assert token not in masked
        assert blob not in masked

    def test_write_nginx_configs_writes_secret_files_at_0600(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Shared Addon")

        manager.write_nginx_configs()

        assert manager.config.nginx_conf_file.stat().st_mode & 0o777 == 0o600
        assert manager.config.tokens_map_file.stat().st_mode & 0o777 == 0o600


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
        # The directory, never single files: see test_reload_proves_the_new_map_landed.
        assert f"{gateway.state_dir}:{gateway_mod.GATEWAY_CONFIG_DIR}:ro" in content
        assert "nginx.conf:" not in content
        assert "tokens.map:" not in content

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


class TestGatewayReload:
    def _manager(
        self,
        tmp_path: Path,
        *,
        conf_hash: str = "match",
        map_hash: str = "match",
    ) -> tuple[CometGatewayManager, FakeRunner]:
        config = make_comet_gateway_config(tmp_path)
        manager = CometGatewayManager(config, runner := FakeRunner({}))
        manager.write_nginx_configs()
        nginx = [
            "docker",
            "exec",
            "cid",
            "nginx",
            "-c",
            f"{gateway_mod.GATEWAY_CONFIG_DIR}/nginx.conf",
        ]
        runner.responses[(*nginx, "-t")] = completed([], stdout="")
        runner.responses[(*nginx, "-s", "reload")] = completed([], stdout="")
        for name, host_file, mode in (
            ("nginx.conf", config.nginx_conf_file, conf_hash),
            ("tokens.map", config.tokens_map_file, map_hash),
        ):
            digest = (
                hashlib.sha256(host_file.read_bytes()).hexdigest() if mode == "match" else "0" * 64
            )
            container_path = f"{gateway_mod.GATEWAY_CONFIG_DIR}/{name}"
            runner.responses[("docker", "exec", "cid", "sha256sum", container_path)] = completed(
                [], stdout=f"{digest}  {container_path}\n"
            )
        return manager, runner

    def test_reload_proves_the_new_map_landed(self, tmp_path: Path) -> None:
        manager, runner = self._manager(tmp_path)
        with mock.patch.object(manager, "service_container_id", return_value="cid"):
            manager.reload_nginx()
        assert runner.calls[-1][-2:] == ["-s", "reload"]
        assert "-t" in runner.calls[0]
        sha_calls = [call for call in runner.calls if "sha256sum" in call]
        assert len(sha_calls) == 2

    def test_render_nginx_enforces_addon_allowlist_and_forwards_encoded_paths(
        self,
        tmp_path: Path,
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Shared Addon")
        rendered = manager.render_nginx_conf()

        allowlist_header = [
            line for line in rendered.splitlines() if "location ~" in line and "configure" in line
        ][0]
        allowlist_re = re.compile(allowlist_header.split('"', 2)[1])
        assert allowlist_re.match("/configure")
        assert allowlist_re.match("/static/app.js")
        assert allowlist_re.match("/health")
        assert not allowlist_re.match("/admin")
        assert not allowlist_re.match("/admin/login")
        assert not allowlist_re.match("/kodi/get_manifest/123456")

        assert "map $request_uri $gateway_token {" in rendered
        assert "map $request_uri $raw_comet_path {" in rendered
        assert "map $raw_comet_path $comet_route_action {" in rendered
        assert 'if ($raw_comet_path = "") {\n                return 400;\n            }' in rendered
        assert "proxy_pass $comet_upstream$raw_comet_path$is_args$args;" in rendered
        assert "return 302 /comet/$gateway_token/configure;" in rendered
        assert "~*^\\s*https(?:[\\s,]|$) https;" in rendered
        assert "token_re" not in rendered and "[A-Za-z0-9_-]+" in rendered

    def test_reload_refuses_when_the_container_sees_a_stale_map(self, tmp_path: Path) -> None:
        # A file bind mount keeps the old inode: nginx would reload the old
        # tokens and a revoked token would keep working.
        manager, runner = self._manager(tmp_path, map_hash="stale")
        with (
            mock.patch.object(manager, "service_container_id", return_value="cid"),
            pytest.raises(RuntimeError, match="tokens.map"),
        ):
            manager.reload_nginx()
        assert not any(call[-2:] == ["-s", "reload"] for call in runner.calls)

    def test_reload_refuses_when_the_container_sees_a_stale_nginx_conf(
        self, tmp_path: Path
    ) -> None:
        manager, runner = self._manager(tmp_path, conf_hash="stale")
        with (
            mock.patch.object(manager, "service_container_id", return_value="cid"),
            pytest.raises(RuntimeError, match="nginx.conf"),
        ):
            manager.reload_nginx()
        assert not any(call[-2:] == ["-s", "reload"] for call in runner.calls)

    def test_reload_refuses_when_container_not_running(self, tmp_path: Path) -> None:
        manager, runner = self._manager(tmp_path)
        with (
            mock.patch.object(manager, "service_container_id", return_value=None),
            pytest.raises(RuntimeError, match="not running"),
        ):
            manager.reload_nginx()
        assert runner.calls == []


def test_access_log_masks_every_path_but_the_gateway_admin_ones(tmp_path: Path) -> None:
    # Emulates nginx's map: regexes in order, first match wins.
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    body = conf.split("map $request $request_masked {", 1)[1].split("\n    }", 1)[0]
    rules = []
    for line in body.strip().splitlines():
        pattern, value = line.strip().rstrip(";").rsplit(" ", 1)
        if pattern == "default":
            continue
        rules.append((re.compile(pattern.strip('"').lstrip("~").replace("(?<", "(?P<")), value))

    def masked(request: str) -> str:
        for regex, value in rules:
            if match := regex.match(request):
                if value == "$request":
                    return request
                groups = match.groupdict()
                return (
                    value.strip('"')
                    .replace("${mrh}", groups.get("mrh", ""))
                    .replace("${mrt}", groups.get("mrt", ""))
                )
        return request

    assert masked("GET /comet/AbCdEfGh/eyJrZXkiOiJzZWNyZXQifQ==/manifest.json HTTP/1.1") == (
        "GET /comet/*** HTTP/1.1"
    )
    assert masked("GET /eyJrZXkiOiJzZWNyZXQifQ==/manifest.json HTTP/1.1") == "GET /*** HTTP/1.1"
    assert masked("GET /configure HTTP/1.1") == "GET /configure HTTP/1.1"
    assert masked("GET /configure?secret=pw HTTP/1.1") == "GET /configure HTTP/1.1"
    assert masked("GET /admin HTTP/1.1") == "GET /*** HTTP/1.1"
    assert masked("GET /kodi/get_manifest/123456 HTTP/1.1") == "GET /*** HTTP/1.1"
    assert masked("GET / HTTP/1.1") == "GET / HTTP/1.1"
    assert masked("GET /?token=secret HTTP/1.1") == "GET / HTTP/1.1"
    for leaky in (
        "GET /configure/../comet/AbCdEfGh/secret/manifest.json HTTP/1.1",
        "GET /configure/%2e%2e/comet/AbCdEfGh/secret HTTP/1.1",
        "GET /configure/%2e%2e/%63omet/AbCdEfGh/secret HTTP/1.1",
        "GET /configure/.. HTTP/1.1",
        "GET /configure?next=%2Fcomet%2FAbCdEfGh HTTP/1.1",
        "GET /comet/AbCdEfGh",
    ):
        result = masked(leaky)
        assert "AbCdEfGh" not in result
        assert "secret" not in result


def _nginx_maps(text: str) -> dict[tuple[str, str], dict[str, str]]:
    """Every `map $source $target { key value; }` block as a dict."""
    maps: dict[tuple[str, str], dict[str, str]] = {}
    for match in re.finditer(r"map (\$\w+) (\$\w+) \{\n(.*?)\n\}", text, re.DOTALL):
        entries: dict[str, str] = {}
        for line in match.group(3).splitlines():
            key, value = line.strip().rstrip(";").rsplit(" ", 1)
            entries[key.strip('"')] = value.strip('"')
        maps[(match.group(1), match.group(2))] = entries
    return maps


def test_access_log_attributes_requests_by_token_id_never_token(tmp_path: Path) -> None:
    manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
    first_id, first = manager.add_token("Living room")
    second_id, second = manager.add_token("Phone")
    manager.write_nginx_configs()
    tokens_map = manager.config.tokens_map_file.read_text(encoding="utf-8")

    maps = _nginx_maps(tokens_map)
    assert maps[("$gateway_token", "$token_valid")] == {
        "default": "0",
        f"~^{first}$": "1",
        f"~^{second}$": "1",
    }
    ids = maps[("$gateway_token", "$gateway_token_id")]
    assert ids == {"default": "-", f"~^{first}$": first_id, f"~^{second}$": second_id}
    # A token is only ever a map KEY; no value nginx can log is a token.
    for table in maps.values():
        assert not {first, second} & set(table.values())

    conf = manager.config.nginx_conf_file.read_text(encoding="utf-8")
    log_format = conf.split("log_format main", 1)[1].split(";", 1)[0]
    assert "tid=$gateway_token_id" in log_format
    assert "$gateway_token " not in log_format and "$gateway_token'" not in log_format
    assert first not in conf and second not in conf

    # A revoked token disappears from both maps.
    manager.revoke_token(first_id)
    maps = _nginx_maps(manager.render_tokens_map())
    assert f"~^{first}$" not in maps[("$gateway_token", "$gateway_token_id")]
    assert f"~^{first}$" not in maps[("$gateway_token", "$token_valid")]


def test_token_commands_reload_nginx_but_never_republish_the_stack(tmp_path: Path) -> None:
    from stremioguard.cli.commands import comet_token

    state = tmp_path / ".stremio"
    state.mkdir(exist_ok=True)
    published = {
        "docker-compose.bindings.yml": b"# published override\n",
        "env.snapshot": b"# published snapshot\n",
        "compose.base.yml": b"# published base\n",
    }
    for name, content in published.items():
        (state / name).write_bytes(content)
    # An undeployed .env edit that a republish would pick up.
    (tmp_path / ".env").write_text("STREMIO_BIND_ADDRS=10.9.9.9\nCOMET_ENABLED=1\n")
    manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
    with (
        mock.patch.object(comet_token, "_comet_gateway_manager", return_value=manager),
        mock.patch.object(manager, "container_running", return_value=True),
        mock.patch.object(manager, "reload_nginx") as reload_nginx,
        mock.patch("stremioguard.publishing.StackPublisher.publish") as publish,
    ):
        comet_token.comet_token_add("Phone", make_default=False)
        token_id = manager.list_tokens()[0]["id"]
        comet_token.comet_token_revoke(str(token_id))
    assert reload_nginx.call_count == 2
    publish.assert_not_called()
    for name, content in published.items():
        assert (state / name).read_bytes() == content, name


def _parse_map_rules(conf: str, source: str, target: str) -> list[tuple[str, str]]:
    """Parse an nginx `map <source> <target> { ... }` block into (pattern, value) pairs."""
    header = f"map {source} {target} {{"
    body = re.split(r"\n[ ]*\}", conf.split(header, 1)[1], maxsplit=1)[0]
    rules: list[tuple[str, str]] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pattern, value = line.rstrip(";").rsplit(None, 1)
        if pattern.startswith('"') and pattern.endswith('"'):
            pattern = pattern[1:-1]
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        rules.append((pattern, value))
    return rules


def _emulate_nginx_map(rules: list[tuple[str, str]], value: str) -> str:
    """Emulate nginx `map` evaluation (exact strings case-insensitively, then regexes in order)."""
    default = ""
    regex_rules: list[tuple[str, str]] = []
    for pattern, out in rules:
        if pattern == "default":
            default = out
        elif pattern.startswith("~"):
            regex_rules.append((pattern, out))
        elif pattern.lower() == value.lower():
            return out
    for pattern, out in regex_rules:
        flags = re.IGNORECASE if pattern.startswith("~*") else 0
        regex_text = pattern[2:] if flags else pattern[1:]
        # Unescape nginx double-quoted \x5c -> \ for Python re emulation.
        regex_text = regex_text.replace("(?<", "(?P<")
        match = (
            re.match(regex_text, value, flags)
            if regex_text.startswith("^")
            else re.search(regex_text, value, flags)
        )
        if match:
            if out.startswith("$"):
                return match.group(out[1:])
            return out
    return default


def test_d1_d2_addon_route_allowlist_and_raw_path_emulation(tmp_path: Path) -> None:
    """D1, D2 (default-suite emulation): allowlist and raw-path rules match spec."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    assert "location ^~ /comet/ {" in conf
    assert "(?<gateway_token>" not in conf
    assert "proxy_pass $comet_upstream$raw_comet_path$is_args$args;" in conf

    token_rules = _parse_map_rules(conf, "$request_uri", "$gateway_token")
    path_rules = _parse_map_rules(conf, "$request_uri", "$raw_comet_path")
    action_rules = _parse_map_rules(conf, "$raw_comet_path", "$comet_route_action")

    def decide(request_uri: str) -> tuple[str, str, str]:
        tok = _emulate_nginx_map(token_rules, request_uri)
        raw_path = _emulate_nginx_map(path_rules, request_uri)
        action = _emulate_nginx_map(action_rules, raw_path)
        return tok, raw_path, action

    tok = "GwTok3nA"
    api = "Api_Tok-1"
    cfg = "eyJhIjoiYisiLCJiIjoxfQ=="

    for allowed_path in (
        f"/s/{api}/manifest.json",
        f"/s/{api}/{cfg}/manifest.json",
        f"/s/{api}/stream/movie/tt0111161.json",
        f"/s/{api}/{cfg}/stream/series/tt0903747%3A1%3A2.json",
        f"/s/{api}/{cfg}/stream/series/tt0903747:1:2.json",
        f"/s/{api}/{cfg}/playback/abc123/0/1/1/2",
        f"/s/{api}/{cfg}/playback/h/0/file%20name%2B1/1/1",
        "/configure",
        f"/{cfg}/configure",
        f"/s/{api}/configure",
        f"/s/{api}/{cfg}/configure",
        "/configure/login",
    ):
        extracted_tok, raw_path, action = decide(f"/comet/{tok}{allowed_path}?q=1")
        assert extracted_tok == tok, allowed_path
        assert raw_path == allowed_path, allowed_path
        assert action == "proxy", allowed_path

    for base_uri in (f"/comet/{tok}", f"/comet/{tok}/", f"/comet/{tok}?x=1", f"/comet/{tok}/?x=1"):
        extracted_tok, _, action = decide(base_uri)
        assert extracted_tok == tok
        assert action == "redirect", base_uri

    for forbidden_path in (
        f"/s/{api}/torznab/api",
        f"/s/{api}/{cfg}/debrid-sync/0",
        f"/s/{api}/manifest",
        f"/s/{api}/streams",
        f"/s/{api}/configure/login",
        "/manifest.json",
        f"/{cfg}/manifest.json",
        "/stream/movie/tt0111161.json",
        f"/{cfg}/playback/a/0/1/1/1",
        "/admin",
        "/kodi/get_manifest/1",
        "/cometnet/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        f"/s/{api}/{cfg}/playback/a/b/c/d",
        f"/s/{api}/{cfg}/playback/a/b/c/d/e/f",
        f"/s/{api}/stream/movie/.json",
        f"//s/{api}/manifest.json",
        f"/s/{api}//manifest.json",
        f"/s/{api}/./manifest.json",
        f"/s/{api}/x/../manifest.json",
        f"/s/{api}/%2e/manifest.json",
        f"/s/{api}/%2E%2E/torznab/api",
        f"/s%2F{api}/manifest.json",
        f"/s%2f{api}/manifest.json",
        f"/s/{api}/x%5C/manifest.json",
        f"/s/{api}/x\\y/manifest.json",
        f"/s/{api}/manifest.json;p=1",
        f"/s/{api}/manifest.json#frag",
        f"/s/{api}/MANIFEST.JSON",
        f"/S/{api}/manifest.json",
        f"/s/{api}/m%61nifest.json",
        f"/s/{api}/manifest%2Ejson",
        "/configure/",
        "/configure/login/",
        "//",
    ):
        _, _, action = decide(f"/comet/{tok}{forbidden_path}")
        assert action == "deny", forbidden_path

    # Encoded or traversal tokens fail raw token extraction (D2, D3).
    assert _emulate_nginx_map(token_rules, f"/comet/%41bCdEfGh/s/{api}/manifest.json") == ""
    assert _emulate_nginx_map(token_rules, f"/x/../comet/{tok}/s/{api}/manifest.json") == ""
    assert _emulate_nginx_map(token_rules, f"/COMET/{tok}/s/{api}/manifest.json") == ""


def test_d3_exact_case_sensitive_token_map_and_raw_extraction(tmp_path: Path) -> None:
    """D3: tokens.map uses ~^<token>$ regex keys so lookup is case-sensitive."""
    manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
    manager.save_state(
        {
            "default": "t1",
            "tokens": {"t1": {"label": "Mixed", "token": "GwTok3nA", "created": "2026-11-16"}},
        }
    )
    tokens_map = manager.render_tokens_map()
    valid_rules = _parse_map_rules(tokens_map, "$gateway_token", "$token_valid")
    id_rules = _parse_map_rules(tokens_map, "$gateway_token", "$gateway_token_id")

    assert _emulate_nginx_map(valid_rules, "GwTok3nA") == "1"
    assert _emulate_nginx_map(id_rules, "GwTok3nA") == "t1"
    for wrong in ("GWTOK3NA", "gwtok3na", "gwTok3nA", "GwTok3nAx", "xGwTok3nA", ""):
        assert _emulate_nginx_map(valid_rules, wrong) == "0", wrong
        assert _emulate_nginx_map(id_rules, wrong) == "-", wrong


def test_d4_denials_base_redirect_and_no_upgrade_on_token_location(tmp_path: Path) -> None:
    """D4: relative 302 redirect, access-phase deny with limit_req, and no WebSocket upgrade."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    assert "absolute_redirect off;" in conf
    assert "return 302 /comet/$gateway_token/configure;" in conf
    assert "return 301" not in conf
    assert 'return 403 "Forbidden\\n";' not in conf
    assert (
        "location = /__sg_forbidden {\n"
        "            internal;\n"
        "            limit_req zone=gateway_fail burst=3 nodelay;\n"
        "            deny all;\n"
        "        }" in conf
    )

    token_block = conf.split("location ^~ /comet/ {", 1)[1].split("\n        }", 1)[0]
    assert 'Connection "upgrade"' not in token_block
    assert 'proxy_set_header Upgrade "";' in token_block


def test_d5_host_validation_and_port_preservation_emulation(tmp_path: Path) -> None:
    """D5 (default-suite emulation): $valid_host rejects bad Hosts and proxies keep $http_host."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    assert "$redirect_host" not in conf
    assert "if ($valid_host = 0) {\n            return 400;\n        }" in conf
    assert conf.count("proxy_set_header Host $http_host;") == 3
    assert conf.count("proxy_set_header X-Forwarded-Host $http_host;") == 3
    assert "proxy_set_header Host $host;" not in conf
    assert "proxy_set_header X-Forwarded-Host $host;" not in conf

    host_rules = _parse_map_rules(conf, "$http_host", "$valid_host")
    for good in (
        "192.0.2.10:18001",
        "[2001:db8::1]:18001",
        "[::1]",
        "comet.example.com",
        "Comet.Example.COM:8443",
    ):
        assert _emulate_nginx_map(host_rules, good) == "1", good

    for bad in ("", "x.com'y", "x(y)", "x,y", "x.com;y", "x%2fy", "x.com:", "x.com:123456"):
        assert _emulate_nginx_map(host_rules, bad) == "0", bad


def test_d6_clears_all_14_comet_ip_proxy_headers_on_every_proxy(tmp_path: Path) -> None:
    """D6: every proxied location clears all 14 Comet IP_PROXY_HEADERS with provenance comment."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    assert "comet/utils/network.py" in conf
    assert "sha256:31a41fa64ed2e174fe0bae915a168a0c77ae4bca17b7efb8fa3a31d7c9f164ea" in conf
    expected_headers = (
        "CF-Connecting-IP",
        "True-Client-IP",
        "X-Real-IP",
        "X-Client-IP",
        "DO-Connecting-IP",
        "Fastly-Client-IP",
        "X-Cluster-Client-IP",
        "X-Forwarded-For",
        "X-Forwarded",
        "Forwarded-For",
        "Forwarded",
        "X-AppEngine-User-IP",
        "CF-Pseudo-IPv4",
        "X-AIOStreams-User-IP",
    )
    assert len(expected_headers) == 14
    for header in expected_headers:
        assert conf.count(f'proxy_set_header {header} "";') == 3, header


def test_d7_x_forwarded_prefix_set_on_token_and_cleared_on_public(tmp_path: Path) -> None:
    """D7: token location sets X-Forwarded-Prefix; public/root locations clear it."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    token_block = conf.split("location ^~ /comet/ {", 1)[1].split("\n        }", 1)[0]
    public_block = conf.split('location ~ "^/(?:configure', 1)[1].split("\n        }", 1)[0]
    root_block = conf.split("location = / {", 1)[1].split("\n        }", 1)[0]

    assert "proxy_set_header X-Forwarded-Prefix /comet/$gateway_token;" in token_block
    assert 'proxy_set_header X-Forwarded-Prefix "";' in public_block
    assert 'proxy_set_header X-Forwarded-Prefix "";' in root_block


class TestTokenStateValidation:
    """AC-11 / D9: corrupt, wrong-shape, or injection-bearing tokens.json is refused."""

    def test_absent_tokens_file_returns_empty_state(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        assert manager.load_state() == {"default": None, "tokens": {}}

    def test_short_four_char_valid_token_renders(self, tmp_path: Path) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.save_state(
            {"default": "old1", "tokens": {"old1": {"label": "Legacy", "token": "Ab1_"}}}
        )
        rendered = manager.render_tokens_map()
        assert '"~^Ab1_$" 1;' in rendered
        assert '"~^Ab1_$" "old1";' in rendered

    @pytest.mark.parametrize(
        "raw_bytes",
        [
            b"",
            b"{",
            b"null",
            b"[]",
            b'{"tokens": []}',
            b'{"tokens": {"a": "x"}}',
            b'{"default": 123, "tokens": {}}',
        ],
    )
    def test_malformed_json_shapes_refuse_and_preserve_rendered_files(
        self, tmp_path: Path, raw_bytes: bytes
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Existing")
        before_conf = manager.config.nginx_conf_file.read_bytes()
        before_map = manager.config.tokens_map_file.read_bytes()

        manager.config.tokens_file.write_bytes(raw_bytes)
        with pytest.raises(RuntimeError) as exc_info:
            manager.write_nginx_configs()

        assert str(manager.config.tokens_file) in str(exc_info.value)
        assert manager.config.nginx_conf_file.read_bytes() == before_conf
        assert manager.config.tokens_map_file.read_bytes() == before_map

    def test_unreadable_tokens_file_refuses_without_touching_rendered_files(
        self, tmp_path: Path
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Existing")
        before_conf = manager.config.nginx_conf_file.read_bytes()
        before_map = manager.config.tokens_map_file.read_bytes()

        with (
            mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")),
            pytest.raises(RuntimeError) as exc_info,
        ):
            manager.write_nginx_configs()

        assert str(manager.config.tokens_file) in str(exc_info.value)
        assert manager.config.nginx_conf_file.read_bytes() == before_conf
        assert manager.config.tokens_map_file.read_bytes() == before_map

    @pytest.mark.parametrize(
        "bad_token",
        [
            None,
            123,
            "",
            'bad"tok',
            "bad\ntok",
            "bad tok",
            "bad$tok",
            "bad~tok",
            "bad}tok",
            "A" * 257,
            "valid\n",
        ],
    )
    def test_invalid_token_values_refuse_without_leaking_token(
        self, tmp_path: Path, bad_token: object
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Existing")
        before_conf = manager.config.nginx_conf_file.read_bytes()
        before_map = manager.config.tokens_map_file.read_bytes()

        entry: dict[str, object] = {"label": "Bad"}
        if bad_token is not None:
            entry["token"] = bad_token
        manager.save_state({"default": "bad1", "tokens": {"bad1": entry}})

        with pytest.raises(RuntimeError) as exc_info:
            manager.write_nginx_configs()

        message = str(exc_info.value)
        assert "bad1" in message
        if isinstance(bad_token, str) and len(bad_token) >= 4:
            assert bad_token not in message
        assert manager.config.nginx_conf_file.read_bytes() == before_conf
        assert manager.config.tokens_map_file.read_bytes() == before_map

    @pytest.mark.parametrize(
        "bad_id",
        [
            'id"x',
            "id\nx",
            "id;x",
            "id\n",
            "a" * 65,
            'a"; }\nserver { listen 9999; }\n#',
        ],
    )
    def test_invalid_token_ids_including_f8_injection_refuse(
        self, tmp_path: Path, bad_id: str
    ) -> None:
        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.add_token("Existing")
        before_conf = manager.config.nginx_conf_file.read_bytes()
        before_map = manager.config.tokens_map_file.read_bytes()

        secret = "SecretValue123"
        manager.save_state({"default": None, "tokens": {bad_id: {"label": "X", "token": secret}}})

        with pytest.raises(RuntimeError) as exc_info:
            manager.write_nginx_configs()

        message = str(exc_info.value)
        assert repr(bad_id) in message
        assert secret not in message
        assert manager.config.nginx_conf_file.read_bytes() == before_conf
        assert manager.config.tokens_map_file.read_bytes() == before_map


class TestTokenCliAndGatewayReload:
    """AC-12 / D10: token commands fail loudly when not applied; reload checks both files."""

    @pytest.mark.parametrize("action", ["add", "revoke", "rotate", "use"])
    def test_ac12a_reload_failure_exits_1_with_no_success_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
    ) -> None:
        import typer

        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        manager = CometGatewayManager(config, runner=FakeRunner({}))
        tid, _ = manager.add_token("Existing")
        events: list[tuple[str, str]] = []
        echoed: list[str] = []
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)
        monkeypatch.setattr(manager, "container_running", lambda: True)
        monkeypatch.setattr(
            manager,
            "reload_nginx",
            mock.Mock(side_effect=RuntimeError("nginx -t failed")),
        )
        monkeypatch.setattr(typer, "echo", echoed.append)

        def fake_fail(msg: str) -> None:
            events.append(("error", msg))
            raise typer.Exit(1)

        class FakeLogger:
            def info(self, msg: str) -> None:
                events.append(("info", msg))

            def success(self, msg: str) -> None:
                events.append(("success", msg))

        monkeypatch.setattr(comet_token, "logger", FakeLogger())
        monkeypatch.setattr(comet_token, "fail", fake_fail)

        with pytest.raises(typer.Exit) as exc_info:
            if action == "add":
                comet_token.comet_token_add("Second", make_default=False)
            elif action == "revoke":
                comet_token.comet_token_revoke(tid)
            elif action == "rotate":
                comet_token.comet_token_rotate(tid)
            else:
                comet_token.comet_token_use(tid)

        assert exc_info.value.exit_code == 1
        assert not any(kind == "success" for kind, _ in events)
        assert echoed == []
        err_msgs = [msg for kind, msg in events if kind == "error"]
        assert len(err_msgs) == 1
        assert "NOT active in the running gateway" in err_msgs[0]
        assert "./stremio comet gateway-reload" in err_msgs[0]
        assert "./stremio restart" in err_msgs[0]
        if action in {"revoke", "rotate"}:
            assert "old token still works" in err_msgs[0]

    def test_ac12b_unknown_gateway_state_compose_fail_timeout_and_inspect_fail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        import typer

        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        compose_ps = (
            "docker",
            "compose",
            "-f",
            str(tmp_path / "docker-compose.yml"),
            "ps",
            "-q",
            "comet-gateway",
        )

        # 1) Compose query fails -> container_running() is None -> error + exit 1.
        runner_fail = FakeRunner({compose_ps: completed([], returncode=1, stderr="daemon down")})
        manager_fail = CometGatewayManager(config, runner=runner_fail)
        assert manager_fail.container_running() is None

        # 2) Compose query times out -> container_running() is None.
        timeout_runner = mock.Mock()
        timeout_runner.run.side_effect = subprocess.TimeoutExpired(["docker", "compose"], 30)
        manager_timeout = CometGatewayManager(config, runner=timeout_runner)
        assert manager_timeout.container_running() is None

        # 3) Compose succeeds with cid, then docker inspect fails -> container_running() is None.
        runner_inspect_fail = FakeRunner(
            {
                compose_ps: completed([], stdout="cid\n"),
                ("docker", "inspect", "--format", "{{.State.Running}}", "cid"): completed(
                    [], returncode=1, stderr="inspect failed"
                ),
            }
        )
        manager_inspect_fail = CometGatewayManager(config, runner=runner_inspect_fail)
        assert manager_inspect_fail.container_running() is None

        events: list[tuple[str, str]] = []
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager_inspect_fail)
        monkeypatch.setattr(comet_token, "fail", lambda msg: (_ for _ in ()).throw(typer.Exit(1)))
        err_captured: list[str] = []

        def fake_fail(msg: str) -> None:
            err_captured.append(msg)
            raise typer.Exit(1)

        class FakeLogger:
            def info(self, msg: str) -> None:
                events.append(("info", msg))

            def success(self, msg: str) -> None:
                events.append(("success", msg))

        monkeypatch.setattr(comet_token, "fail", fake_fail)
        monkeypatch.setattr(comet_token, "logger", FakeLogger())

        with pytest.raises(typer.Exit) as exc_info:
            comet_token.comet_token_add("Test", make_default=False)
        assert exc_info.value.exit_code == 1
        assert not events
        assert "NOT active in the running gateway" in err_captured[0]

    def test_ac12c_definitely_not_running_succeeds_with_next_start(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        compose_ps = (
            "docker",
            "compose",
            "-f",
            str(tmp_path / "docker-compose.yml"),
            "ps",
            "-q",
            "comet-gateway",
        )
        # Empty stdout with returncode 0 means definitely not running.
        manager = CometGatewayManager(
            config, runner=FakeRunner({compose_ps: completed([], stdout="")})
        )
        assert manager.container_running() is False

        # Container exists but State.Running is false -> also definitely not running.
        manager_stopped = CometGatewayManager(
            config,
            runner=FakeRunner(
                {
                    compose_ps: completed([], stdout="cid\n"),
                    ("docker", "inspect", "--format", "{{.State.Running}}", "cid"): completed(
                        [], stdout="false\n"
                    ),
                }
            ),
        )
        assert manager_stopped.container_running() is False

        events: list[tuple[str, str]] = []
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)
        monkeypatch.setattr(typer, "echo", lambda msg: events.append(("echo", msg)))

        class FakeLogger:
            def info(self, msg: str) -> None:
                events.append(("info", msg))

            def success(self, msg: str) -> None:
                events.append(("success", msg))

        monkeypatch.setattr(comet_token, "logger", FakeLogger())

        comet_token.comet_token_add("Phone", make_default=False)
        assert any(
            "applies on next start" in msg or "apply on next start" in msg
            for kind, msg in events
            if kind == "info"
        )
        assert any(kind == "success" for kind, _ in events)

    def test_ac12d_prints_success_after_reload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        manager = CometGatewayManager(config, runner=FakeRunner({}))
        order: list[str] = []

        def fake_reload() -> None:
            order.append("reload")

        class FakeLogger:
            def info(self, msg: str) -> None:
                order.append(f"info:{msg}")

            def success(self, msg: str) -> None:
                order.append(f"success:{msg}")

        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)
        monkeypatch.setattr(manager, "container_running", lambda: True)
        monkeypatch.setattr(manager, "reload_nginx", fake_reload)
        monkeypatch.setattr(comet_token, "logger", FakeLogger())
        monkeypatch.setattr(typer, "echo", lambda msg: order.append(f"echo:{msg}"))

        comet_token.comet_token_add("Phone", make_default=False)
        reload_idx = order.index("reload")
        success_idx = next(i for i, item in enumerate(order) if item.startswith("success:"))
        echo_idx = next(i for i, item in enumerate(order) if item.startswith("echo:"))
        assert reload_idx < success_idx < echo_idx

    def test_ac12e_malformed_state_exits_1_via_fail_without_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from stremioguard.cli import APP as cli_app
        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        config.state_dir.mkdir(parents=True, exist_ok=True)
        config.tokens_file.write_text("{", encoding="utf-8")
        manager = CometGatewayManager(config, runner=FakeRunner({}))
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)

        result = CliRunner().invoke(cli_app, ["comet", "token", "list"])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Traceback" not in result.output

    def test_ac12f_g_h_gateway_reload_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from stremioguard.cli.commands import comet_token

        config = make_comet_gateway_config(tmp_path)
        compose_ps = (
            "docker",
            "compose",
            "-f",
            str(tmp_path / "docker-compose.yml"),
            "ps",
            "-q",
            "comet-gateway",
        )

        # (f) running, matching hashes -> nginx -t, both sha256sum checks, -s reload
        seed_mgr = CometGatewayManager(config, runner=FakeRunner({}))
        seed_mgr.write_nginx_configs()
        conf_sha = hashlib.sha256(config.nginx_conf_file.read_bytes()).hexdigest()
        map_sha = hashlib.sha256(config.tokens_map_file.read_bytes()).hexdigest()
        nginx_cmd = (
            "docker",
            "exec",
            "cid",
            "nginx",
            "-c",
            f"{gateway_mod.GATEWAY_CONFIG_DIR}/nginx.conf",
        )
        conf_path = f"{gateway_mod.GATEWAY_CONFIG_DIR}/nginx.conf"
        map_path = f"{gateway_mod.GATEWAY_CONFIG_DIR}/tokens.map"
        inspect_cmd = ("docker", "inspect", "--format", "{{.State.Running}}", "cid")
        conf_sha_cmd = ("docker", "exec", "cid", "sha256sum", conf_path)
        map_sha_cmd = ("docker", "exec", "cid", "sha256sum", map_path)

        runner_ok = FakeRunner(
            {
                compose_ps: [completed([], stdout="cid\n"), completed([], stdout="cid\n")],
                inspect_cmd: completed([], stdout="true\n"),
                (*nginx_cmd, "-t"): completed([]),
                conf_sha_cmd: completed([], stdout=f"{conf_sha}  {conf_path}\n"),
                map_sha_cmd: completed([], stdout=f"{map_sha}  {map_path}\n"),
                (*nginx_cmd, "-s", "reload"): completed([]),
            }
        )
        mgr_ok = CometGatewayManager(config, runner=runner_ok)
        events: list[str] = []
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: mgr_ok)

        class FakeLogger:
            def success(self, msg: str) -> None:
                events.append(f"success:{msg}")

        monkeypatch.setattr(comet_token, "logger", FakeLogger())
        comet_token.comet_gateway_reload()
        assert any("nginx" in call and "-t" in call for call in runner_ok.calls)
        assert any(conf_path in call for call in runner_ok.calls)
        assert any(map_path in call for call in runner_ok.calls)
        assert runner_ok.calls[-1][-2:] == ["-s", "reload"]
        assert events == ["success:Comet gateway config reloaded."]

        # (g) stale nginx.conf hash -> refuses before reload
        runner_stale = FakeRunner(
            {
                compose_ps: [completed([], stdout="cid\n"), completed([], stdout="cid\n")],
                inspect_cmd: completed([], stdout="true\n"),
                (*nginx_cmd, "-t"): completed([]),
                conf_sha_cmd: completed([], stdout=f"{'0' * 64}  {conf_path}\n"),
                map_sha_cmd: completed([], stdout=f"{map_sha}  {map_path}\n"),
            }
        )
        mgr_stale = CometGatewayManager(config, runner=runner_stale)
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: mgr_stale)
        monkeypatch.setattr(comet_token, "fail", lambda msg: (_ for _ in ()).throw(typer.Exit(1)))
        with pytest.raises(typer.Exit) as exc_info:
            comet_token.comet_gateway_reload()
        assert exc_info.value.exit_code == 1
        assert not any(call[-2:] == ["-s", "reload"] for call in runner_stale.calls)

        # (h) not running -> exits 1
        runner_down = FakeRunner({compose_ps: completed([], stdout="")})
        mgr_down = CometGatewayManager(config, runner=runner_down)
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: mgr_down)
        with pytest.raises(typer.Exit) as exc_info2:
            comet_token.comet_gateway_reload()
        assert exc_info2.value.exit_code == 1

    def test_ac12_token_url_rejects_chilllink_manifest_accepts_manifest_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import typer

        from stremioguard.cli.commands import comet_token

        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        tid, token = manager.add_token("Phone")
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)

        echoed: list[str] = []
        errors: list[str] = []
        monkeypatch.setattr(typer, "echo", echoed.append)

        def fake_fail(msg: str) -> None:
            errors.append(msg)
            raise typer.Exit(1)

        monkeypatch.setattr(comet_token, "fail", fake_fail)

        with pytest.raises(typer.Exit) as exc_info:
            comet_token.comet_token_url(tid, manifest="https://comet.example/s/api123/manifest")
        assert exc_info.value.exit_code == 1
        assert "/manifest.json" in errors[0]

        comet_token.comet_token_url(
            tid, manifest="https://old.example/comet/oldtok/s/api123/cfg/manifest.json"
        )
        assert echoed == [f"https://comet.example.com/comet/{token}/s/api123/cfg/manifest.json"]


def _extract_location_block(conf: str, header_prefix: str) -> str:
    start = conf.index(header_prefix)
    brace_start = conf.index("{", start)
    depth = 0
    for idx in range(brace_start, len(conf)):
        if conf[idx] == "{":
            depth += 1
        elif conf[idx] == "}":
            depth -= 1
            if depth == 0:
                return conf[brace_start + 1 : idx]
    raise AssertionError(f"Unclosed block for {header_prefix}")


def _emulate_token_location(conf: str, tokens_map: str, request_uri: str) -> tuple[object, ...]:
    """Emulate nginx's map evaluation + sequential `location ^~ /comet/` execution."""
    gateway_token = _emulate_nginx_map(
        _parse_map_rules(conf, "$request_uri", "$gateway_token"), request_uri
    )
    raw_comet_path = _emulate_nginx_map(
        _parse_map_rules(conf, "$request_uri", "$raw_comet_path"), request_uri
    )
    comet_route_action = _emulate_nginx_map(
        _parse_map_rules(conf, "$raw_comet_path", "$comet_route_action"), raw_comet_path
    )
    token_valid = _emulate_nginx_map(
        _parse_map_rules(tokens_map, "$gateway_token", "$token_valid"), gateway_token
    )
    variables = {
        "$gateway_token": gateway_token,
        "$raw_comet_path": raw_comet_path,
        "$comet_route_action": comet_route_action,
        "$token_valid": token_valid,
    }

    block = _extract_location_block(conf, "location ^~ /comet/")
    pos = 0
    while pos < len(block):
        while pos < len(block) and block[pos].isspace():
            pos += 1
        if pos >= len(block):
            break
        if block[pos] == "#":
            nl = block.find("\n", pos)
            pos = len(block) if nl == -1 else nl + 1
            continue
        if block.startswith("if", pos):
            match = re.match(
                r"if\s*\(\s*(\$\w+)\s*(!?=)\s*([^)]+?)\s*\)\s*\{([^}]*)\}", block[pos:]
            )
            assert match is not None, f"Unparseable if block at: {block[pos : pos + 80]}"
            var_name, op, rhs, body = match.groups()
            lhs_val = variables[var_name]
            rhs_val = rhs.strip().strip('"')
            cond = (lhs_val == rhs_val) if op == "=" else (lhs_val != rhs_val)
            pos += match.end()
            if cond:
                stmt = body.strip()
                if rew := re.fullmatch(r"rewrite\s+\^\s+(\S+)\s+last;", stmt):
                    return ("rewrite", rew.group(1))
                if ret := re.fullmatch(r"return\s+(\d+)(?:\s+([^;]+))?;", stmt):
                    arg = (ret.group(2) or "").replace("$gateway_token", gateway_token)
                    return ("return", int(ret.group(1)), arg)
                raise AssertionError(f"Unsupported or empty action inside matching if: {stmt!r}")
            continue
        semi = block.find(";", pos)
        assert semi != -1, f"Missing semicolon at: {block[pos:]}"
        directive = block[pos:semi].strip()
        pos = semi + 1
        if directive.startswith("proxy_pass "):
            return ("proxy", directive.removeprefix("proxy_pass ").strip())
    raise AssertionError(
        "Reached end of location ^~ /comet/ without rewrite, return, or proxy_pass"
    )


def test_ac16_token_location_wiring_and_maps_emulation(tmp_path: Path) -> None:
    """AC-16 / R1-1 (INV-1, default-suite emulation): location ^~ /comet/ enforces maps in order."""
    manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
    manager.save_state(
        {
            "default": "t1",
            "tokens": {"t1": {"label": "Mixed", "token": "GwTok3nA", "created": "2026-11-16"}},
        }
    )
    conf = manager.render_nginx_conf()
    tokens_map = manager.render_tokens_map()

    # Valid token + allowed paths reach proxy_pass.
    for allowed in (
        "/comet/GwTok3nA/s/Api_1/manifest.json",
        "/comet/GwTok3nA/s/Api_1/cfg1/playback/h/0/1/1/2",
        "/comet/GwTok3nA/configure",
        "/comet/GwTok3nA/configure/login",
    ):
        assert _emulate_token_location(conf, tokens_map, allowed) == (
            "proxy",
            "$comet_upstream$raw_comet_path$is_args$args",
        ), allowed

    # Valid token + base URL returns relative 302.
    for base in ("/comet/GwTok3nA", "/comet/GwTok3nA/", "/comet/GwTok3nA/?x=1"):
        assert _emulate_token_location(conf, tokens_map, base) == (
            "return",
            302,
            "/comet/GwTok3nA/configure",
        ), base

    # Valid token + forbidden paths rewrite to /__sg_forbidden before proxy_pass.
    for forbidden in (
        "/comet/GwTok3nA/s/Api_1/torznab/api",
        "/comet/GwTok3nA/s/Api_1/cfg1/debrid-sync/0",
        "/comet/GwTok3nA/admin",
        "/comet/GwTok3nA/s/Api_1/../torznab/api",
        "/comet/GwTok3nA//",
    ):
        assert _emulate_token_location(conf, tokens_map, forbidden) == (
            "rewrite",
            "/__sg_forbidden",
        ), forbidden

    # Invalid token (on allowed, base, or forbidden paths) always hits /__sg_invalid_token first.
    for invalid in (
        "/comet/WrongTok/s/Api_1/manifest.json",
        "/comet/GWTOK3NA/s/Api_1/manifest.json",
        "/comet/WrongTok",
        "/comet/WrongTok/",
        "/comet/WrongTok/s/Api_1/torznab/api",
    ):
        assert _emulate_token_location(conf, tokens_map, invalid) == (
            "rewrite",
            "/__sg_invalid_token",
        ), invalid


def test_ac17_write_nginx_configs_preserves_sentinel_bytes_on_render_failure(
    tmp_path: Path,
) -> None:
    """AC-17 / R1-2 (INV-8, D9): pre-seeded sentinel bytes survive when rendering fails."""
    manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
    manager.config.state_dir.mkdir(parents=True, exist_ok=True)
    sentinel_conf = b"# SENTINEL nginx.conf - must never be overwritten on error\n"
    sentinel_map = b"# SENTINEL tokens.map - must never be overwritten on error\n"
    manager.config.nginx_conf_file.write_bytes(sentinel_conf)
    manager.config.tokens_map_file.write_bytes(sentinel_map)

    manager.save_state(
        {"default": "bad1", "tokens": {"bad1": {"label": "Bad", "token": "bad tok"}}}
    )
    with pytest.raises(RuntimeError, match="bad1"):
        manager.write_nginx_configs()

    assert manager.config.nginx_conf_file.read_bytes() == sentinel_conf
    assert manager.config.tokens_map_file.read_bytes() == sentinel_map


class TestTokenCrudPreMutationValidation:
    """AC-18 / R1-4 (INV-8, INV-9): CRUD methods and CLI refuse malformed entries first."""

    @pytest.mark.parametrize("bad_kind", ["bad_value", "bad_id"])
    def test_ac18_manager_and_cli_refuse_before_mutating_state_or_rendered_files(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        bad_kind: str,
    ) -> None:
        from loguru import logger as loguru_logger
        from typer.testing import CliRunner

        from stremioguard.cli import APP as cli_app
        from stremioguard.cli.commands import comet_token

        manager = CometGatewayManager(make_comet_gateway_config(tmp_path))
        manager.config.state_dir.mkdir(parents=True, exist_ok=True)
        valid_secret = "GoodTok123"
        bad_secret = "bad value!"
        if bad_kind == "bad_value":
            bad_id = "bad1"
            tokens_data = {
                "good1": {"label": "Good", "token": valid_secret, "created": "2026-11-16T00:00:00"},
                bad_id: {"label": "Bad", "token": bad_secret, "created": "2026-11-16T00:00:01"},
            }
        else:
            bad_id = "bad;id"
            tokens_data = {
                "good1": {"label": "Good", "token": valid_secret, "created": "2026-11-16T00:00:00"},
                bad_id: {"label": "Bad", "token": "OtherTok99", "created": "2026-11-16T00:00:01"},
            }
        manager.save_state({"default": "good1", "tokens": tokens_data})
        sentinel_conf = b"# sentinel conf\n"
        sentinel_map = b"# sentinel map\n"
        manager.config.nginx_conf_file.write_bytes(sentinel_conf)
        manager.config.tokens_map_file.write_bytes(sentinel_map)
        before_tokens = manager.config.tokens_file.read_bytes()

        # 1) Manager CRUD calls refuse before modifying tokens.json, nginx.conf, or tokens.map.
        calls = (
            lambda: manager.add_token("New"),
            lambda: manager.revoke_token("good1"),
            lambda: manager.rotate_token("good1"),
            lambda: manager.use_token("good1"),
        )
        for call in calls:
            with pytest.raises(RuntimeError) as exc_info:
                call()
            msg = str(exc_info.value)
            assert repr(bad_id) in msg
            assert valid_secret not in msg
            assert bad_secret not in msg
            assert "OtherTok99" not in msg
            assert manager.config.tokens_file.read_bytes() == before_tokens
            assert manager.config.nginx_conf_file.read_bytes() == sentinel_conf
            assert manager.config.tokens_map_file.read_bytes() == sentinel_map

        # 2) CLI commands exit 1 with D9 message (no token value) and leave files unchanged.
        monkeypatch.setattr(comet_token, "_comet_gateway_manager", lambda: manager)
        runner = CliRunner()
        log_messages: list[str] = []
        sink_id = loguru_logger.add(log_messages.append, format="{message}")
        try:
            for cli_args in (
                ["comet", "token", "add", "New"],
                ["comet", "token", "revoke", "good1"],
                ["comet", "token", "rotate", "good1"],
                ["comet", "token", "use", "good1"],
            ):
                log_messages.clear()
                res = runner.invoke(cli_app, cli_args)
                combined = res.output + "\n".join(log_messages)
                assert res.exit_code == 1, (cli_args, combined)
                assert "Traceback" not in combined
                assert repr(bad_id) in combined
                assert valid_secret not in combined
                assert bad_secret not in combined
                assert "OtherTok99" not in combined
                assert manager.config.tokens_file.read_bytes() == before_tokens
                assert manager.config.nginx_conf_file.read_bytes() == sentinel_conf
                assert manager.config.tokens_map_file.read_bytes() == sentinel_map
        finally:
            loguru_logger.remove(sink_id)


def test_rendered_gateway_hides_its_version_and_sets_security_headers(tmp_path: Path) -> None:
    """Default-suite check of what the real-nginx test proves per response."""
    conf = CometGatewayManager(make_comet_gateway_config(tmp_path)).render_nginx_conf()
    http_block = conf.split("http {", 1)[1].split("    server {", 1)[0]
    assert "    server_tokens off;\n" in http_block
    for header, value in (
        ("X-Content-Type-Options", '"nosniff"'),
        ("X-Frame-Options", '"DENY"'),
        ("Referrer-Policy", '"same-origin"'),
    ):
        assert f"    proxy_hide_header {header};\n" in http_block
        assert f"    add_header {header} {value} always;\n" in http_block
    # A location with its own add_header would silently drop the inherited ones.
    servers = conf.split("    server {", 1)[1]
    assert "add_header" not in servers
