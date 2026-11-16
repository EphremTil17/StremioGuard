"""Unit tests for the pure logic in scripts/lab.py (no Docker container runs)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest import mock

import pytest

from scripts import lab


class TestBuildGatewayCases:
    def test_covers_allowed_denied_redirect_header_and_health_cases(self) -> None:
        token = "AbCdEfGh"
        cfg_blob = "SGVsbG9MYWJUZXN0Q29uZmln"
        api_token = "LabApi_Token-1"
        cases = lab.build_gateway_cases(token, cfg_blob, "127.0.0.1:8090", api_token=api_token)
        by_name = {c.name: c for c in cases}

        assert by_name["valid_manifest_no_cfg"].raw_target == (
            f"/comet/{token}/s/{api_token}/manifest.json"
        )
        assert by_name["valid_manifest_no_cfg"].expected_upstream_path == (
            f"/s/{api_token}/manifest.json"
        )
        assert by_name["valid_manifest_no_cfg"].expected_forwarded_prefix == f"/comet/{token}"

        assert by_name["valid_manifest_with_cfg"].raw_target == (
            f"/comet/{token}/s/{api_token}/{cfg_blob}/manifest.json"
        )
        assert by_name["valid_manifest_with_cfg"].expected_upstream_path == (
            f"/s/{api_token}/{cfg_blob}/manifest.json"
        )

        assert by_name["valid_stream_query_preserved"].expected_upstream_path == (
            f"/s/{api_token}/stream/movie/tt1234567.json?foo=bar&baz=1%202"
        )
        assert by_name["valid_playback_encoded_space"].expected_upstream_path == (
            f"/s/{api_token}/{cfg_blob}/playback/host/0/Movie%20Title/1/2"
        )
        assert by_name["valid_token_configure"].expected_upstream_path == "/configure"
        assert by_name["valid_token_configure_login"].method == "POST"
        assert by_name["valid_token_configure_login"].expected_upstream_path == "/configure/login"

        assert by_name["public_configure"].forbidden_upstream_headers == ("X-Forwarded-Prefix",)
        assert by_name["host_port_and_stripped_ip_headers"].host_header == "gw.example.test:8443"
        assert by_name["host_port_and_stripped_ip_headers"].expected_host == "gw.example.test:8443"
        assert (
            by_name["host_port_and_stripped_ip_headers"].expected_forwarded_host
            == "gw.example.test:8443"
        )
        assert by_name["host_port_and_stripped_ip_headers"].forbidden_upstream_headers == (
            "X-Forwarded-For",
            "CF-Connecting-IP",
        )

        assert by_name["token_base_redirect"].expected_status == 302
        assert by_name["token_base_redirect"].expected_location == f"/comet/{token}/configure"
        assert by_name["http10_no_host"].http_version == "HTTP/1.0"
        assert by_name["http10_no_host"].send_host is False
        assert by_name["http10_no_host"].expected_status == 400

        blocked_targets = {c.raw_target for c in cases if c.expected_status == 403}
        for expected_blocked in (
            f"/comet/{token}/admin",
            f"/comet/{token}/%61dmin/",
            f"/comet/{token}//admin",
            f"/comet/{token}/ADMIN",
            f"/comet/{token}/x/../admin",
            f"/comet/{token}/configure/../admin",
            f"/comet/{token}/kodi/get_manifest/123",
            f"/comet/{token}/%6bodi/get_manifest/123",
            f"/comet/{token}/s/{api_token}/torznab/api",
            f"/comet/{token}/s/{api_token}/{cfg_blob}/debrid-sync/0",
            f"/comet/{token}/cometnet/status",
            f"/comet/{token}/administrator",
            f"/comet/{token}/kodiak",
            f"/comet/{token}/s/{api_token}/{cfg_blob}/playback/host/0/Movie%2FTitle/1/2",
            f"/comet/{token}/s/{api_token}/manifest%2Ejson",
            f"/comet/{token.swapcase()}/s/{api_token}/manifest.json",
            "/admin",
            "/%61dmin/",
            "//admin",
            "/ADMIN",
            "/x/../admin",
            "/configure/../admin",
            "/kodi/x",
            "/%6bodi/x",
            "/__sg_alive",
        ):
            assert expected_blocked in blocked_targets

        # AC-18: restored probes keep exact 1a23201 names, raw targets, and 403/unproxied
        restored_1a23201 = {
            "token_pct_admin": f"/comet/{token}/%61dmin/",
            "token_double_slash_admin": f"/comet/{token}//admin",
            "token_upper_admin": f"/comet/{token}/ADMIN",
            "token_configure_dotdot_admin": f"/comet/{token}/configure/../admin",
            "token_pct_kodi": f"/comet/{token}/%6bodi/get_manifest/123",
            "top_pct_admin": "/%61dmin/",
            "top_double_slash_admin": "//admin",
            "top_upper_admin": "/ADMIN",
            "top_dotdot_admin": "/x/../admin",
            "top_configure_dotdot_admin": "/configure/../admin",
            "top_pct_kodi": "/%6bodi/x",
        }
        for name, target in restored_1a23201.items():
            assert by_name[name].raw_target == target
            assert by_name[name].expected_status == 403
            assert by_name[name].expect_proxied is False

        assert by_name["health_alive_204"].target_port == 8099
        assert by_name["health_alive_204"].expected_status == 204
        assert by_name["health_root_404"].target_port == 8099
        assert by_name["health_root_404"].expected_status == 404

        for case in cases:
            if case.expected_status in (400, 403, 404, 204, 302):
                assert case.expect_proxied is False


class TestDockerRunArgsAndPrefixValidation:
    def test_echo_and_nginx_docker_run_args_have_no_network_no_ports_and_hardening(
        self, tmp_path: Path
    ) -> None:
        echo_args = lab.build_echo_docker_run_args(
            echo_name="sgfix12-lab-1234-echo",
            echo_image="g0ldyy/comet@sha256:abc",
            pull=False,
        )
        assert "--network" in echo_args
        assert echo_args[echo_args.index("--network") + 1] == "none"
        assert "--no-healthcheck" in echo_args
        assert "-p" not in echo_args
        assert "--publish" not in echo_args
        assert "stremioguard.lab=1" in echo_args

        spec = lab.load_gateway_service_spec(
            lab.REPO_ROOT / "docker-compose.yml", name_prefix="sgfix12-lab-"
        )
        nginx_args = lab.build_nginx_docker_run_args(
            nginx_name="sgfix12-lab-1234-nginx",
            echo_name="sgfix12-lab-1234-echo",
            state_dir=tmp_path / "gw",
            spec=spec,
            gateway_image=None,
            pull=False,
        )
        assert nginx_args[nginx_args.index("--network") + 1] == "container:sgfix12-lab-1234-echo"
        assert "-p" not in nginx_args
        assert "--publish" not in nginx_args
        assert "--read-only" in nginx_args
        assert "--cap-drop" in nginx_args
        assert nginx_args[nginx_args.index("--cap-drop") + 1] == "ALL"
        added_caps = {nginx_args[i + 1] for i, tok in enumerate(nginx_args) if tok == "--cap-add"}
        assert added_caps == {"CHOWN", "SETGID", "SETUID"}
        assert "no-new-privileges:true" in nginx_args
        tmpfs_targets = {nginx_args[i + 1] for i, tok in enumerate(nginx_args) if tok == "--tmpfs"}
        assert tmpfs_targets == {"/tmp", "/var/cache/nginx"}

    @pytest.mark.parametrize(
        "bad_prefix",
        ["", "-bad", "BadPrefix-", "bad_prefix", "a" * 32, "bad/prefix"],
    )
    def test_rejected_name_prefix_runs_no_docker_command(
        self, bad_prefix: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with mock.patch.object(lab.subprocess, "run") as run_mock:
            rc = lab.main(["gateway", f"--name-prefix={bad_prefix}"])
        assert rc == 1
        run_mock.assert_not_called()
        assert "Invalid --name-prefix" in capsys.readouterr().err

    def test_accepts_valid_prefixes(self) -> None:
        assert lab.validate_name_prefix("sglab-") == "sglab-"
        assert lab.validate_name_prefix("sgfix12-lab-") == "sgfix12-lab-"
        assert lab.validate_name_prefix("a" + "b" * 30) == "a" + "b" * 30


class TestResponseParsing:
    def test_parses_http11_response_and_case_insensitive_headers(self) -> None:
        raw = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: /comet/AbCdEfGh/configure\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        resp = lab.parse_http_response(raw)
        assert resp.status == 302
        assert resp.headers["location"] == "/comet/AbCdEfGh/configure"
        assert resp.body == b""
        assert resp.is_http09 is False

    def test_parses_http09_raw_body_and_http_error_fallback(self) -> None:
        raw_body = b'{"path": "/manifest.json"}\n'
        resp = lab.parse_http_response(raw_body, http09=True)
        assert resp.is_http09 is True
        assert resp.status is None
        assert resp.body == raw_body

        err = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad"
        resp_err = lab.parse_http_response(err, http09=True)
        assert resp_err.is_http09 is False
        assert resp_err.status == 400
        assert resp_err.body == b"bad"

    def test_rejects_malformed_http_response(self) -> None:
        with pytest.raises(ValueError, match="header terminator"):
            lab.parse_http_response(b"HTTP/1.1 200 OK")
        with pytest.raises(ValueError, match="status line"):
            lab.parse_http_response(b"NOTHTTP\r\n\r\n")


class TestEvaluationAndLogMasking:
    def test_parse_echo_records_filters_readiness_and_non_json(self) -> None:
        logs = "\n".join(
            [
                "not json",
                json.dumps({"case": lab.READINESS_CASE_ID, "path": "/health"}),
                json.dumps({"case": "valid_manifest_no_cfg", "path": "/s/api/manifest.json"}),
            ]
        )
        records = lab.parse_echo_records(logs)
        assert len(records) == 1
        assert records[0]["case"] == "valid_manifest_no_cfg"

    def test_evaluate_gateway_case_checks_headers_and_connection_errors(self) -> None:
        case = lab.GatewayCase(
            name="host_port_and_stripped_ip_headers",
            method="GET",
            raw_target="/comet/tok/s/api/manifest.json",
            expected_status=200,
            expect_proxied=True,
            expected_upstream_path="/s/api/manifest.json",
            expected_forwarded_prefix="/comet/tok",
            expected_host="gw.example.test:8443",
            expected_forwarded_host="gw.example.test:8443",
            forbidden_upstream_headers=("X-Forwarded-For", "CF-Connecting-IP"),
        )
        ok_resp = lab.HttpResponse(status=200, headers={}, body=b"{}")
        ok_records: list[dict[str, object]] = [
            {
                "case": "host_port_and_stripped_ip_headers",
                "path": "/s/api/manifest.json",
                "headers": {
                    "Host": "gw.example.test:8443",
                    "X-Forwarded-Prefix": "/comet/tok",
                    "X-Forwarded-Host": "gw.example.test:8443",
                    "X-Forwarded-For": None,
                    "CF-Connecting-IP": None,
                },
            }
        ]
        assert lab.evaluate_gateway_case(case, ok_resp, ok_records).passed is True

        leaked_records: list[dict[str, object]] = [
            {
                "case": "host_port_and_stripped_ip_headers",
                "path": "/s/api/manifest.json",
                "headers": {
                    "Host": "gw.example.test:8443",
                    "X-Forwarded-Prefix": "/comet/tok",
                    "X-Forwarded-Host": "gw.example.test:8443",
                    "X-Forwarded-For": "198.51.100.77",
                    "CF-Connecting-IP": None,
                },
            }
        ]
        assert lab.evaluate_gateway_case(case, ok_resp, leaked_records).passed is False

        health_case = lab.GatewayCase(
            name="health_alive_204",
            method="GET",
            raw_target="/__sg_alive",
            target_port=8099,
            expected_status=204,
            expect_proxied=False,
        )
        failed = lab.evaluate_gateway_case(health_case, "error:ConnectionRefusedError", [])
        assert failed.passed is False
        assert "ConnectionRefusedError" in failed.observed

        http09_case = lab.GatewayCase(
            name="log_probe_http09",
            method="GET",
            raw_target="/comet/tok/s/api/cfg/manifest.json",
            http_version=None,
            expected_status=400,
            expect_proxied=False,
        )
        assert (
            lab.evaluate_gateway_case(
                http09_case,
                lab.HttpResponse(
                    status=None, headers={}, body=b"<html>400 Bad Request</html>", is_http09=True
                ),
                [],
            ).passed
            is True
        )
        assert (
            lab.evaluate_gateway_case(
                http09_case,
                lab.HttpResponse(status=None, headers={}, body=b'{"path":"/x"}', is_http09=True),
                [],
            ).passed
            is False
        )

    def test_check_access_log_secrets_detects_empty_and_leaks(self) -> None:
        empty_results = lab.check_access_log_secrets("", {"token": "SecretTok", "cfg_blob": "Cfg"})
        assert empty_results[0].name == "access_log_nonempty"
        assert empty_results[0].passed is False

        clean_log = '127.0.0.1 [14/Nov/2026:18:00:00 +0000] "GET /comet/*** HTTP/1.1" 200 10\n'
        clean = lab.check_access_log_secrets(
            clean_log, {"token": "SecretTok", "cfg_blob": "CfgBlob123"}
        )
        assert all(r.passed for r in clean)

        leaky_log = (
            "127.0.0.1 [14/Nov/2026:18:00:00 +0000] "
            '"GET /configure?next=/comet/SecretTok&cfg=CfgBlob123 HTTP/1.1" 200 10\n'
        )
        leaky = {
            r.name: r
            for r in lab.check_access_log_secrets(
                leaky_log, {"token": "SecretTok", "cfg_blob": "CfgBlob123"}
            )
        }
        assert leaky["access_log_leak_token"].passed is False
        assert "1 occurrences" in leaky["access_log_leak_token"].observed
        assert leaky["access_log_leak_cfg_blob"].passed is False

    def test_evaluate_render_manifest_distinguishes_required_and_optional_skips(self) -> None:
        manifest: dict[str, object] = {
            "applied": [
                "api_app",
                "response_guard",
                "logger",
                "stream",
                "media_search",
                "config",
                "template",
                "filtering",
                "orchestration",
            ],
            "skipped": [
                {"name": "formatter", "reason": "disabled"},
                {"name": "torrentio", "reason": "anchor missing"},
            ],
            "outputs": {"app.py": "/app/comet/api/app.py"},
        }
        results = {r.name: r for r in lab.evaluate_render_manifest(manifest, gateway_enabled=True)}
        assert results["patch:api_app"].passed is True
        assert results["patch:formatter"].passed is True
        assert results["patch:torrentio"].passed is True
        assert "skipped: anchor missing" in results["patch:torrentio"].observed

        broken_manifest: dict[str, object] = {
            "applied": ["logger"],
            "skipped": [{"name": "api_app", "reason": "anchor missing"}],
            "outputs": {},
        }
        broken = {
            r.name: r for r in lab.evaluate_render_manifest(broken_manifest, gateway_enabled=True)
        }
        assert broken["patch:api_app"].passed is False
        assert broken["patch:config"].passed is False


class TestConfigAndResourceHelpers:
    def test_resolve_echo_image_priority_and_missing_state_error(self, tmp_path: Path) -> None:
        assert lab.resolve_echo_image("custom/comet:test", tmp_path) == "custom/comet:test"

        with pytest.raises(lab.LabError, match="--echo-image"):
            lab.resolve_echo_image(None, tmp_path)

        state_file = tmp_path / ".stremio" / "comet" / "state.json"
        state_file.parent.mkdir(parents=True)
        digest = "sha256:" + "a" * 64
        state_file.write_text(json.dumps({"active_digest": digest}), encoding="utf-8")
        assert lab.resolve_echo_image(None, tmp_path) == f"g0ldyy/comet@{digest}"

    def test_lab_resources_cleans_up_on_keyboard_interrupt(self) -> None:
        removed: list[list[str]] = []
        created_dir: Path | None = None

        def fake_run(args: list[str], **_kwargs: object) -> object:
            removed.append(args)
            return None

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=fake_run),
            pytest.raises(KeyboardInterrupt),
            lab.lab_resources(name_prefix="sgtest-") as (tmpdir, containers),
        ):
            created_dir = tmpdir
            assert tmpdir.name.startswith("sgtest-")
            containers.extend(["sgtest-1-echo", "sgtest-1-nginx"])
            assert tmpdir.is_dir()
            raise KeyboardInterrupt

        assert created_dir is not None
        assert not created_dir.exists()
        assert removed == [
            ["docker", "rm", "-f", "sgtest-1-nginx"],
            ["docker", "rm", "-f", "sgtest-1-echo"],
        ]

    def test_format_case_line(self) -> None:
        line = lab.format_case_line(
            lab.CaseResult(passed=False, name="token_admin", expected="403", observed="200")
        )
        assert line == "FAIL  token_admin  expected=403  observed=200"

    def test_ac16_load_gateway_service_spec_never_reads_env_or_secret_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC-16 (R1-1, INV-9): load_gateway_service_spec skips .env and secret env_file merges."""
        shutil.copy2(lab.REPO_ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
        sentinels = {
            ".env": ("SERVER_COUNTRIES=SG12_LAB_SENTINEL_A\n", "SG12_LAB_SENTINEL_A"),
            ".stremio/gluetun.env": (
                "OPENVPN_PASSWORD=SG12_LAB_SENTINEL_B\n",
                "SG12_LAB_SENTINEL_B",
            ),
            ".stremio/comet/postgres.env": (
                "POSTGRES_PASSWORD=SG12_LAB_SENTINEL_C\n",
                "SG12_LAB_SENTINEL_C",
            ),
            ".stremio/stremthru/stremthru.env": (
                "STREMTHRU_AUTH=user:SG12_LAB_SENTINEL_D\n",
                "SG12_LAB_SENTINEL_D",
            ),
        }
        for rel, (body, _) in sentinels.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")

        captured: list[tuple[list[str], bytes]] = []
        real_run = lab._run

        def spy_run(args: list[str], **kwargs: object) -> object:
            proc = real_run(args, **kwargs)  # type: ignore[arg-type]
            captured.append((list(args), proc.stdout))
            return proc

        monkeypatch.setattr(lab, "_run", spy_run)
        spec = lab.load_gateway_service_spec(
            tmp_path / "docker-compose.yml", name_prefix="sgfix12-ac16-"
        )

        assert spec.image.startswith("nginx:") and "@sha256:" in spec.image
        assert spec.cap_drop == ("ALL",)
        assert set(spec.cap_add) == {"CHOWN", "SETGID", "SETUID"}
        assert spec.security_opt == ("no-new-privileges:true",)
        assert spec.read_only is True
        assert set(spec.tmpfs) == {"/tmp", "/var/cache/nginx"}

        assert len(captured) == 1
        argv, raw_stdout = captured[0]
        env_idx = argv.index("--env-file")
        assert argv[env_idx + 1] == "/dev/null"
        assert env_idx < argv.index("-f")
        assert "--no-env-resolution" in argv
        assert "--no-interpolate" in argv

        output_text = raw_stdout.decode("utf-8")
        for _, sentinel in sentinels.values():
            assert sentinel not in output_text
