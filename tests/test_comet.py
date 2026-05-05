"""Tests for unified Comet lifecycle, runtime rendering, and playback probing."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import typer

from stremioguard import cli as cli_mod
from stremioguard import comet as comet_mod
from stremioguard.comet import CometManager
from stremioguard.env import env_file_value
from stremioguard.publishing import render_stack_compose_override

from .conftest import FakeRunner, completed, make_comet_config, make_config


def _write_lock(path: Path, commit: str = "abc123") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "upstream_url": "https://github.com/g0ldyy/comet",
                "pinned_commit": commit,
                "default_branch": "main",
            }
        ),
        encoding="utf-8",
    )


def _write_upstream_patch_sources(cfg) -> None:
    formatting_file = cfg.repo_dir / "comet" / "utils" / "formatting.py"
    stream_file = cfg.repo_dir / "comet" / "api" / "endpoints" / "stream.py"
    torrentio_file = cfg.repo_dir / "comet" / "scrapers" / "torrentio.py"
    filtering_file = cfg.repo_dir / "comet" / "services" / "filtering.py"
    orchestration_file = cfg.repo_dir / "comet" / "services" / "orchestration.py"
    formatting_file.parent.mkdir(parents=True, exist_ok=True)
    stream_file.parent.mkdir(parents=True, exist_ok=True)
    torrentio_file.parent.mkdir(parents=True, exist_ok=True)
    filtering_file.parent.mkdir(parents=True, exist_ok=True)
    orchestration_file.parent.mkdir(parents=True, exist_ok=True)
    formatting_file.write_text(
        "def get_formatted_components(\n"
        "    data: ParsedData,\n"
        "    ttitle: str,\n"
        "    seeders: int,\n"
        "    size: int,\n"
        "    tracker: str,\n"
        "    result_format: list,\n"
        "):\n"
        "    return _get_formatted_components(\n"
        "        data, ttitle, seeders, size, tracker, result_format, _STYLE_EMOJI\n"
        "    )\n",
        encoding="utf-8",
    )
    stream_file.write_text(
        "def _build_stream_name(\n"
        "    kodi: bool,\n"
        "    service: str,\n"
        "    resolution,\n"
        '    icon: str = "",\n'
        "    formatted_components: dict | None = None,\n"
        "    seeders: int | None = None,\n"
        '    status: str = "",\n'
        "):\n"
        "    if not kodi:\n"
        '        return f"[{service}{icon}] Comet {resolution}"\n',
        encoding="utf-8",
    )
    torrentio_file.write_text(
        "import re\n"
        "\n"
        "DATA_PATTERN = re.compile(\n"
        '    r"(?:👤 (\\d+) )?💾 ([\\\\d.]+ [KMGT]B)(?: ⚙️ (\\\\w+))?", re.IGNORECASE\n'
        ")\n"
        "\n"
        "def scrape(self, torrent, torrents, title, seeders, size, tracker):\n"
        "    torrents.append(\n"
        "        {\n"
        '            "title": title,\n'
        '            "infoHash": torrent["infoHash"].lower(),\n'
        '            "fileIndex": torrent.get("fileIdx", None),\n'
        '            "seeders": seeders,\n'
        '            "size": size,\n'
        '            "tracker": f"Torrentio|{tracker}",\n'
        '            "sources": torrent.get("sources", []),\n'
        "        }\n"
        "    )\n",
        encoding="utf-8",
    )
    filtering_file.write_text(
        "from RTN import title_match\n"
        "\n"
        "def quick_alias_match(text_normalized: str, ez_aliases_normalized: list[str]):\n"
        "    return False\n"
        "\n"
        "def scrub(t: str):\n"
        "    return t\n"
        "\n"
        "def filter_worker("
        "torrents, title, year, year_end, "
        "media_type, aliases, remove_adult_content):\n"
        "    results = []\n"
        "    ez_aliases_normalized = []\n"
        "    for torrent in torrents:\n"
        "        torrent_title = torrent['title']\n"
        "        parsed = type('P', (), {'parsed_title': torrent_title})()\n"
        "        alias_matched = ez_aliases_normalized"
        " and quick_alias_match("
        "scrub(torrent_title), ez_aliases_normalized)\n"
        "        if not alias_matched:\n"
        "            if not title_match(title, parsed.parsed_title, aliases=aliases):\n"
        "                continue\n"
        "        results.append(torrent)\n"
        "    return results\n",
        encoding="utf-8",
    )
    orchestration_file.write_text(
        "from RTN import ParsedData\n"
        "from comet.utils.parsing import parsed_matches_target\n"
        "\n"
        "class TorrentManager:\n"
        "    def _matches_requested_scope(\n"
        "        self,\n"
        "        parsed: ParsedData,\n"
        "        *,\n"
        "        reject_unknown_override: bool | None = None,\n"
        "    ) -> bool:\n"
        "        reject_unknown = (\n"
        "            self.reject_unknown_episode_files\n"
        "            if reject_unknown_override is None\n"
        "            else reject_unknown_override\n"
        "        )\n"
        "        return parsed_matches_target(\n"
        "            parsed,\n"
        "            self.search_season,\n"
        "            self.search_episode,\n"
        "            target_air_date=self.target_air_date,\n"
        "            reject_unknown_episode_files=reject_unknown,\n"
        "        )\n"
        "\n"
        "    async def scrape_torrents(self):\n"
        "        for torrent in self.ready_to_cache:\n"
        '            if not self._matches_requested_scope(torrent["parsed"]):\n'
        "                continue\n"
        "\n"
        "    async def get_cached_torrents(self):\n"
        "        if not self._matches_requested_scope(\n"
        "            parsed_data, reject_unknown_override=reject_unknown_override\n"
        "        ):\n"
        "            return\n"
        "\n"
        "    def _append_cache_file_infos(self, file_infos: list[dict], torrent: dict):\n"
        '        parsed = torrent["parsed"]\n'
        "        if not self._matches_requested_scope(parsed, reject_unknown_override=True):\n"
        "            return\n",
        encoding="utf-8",
    )


class CometManagerTests(unittest.TestCase):
    def test_load_lock_reads_expected_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_lock(cfg.lock_file, commit="deadbeef")
            lock = comet_mod.CometLock.load(cfg.lock_file)
            self.assertEqual(lock.upstream_url, "https://github.com/g0ldyy/comet")
            self.assertEqual(lock.pinned_commit, "deadbeef")
            self.assertEqual(lock.default_branch, "main")

    def test_fetch_and_checkout_pinned_runs_clone_fetch_and_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_lock(cfg.lock_file, commit="deadbeef")
            runner = FakeRunner(
                {
                    (
                        "git",
                        "clone",
                        "https://github.com/g0ldyy/comet",
                        str(cfg.repo_dir),
                    ): completed(["git", "clone"], ""),
                    ("git", "-C", str(cfg.repo_dir), "status", "--porcelain"): completed(
                        ["git", "status"], ""
                    ),
                    ("git", "-C", str(cfg.repo_dir), "fetch", "origin"): completed(
                        ["git", "fetch"], ""
                    ),
                    ("git", "-C", str(cfg.repo_dir), "checkout", "--detach", "deadbeef"): completed(
                        ["git", "checkout"], ""
                    ),
                }
            )
            manager = CometManager(cfg, runner)
            manager.fetch_and_checkout_pinned()
            self.assertIn(
                ["git", "clone", "https://github.com/g0ldyy/comet", str(cfg.repo_dir)],
                runner.calls,
            )

    def test_fetch_and_checkout_warns_on_dirty_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            _write_lock(cfg.lock_file, commit="deadbeef")
            (cfg.repo_dir / ".git").mkdir(parents=True, exist_ok=True)
            runner = FakeRunner(
                {
                    ("git", "-C", str(cfg.repo_dir), "status", "--porcelain"): completed(
                        ["git", "status"], " M README.md\n"
                    ),
                    ("git", "-C", str(cfg.repo_dir), "fetch", "origin"): completed(
                        ["git", "fetch"], ""
                    ),
                    ("git", "-C", str(cfg.repo_dir), "checkout", "--detach", "deadbeef"): completed(
                        ["git", "checkout"], ""
                    ),
                }
            )
            manager = CometManager(cfg, runner)
            with mock.patch.object(manager, "warn") as warn:
                manager.fetch_and_checkout_pinned()
            warn.assert_called_once()

    def test_render_runtime_env_uses_localhost_postgres_and_server_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(
                tmp_path,
                public_base_url="https://comet.example.com",
                proxy_max_connections=2,
                default_debrid_service="torbox",
                default_debrid_apikey="tb-key",
            )
            manager = CometManager(cfg, FakeRunner({}))
            rendered = manager.render_runtime_env()
            self.assertIn("DATABASE_URL=comet:comet@127.0.0.1:5432/comet", rendered)
            self.assertIn("PUBLIC_BASE_URL=https://comet.example.com", rendered)
            self.assertIn("CONFIGURE_PAGE_PASSWORD=cfg-password", rendered)
            self.assertIn("PROXY_DEBRID_STREAM=True", rendered)
            self.assertIn("PROXY_DEBRID_STREAM_MAX_CONNECTIONS=2", rendered)
            self.assertIn("PROXY_DEBRID_STREAM_DEBRID_DEFAULT_SERVICE=torbox", rendered)
            self.assertIn("PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY=tb-key", rendered)

    def test_render_runtime_env_allows_blank_server_owned_debrid_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path, default_debrid_apikey=None)
            manager = CometManager(cfg, FakeRunner({}))
            rendered = manager.render_runtime_env()
            self.assertIn("PROXY_DEBRID_STREAM_DEBRID_DEFAULT_APIKEY=", rendered)

    def test_write_stack_override_mounts_runtime_files_through_root_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            make_config(tmp_path)
            cfg = make_comet_config(tmp_path, bind_addresses=("10.0.0.5", "100.64.0.8"))
            _write_upstream_patch_sources(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            manager.write_stack_override_file()
            root_override = tmp_path / ".stremio" / "docker-compose.bindings.yml"
            content = root_override.read_text(encoding="utf-8")
            self.assertIn('"10.0.0.5:18000:8000"', content)
            self.assertIn('"100.64.0.8:18000:8000"', content)
            self.assertIn(str(cfg.runtime_env_file), content)
            self.assertIn(
                f"{cfg.state_dir / 'formatting.py'}:/app/comet/utils/formatting.py:ro",
                content,
            )
            self.assertIn(
                f"{cfg.state_dir / 'stream.py'}:/app/comet/api/endpoints/stream.py:ro",
                content,
            )
            self.assertIn(
                f"{cfg.state_dir / 'torrentio.py'}:/app/comet/scrapers/torrentio.py:ro",
                content,
            )
            self.assertIn(
                f"{cfg.state_dir / 'filtering.py'}:/app/comet/services/filtering.py:ro",
                content,
            )
            self.assertIn(
                f"{cfg.state_dir / 'orchestration.py'}:/app/comet/services/orchestration.py:ro",
                content,
            )
            filtering_override = (cfg.state_dir / "filtering.py").read_text(encoding="utf-8")
            torrentio_override = (cfg.state_dir / "torrentio.py").read_text(encoding="utf-8")
            self.assertIn("TITLE_TOKEN_STOPWORDS", filtering_override)
            self.assertIn("resolvedFileName", filtering_override)
            self.assertIn("sourceTitle", torrentio_override)
            self.assertIn("resolvedFileName", torrentio_override)

    def test_write_stack_override_omits_orchestration_mount_when_patch_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            make_config(tmp_path)
            cfg = make_comet_config(tmp_path, patch_episode_pack_results=False)
            _write_upstream_patch_sources(cfg)
            manager = CometManager(cfg, FakeRunner({}))
            manager.write_stack_override_file()
            root_override = tmp_path / ".stremio" / "docker-compose.bindings.yml"
            content = root_override.read_text(encoding="utf-8")
            self.assertNotIn("/app/comet/services/orchestration.py:ro", content)
            self.assertFalse((cfg.state_dir / "orchestration.py").exists())

    def test_render_stack_compose_override_omits_comet_when_disabled(self) -> None:
        content = render_stack_compose_override(
            bind_addresses=["127.0.0.1"],
            stremio_host_port=11470,
            stremio_container_port=11470,
            comet_config=None,
        )
        self.assertIn('"127.0.0.1:11470:11470"', content)
        self.assertNotIn("comet-postgres", content)
        self.assertNotIn("/app/data", content)

    def test_healthcheck_prefers_container_local_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            cfg = make_comet_config(tmp_path)
            runner = FakeRunner(
                {
                    (
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Health.Status}}",
                        cfg.container_name,
                    ): completed(["docker", "inspect"], "healthy\n"),
                    (
                        "docker",
                        "exec",
                        cfg.container_name,
                        "wget",
                        "-qO-",
                        "http://127.0.0.1:8000/health",
                    ): completed(["docker", "exec"], '{"status":"ok"}'),
                }
            )
            manager = CometManager(cfg, runner)
            self.assertTrue(manager.healthcheck())

    def test_doctor_checks_network_mode_and_matching_public_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            make_config(tmp_path)
            cfg = make_comet_config(tmp_path, bind_addresses=("127.0.0.1",))
            _write_lock(cfg.lock_file, commit="deadbeef")
            (cfg.repo_dir / ".git").mkdir(parents=True, exist_ok=True)
            _write_upstream_patch_sources(cfg)
            cfg.runtime_env_file.parent.mkdir(parents=True, exist_ok=True)
            cfg.runtime_env_file.write_text(
                "PROXY_DEBRID_STREAM=True\nCONFIGURE_PAGE_PASSWORD=cfg-password\n",
                encoding="utf-8",
            )
            runner = FakeRunner(
                {
                    ("git", "-C", str(cfg.repo_dir), "rev-parse", "HEAD"): completed(
                        ["git", "rev-parse"], "deadbeef\n"
                    ),
                    (
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Health.Status}}",
                        cfg.container_name,
                    ): completed(["docker", "inspect"], "healthy\n"),
                    (
                        "docker",
                        "exec",
                        cfg.container_name,
                        "wget",
                        "-qO-",
                        "http://127.0.0.1:8000/health",
                    ): completed(["docker", "exec"], '{"status":"ok"}'),
                    (
                        "docker",
                        "compose",
                        "-f",
                        str(tmp_path / "docker-compose.yml"),
                        "-f",
                        str(tmp_path / ".stremio" / "docker-compose.bindings.yml"),
                        "ps",
                        "gluetun",
                    ): completed(
                        ["docker", "compose", "ps"],
                        "gluetun  running  127.0.0.1:18000->8000/tcp\n",
                    ),
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed(
                        ["docker", "ps", "--format", "{{.ID}}"],
                        "abc123\n",
                    ),
                    ("docker", "inspect", "-f", "{{.Id}}", "gluetun"): completed(
                        ["docker", "inspect"], "gluetun-id\n"
                    ),
                    (
                        "docker",
                        "inspect",
                        "-f",
                        "{{.HostConfig.NetworkMode}}",
                        cfg.container_name,
                    ): completed(["docker", "inspect"], "container:gluetun-id\n"),
                    (
                        "docker",
                        "exec",
                        "gluetun",
                        "wget",
                        "-qO-",
                        "https://api.ipify.org",
                    ): completed(["docker", "exec"], "203.0.113.10"),
                    (
                        "docker",
                        "exec",
                        cfg.container_name,
                        "wget",
                        "-qO-",
                        "https://api.ipify.org",
                    ): completed(["docker", "exec"], "203.0.113.10"),
                }
            )
            manager = CometManager(cfg, runner)
            with mock.patch.object(manager, "host_healthcheck", return_value=True):
                manager.doctor()

    def test_doctor_fails_when_egress_differs_from_gluetun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            make_config(tmp_path)
            cfg = make_comet_config(tmp_path)
            _write_lock(cfg.lock_file, commit="deadbeef")
            (cfg.repo_dir / ".git").mkdir(parents=True, exist_ok=True)
            _write_upstream_patch_sources(cfg)
            cfg.runtime_env_file.parent.mkdir(parents=True, exist_ok=True)
            cfg.runtime_env_file.write_text(
                "PROXY_DEBRID_STREAM=True\nCONFIGURE_PAGE_PASSWORD=cfg-password\n",
                encoding="utf-8",
            )
            runner = FakeRunner(
                {
                    ("git", "-C", str(cfg.repo_dir), "rev-parse", "HEAD"): completed(
                        ["git", "rev-parse"], "deadbeef\n"
                    ),
                    (
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Health.Status}}",
                        cfg.container_name,
                    ): completed(["docker", "inspect"], "healthy\n"),
                    (
                        "docker",
                        "exec",
                        cfg.container_name,
                        "wget",
                        "-qO-",
                        "http://127.0.0.1:8000/health",
                    ): completed(["docker", "exec"], '{"status":"ok"}'),
                    (
                        "docker",
                        "compose",
                        "-f",
                        str(tmp_path / "docker-compose.yml"),
                        "-f",
                        str(tmp_path / ".stremio" / "docker-compose.bindings.yml"),
                        "ps",
                        "gluetun",
                    ): completed(
                        ["docker", "compose", "ps"],
                        "gluetun  running  127.0.0.1:18000->8000/tcp\n",
                    ),
                    ("docker", "compose", "version"): completed(["docker", "compose", "version"]),
                    ("docker", "ps", "--format", "{{.ID}}"): completed(
                        ["docker", "ps", "--format", "{{.ID}}"],
                        "abc123\n",
                    ),
                    ("docker", "inspect", "-f", "{{.Id}}", "gluetun"): completed(
                        ["docker", "inspect"], "gluetun-id\n"
                    ),
                    (
                        "docker",
                        "inspect",
                        "-f",
                        "{{.HostConfig.NetworkMode}}",
                        cfg.container_name,
                    ): completed(["docker", "inspect"], "container:gluetun-id\n"),
                    (
                        "docker",
                        "exec",
                        "gluetun",
                        "wget",
                        "-qO-",
                        "https://api.ipify.org",
                    ): completed(["docker", "exec"], "203.0.113.10"),
                    (
                        "docker",
                        "exec",
                        cfg.container_name,
                        "wget",
                        "-qO-",
                        "https://api.ipify.org",
                    ): completed(["docker", "exec"], "198.51.100.9"),
                }
            )
            manager = CometManager(cfg, runner)
            with (
                mock.patch.object(manager, "host_healthcheck", return_value=True),
                self.assertRaises(RuntimeError) as ctx,
            ):
                manager.doctor()
            self.assertIn("does not match gluetun", str(ctx.exception))


class PlaybackProbeTests(unittest.TestCase):
    def test_classify_playback_response_marks_external_location_as_redirect(self) -> None:
        result = comet_mod.classify_playback_response(
            status_code=302,
            headers={"Location": "https://provider.example/stream"},
            request_url="http://comet.example/playback/abc",
        )
        self.assertEqual(result, "redirected")

    def test_classify_playback_response_marks_range_capable_success_as_proxied(self) -> None:
        result = comet_mod.classify_playback_response(
            status_code=206,
            headers={"Accept-Ranges": "bytes", "Content-Type": "video/mp4"},
            request_url="http://comet.example/playback/abc",
        )
        self.assertEqual(result, "proxied")

    def test_probe_playback_raises_when_redirect_observed_but_proxy_expected(self) -> None:
        manager = CometManager(make_comet_config(Path("/tmp")), FakeRunner({}))
        with (
            mock.patch.object(
                comet_mod,
                "probe_playback_url",
                return_value=comet_mod.PlaybackProbeResult(
                    status_code=302,
                    classification="redirected",
                    location="https://provider.example/file.mkv",
                    content_type=None,
                ),
            ),
            self.assertRaises(RuntimeError) as ctx,
        ):
            manager.probe_playback("http://comet.example/playback/abc", expect_proxy=True)
        self.assertIn("Expected proxied playback", str(ctx.exception))


class CometCliTests(unittest.TestCase):
    def test_cli_comet_install_prompts_then_installs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_file = temp_root / ".env"
            env_file.write_text("COMET_ENABLED=0\n", encoding="utf-8")
            with (
                mock.patch.object(cli_mod, "ROOT_DIR", temp_root),
                mock.patch.object(cli_mod, "is_interactive", return_value=True),
                mock.patch.object(cli_mod, "prompt_comet_setup") as setup,
                mock.patch.object(cli_mod, "CometManager") as manager_cls,
                mock.patch.object(cli_mod, "logger"),
            ):
                cli_mod.comet_install()
            setup.assert_called_once()
            manager_cls.return_value.install.assert_called_once()

    def test_cli_comet_install_requires_tty(self) -> None:
        with (
            mock.patch.object(cli_mod, "is_interactive", return_value=False),
            self.assertRaises(typer.Exit) as ctx,
        ):
            cli_mod.comet_install()
        self.assertEqual(ctx.exception.exit_code, 1)

    def test_prompt_debrid_provider_accepts_numeric_choice(self) -> None:
        with (
            mock.patch.object(typer, "prompt", return_value="2"),
            mock.patch.object(typer, "echo"),
        ):
            self.assertEqual(comet_mod._prompt_debrid_provider("realdebrid"), "torbox")

    def test_prompt_comet_setup_preserves_existing_scraper_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            env_file = temp_root / ".env"
            env_file.write_text(
                "\n".join(
                    [
                        "COMET_ENABLED=0",
                        "COMET_HOST_PORT=18000",
                        "COMET_SCRAPE_TORRENTIO=background",
                        "COMET_TORRENTIO_URL=https://torrentio.example/custom",
                        "COMET_SCRAPE_ZILEAN=off",
                        "COMET_ZILEAN_URL=https://zilean.example/custom",
                        "COMET_RESULT_FORMAT_STYLE=emoji",
                        "COMET_PROXY_MAX_CONNECTIONS=7",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            cfg = make_comet_config(
                temp_root,
                scrape_torrentio="background",
                torrentio_url="https://torrentio.example/custom",
                scrape_zilean="off",
                zilean_url="https://zilean.example/custom",
                result_format_style="emoji",
                proxy_max_connections=7,
            )
            with (
                mock.patch.object(
                    typer,
                    "prompt",
                    side_effect=[
                        "18000",  # host port
                        "cfg-pass",  # configure password
                        "7",  # max connections
                    ],
                ),
                mock.patch.object(
                    typer,
                    "confirm",
                    side_effect=[
                        True,  # episode-pack patch
                        True,  # proxy enabled
                        False,  # no server default creds
                    ],
                ),
                mock.patch.object(typer, "echo"),
            ):
                comet_mod.prompt_comet_setup(cfg)

            self.assertEqual(env_file_value(env_file, "COMET_SCRAPE_TORRENTIO"), "background")
            self.assertEqual(
                env_file_value(env_file, "COMET_TORRENTIO_URL"),
                "https://torrentio.example/custom",
            )
            self.assertEqual(env_file_value(env_file, "COMET_SCRAPE_ZILEAN"), "off")
            self.assertEqual(
                env_file_value(env_file, "COMET_ZILEAN_URL"),
                "https://zilean.example/custom",
            )
            self.assertEqual(env_file_value(env_file, "COMET_RESULT_FORMAT_STYLE"), "emoji")

    def test_prompt_comet_setup_rejects_invalid_proxy_max_connections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            cfg = make_comet_config(temp_root, proxy_max_connections=7)
            with (
                mock.patch.object(
                    typer,
                    "prompt",
                    side_effect=[
                        "18000",  # host port
                        "cfg-pass",  # configure password
                        "0",  # invalid max connections
                    ],
                ),
                mock.patch.object(
                    typer,
                    "confirm",
                    side_effect=[
                        True,  # episode-pack patch
                        True,  # proxy enabled
                    ],
                ),
                mock.patch.object(typer, "echo"),
                self.assertRaises(typer.Exit) as ctx,
            ):
                comet_mod.prompt_comet_setup(cfg)
            self.assertEqual(ctx.exception.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
