from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock

from stremioguard.overrides.admin import render_admin_override
from stremioguard.overrides.api_app import render_api_app_override
from stremioguard.overrides.bundle import (
    SPECS,
    OverrideSpec,
    Requirement,
    write_override_bundle,
)
from stremioguard.publishing import StackPublisher

from .conftest import (
    COMET_ADMIN_SOURCE,
    COMET_API_APP_SOURCE,
    make_comet_config,
    make_comet_gateway_config,
    record_test_digest,
    write_bundle,
    write_comet_admin,
    write_comet_api_app,
    write_comet_logger,
    write_required_comet_sources,
)


class TestOverridesBundle(unittest.TestCase):
    def test_write_override_bundle_success_and_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            repo_dir = Path("/dummy/repo")

            def torrentio_fail(rd, ctx):
                raise RuntimeError("torrentio fail")

            mock_specs = [
                OverrideSpec(
                    name="formatter",
                    feature="formatter description",
                    container_path="/app/formatter",
                    output_name="formatting.py",
                    requirement=Requirement.OPTIONAL,
                    render=lambda rd, ctx: "formatter content",
                ),
                OverrideSpec(
                    name="stream",
                    feature="stream description",
                    container_path="/app/stream",
                    output_name="stream.py",
                    requirement=Requirement.REQUIRED_WHEN_GATEWAY,
                    render=lambda rd, ctx: "stream content",
                ),
                OverrideSpec(
                    name="config",
                    feature="config description",
                    container_path="/app/config",
                    output_name="config.py",
                    requirement=Requirement.REQUIRED_WHEN_GATEWAY,
                    render=lambda rd, ctx: None,
                ),
                OverrideSpec(
                    name="torrentio",
                    feature="torrentio description",
                    container_path="/app/torrentio",
                    output_name="torrentio.py",
                    requirement=Requirement.OPTIONAL,
                    render=torrentio_fail,
                ),
            ]

            with mock.patch("stremioguard.overrides.bundle.SPECS", mock_specs):
                # 1. With gateway_enabled=False: should NOT raise even though
                # config/torrentio failed/skipped
                write_override_bundle(
                    repo_dir=repo_dir,
                    state_dir=state_dir,
                    result_format_style="emoji",
                    patch_episode_pack_results=False,
                    gateway_enabled=False,
                    image_digest="sha256:123",
                    patch_fingerprint="fp123",
                )

                # Check outputs written
                self.assertTrue((state_dir / "formatting.py").exists())
                self.assertTrue((state_dir / "stream.py").exists())
                self.assertFalse((state_dir / "config.py").exists())
                self.assertFalse((state_dir / "torrentio.py").exists())

                # Check manifest.json
                manifest_path = state_dir / "bundle-manifest.json"
                self.assertTrue(manifest_path.exists())
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(manifest["image_digest"], "sha256:123")
                self.assertEqual(manifest["applied"], ["formatter", "stream"])
                self.assertEqual(len(manifest["skipped"]), 2)
                self.assertEqual(manifest["skipped"][0]["name"], "config")
                self.assertEqual(manifest["skipped"][1]["name"], "torrentio")
                self.assertEqual(
                    manifest["outputs"],
                    {"formatting.py": "/app/formatter", "stream.py": "/app/stream"},
                )

                # 2. With gateway_enabled=True: should raise RuntimeError because
                # 'config' (REQUIRED_WHEN_GATEWAY) is skipped/failed
                with self.assertRaises(RuntimeError) as ctx:
                    write_override_bundle(
                        repo_dir=repo_dir,
                        state_dir=state_dir,
                        result_format_style="emoji",
                        patch_episode_pack_results=False,
                        gateway_enabled=True,
                        image_digest="sha256:123",
                        patch_fingerprint="fp123",
                    )
                self.assertIn("Required patch 'config' failed to apply", str(ctx.exception))

    def test_stack_publisher_mounts_only_applied_patches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Write a dummy .env
            env_path = root / ".env"
            env_path.write_text(
                "STREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_ENABLED=1\nCOMET_ENABLED=1\n",
                encoding="utf-8",
            )

            # Mock comet config to point to state_dir
            comet_cfg = make_comet_config(root, enabled=True)
            comet_cfg.state_dir.mkdir(parents=True, exist_ok=True)

            # A bundle listing all required rank-context mounts, rendered for
            # the active digest and present on disk.
            record_test_digest(comet_cfg.state_dir)
            bundle_dir = write_bundle(
                comet_cfg,
                outputs={
                    "app.py": "/app/comet/api/app.py",
                    "stremioguard_response_guard.py": "/app/comet/stremioguard_response_guard.py",
                    "logger.py": "/app/comet/core/logger.py",
                    "formatting.py": "/app/comet/utils/formatting.py",
                    "stream.py": "/app/comet/api/endpoints/stream.py",
                    "media_search.py": "/app/comet/services/media_search.py",
                    "stremioguard_stream_guard.py": "/app/comet/stremioguard_stream_guard.py",
                    "playback.py": "/app/comet/api/endpoints/playback.py",
                    "config_validation.py": "/app/comet/core/config_validation.py",
                    "admin.py": "/app/comet/api/endpoints/admin.py",
                },
                extra={
                    "image_digest": "sha256:123",
                    "patch_fingerprint": "fp123",
                    "format_style": "emoji",
                    "patch_episode_pack": False,
                    "applied": ["response_guard", "formatter", "stream", "media_search"],
                    "skipped": [],
                },
            )
            # Run StackPublisher
            pub = StackPublisher(root)
            with (
                mock.patch("stremioguard.publishing.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.publishing.CometGatewayConfig.from_env",
                    return_value=make_comet_gateway_config(root, enabled=False),
                ),
            ):
                pub.publish()

            override_content = pub.compose_override_file.read_text(encoding="utf-8")

            # Formatting and stream should be in volume mounts, from the bundle
            # directory of the active digest.
            for name, target in (
                ("formatting.py", "/app/comet/utils/formatting.py"),
                ("stream.py", "/app/comet/api/endpoints/stream.py"),
                ("media_search.py", "/app/comet/services/media_search.py"),
            ):
                self.assertIn(f"- {bundle_dir / name}:{target}:ro", override_content)

            # Others like config or torrentio should NOT be in volume mounts
            self.assertNotIn("/app/comet/api/endpoints/config.py:ro", override_content)
            self.assertNotIn("/app/comet/scrapers/torrentio.py:ro", override_content)


_FILTERING_FIXTURE_HEAD = """\
class ValidationError(Exception):
    pass


def _parse_with_cache(text):
    raise ValidationError()


def title_match(title, parsed_title, aliases=None):
    return "direct-match" in parsed_title


def alternate_title_match(torrent_title, title, aliases):
    return "alt-match" in torrent_title


def quick_alias_match(text_normalized: str, ez_aliases_normalized: list[str]):
    return False


def scrub(t: str):
    return " ".join(t.lower().split())


"""

_FILTERING_FIXTURE_WORKER_NEW = """\
def filter_worker(torrents, title, aliases):
    results = []
    ez_aliases_normalized = []
    for torrent in torrents:
        torrent_title = torrent["title"]
        parsed = type("P", (), {"parsed_title": torrent_title})()
        alias_matched = ez_aliases_normalized and quick_alias_match(
            scrub(torrent_title), ez_aliases_normalized
        )
        if not alias_matched:
            if not title_match(
                title, parsed.parsed_title, aliases=aliases
            ) and not alternate_title_match(torrent_title, title, aliases):
                continue
        results.append(torrent)
    return results
"""

_FILTERING_FIXTURE_WORKER_OLD = """\
def filter_worker(torrents, title, aliases):
    results = []
    ez_aliases_normalized = []
    for torrent in torrents:
        torrent_title = torrent["title"]
        parsed = type("P", (), {"parsed_title": torrent_title})()
        alias_matched = ez_aliases_normalized and quick_alias_match(
            scrub(torrent_title), ez_aliases_normalized
        )
        if not alias_matched:
            if not title_match(title, parsed.parsed_title, aliases=aliases):
                continue
        results.append(torrent)
    return results
"""


class RenderFilteringOverrideTests(unittest.TestCase):
    """The filtering renderer must support both known upstream call-site
    shapes (pre- and post-2026-06 alternate_title_match) and fail closed on
    anything else."""

    def _render(self, upstream_source: str) -> str:
        from stremioguard.overrides.filtering import render_filtering_override

        with tempfile.TemporaryDirectory() as directory:
            filtering_file = Path(directory) / "comet" / "services" / "filtering.py"
            filtering_file.parent.mkdir(parents=True)
            filtering_file.write_text(upstream_source, encoding="utf-8")
            return render_filtering_override(Path(directory))

    def test_old_single_line_shape_is_patched(self) -> None:
        rendered = self._render(_FILTERING_FIXTURE_HEAD + _FILTERING_FIXTURE_WORKER_OLD)
        self.assertIn(
            "if not _titles_compat_match(torrent, torrent_title, title, "
            "parsed.parsed_title, aliases):",
            rendered,
        )
        compile(rendered, "<rendered>", "exec")

    def test_new_alternate_match_shape_is_patched(self) -> None:
        rendered = self._render(_FILTERING_FIXTURE_HEAD + _FILTERING_FIXTURE_WORKER_NEW)
        self.assertIn("_titles_compat_match(torrent, torrent_title", rendered)
        self.assertNotIn("and not alternate_title_match", rendered)
        compile(rendered, "<rendered>", "exec")

    def test_unknown_shape_fails_closed(self) -> None:
        source = (_FILTERING_FIXTURE_HEAD + _FILTERING_FIXTURE_WORKER_NEW).replace(
            "aliases=aliases", "aliases=aliases, strict=True"
        )
        with self.assertRaises(RuntimeError) as raised:
            self._render(source)
        self.assertIn("title-match block has changed", str(raised.exception))

    def test_missing_helper_marker_fails_closed(self) -> None:
        source = (_FILTERING_FIXTURE_HEAD + _FILTERING_FIXTURE_WORKER_OLD).replace(
            "def quick_alias_match", "def quick_alias_probe"
        )
        with self.assertRaises(RuntimeError) as raised:
            self._render(source)
        self.assertIn("helper marker has changed", str(raised.exception))

    def test_patched_chain_widens_but_never_narrows_matching(self) -> None:
        # Execute the rendered module: upstream's own matchers must still
        # win, upstream's alternate fallback must stay in the chain, and our
        # evidence match must only ADD results.
        rendered = self._render(_FILTERING_FIXTURE_HEAD + _FILTERING_FIXTURE_WORKER_NEW)
        namespace: dict[str, object] = {}
        exec(compile(rendered, "<rendered>", "exec"), namespace)
        filter_worker = namespace["filter_worker"]
        assert callable(filter_worker)

        kept_by_title = {"title": "direct-match show"}
        kept_by_upstream_alternate = {"title": "Инициал Ди / alt-match segment"}
        kept_by_our_evidence = {
            "title": "BRANDED.Release.Junk",
            "resolvedFileName": "The Requested Show S01E01 1080p.mkv",
        }
        rejected = {"title": "unrelated thing entirely"}

        results = cast(
            "list[dict[str, str]]",
            filter_worker(
                [kept_by_title, kept_by_upstream_alternate, kept_by_our_evidence, rejected],
                "The Requested Show",
                {},
            ),
        )
        self.assertIn(kept_by_title, results)
        self.assertIn(kept_by_upstream_alternate, results)
        self.assertIn(kept_by_our_evidence, results)
        self.assertNotIn(rejected, results)


class ReplaceFirstMatchingTests(unittest.TestCase):
    """The primitive every renderer edit routes through. str.replace() returns
    content unchanged when the anchor is missing, which would ship a
    half-patched file that still reports as applied — this must fail closed."""

    def test_applies_first_matching_candidate(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        out = replace_first_matching(
            "b = 2", (("a = 1", "a = 99"), ("b = 2", "b = 99")), error="nope"
        )
        self.assertEqual(out, "b = 99")

    def test_raises_when_no_candidate_matches(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        with self.assertRaises(RuntimeError) as raised:
            replace_first_matching("c = 3", (("a = 1", "a = 99"),), error="anchor gone")
        self.assertIn("anchor gone", str(raised.exception))

    def test_raises_on_unexpected_occurrence_count(self) -> None:
        # A changed occurrence count means the code moved; the edit can no
        # longer be trusted to land where it used to.
        from stremioguard.overrides._patching import replace_first_matching

        with self.assertRaises(RuntimeError) as raised:
            replace_first_matching("x\nx\n", (("x", "y"),), error="drifted", expected=1)
        self.assertIn("matched 2 sites, expected 1", str(raised.exception))

    def test_already_applied_is_a_no_op(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        content = "for t in items:\n    record(t)\n"
        out = replace_first_matching(
            content,
            (("for t in items:\n", "for t in items:\n    record(t)\n"),),
            error="nope",
        )
        self.assertEqual(out, content)


_FILTERING_FIXTURE_MATCHER = """\
class ValidationError(Exception):
    pass


def _parse_with_cache(text):
    raise ValidationError()


def title_match(title, parsed_title, aliases=None):
    return "direct-match" in parsed_title


def alternate_title_match(torrent_title, title, aliases):
    return "alt-match" in torrent_title


def exact_alias_match(text_normalized, ez_aliases_normalized):
    return bool(text_normalized) and text_normalized in ez_aliases_normalized


def scrub(t: str):
    return " ".join(t.lower().split())


class TitleMatcher:
    def __init__(self, title, aliases):
        self.title = title
        self.aliases = aliases
        self.aliases_normalized = frozenset()

    def matches_title(self, torrent_title, parsed_title):
        if exact_alias_match(scrub(parsed_title), self.aliases_normalized):
            return True
        return title_match(
            self.title, parsed_title, aliases=self.aliases
        ) or alternate_title_match(torrent_title, self.title, self.aliases)


def filter_worker(torrents, title, aliases):
    results = []
    matcher = TitleMatcher(title, aliases)
    aliases = matcher.aliases
    for torrent in torrents:
        torrent_title = torrent["title"]
        parsed = type("P", (), {"parsed_title": torrent_title})()
        if not matcher.matches_title(torrent_title, parsed.parsed_title):
            continue
        results.append(torrent)
    return results
"""


class RenderFilteringTitleMatcherShapeTests(unittest.TestCase):
    """2026-07 consolidated upstream's matchers behind a TitleMatcher class."""

    def _render(self, source: str) -> str:
        from stremioguard.overrides.filtering import render_filtering_override

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comet" / "services" / "filtering.py"
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            return render_filtering_override(Path(directory))

    def test_delegates_to_the_live_matcher(self) -> None:
        rendered = self._render(_FILTERING_FIXTURE_MATCHER)
        self.assertIn(
            "_titles_compat_match(torrent, torrent_title, title, parsed.parsed_title, "
            "aliases, matcher)",
            rendered,
        )
        compile(rendered, "<rendered>", "exec")

    def test_upstream_matcher_chain_still_wins_and_evidence_only_widens(self) -> None:
        rendered = self._render(_FILTERING_FIXTURE_MATCHER)
        namespace: dict[str, object] = {}
        exec(compile(rendered, "<rendered>", "exec"), namespace)
        filter_worker = namespace["filter_worker"]
        assert callable(filter_worker)

        by_title = {"title": "direct-match show"}
        by_upstream_alternate = {"title": "Инициал Ди / alt-match segment"}
        by_our_evidence = {
            "title": "BRANDED.Release.Junk",
            "resolvedFileName": "The Requested Show S01E01 1080p.mkv",
        }
        rejected = {"title": "unrelated thing entirely"}

        results = cast(
            "list[dict[str, str]]",
            filter_worker(
                [by_title, by_upstream_alternate, by_our_evidence, rejected],
                "The Requested Show",
                {},
            ),
        )
        self.assertIn(by_title, results)
        self.assertIn(by_upstream_alternate, results)
        self.assertIn(by_our_evidence, results)
        self.assertNotIn(rejected, results)


_ORCHESTRATION_FIXTURE_NEW = """\
from comet.utils.parsing import MediaScope, load_cached_parsed, resolve_media_scope


class TorrentManager:
    def __init__(self):
        self.primary_cached = False

    def _matches_requested_scope(
        self,
        parsed: ParsedData,
        *,
        reject_unknown_override: bool | None = None,
        scope_is_known: bool = False,
    ) -> bool:
        reject_unknown = (
            self.reject_unknown_episode_files
            if reject_unknown_override is None
            else reject_unknown_override
        )
        return self.media_scope.matches_parsed(
            parsed,
            self.search_season,
            self.search_episode,
            target_air_date=self.target_air_date,
            reject_unknown_episode_files=reject_unknown,
            scope_is_known=scope_is_known,
        )

    async def collect_live(self):
        for torrent in self.ready_to_cache:
            if not self._matches_requested_scope(torrent["parsed"]):
                continue

            info_hash = torrent["infoHash"]
            self.torrents[info_hash] = {
                "fileIndex": torrent["fileIndex"],
                "parsed": torrent["parsed"],
            }

    async def collect_cached(self, rows):
        for row in rows:
            parsed_data = load_cached_parsed(row["parsed_json"])
            reject_unknown_override = True
            if not self._matches_requested_scope(
                parsed_data,
                reject_unknown_override=reject_unknown_override,
                scope_is_known=True,
            ):
                continue

            info_hash = row["info_hash"]
            self.torrents[info_hash] = {
                "fileIndex": row["file_index"],
                "parsed": parsed_data,
            }

    def _append_cache_file_infos(self, file_infos, torrent):
        parsed = torrent["parsed"]
        if not self._matches_requested_scope(parsed, reject_unknown_override=True):
            return

    def flush(self):
        for torrent in self.ready_to_cache:
            self._append_cache_file_infos([], torrent)
"""


class RenderOrchestrationNewShapeTests(unittest.TestCase):
    """2026-07 routed scope matching through self.media_scope.matches_parsed
    and dropped the parsed_matches_target import."""

    def _render(self, source: str) -> str:
        from stremioguard.overrides.orchestration import render_orchestration_override

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comet" / "services" / "orchestration.py"
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            return render_orchestration_override(Path(directory))

    def test_patched_body_calls_the_primitive_this_version_has(self) -> None:
        # Emitting parsed_matches_target() here would raise NameError at
        # request time — a runtime failure the import-smoke stage cannot see,
        # since importing the module never executes the method body.
        rendered = self._render(_ORCHESTRATION_FIXTURE_NEW)
        self.assertNotIn("parsed_matches_target", rendered)
        self.assertIn("self.media_scope.matches_parsed(", rendered)
        self.assertIn("scope_is_known=scope_is_known,", rendered)
        compile(rendered, "<rendered>", "exec")

    def test_every_edit_lands_on_the_new_shape(self) -> None:
        rendered = self._render(_ORCHESTRATION_FIXTURE_NEW)
        self.assertIn("self.pack_backed_hashes = set()", rendered)
        # Two live ready_to_cache loops plus the cached-rows loop.
        self.assertEqual(rendered.count("self._record_pack_backed_candidate("), 3)
        self.assertEqual(rendered.count('"packBacked": await self._is_pack_backed_candidate('), 2)
        self.assertIn(
            'if not self._matches_requested_scope(torrent["parsed"], '
            'file_index=torrent["fileIndex"]):',
            rendered,
        )
        # The cached-rows path must thread file_index too; before this was
        # verified, a reformat here silently no-opped and shipped "applied".
        self.assertIn('                file_index=row["file_index"],\n', rendered)
        self.assertIn(
            'parsed, file_index=torrent["fileIndex"], reject_unknown_override=True', rendered
        )

    def test_unknown_scope_shape_fails_closed(self) -> None:
        source = _ORCHESTRATION_FIXTURE_NEW.replace(
            "reject_unknown_episode_files=reject_unknown,", "reject_unknown_files=reject_unknown,"
        )
        with self.assertRaises(RuntimeError) as raised:
            self._render(source)
        self.assertIn("scope matcher has changed", str(raised.exception))

    def test_missing_cached_row_edit_fails_closed(self) -> None:
        # The regression that motivated verifying every edit: upstream renamed
        # this call and str.replace() silently did nothing.
        source = _ORCHESTRATION_FIXTURE_NEW.replace(
            '            parsed_data = load_cached_parsed(row["parsed_json"])\n',
            '            parsed_data = decode_parsed(row["parsed_json"])\n',
        )
        with self.assertRaises(RuntimeError) as raised:
            self._render(source)
        self.assertIn("pack-backed recording for cached rows", str(raised.exception))


class ReplaceFirstMatchingEveryOccurrenceTests(unittest.TestCase):
    def test_expected_none_replaces_every_occurrence(self) -> None:
        # Edits whose intent is "every call site" must not treat a differing
        # count as drift — upstream merging or adding a loop is legitimate.
        from stremioguard.overrides._patching import replace_first_matching

        for source, wanted in (("x\n", "y\n"), ("x\nx\n", "y\ny\n"), ("x\nx\nx\n", "y\ny\ny\n")):
            self.assertEqual(
                replace_first_matching(source, (("x\n", "y\n"),), error="nope", expected=None),
                wanted,
            )

    def test_expected_none_still_fails_closed_on_no_match(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        with self.assertRaises(RuntimeError):
            replace_first_matching("z\n", (("x\n", "y\n"),), error="anchor gone", expected=None)


class RenderApiAppOverrideTests(unittest.TestCase):
    def test_request_log_uses_route_template_not_raw_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_required_comet_sources(root)
            rendered = render_api_app_override(root)

        self.assertNotIn("request.url.path", rendered)
        self.assertIn(
            'f"{method} {_metrics_route(request)} - {status_code} - {process_time:.2f}s",',
            rendered,
        )
        compile(rendered, "app.py", "exec")

    def test_logged_path_carries_no_token_or_config(self) -> None:
        # Execute the patched logger against a real addon path shape.
        import sys
        import types

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_required_comet_sources(root)
            rendered = render_api_app_override(root)

        comet_pkg = types.ModuleType("comet")
        guard_mod = types.ModuleType("comet.stremioguard_response_guard")
        guard_mod.StremioGuardResponseGuard = type("StremioGuardResponseGuard", (), {})  # type: ignore[attr-defined]
        namespace: dict[str, object] = {}
        with mock.patch.dict(
            sys.modules,
            {"comet": comet_pkg, "comet.stremioguard_response_guard": guard_mod},
        ):
            exec(compile(rendered, "app.py", "exec"), namespace)
        route = mock.Mock(path="/s/secret-token/{b64config}/playback/{hash}")
        request = mock.Mock()
        request.scope = {"route": route}
        request.url.path = "/s/secret-token/eyJhcGlLZXkiOiJzZWNyZXQifQ==/playback/abc"
        logged: list[str] = []
        with mock.patch.object(
            namespace["logger"], "log", side_effect=lambda _lvl, msg: logged.append(msg)
        ):
            import asyncio

            asyncio.run(namespace["dispatch"](request, "GET", 200, 0.5))  # type: ignore[operator]

        self.assertEqual(logged, ["GET /s/{token}/{b64config}/playback/{hash} - 200 - 0.50s"])

    def test_unknown_log_shape_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_comet_logger(root)
            write_comet_api_app(
                root,
                COMET_API_APP_SOURCE.replace("{request.url.path} - ", "{request.url} - "),
            )
            with self.assertRaisesRegex(RuntimeError, "request log line has changed"):
                render_api_app_override(root)

    def test_missing_sanitizer_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_comet_logger(root)
            write_comet_logger(root)
            write_comet_api_app(
                root, COMET_API_APP_SOURCE.replace("def _metrics_route", "def _route_label")
            )
            with self.assertRaisesRegex(RuntimeError, "no longer defines _metrics_route"):
                render_api_app_override(root)

    def test_api_app_patch_is_required(self) -> None:
        spec = next(spec for spec in SPECS if spec.name == "api_app")
        self.assertEqual(spec.requirement, Requirement.REQUIRED)
        self.assertEqual(spec.container_path, "/app/comet/api/app.py")


class Ac3ResponseGuardRenderAndMountTests(unittest.TestCase):
    """AC-3: rendering app.py guard install, response_guard spec, and publisher mount."""

    def test_ac3_app_override_installs_guard_at_top_level_and_is_idempotent(self) -> None:
        import ast

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_required_comet_sources(root)
            rendered = render_api_app_override(root)

            # Re-rendering its own output must not append twice.
            write_comet_api_app(root, rendered)
            self.assertEqual(render_api_app_override(root), rendered)

        tree = ast.parse(rendered)
        self.assertGreaterEqual(len(tree.body), 2)
        last_two = tree.body[-2:]
        assert isinstance(last_two[0], ast.ImportFrom)
        self.assertEqual(last_two[0].module, "comet.stremioguard_response_guard")
        assert isinstance(last_two[1], ast.Expr)
        call = last_two[1].value
        assert isinstance(call, ast.Call)
        assert isinstance(call.func, ast.Attribute)
        self.assertEqual(call.func.attr, "add_middleware")

    def test_ac3_zero_or_two_fastapi_lines_raise_runtime_error(self) -> None:
        cases = (
            "# no fastapi app\n",
            'app = FastAPI(title="1")\napp = FastAPI(title="2")\n',
        )
        for replacement in cases:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_comet_api_app(
                    root,
                    COMET_API_APP_SOURCE.replace('app = FastAPI(title="Comet")\n', replacement),
                )
                with self.assertRaises(RuntimeError):
                    render_api_app_override(root)

    def test_ac3_response_guard_spec_required_and_mounted_read_only(self) -> None:
        from stremioguard.overrides.bundle import required_output_names

        spec = next(sp for sp in SPECS if sp.name == "response_guard")
        self.assertEqual(spec.requirement, Requirement.REQUIRED)
        self.assertEqual(spec.output_name, "stremioguard_response_guard.py")
        self.assertEqual(spec.container_path, "/app/comet/stremioguard_response_guard.py")
        for gateway_enabled in (False, True):
            self.assertIn(
                "stremioguard_response_guard.py",
                required_output_names(gateway_enabled=gateway_enabled),
            )

        guard_source = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "stremioguard"
            / "overrides"
            / "response_guard.py"
        ).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "STREMIO_BIND_ADDRS=127.0.0.1\nSTREMIO_ENABLED=1\nCOMET_ENABLED=1\n",
                encoding="utf-8",
            )
            comet_cfg = make_comet_config(root, enabled=True)
            record_test_digest(comet_cfg.state_dir)
            bundle_dir = write_bundle(comet_cfg)
            rendered = spec.render(root, mock.Mock())
            self.assertEqual(rendered, guard_source)

            pub = StackPublisher(root)
            with (
                mock.patch("stremioguard.publishing.CometConfig.from_env", return_value=comet_cfg),
                mock.patch(
                    "stremioguard.publishing.CometGatewayConfig.from_env",
                    return_value=make_comet_gateway_config(root, enabled=False),
                ),
            ):
                pub.publish()
            override_content = pub.compose_override_file.read_text(encoding="utf-8")
            expected_mount = (
                f"- {bundle_dir / 'stremioguard_response_guard.py'}"
                ":/app/comet/stremioguard_response_guard.py:ro"
            )
            self.assertIn(expected_mount, override_content)


class Ac10PatchHelpersTests(unittest.TestCase):
    """AC-10: replace_first_matching and write_override_bundle manifest cleanup."""

    def test_ac10_replacement_in_comment_still_patches_remaining_anchor(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        out = replace_first_matching(
            "# note: NEW_VAL\ndef foo():\n    x = OLD_VAL\n",
            (("OLD_VAL", "NEW_VAL"),),
            error="err",
        )
        self.assertEqual(out, "# note: NEW_VAL\ndef foo():\n    x = NEW_VAL\n")

    def test_ac10_overlapping_replacement_and_remaining_anchor_raises(self) -> None:
        from stremioguard.overrides._patching import replace_first_matching

        anchor = "for t in items:\n"
        replacement = "for t in items:\n    record(t)\n"
        content = f"{replacement}# second site:\n{anchor}"
        with self.assertRaisesRegex(RuntimeError, "matched 2 sites, expected 1"):
            replace_first_matching(content, ((anchor, replacement),), error="drifted", expected=1)

    def test_ac10_failed_required_patch_removes_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            manifest_path = state_dir / "bundle-manifest.json"
            manifest_path.write_text('{"stale": true}\n', encoding="utf-8")

            def failing_render(rd, ctx):
                raise RuntimeError("boom")

            mock_specs = [
                OverrideSpec(
                    name="api_app",
                    feature="api_app",
                    container_path="/app/comet/api/app.py",
                    output_name="app.py",
                    requirement=Requirement.REQUIRED,
                    render=failing_render,
                ),
            ]
            with (
                mock.patch("stremioguard.overrides.bundle.SPECS", mock_specs),
                self.assertRaisesRegex(RuntimeError, "Required patch 'api_app' failed"),
            ):
                write_override_bundle(
                    repo_dir=Path("/dummy"),
                    state_dir=state_dir,
                    result_format_style="plain",
                    patch_episode_pack_results=False,
                    gateway_enabled=False,
                )
            self.assertFalse(manifest_path.exists())


class CredentialFreeCorsTests(unittest.TestCase):
    """Comet must never let a cross-site page read a response with the owner's cookies."""

    def test_render_switches_credentials_off_and_keeps_every_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_required_comet_sources(root)
            rendered = render_api_app_override(root)
            write_comet_api_app(root, rendered)
            self.assertEqual(render_api_app_override(root), rendered)
        self.assertIn("    allow_credentials=False,\n", rendered)
        self.assertNotIn("allow_credentials=True", rendered)
        self.assertIn('    allow_origins=["*"],\n', rendered)

    def test_changed_cors_setup_fails_loudly(self) -> None:
        for changed in (
            COMET_API_APP_SOURCE.replace('allow_origins=["*"]', "allow_origins=ORIGINS"),
            COMET_API_APP_SOURCE.replace("    allow_credentials=True,\n", ""),
        ):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_comet_api_app(root, changed)
                with self.assertRaisesRegex(RuntimeError, "credentialed CORS"):
                    render_api_app_override(root)


class AdminCookieOverrideTests(unittest.TestCase):
    """Admin login must set Secure on admin_session behind TLS termination."""

    def test_render_admin_override_honors_forwarded_proto_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_comet_admin(root)
            rendered = render_admin_override(root)
            self.assertIn("def _is_secure_request(request: Request) -> bool:", rendered)
            self.assertIn("secure=_is_secure_request(request),", rendered)
            self.assertNotIn('secure=request.url.scheme == "https",', rendered)
            compile(rendered, "admin.py", "exec")

    def test_changed_admin_cookie_anchor_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            changed = COMET_ADMIN_SOURCE.replace(
                'secure=request.url.scheme == "https",', "secure=False,"
            )
            write_comet_admin(root, changed)
            with self.assertRaisesRegex(RuntimeError, "admin cookie patch"):
                render_admin_override(root)
