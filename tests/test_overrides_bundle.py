from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock

from stremioguard.overrides.bundle import (
    OverrideSpec,
    Requirement,
    write_override_bundle,
)
from stremioguard.publishing import StackPublisher

from .conftest import make_comet_config, make_comet_gateway_config


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

            # Write dummy manifest listing only 'stream' and 'formatter' as applied
            manifest = {
                "image_digest": "sha256:123",
                "patch_fingerprint": "fp123",
                "format_style": "emoji",
                "patch_episode_pack": False,
                "applied": ["formatter", "stream"],
                "skipped": [],
                "outputs": {
                    "formatting.py": "/app/comet/utils/formatting.py",
                    "stream.py": "/app/comet/api/endpoints/stream.py",
                },
            }
            (comet_cfg.state_dir / "bundle-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
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

            # Formatting and stream should be in volume mounts
            self.assertIn("/app/comet/utils/formatting.py:ro", override_content)
            self.assertIn("/app/comet/api/endpoints/stream.py:ro", override_content)

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
