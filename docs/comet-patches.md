# Comet Patches

This project applies a small set of managed runtime patches to Comet in order to
make it behave better in a self-hosted StremioGuard deployment.

The goal is not to fork Comet permanently. The goal is to keep upstream Comet
vendored as-is, then generate a few narrow override files during setup/start so
that:

- proxy behavior remains reproducible
- formatting stays readable on TV clients
- Torrentio-backed episode results survive more like native Torrentio
- Torrentio-style ranking signals are preserved more faithfully
- the native RTN numeric rank remains visible beside the stream size

## Why Patch Comet

Stock Comet is powerful, but in this setup there were a few practical gaps:

1. Stream presentation was noisy for TV use.
2. Torrentio scraper output was not always preserved well when Comet consumed
   resolved/debrid-style Torrentio results.
3. Episode results inside season packs were being dropped too aggressively.
4. Title filtering could reject valid results whose outer release title did not
   strictly match the Stremio metadata title, even when the resolved filename
   clearly matched the requested episode.
5. Some valid results survived filtering but were still ranked or labeled badly
   because Comet parsed a stripped filename instead of Torrentio's richer title
   line.

That last point matters a lot for multilingual and branded titles. Native
Torrentio is often more permissive there, so without patching, Comet could show
far fewer results than the user expected.

## Methodology

The patch strategy is dynamically compiled and verified:

- We extract the original source code directly from the **active image's**
  own layer structure (e.g. `g0ldyy/comet@sha256:...`) at runtime.
- We generate override files dynamically under `.stremio/comet/` and mount
  them read-only into the container.

### Patch Specs & Requirements

Each patch is managed as a declarative spec with an explicit requirement class:

| Patch Name | Feature / Purpose | Requirement Class | Degraded Mode (If Failed) |
|------------|-------------------|-------------------|---------------------------|
| `stream` | P2P stream block (structural second layer via `_assert_p2p_blocked`), amber uncached marker, TV-readable stream naming, gateway playback URLs, and RTN rank display | `REQUIRED` | Hard failure in every deployment: it carries the inner `stream.py` P2P block (`_assert_p2p_blocked`), a structural second layer behind `response_guard`, and is a required half of the current RTN display contract. |
| `media_search` | Carries RTN scores to stream rendering | `REQUIRED` | Hard failure; score display cannot silently disappear. |
| `config` | Protected gateway `/configure` credentials integration | `REQUIRED_WHEN_GATEWAY` | Hard failure if gateway enabled; the gateway deployment is not published. |
| `template` | Configure page installer link customization | `REQUIRED_WHEN_GATEWAY` | Hard failure if gateway enabled; the gateway deployment is not published. |
| `torrentio` | Preserves richer Torrentio scraper title and index metadata | `OPTIONAL` | Falls back to stock Torrentio parser (missing HDR, resolution tags on some items). |
| `filtering` | Permissively filters branded/multilingual titles | `OPTIONAL` | Falls back to stock strict title matching. |
| `formatter` | Curated TV-safe emoji/text layout | `OPTIONAL` | Stream labels default to upstream format layout. |
| `orchestration` | Preserves episode-pack season priority and badges | `OPTIONAL` | Season pack items are dropped or ranked below single files. |
| `logger` | Secret redaction in Comet's logs: upstream's `censor()` printed the first half of every secret (the TorBox key, admin and configure-page passwords, database credentials), `censor_url()` masked only URLs containing `://`, the protected API prefix showed ten characters of the public API token, and scraper errors printed TorBox's API key in full plus raw exceptions whose URLs carry configs. `censor()` and the token preview now print `********`, `censor_url()` masks userinfo with or without a scheme, and `DATABASE_URL` always carries the `postgresql://` scheme. Both log sinks (stderr and the `/admin/api/logs` capture) write through a scrubber that masks every credential setting's value wherever it appears, and the debrid keys of recently parsed addon configs, and scraper errors show only scheme and host (see [security-model.md](security-model.md)) | `REQUIRED` | Hard failure; a candidate whose masking code moved is rejected rather than allowed to leak. |
| `api_app` | Hardened API key management and response guard installation: logs each request's route template (`/s/{token}/{b64config}/…`, via upstream's `_metrics_route`) instead of the raw path containing user credentials, installs `StremioGuardResponseGuard` as the outermost user middleware on `app`, and turns off credentials in upstream's allow-every-origin CORS setup, so no other site can read a page with your session | `REQUIRED` | Hard failure; a drifted candidate, a missing `app = FastAPI(` line or a changed CORS setup is rejected so neither the guard nor the CORS fix can be silently omitted. |
| `stream_guard` | Stream proxy hardening, installed into the `mediaflow_proxy` library behind `/playback`: proxy headers come only from the request's own `Range`/`If-Range`, never from `h_`/`r_`/`rp_`/`x_headers` query parameters; the proxy connects only to plainly public addresses (reserved forms refused; IPv6 forms carrying an IPv4 address, NAT64 included, judged by that address), on the first request and on every redirect; upstream errors reach the client as a status and a fixed message; `admission_key` counts a gateway request's concurrent streams under its token's ID, only for a loopback request without any client-address header (Comet's server trusts `X-Forwarded-For` from anyone) | `REQUIRED` | Hard failure; the import smoke test also checks that it is installed. |
| `playback` | Routes `/playback`'s proxy headers through `stream_guard` (and imports it, installing its connector and error handling), and counts its concurrent-stream limit per gateway token (`X-StremioGuard-Client`, honoured only from the gateway's loopback connection) instead of in one pool for every gateway client; the `ip` Comet passes to debrid services is unchanged | `REQUIRED` | Hard failure; a changed playback endpoint is rejected. |
| `config_limits` | Bounded addon config parsing in `comet/core/config_validation.py`: a config over 8 KB of base64 or with more than 10 debrid services is invalid (refused by a strict check, the default config otherwise, as upstream treats any invalid config), and at most 256 parsed configs are cached (upstream 4096); every valid config's debrid keys are handed to the `logger` scrubber, which masks them from then on | `REQUIRED` | Hard failure; a changed config validation is rejected, and the import smoke test checks the limits by behaviour. |
| `response_guard` | Response-boundary P2P filter and torznab block (`StremioGuardResponseGuard` pure-ASGI middleware): enforces that no top-level JSON `streams` list leaves Comet with a P2P entry (`infoHash` or `magnet:` `url`/`externalUrl`) across any JSON media type (`<type>/json`, `<type>/<subtype>+json`) as well as non-206 responses with missing/empty `content-type` or `text/plain` whose body begins (after optional UTF-8 BOM and JSON whitespace) with `{` or `[` (refusing non-identity `content-encoding` with 502 while streaming binary/206/non-JSON bodies unbuffered), and answers every request with a `torznab` path segment with 404 (alongside `DISABLE_TORRENT_STREAMS=True`) | `REQUIRED` | Hard failure; Comet cannot run without the response-boundary guard mounted. |

### Canary & PR Flow for Maintainers

To keep these patches robust against upstream updates, the project operates
an automated validation pipeline:

1. **Daily Canary Workflow:** A daily GitHub Actions job
   (`.github/workflows/comet-canary.yml`) compares the upstream registry
   digest of `:latest` against the lock's `tested_digest`.
2. **Automated Validation:** If a new digest is detected, the job runs
   `python -m stremioguard.comet.validate` to extract, patch, compile, and
   import-smoke-test the entire patch suite inside the candidate image. The
   import-smoke stage imports every patched module, scans all nested code
   objects for undefined globals/names, and drives the real `app` through
   ASGI to prove `StremioGuardResponseGuard` is the outermost middleware,
   strips P2P entries from JSON `streams` lists, and blocks torznab with 404.
   The validator force-enables every feature (gateway on, episode packs on)
   so `tested_digest` vouches for all deployment shapes, and any skipped patch
   — even an optional one — fails the run as upstream drift.
3. **Feedback Actions:**
   - **Pass:** The canary opens an automated PR bumping `tested_digest` in
     `vendor/comet.lock.json`, embedding the JSON validation report.
   - **Fail:** The canary opens (or comments on) a tracking issue carrying
     the `comet-canary` marker label, with the failure diagnostic from the
     JSON report, so maintainers can update the patch anchors.

The regression gate (`.github/workflows/ci.yml`) runs the same validator
against the lock's current `tested_digest` on every push and PR, so a change
to `src/stremioguard/overrides/` that breaks against the digest we claim to
support cannot land.

The generated files currently include:

- `formatting.py`
- `stream.py`
- `media_search.py`
- `torrentio.py`
- `filtering.py`
- `orchestration.py`
- `metadata_service.py`
- `config.py`
- `index.html`
- `app.py`
- `stremioguard_response_guard.py`
- `logger.py`

## Current Patch Logic

### 1. Formatter patch

Purpose:

- reduce emoji-heavy output
- make stream rows easier to scan on dark TV interfaces

Approach:

- switch Comet formatting to a plainer style
- use a small curated symbol set and simpler left-side naming

### 2. RTN rank-context and display patch

Purpose:

- preserve the numeric RTN score that Comet already calculated
- show `R:<score>` beside the stream size without changing native result order,
  cache policy, or playback behaviour

Approach:

- patch the current `services/media_search.py` handoff to add a scalar
  `rtn_ranks` map to `MediaSearchResult`
- derive that map from `torrent_manager.ranked_torrents` after Comet has
  completed native RTN ranking
- patch `api/endpoints/stream.py` to read
  `search_result.rtn_ranks.get(info_hash)` while it formats each result
- render `10.6 GB • R:5850` when a size exists; render a separate
  `– R:5850` line when it does not

This is a presentation-only handoff. StremioGuard never sorts, recomputes,
promotes, or otherwise interprets an RTN rank. The current architecture is:

```text
TorrentManager.ranked_torrents
  -> MediaSearchResult.rtn_ranks
  -> stream endpoint display
```

The old endpoint-owned `torrent_manager` shape is deliberately unsupported.
If Comet changes this handoff, rendering fails closed and the patch must be
deliberately updated for the new architecture; no legacy shim is retained.

### 3. Stream-name patch

Purpose:

- reduce left-side duplication like `TB`, `Comet`, and raw resolution spam
- degrade more gracefully when a torrent lacks explicit resolution metadata
- keep cached status visible: the compact names drop Comet's `⚡`/`⬇️`
  icons, so an uncached entry's media-type line (`WEB-DL`, `BluRay`, …)
  starts with an amber `🔸` instead of the usual `–`. Stremio cannot colour
  text on any client, so this glyph is the nearest thing to an amber row;
  cached entries are unchanged
- never offer direct-torrent (P2P) streams: Stremio plays those with the
  client device's own torrent engine, outside the VPN. Torznab is disabled
  (`DISABLE_TORRENT_STREAMS=True` and 404 at `response_guard`), and
  `response_guard` (`StremioGuardResponseGuard`) enforces P2P removal at
  Comet's ASGI response boundary for every top-level JSON `streams` list.
  In `stream.py`, forcing `enable_torrent = False` and checking it with
  `_assert_p2p_blocked` acts as a structural second layer; both `stream` and
  `response_guard` are `REQUIRED` in every deployment

Approach:

- normalize the left-side label to mostly resolution-oriented naming such as
  `UHD`, `FHD`, `HD`
- add a compact inline HDR indicator like `UHD | HDR` when the parsed metadata
  clearly contains `HDR` or `DV`
- if resolution is missing, fall back to more useful labels such as:
  - `WEBRip`
  - `WEB-DL`
  - `HDTV`
  - weak codec/container hints in lower-confidence cases

### 4. Torrentio scraper patch

Purpose:

- support configured/native Torrentio-style resolved results better
- preserve richer ranking metadata from Torrentio instead of collapsing too
  early to a bare filename

Approach:

- extract `infoHash` and `fileIndex` not only from direct scraper fields, but
  also from:
  - `behaviorHints.bingeGroup`
  - resolved Torrentio URLs
  - resolved filename hints
- keep both:
  - a richer display title for RTN parsing/ranking
  - a resolved filename for exact episode/file matching
- prefer the most metadata-rich line when Torrentio returns a multi-line title
  block with one line for release metadata and another for the resolved file

This lets Comet ingest more of the same results that native Torrentio surfaces.
It also reduces cases where a result survives filtering but gets buried because
resolution, HDR, quality, or codec signals were lost before parsing.

### 5. Episode-pack preservation patch

Purpose:

- avoid dropping valid episode results just because they came from a season pack
  and the parsed metadata lacked explicit episode detail

Approach:

- relax Comet's episode-scope gate when there is still strong evidence that a
  result belongs to the requested season/episode context
- retain candidates with a usable playback identity when episode metadata is
  incomplete, malformed, cached, or only partially resolved
- use the P badge to show credible multi-file evidence; it does not claim that
  a complete season is present
- preserve Comet/RTN native ranking and cached/uncached behavior. Pack status
  never moves a lower-ranked pack ahead of another result

This patch is optional in setup and is controlled by:

- `COMET_PATCH_EPISODE_PACK_RESULTS=1`

### 6. Title-compatibility filtering patch

Purpose:

- preserve results where the resolved file clearly matches the requested title,
  but the outer torrent title is branded, multilingual, or otherwise formatted
  differently from the metadata title

Approach:

- first try stock `title_match(...)`
- if that fails, inspect stronger evidence:
  - parsed title
  - raw source title
  - resolved filename
- if those clearly contain the requested Stremio title phrase, keep the result

This is deliberately heuristic rather than a static studio-name mapping.

## What These Patches Fix In Practice

In practice, the patch set is aimed at a few recurring Torrentio/Comet mismatch
patterns:

1. Branded or multilingual titles such as `Marvel's Daredevil` versus plain
   `Daredevil`
2. Season-pack results where Torrentio already resolved a concrete episode file
3. Multi-line Torrentio titles where the first line contains the useful ranking
   metadata but a later line contains only the resolved filename
4. Results with incomplete resolution metadata that should still display as
   `WEBRip` or `HDTV` instead of `unknown`

The goal is not to duplicate Torrentio internals exactly. The goal is to keep
the same kinds of evidence Torrentio already gives us, then let Comet preserve
and use that evidence more faithfully.

## Why This Is Safer Than Ad-Hoc Container Patching

This project used to rely more heavily on “patch and test” style iteration while
developing the behavior. The standardized version is safer because:

- overrides are regenerated deterministically
- they live in project-controlled state on disk
- mounts are visible in the generated Compose override
- rebuild/restart does not lose the patch behavior

## Known Tradeoffs

These patches improve parity, but they are still heuristics.

Tradeoffs:

- more permissive matching can admit occasional false positives
- upstream Comet changes can require refreshes to the patch generator
- exact native Torrentio parity is still not guaranteed

- RTN score display supports the current `MediaSearchResult` architecture
  only; an upstream boundary change stops the compatible bundle rather than silently displaying incomplete information

So the philosophy here is:

- preserve obviously valid results
- stay conservative enough to avoid garbage
- avoid turning this into a giant custom fork

## Areas for Improvement

The best future improvements are:

1. Prefer resolved filename/file-level evidence even more systematically.
2. Carry scraper provenance through the full pipeline more explicitly.
3. Version or invalidate local Comet cache more intelligently when patch logic
   changes.
4. Reduce the amount of source-code text replacement by moving toward more
   structured extension points if upstream Comet ever exposes them.

## Practical Recommendation

If you enable Comet in StremioGuard, the optional episode/title compatibility
patches are strongly recommended. Without them, Comet may surface materially
fewer episode results than native Torrentio for some titles.
