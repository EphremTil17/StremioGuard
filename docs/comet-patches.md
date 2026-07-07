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
- The local `vendor/comet` checkout is demoted to a maintainer aid used only
  for local diffing and anchor alignment via `./stremio comet vendor-sync`.

### Patch Specs & Requirements

Each patch is managed as a declarative spec with an explicit requirement class:

| Patch Name | Feature / Purpose | Requirement Class | Degraded Mode (If Failed) |
|------------|-------------------|-------------------|---------------------------|
| `stream` | TV-readable stream naming and gateway playback URLs | `REQUIRED_WHEN_GATEWAY` | Hard failure if gateway enabled; fallback to default stream handler otherwise. |
| `config` | Protected gateway `/configure` credentials integration | `REQUIRED_WHEN_GATEWAY` | Hard failure if gateway enabled; public `/configure` remains exposed. |
| `template` | Configure page installer link customization | `REQUIRED_WHEN_GATEWAY` | Addon installation URL defaults to direct localhost address. |
| `torrentio` | Preserves richer Torrentio scraper title and index metadata | `OPTIONAL` | Falls back to stock Torrentio parser (missing HDR, resolution tags on some items). |
| `filtering` | Permissively filters branded/multilingual titles | `OPTIONAL` | Falls back to stock strict title matching. |
| `formatter` | Curated TV-safe emoji/text layout | `OPTIONAL` | Stream labels default to upstream format layout. |
| `orchestration` | Preserves episode-pack season priority and badges | `OPTIONAL` | Season pack items are dropped or ranked below single files. |
| `metadata_service` | Cinemeta caching and season episode count verification | `OPTIONAL` | In-memory count resolution only (higher API latency). |

### Canary & PR Flow for Maintainers

To keep these patches robust against upstream updates, the project operates
an automated validation pipeline:

1. **Daily Canary Workflow:** A daily GitHub Actions job
   (`.github/workflows/comet-canary.yml`) compares the upstream registry
   digest of `:latest` against the lock's `tested_digest`.
2. **Automated Validation:** If a new digest is detected, the job runs
   `python -m stremioguard.comet.validate` to extract, patch, compile, and
   smoke-import the entire patch suite. The validator force-enables every
   feature (gateway on, episode packs on) so `tested_digest` vouches for all
   deployment shapes, and any skipped patch — even an optional one — fails
   the run as upstream drift.
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
- `torrentio.py`
- `filtering.py`
- `orchestration.py`
- `metadata_service.py`
- `config.py`
- `index.html`

## Current Patch Logic

### 1. Formatter patch

Purpose:

- reduce emoji-heavy output
- make stream rows easier to scan on dark TV interfaces

Approach:

- switch Comet formatting to a plainer style
- use a small curated symbol set and simpler left-side naming

### 2. Stream-name patch

Purpose:

- reduce left-side duplication like `TB`, `Comet`, and raw resolution spam
- degrade more gracefully when a torrent lacks explicit resolution metadata

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

### 3. Torrentio scraper patch

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

### 4. Episode-pack preservation patch

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

### 5. Title-compatibility filtering patch

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
