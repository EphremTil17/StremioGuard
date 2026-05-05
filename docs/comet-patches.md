# Comet Patches

This project applies a small set of managed runtime patches to Comet in order to
make it behave better in a self-hosted StremioGuard deployment.

The goal is not to fork Comet permanently. The goal is to keep upstream Comet
vendored as-is, then generate a few narrow override files during setup/start so
that:

- proxy behavior remains reproducible
- formatting stays readable on TV clients
- Torrentio-backed episode results survive more like native Torrentio

## Why Patch Comet

Stock Comet is powerful, but in this setup there were a few practical gaps:

1. Stream presentation was noisy for TV use.
2. Torrentio scraper output was not always preserved well when Comet consumed
   resolved/debrid-style Torrentio results.
3. Episode results inside season packs were being dropped too aggressively.
4. Title filtering could reject valid results whose outer release title did not
   strictly match the Stremio metadata title, even when the resolved filename
   clearly matched the requested episode.

That last point matters a lot for multilingual and branded titles. Native
Torrentio is often more permissive there, so without patching, Comet could show
far fewer results than the user expected.

## Methodology

The patch strategy is intentionally simple:

- keep the upstream Comet checkout in `vendor/comet`
- generate override files under `.stremio/comet/`
- mount those files read-only into the Comet container through the generated
  Compose override

This means we are **not** editing files inside the running container by hand and
we are **not** maintaining a full hard fork of Comet in the repo.

By default, StremioGuard keeps `COMET_TORRENTIO_URL` pointed at the generic
`https://torrentio.strem.fun` root instead of expecting a user to paste a
private configured Torrentio URL into the root `.env`. The compatibility
patches are meant to improve Comet's handling of ordinary Torrentio scraper
results without turning a secret-bearing addon URL into setup state.

The generator entrypoints are:

- `scripts/generate_comet_overrides.py`
- `src/stremioguard/comet_overrides.py`

The generated files currently include:

- `formatting.py`
- `stream.py`
- `torrentio.py`
- `filtering.py`
- `orchestration.py`

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

Approach:

- normalize the left-side label to mostly resolution-oriented naming such as
  `UHD`, `FHD`, `HD`

### 3. Torrentio scraper patch

Purpose:

- support configured/native Torrentio-style resolved results better

Approach:

- extract `infoHash` and `fileIndex` not only from direct scraper fields, but
  also from:
  - `behaviorHints.bingeGroup`
  - resolved Torrentio URLs
  - resolved filename hints

This lets Comet ingest more of the same results that native Torrentio surfaces.

### 4. Episode-pack preservation patch

Purpose:

- avoid dropping valid episode results just because they came from a season pack
  and the parsed metadata lacked explicit episode detail

Approach:

- relax Comet's episode-scope gate when there is still strong evidence that a
  result belongs to the requested season/episode context
- prefer concrete file-level evidence over overly strict pack-level rejection

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
