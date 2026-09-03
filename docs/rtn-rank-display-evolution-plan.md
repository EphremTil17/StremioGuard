# RTN Rank Display — Forward-Only Architecture

## Status

Implemented for the current Comet image direction. The managed bundle now
mounts both `media_search.py` and `stream.py`, and rejects an incomplete
cross-file RTN display handoff before Compose publication.

This document records the compatibility contract and its regression strategy;
it is not a request to preserve the former endpoint-owned architecture.

## Objective

Restore the user-visible RTN numeric score (`R:<score>`) beside each stream's
size, while preserving Comet's native filtering, cache behaviour, and result
ordering exactly.

This is a forward-only migration to the Comet image architecture introduced in
`g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe`.
It intentionally does not retain source anchors, shims, or fallback paths for
the old endpoint-owned `torrent_manager` architecture.

## Incident Summary

The former display patch copied scores at the old stream-endpoint boundary:

```python
torrent_manager.ranked_torrents[info_hash].rank
```

The current Comet image moved search/ranking work behind `search_media()`.
The stream endpoint now receives a `MediaSearchResult` with:

```python
torrents: dict
ranked_info_hashes: list[str]
```

The ordered hash list preserves RTN's ordering but discards the RTN `Torrent`
objects that carry `.rank`. The old renderer looked for
`torrents = torrent_manager.torrents`; that anchor no longer exists. Because
the renderer used silent conditional replacements, it applied the unrelated
name/gateway edits, skipped score propagation and score display, and still
reported the broad `stream` override as applied.

## Design Principles

- RTN remains the sole ranking authority. StremioGuard must not recompute,
  sort, bucket, promote, or otherwise reinterpret ranks.
- Transfer the score at the new explicit architecture boundary:
  `TorrentManager.ranked_torrents` -> `MediaSearchResult` -> stream renderer.
- Transfer only the scalar score needed for presentation. Do not leak RTN
  objects or re-create ranking work in the endpoint.
- Every edit that makes the feature work is required and fail-closed. A stream
  bundle without working score transfer is not a successful stream bundle.
- Render against the active image and use one current-source shape only. A
  future Comet refactor requires a deliberate patch update, not a compatibility
  branch hidden in the renderer.

## Target Architecture

Comet's current rank worker constructs RTN `Torrent` values and `sort_torrents`
returns the native ordered mapping. Its rank data is available after
`TorrentManager.rank_torrents()` but before `MediaSearchResult` is built.

```text
RTN check_fetch_and_rank_many()
  -> native RTN Torrent(rank=<integer>) mapping
  -> native sort_torrents() order
  -> MediaSearchResult(
       ranked_info_hashes=[...],
       rtn_ranks={info_hash: integer, ...},
     )
  -> stream endpoint reads rtn_ranks[info_hash]
  -> formatted size: "10.6 GB • R:5850"
```

`rtn_ranks` is presentation metadata only. It must never be used to order
streams, choose cached streams, enforce max-results limits, or decide playback.

## Implemented Design

### 1. Add a first-class rank-context override

The renderer for the current image's
`/app/comet/services/media_search.py`, for example
`overrides/media_search.py`.

It makes exactly two source edits:

1. Add `rtn_ranks: dict[str, int] = field(default_factory=dict)` to
   `MediaSearchResult`.
2. At the existing successful `MediaSearchResult(...)` construction, derive
   the map from the already-ranked native mapping:

   ```python
   rtn_ranks = (
       {
           info_hash: ranked_torrent.rank
           for info_hash, ranked_torrent in torrent_manager.ranked_torrents.items()
       },
   )
   ```

Use the active image's exact result-construction anchor. Do not modify
`rank_worker`, do not mutate `self.torrents` from its executor, and do not run
RTN ranking a second time. This avoids cross-executor mutation assumptions and
keeps the data transfer at the process-safe handoff point.

### 2. Rewrite the stream score display for `MediaSearchResult`

Replace the obsolete rank-stamping edit in `render_stream_override()` with a
single explicit current-architecture edit:

```python
_sg_rank = search_result.rtn_ranks.get(info_hash)
```

This belongs in the per-stream loop immediately before the formatted title is
built. Keep the current presentation contract:

- score appends to a non-empty size component as ` • R:<score>`;
- if a score exists but size does not, show `– R:<score>` on its own line;
- raw release title stays last so Android TV truncation does not hide technical
  metadata or the score;
- the score is never exposed in stream `name`, playback URL, behavior hints,
  or sorting fields.

### 3. Bundle dependency and semantic contract

Register `media_search.py` as a named override spec. Treat it and the score
portion of `stream.py` as required for every supported Comet deployment, not
as optional cosmetics and not merely as gateway-required behavior.

Split the stream renderer internally into verified edits with clear diagnostics:

- gateway external-base edit;
- compact stream-name edit;
- `MediaSearchResult.rtn_ranks` consumption;
- score-to-size/title rendering.

Every score edit uses `replace_first_matching` (or an equivalent exact,
occurrence-checked helper). Remove all silent `if anchor in content` / plain
`str.replace` paths for score propagation and rendering. If any required score
edit cannot be applied, omit the affected output, mark the spec skipped, and
abort bundle publication before Comet starts.

### 4. Add a semantic bundle contract

Compilation and import-smoke prove syntax/import compatibility, but they do
not catch partial behavior loss. The post-render contract validator now
checks the generated files together:

- `MediaSearchResult` declares `rtn_ranks`;
- the successful result construction populates it from
  `torrent_manager.ranked_torrents` and `.rank`;
- generated `stream.py` reads `search_result.rtn_ranks.get(info_hash)`;
- generated `stream.py` contains both `R:{_sg_rank}` output paths;
- no generated score path references `torrent_manager`.

Use AST-aware checks where practical; string checks may complement them for
the exact display text. The validator is part of runtime preparation,
`comet install`, candidate validation, and CI canary validation.

### 5. Replace stale fixtures with the current image contract

Compact source fixtures from the active `dca621…` image cover:

- `services/media_search.py`;
- `api/endpoints/stream.py`;
- any directly patched dependency required by the new source shape.

Do not keep the old endpoint-owned fixtures as alternate supported shapes.
Tests should explicitly prove that the old source shape is rejected with a
clear “supported Comet architecture changed” diagnostic.

### 6. Add focused regression tests

The regression suite covers:

1. **Bundle rendering:** generated `media_search.py` and `stream.py` contain
   the complete score contract.
2. **Negative anchors:** removing either target anchor fails bundle generation
   and prevents Compose publication.
3. **Ordering invariant:** a synthetic mapping with scores such as 5850 then
   850 reaches output in its native supplied order; rank values are displayed
   but no sort/reorder function is introduced by StremioGuard.
4. **Presentation:** size becomes `10.6 GB • R:5850`; title remains below
   technical metadata; score-only fallback works.
5. **No silent success:** a bundle whose name/gateway portions apply but whose
   score portion does not must be reported as failed, never as `stream`
   applied.
6. **Image validation:** run import-smoke and deep boot validation against the
   active digest after the new `media_search.py` mount is included.

### 7. Verify live and release

1. Run `./stremio comet install --deep` and confirm the manifest lists both
   `media_search` and `stream` with no skips.
2. Restart through `./stremio restart` so the regenerated override is mounted.
3. Open a title with multiple results and verify visible output such as
   `10.6 GB • R:5850`.
4. Confirm the selected stream order remains Comet's native RTN/cache order;
   compare returned stream order before and after only if using a controlled
   test fixture or stable local capture.
5. Run `./stremio comet doctor`, `uv run pytest`, `uv run ruff check`,
   `uv run ruff format --check`, and `uv run pyright`.
6. Make the updated active digest the canary's tested artifact only after the
   semantic contract and live display proof pass.

## Acceptance Criteria

- Every displayed stream with a numeric RTN score and a size visibly shows
  `• R:<score>` on the size line.
- The active image architecture uses `search_result.rtn_ranks`, never the
  obsolete `torrent_manager` endpoint reference.
- A missing score patch prevents a supported deployment from starting; it
  cannot be masked by success from unrelated edits in `stream.py`.
- RTN/Comet native order, cached-first policy, max-results policy, and
  playback behavior are byte-for-byte untouched by the feature.
- The test and canary suite fail on the exact regression seen here.

## Explicit Non-Goals

- No old-architecture compatibility branch, fallback anchor, or shim.
- No post-RTN pack promotion or quality bucketing.
- No score recomputation in the stream endpoint.
- No change to user RTN configuration, Comet filtering, debrid selection, or
  stream URLs.
