# Comet Patches

StremioGuard applies a declarative set of runtime overrides to Comet so the upstream `g0ldyy/comet` image stays untouched while enforcing VPN/security invariants and TV-friendly stream presentation.

## Methodology

On install, update, or start, StremioGuard extracts `/app/comet` directly from the pinned Comet image (no vendored git checkout is used), renders each override with strict fail-closed anchor matching (`replace_first_matching`), writes `.stremio/comet/bundles/<digest>/bundle-manifest.json`, and bind-mounts the rendered files read-only into the container.

## Patch Specs & Requirements

| Patch Name | Target in Container | Purpose | Requirement | If Anchor Drifts |
| :--- | :--- | :--- | :--- | :--- |
| `api_app` | `/app/comet/api/app.py` | Logs route templates (`_metrics_route`) instead of raw paths carrying tokens/configs, installs `StremioGuardResponseGuard` as outermost middleware, and disables credentialed wildcard CORS (`allow_credentials=False`) | `REQUIRED` | Hard failure |
| `response_guard` | `/app/comet/stremioguard_response_guard.py` | Pure-ASGI boundary: strips P2P entries (`infoHash`, `magnet:`, `sources`) from top-level JSON `streams`/`sources` across all JSON media types and non-206 `text/plain`/untyped JSON bodies; refuses non-identity `content-encoding` or inspected/sniffed bodies >16 MiB with `502`; blocks `torznab` paths with `404`; paces `/configure/login` (including `/s/<token>/configure/login`) and `/admin/login` in separate 6/min budgets; emits baseline browser security headers on every response | `REQUIRED` | Hard failure |
| `stream_guard` | `/app/comet/stremioguard_stream_guard.py` | Hardens `mediaflow_proxy`: builds proxy headers only from client `Range`/`If-Range` (ignoring `h_`/`r_`/`rp_`/`x_headers` query params), enforces `PublicOnlyConnector` on initial connections and redirects (blocking loopback, private, link-local, reserved, multicast, `3fff::/20`, and embedded IPv4/NAT64 forms), redacts upstream error bodies, and counts concurrent proxied streams per gateway token ID (`X-StremioGuard-Client`) only on loopback requests carrying no client-IP header | `REQUIRED` | Hard failure |
| `playback` | `/app/comet/api/endpoints/playback.py` | Wires `/playback` into `stream_guard` (`safe_proxy_headers`, `admission_key`, and module import installing the connector/error handler) | `REQUIRED` | Hard failure |
| `config_limits` | `/app/comet/core/config_validation.py` | Rejects `b64config` >8 KB or >10 `debridServices`, shrinks config LRU cache to 256 (upstream 4096), and feeds every parsed config's debrid keys to the log scrubber | `REQUIRED` | Hard failure |
| `admin` | `/app/comet/api/endpoints/admin.py` | Honors `X-Forwarded-Proto` when setting the `Secure` attribute on `admin_session` so TLS-terminated portals (e.g. Cloudflare Access) emit `Secure` cookies | `REQUIRED` | Hard failure |
| `logger` | `/app/comet/core/logger.py` | Replaces half-value `censor()` and token previews with `********`, fixes scheme-less `censor_url()`, scrubs all loguru sinks (stderr and `/admin/api/logs`), trims scraper error URLs to scheme+host, routes stdlib logging into scrubbed loguru, and scrubs `logging.StreamHandler.format` so non-propagating loggers (`gunicorn.error`, `uvicorn.error`) cannot bypass scrubbing | `REQUIRED` | Hard failure |
| `stream` | `/app/comet/api/endpoints/stream.py` | Structural second-layer P2P block (`enable_torrent = False`, AST-checked by `_assert_p2p_blocked`), compact TV-readable stream names (`UHD \| HDR \| P`), amber `🔸` uncached marker, `R:<score>` display beside size, and validated `X-Forwarded-*` playback URLs | `REQUIRED` | Hard failure |
| `media_search` | `/app/comet/services/media_search.py` | Carries RTN's already-calculated scalar `rtn_ranks` map on `MediaSearchResult` to `stream.py` (presentation-only; never reorders or recalculates ranks) | `REQUIRED` | Hard failure |
| `config` | `/app/comet/api/endpoints/config.py` | Validates `X-Forwarded-Prefix` / `X-Forwarded-Proto` for gateway configure redirects and `configure_session` `Secure` cookies | `REQUIRED_WHEN_GATEWAY` | Hard failure when gateway is enabled |
| `template` | `/app/comet/templates/index.html` | Rewrites configure-page install/copy URLs to target the gateway base URL and preserve token paths | `REQUIRED_WHEN_GATEWAY` | Hard failure when gateway is enabled |
| `formatter` | `/app/comet/utils/formatting.py` | Curated TV-safe layout when `COMET_RESULT_FORMAT_STYLE=plain` | `OPTIONAL` | Falls back to upstream formatting |
| `torrentio` | `/app/comet/scrapers/torrentio.py` | Preserves richer multi-line Torrentio outer titles for RTN parsing while passing resolved filenames/file indices separately | `OPTIONAL` | Falls back to stock Torrentio parser |
| `filtering` | `/app/comet/services/filtering.py` | Permissively retains branded/multilingual titles when resolved filename/raw title clearly matches the requested media title | `OPTIONAL` | Falls back to stock strict title match |
| `orchestration` | `/app/comet/services/orchestration.py` | Preserves season-pack episode candidates when `COMET_PATCH_EPISODE_PACK_RESULTS=1` and badges credible pack-backed items with `P` without altering RTN rank order | `OPTIONAL` | Season-pack candidates use stock filtering |
| `metadata_service` | `/app/comet/metadata_service.py` | Bounded (1,024-entry) episode-count cache backed by Comet's DB with a 2 MiB-capped, no-redirect, `PublicOnlyConnector` Cinemeta fallback | `OPTIONAL` | Episode-pack lookup falls back to treating multi-episode candidates as packs |

## Key Invariants & Tradeoffs

- **Dual-layer P2P prevention:** `DISABLE_TORRENT_STREAMS=True`, `stream.py` (`_assert_p2p_blocked`), and `StremioGuardResponseGuard` work together so Stremio clients never receive a direct-torrent stream that would bypass the VPN.
- **Presentation-only RTN scores:** `TorrentManager.ranked_torrents -> MediaSearchResult.rtn_ranks -> stream.py` forwards scalar ranks for display only (`10.6 GB • R:5850`). No legacy shim exists for retired Comet layouts.
- **Heuristics are optional and best-effort:** `torrentio`, `filtering`, and `orchestration` improve parity with native Torrentio for branded titles and season packs, at the trade-off of occasional permissive matches.

## Canary & CI Validation Flow

1. **Daily Canary (`.github/workflows/comet-canary.yml`):** Compares upstream `:latest` against `vendor/comet.lock.json` and runs `python -m stremioguard.comet.validate` with every feature enabled (gateway on, episode packs on, plain style).
2. **Hardened Import Smoke:** Runs inside the candidate image with `--network none --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp`, imports every patched module, scans all nested bytecode objects for undefined names, and drives the real ASGI app to prove `StremioGuardResponseGuard`, `stream_guard`, `config_limits`, `admin` route binding/cookies, and log scrubbing all hold. Any skipped patch — even an `OPTIONAL` one — fails the canary as drift.
3. **CI Regression Gate (`.github/workflows/ci.yml`):** Runs the same validator against `tested_digest` on every push and pull request.
