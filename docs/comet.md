# Comet

[Comet](https://github.com/g0ldyy/comet) is the optional debrid stream addon StremioGuard runs inside `gluetun`'s network namespace. When `COMET_ENABLED=1`, the root `./stremio` commands manage Comet, its Postgres cache, self-hosted StremThru, and the token gateway together.

## Stack components & sources

- **Pinned image & patches:** `vendor/comet.lock.json` stores the fallback `tested_digest` for `g0ldyy/comet`. Runtime patch bundles are extracted directly from the active image into `.stremio/comet/bundles/<digest>/` and mounted read-only (no local Comet git checkout is used).
- **Self-hosted StremThru (`stremthru`):** Listens on `127.0.0.1:8091` inside gluetun's namespace (never published), with public peering and optional features disabled (`STREMTHRU_PEER_URI="-"`), and a generated `.stremio/stremthru/stremthru.env` auth credential so debrid keys never pass through a third-party StremThru instance.
- **Postgres (`comet-postgres`):** Listens on `127.0.0.1` only inside gluetun's namespace with SCRAM-SHA-256 authentication on TCP (`./stremio comet rotate-db-password` rotates the password offline).
- **Scrapers beyond Torrentio and Zilean:**
  - `COMET_TORBOX_API_KEY` enables TorBox's search API (`COMET_SCRAPE_TORBOX`, default `live` once a key is set) for server-side cache discovery.
  - `COMET_SCRAPE_DMM=live` enables local Debrid Media Manager hashlist ingestion (~1.5 GB through the VPN on start and every `COMET_DMM_INGEST_INTERVAL_SECONDS`, default 1 week).
  - Scrape modes accept `live`, `background`, `both`, `true`, or `false` (`off` maps to `false`); invalid values fail closed.
  - `COMET_TORRENTIO_URL` defaults to `https://torrentio.strem.fun` so no secret-bearing URL is required in `.env`.
- **Configure password:** Required by default. Leaving `COMET_CONFIGURE_PAGE_PASSWORD` empty in `.env` preserves the existing password in `.stremio/comet/.env` (or generates a random one on first install) and logs a warning without printing the secret.
- **Compatibility patches:** `COMET_PATCH_EPISODE_PACK_RESULTS=1` preserves season-pack episode results using a bounded Cinemeta fallback cache; RTN numeric scores (`R:<score>`) are carried from `MediaSearchResult` as presentation metadata only without altering RTN's sort order. See [comet-patches.md](comet-patches.md).
- **Scope:** StremioGuard validates debrid video proxy behavior only; it does not claim every subtitle, manifest, or auxiliary request is proxied.

## Commands

```bash
./stremio comet install [--deep]
./stremio comet start
./stremio comet status
./stremio comet doctor
./stremio comet log-canary
./stremio comet probe-playback --url 'https://<your-gateway-host>/.../playback/...'
./stremio comet logs
./stremio comet update [check [--deep]|apply|rollback]
./stremio comet rotate-db-password
./stremio comet stop
```

- `./stremio comet doctor` checks active image, container health, bind surface, gluetun namespace sharing, matching VPN egress IPs, and proxy settings.
- `./stremio comet probe-playback` proves a playback URL streams as `proxied` rather than `redirected`.
- `./stremio comet log-canary` sends a synthetic token through every hop and checks gateway, Comet, StremioGuard, and configured reverse-proxy logs for leaks (see [comet-gateway.md](comet-gateway.md#log-canary)).

## Digest pinning & update workflow

Comet always runs from an immutable `g0ldyy/comet@sha256:...` digest (a reproducibility and patch-compatibility control, not signature verification):

1. **Bootstrap:** First install validates upstream `:latest` against the patch suite (falling back to `vendor/comet.lock.json`'s `tested_digest` on drift) and records the accepted digest. `./stremio comet status` prints the active digest, its OCI revision label, and `tested_digest`.
2. **Daily advisory check:** At most once per 24 hours, `./stremio start` / `restart` checks `:latest` and prints a non-blocking update notice if a newer digest exists.
3. **Explicit promotion:**
   - `./stremio comet update check [--deep]`: Extracts, renders, compiles, and runs the container-isolated `import-smoke` validator (with `--deep` adding an offline `--network none` boot check).
   - `./stremio comet update apply`: Promotes the validated candidate, recreates Comet, proves bundle hashes match inside the container, and reloads a running gateway (failing non-zero if convergence cannot be verified).
   - `./stremio comet update rollback`: Reverts to the previous digest with the same convergence checks.

## Token-managed gateway overview

For shared or remote use, protect Comet behind its token gateway (`COMET_GATEWAY_ENABLED=1`, the default) rather than sharing a Stremio account:

- **Exposure:** With the gateway enabled, raw Comet (`COMET_HOST_PORT`, default `18000`) binds **`127.0.0.1` only** for local operator diagnostics and `/admin` access; only `comet-gateway` (`COMET_GATEWAY_HOST_PORT`, default `18001`) publishes on `STREMIO_BIND_ADDRS`. Point public reverse proxies at `COMET_GATEWAY_HOST_PORT`, never at `COMET_HOST_PORT`.
- **Configure page:** Off the public gateway by default (`403`). Open it on `http://127.0.0.1:18000/configure` (e.g. via SSH tunnel), redirect public configure paths to an authenticated portal via `COMET_GATEWAY_CONFIGURE_URL` (such as Cloudflare Access), or opt back in with `COMET_GATEWAY_PUBLIC_CONFIGURE=1`.
- **Token management:**
  ```bash
  ./stremio comet token add "Shared Addon"
  ./stremio comet token list
  ./stremio comet token rotate <id>
  ./stremio comet token revoke <id>
  ./stremio comet token use <id>
  ./stremio comet token url <id> --manifest <url>
  ./stremio comet gateway-reload
  ./stremio comet gateway-logs
  ```

For the full URL model, route allowlist, reverse-proxy template (using `$http_host`, `client_max_body_size 64k`, and `access_log off`), Cloudflare Access owner portal setup, and rate limits, see [comet-gateway.md](comet-gateway.md). For Tailscale Serve and access tiers, see [secure-access.md](secure-access.md). For rootless Docker caveats, see [rootless-docker.md](rootless-docker.md).
