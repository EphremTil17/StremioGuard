# Comet

Comet, the debrid stream addon StremioGuard runs inside the tunnel: its sources, its patches, how its image is pinned and updated, and the token gateway in front of it.

## Modular Comet playback proxy

[Comet](https://github.com/g0ldyy/comet) is the debrid stream addon StremioGuard runs inside
the tunnel; it is optional and modular. StremioGuard manages Comet as a
first-class part of the same Docker product: when enabled, Comet shares
`gluetun`'s network namespace and the root `./stremio` commands manage it
automatically.

- `vendor/comet.lock.json` pins the fallback `tested_digest` for `g0ldyy/comet`; runtime patch bundles are extracted directly from the pinned Comet image.
- Local Comet runtime state lives under `.stremio/comet/`.
- StremioGuard generates the Comet runtime `.env` plus mounted runtime overrides;
  it does not require a local Comet git checkout.
- Comet reaches debrid services through a self-hosted
  [StremThru](https://github.com/MunifTanjim/stremthru) container (`stremthru`),
  pinned by digest. Comet's default is a public instance run by a third party,
  which sees the debrid key in every request and has gone offline before. Ours
  listens on `127.0.0.1:8091` inside gluetun's namespace, is never published,
  has peering with the public instance and every optional feature turned off,
  and gets a generated user (`.stremio/stremthru/stremthru.env`) so it never
  prints an auto-generated admin password. `./stremio status` reports whether
  Comet can reach it.
- Extra sources beyond Torrentio and Zilean:
  - `COMET_TORBOX_API_KEY` turns on TorBox's own search API
    (`COMET_SCRAPE_TORBOX`, default `live` once a key is set). It finds what
    TorBox already knows about, which is what turns "0 cached" into playable
    results. The key is used server-side for searching only.
  - `COMET_SCRAPE_DMM=live` searches a local copy of Debrid Media Manager's
    hashlists and turns on Comet's ingester. Each ingest downloads the whole
    archive (about 1.5 GB, through the VPN) on every Comet start and then every
    `COMET_DMM_INGEST_INTERVAL_SECONDS` (default one week), and stores the
    entries in Comet's Postgres database. The first import is slow by design.
  - Scrape modes accept `live`, `background`, `both`, `true` or `false` (`off`
    is accepted as `false`). Anything else is rejected, because Comet would
    silently treat a typo as "disabled".
- The default `COMET_TORRENTIO_URL` stays generic (`https://torrentio.strem.fun`)
  so setup does not require pasting a secret-bearing native Torrentio addon URL
  into the root `.env`.
- `./stremio comet install` now protects Comet's `/configure` page by default so
  a shared domain does not let other users rewrite addon settings. If
  `COMET_CONFIGURE_PAGE_PASSWORD` is omitted or empty in `.env`, Comet keeps the
  existing password stored in `.stremio/comet/.env` and warns how to change it
  (rather than silently locking you out); on initial setup, it generates a
  random password and warns where it is stored. Password values are never logged.
- The Comet setup flow also offers an optional episode-pack preservation patch
  so Torrentio/Zilean-backed episode results inside season packs survive more
  like native Torrentio. When enabled (`COMET_PATCH_EPISODE_PACK_RESULTS=1`), this
  uses a precise Cinemeta-backed caching metadata service to check season episode counts,
  ensuring only complete season packs are prioritized and badged.
- These optional Comet compatibility patches are strongly recommended. See
  [comet-patches.md](comet-patches.md) for the logic, methodology,
  and tradeoffs behind them.
- The current compatibility strategy is "resolved-file-first" matching:
  preserve obviously valid Torrentio-backed results when the resolved filename
  and file-level evidence are strong, instead of trusting only the noisy outer
  torrent title.
- The managed Comet patch set also improves ranking and labeling by preserving
  richer Torrentio title metadata and degrading better when resolution is
  missing. See [comet-patches.md](comet-patches.md) for the full
  rationale and tradeoffs.
- RTN rank display follows Comet's current `MediaSearchResult` boundary:
  StremioGuard carries the already-calculated scalar score from media search
  to stream formatting and displays it as `R:<score>` beside size. It never
  reorders or recalculates RTN results, and it deliberately has no shim for
  the retired endpoint-owned ranking architecture.
- Server-owned fallback debrid credentials are optional. If you prefer to do all
  final addon configuration inside Comet's `/configure` page and then distribute
  only the finished addon or Stremio account, you can skip them during setup.
- Comet inherits `STREMIO_BIND_ADDRS` in the unified stack model, so Stremio and
  Comet publish on the same host interfaces with separate ports.
- StremioGuard validates debrid video proxy behavior only. It does **not** claim
  that every subtitle, manifest, or auxiliary playback request is proxied.

Comet commands:

```bash
./stremio comet install [--deep]
./stremio comet start
./stremio comet status
./stremio comet doctor
./stremio comet log-canary
./stremio comet probe-playback --url 'http://<comet-host>:18000/.../playback/...'
./stremio comet logs
./stremio comet update [check [--deep]|apply|rollback]
./stremio comet rotate-db-password
./stremio comet stop
```

### Digest Pinning and Update Workflow

To ensure absolute configuration coherence and prevent upstream Comet updates from silently breaking your deployment, StremioGuard enforces a **digest-pinned model**:

1. **Digest Pinning:** After initial resolution, the stack runs Comet from a specific image digest (e.g., `g0ldyy/comet@sha256:...`) instead of a floating tag. The first resolution evaluates the current upstream `:latest` image against the managed patch suite and persists the accepted digest; the maintainer-tested lock digest is the fallback when required compatibility fails. This is a reproducibility and compatibility control, not a provenance/signature verification policy. `./stremio comet status` prints the active image reference, its `org.opencontainers.image.revision` label (`unknown` if unavailable), and `vendor/comet.lock.json`'s `tested_digest`.
2. **Advisory Start-Time Checks:** Once every 24 hours, running `./stremio start` or `./stremio restart` triggers a throttled check against the upstream `:latest` registry tag. If an update is available, it prints a single notification line without blocking startup.
3. **Comet Update Suite:**
   - `./stremio comet update check`: Resolves the remote registry digest, extracts the code, compiles it in isolation, runs a mandatory container-isolated `import-smoke` check (importing every patched module, scanning all code objects for undefined names, and probing the ASGI app to prove `StremioGuardResponseGuard` is outermost, strips P2P entries, and blocks torznab), and logs a feature diff (applied/skipped patches). Use `--deep` to run an ephemeral boot test with no network access.
   - `./stremio comet update apply`: Promotes the validated candidate digest to active state and restarts the Comet stack, proving Comet runs the active image with the active bundle and reloading a running gateway (exiting non-zero if convergence cannot be proven).
   - `./stremio comet update rollback`: Reverts to the previous active digest, proving the running Comet and gateway converged (exiting non-zero otherwise). `./stremio comet start` enforces the same convergence checks.

Recommended shape:

- publish Stremio and Comet on the same Tailscale and/or LAN bind addresses
- use a server-owned debrid API key when needed
- keep Comet inside `gluetun` so proxy egress matches the Stremio VPN path

`./stremio comet doctor` verifies the running image, container health, bind
surface, gluetun network-namespace sharing, matching VPN egress IPs, and
required proxy settings. `./stremio comet probe-playback` is the proof tool: it
checks whether a playback URL stays on the Comet endpoint or redirects the
client to a provider URL. `./stremio comet log-canary` verifies that no hop
(your reverse proxy, the gateway, Comet) logs addon URL paths, which carry
debrid credentials; see [comet-gateway.md](comet-gateway.md#log-canary).

For the current end-to-end Tailscale/MagicDNS/Serve workflow, see
[tailscale-runbook.md](tailscale-runbook.md).
Longer term, the project direction is to support a cleaner authenticated HTTPS
domain flow in front of Stremio/Comet so Tailscale does not have to be the
primary end-user access UX.

## Token-Managed Comet Gateway

The recommended low-friction access model is to protect Comet, not Stremio.
Users keep their own Stremio accounts, while Comet acts as the token-gated
addon, stream-discovery, and playback relay.

- Configure stays at `https://comet.example.com/configure` and is protected by
  Comet's configure password; opening `https://comet.example.com/comet/<token>/configure`
  preserves that token in the generated install/copy links (since configure
  pages share one configure password and embed the default token, token
  separation applies to manifest-link recipients without that password).
- Under `/comet/<token>/...`, tokens match case-sensitively and only Stremio
  addon routes (`/s/<api>/manifest.json`, `/s/<api>/stream/...`,
  `/s/<api>/<config>/playback/...`) plus the token configure/login routes are
  allowed; `debrid-sync` (meaning Comet Sync streams fail with `403` while
  stream-triggered account sync still runs), `torznab/api`, ChillLink, `/admin`,
  `/kodi/...`, `/cometnet/...`, and traversal/encoded variants are blocked (`403`
  / `503` when rate-limited). Reach `/admin` directly via `COMET_HOST_PORT` on
  LAN or tailnet (Kodi pairing through the gateway is unsupported).
- The gateway clears all 14 Comet client-IP headers and client-supplied
  `X-Forwarded-Prefix`/`X-Forwarded-Host`, and preserves `$http_host` (including
  non-default ports). `./stremio start` and `./stremio restart` re-render
  `nginx.conf` and `tokens.map`, reload a running gateway, recreate a running
  Comet whose mounted patch bundle is stale, and exit `1` (after starting the
  watchdog) when that convergence cannot be shown; `./stremio comet gateway-reload`
  runs the checked gateway reload directly.
- Raw Comet is published only on `COMET_HOST_PORT` on your configured bind
  addresses for local/tailnet operator access and diagnostics.
- Public reverse proxies should point at `COMET_GATEWAY_HOST_PORT`, not the raw
  Comet port.

If you want the details, see:

- [comet-gateway.md](comet-gateway.md)
- [comet-patches.md](comet-patches.md)
- [rootless-docker.md](rootless-docker.md) — optional: the few things
  that behave differently if you run the stack under a rootless daemon

For public reverse proxies such as Nginx Proxy Manager or raw nginx, the
recommended upstream shape is:

```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Real-IP "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
    proxy_http_version 1.1;
    proxy_pass http://<SERVERIP:18001>$request_uri;
}
```

Replace `18001` with your configured `COMET_GATEWAY_HOST_PORT` if you changed
it. Do not point `comet.example.com` directly at raw `COMET_HOST_PORT`.

Restrict the gateway port to the proxy/LAN/tailnet path that should reach it,
and make the proxy overwrite client-supplied `Host` and forwarded-origin headers.

Create and manage gateway tokens with:

```bash
./stremio comet token add "Shared Addon"
./stremio comet token list
./stremio comet token rotate <id>
./stremio comet token revoke <id>
./stremio comet token use <id>
```

Use `./stremio comet gateway-logs` while testing the public domain to confirm
requests are hitting the token gate.
