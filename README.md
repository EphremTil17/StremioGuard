# Stremio VPN Guard

This folder runs Stremio through Docker Compose, behind a [gluetun](https://github.com/qdm12/gluetun) container that owns the network namespace Stremio runs inside. A small Python verifier sits on top as a defense-in-depth watchdog.

## Architecture

```
WSL2 host
└── Docker
     ├── gluetun  (qmcgaw/gluetun)        ← in-kernel firewall, owns ports
     │    └── network namespace shared by:
     └── stremio  (tsaridas/stremio-docker)

Python verifier (./stremio → stremioguard.orchestrator)
├── polls gluetun health (docker inspect)
├── probes egress IP via docker exec gluetun wget
└── stops stremio if either fails
```

The kill switch is gluetun's built-in firewall, which is always on (`FIREWALL` is ignored by gluetun v3.41; StremioGuard pins `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=on` and `DNS_KEEP_NAMESERVER=off`). Traffic that does not exit through the VPN tunnel is dropped at the kernel layer (see [Security notes](#security-notes) for the exact boundary), not by a Python polling loop. The verifier is layer 2: it confirms gluetun is healthy, that the Docker DNS block is active at the top of gluetun's `OUTPUT` chain, and that the egress IP is not your home IP, and stops Stremio if any check fails.

## VPN provider support

The default `.env.example` ships with **NordVPN** and supports both:

- **WireGuard / NordLynx**: recommended for performance
- **OpenVPN**: supported through NordVPN service credentials

Switching to any of [gluetun's 30+ supported providers](https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers) — Mullvad, ProtonVPN, Surfshark, ExpressVPN, etc. — is still a one-line `VPN_SERVICE_PROVIDER` change in `.env` plus the relevant credentials. Only NordVPN is tested in this repo.

## First-time setup

Before the first run on Linux, make sure these are in place:

- Docker with the Compose plugin installed and working.
- Your Linux user able to talk to Docker without sudo (for example via the `docker` group or rootless Docker). `docker ps` should work before you run `./stremio`.
- `/dev/net/tun` available on the Linux host or WSL2 guest.
- systemd 254 or newer with a user service manager and lingering enabled for your user (`loginctl enable-linger $USER`). The watchdog runs as a systemd user service; `./stremio start` refuses to start anything without one.
- A VPN provider account and the credentials needed for your chosen setup.

On Debian/Ubuntu/WSL, that usually means:

```bash
ls /dev/net/tun
```

Run the guided initializer:

```bash
./stremio init
```

This creates `.env` from `.env.example` if needed, offers a couple of optional Stremio toggles up front, and then walks through NordVPN protocol setup. On a later `./stremio init`, a structurally valid `.env` is summarized with secrets redacted; accept the default to reuse it and restart without re-entering credentials, or decline to edit the setup with its current values as prompt defaults. `.stremio` JSON and generated runtime files are not setup inputs: they are operational state and never override `.env`.
The same guided flow now also offers an optional Comet branch so you can leave
Comet disabled on Stremio-only deployments or configure it in the same pass.

During guided setup, Stremio asks which deployment **tier** you're running:

- **Tier 1 — LAN + Tailscale only.** No public domain. Init writes `STREMIO_BIND_ADDRS=<host-LAN-IP>,<host-tailscale-IP>` when you choose both addresses and clears `EXTERNAL_BASE_URL`. LAN clients reach Stremio at `http://<host-LAN-IP>:<STREMIO_HOST_PORT>`. Tailnet clients can still reach the raw Tailscale IP directly, but the recommended browser/addon path is Tailscale Serve HTTPS on the node's `*.ts.net` hostname. See [docs/tailscale-runbook.md](docs/tailscale-runbook.md) for the end-to-end Serve flow.
- **Tier 2 / 3 — reverse-proxied behind a domain.** Init writes the selected bind addresses plus `EXTERNAL_BASE_URL=https://<your-domain>`. You provide the proxy (NPM, Caddy, Traefik, raw nginx); it upstreams to one selected host address on `STREMIO_HOST_PORT` and applies whatever access control fits your threat model. Tier 2 is tailnet-only via a Cloudflare → CGNAT DNS pivot; Tier 3 is publicly routable. The Stremio-side config is identical for both.

`init` is idempotent — re-run it to switch tiers. Start the stack through `./stremio` (plain `docker compose up` is intentionally blocked by a compose gate service so Comet never comes up unpinned or unpatched). `./stremio start` generates a local Compose override from `STREMIO_BIND_ADDRS` publishing Stremio's host port along with Comet's image pin and patched files. Ordinary inspection commands such as `docker compose logs -f` and `docker compose ps` still work normally against the base file, and Postgres finds its real data directory either way because that path lives in `docker-compose.yml` rather than in the generated override. See [docs/secure-access.md](docs/secure-access.md) for the full per-tier runbook, threat model, and verification steps.

For NordVPN, `init` offers two protocol paths:

- Recommended: **WireGuard / NordLynx** (for performance and instant handshakes)
- Alternative: **OpenVPN** with NordVPN manual service credentials

If you choose **WireGuard**, `init` allows you to:

- **Generate via NordVPN Access Token (recommended)**: Paste an Access Token from your [Nord Account Dashboard](https://my.nordaccount.com/dashboard/nordvpn/access-tokens/). StremioGuard queries NordVPN's API directly to retrieve your account's permanent WireGuard private key without any host routing changes or sudo requirements.
- **Paste an existing WireGuard private key**: Paste a known 44-character Base64 WireGuard key directly.

If you choose **OpenVPN**, `init` prompts for your NordVPN **service credentials** (from your Nord Account manual setup section) and writes them into `.env`.

The initializer does **not** install these for you:

- WSL2 needs `/dev/net/tun`. Modern WSL2 kernels (≥5.6) include it by default. Verify with `ls /dev/net/tun`; if missing, `sudo modprobe tun` enables it for the session.
- NordVPN OpenVPN uses **service credentials**, not your account email/password. You can retrieve them from Nord Account under manual setup.

## First run

From this directory:

```bash
./stremio
```

The wrapper runs the Python orchestrator through `uv`, creates the project environment from `uv.lock`, ensures `gluetun` is healthy, verifies the egress IP, starts Stremio, and starts the watchdog as a systemd user service.

Minimum host requirements:

- `uv`
- Docker with the Compose plugin
- `/dev/net/tun` available
- A populated `.env` (see [First-time setup](#first-time-setup))

Useful first-run checks:

```bash
./stremio status
./stremio logs
./stremio stop
```

## Modular Comet playback proxy

Phase 1 now includes an optional, modular [Comet](https://github.com/g0ldyy/comet)
subsystem for debrid stream proxy experiments. StremioGuard manages Comet as a
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
  [docs/comet-patches.md](docs/comet-patches.md) for the logic, methodology,
  and tradeoffs behind them.
- The current compatibility strategy is "resolved-file-first" matching:
  preserve obviously valid Torrentio-backed results when the resolved filename
  and file-level evidence are strong, instead of trusting only the noisy outer
  torrent title.
- The managed Comet patch set also improves ranking and labeling by preserving
  richer Torrentio title metadata and degrading better when resolution is
  missing. See [docs/comet-patches.md](docs/comet-patches.md) for the full
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
- Phase 1 validates debrid video proxy behavior only. It does **not** claim
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

Recommended phase-1 shape:

- publish Stremio and Comet on the same Tailscale and/or LAN bind addresses
- use a server-owned debrid API key when needed
- keep Comet inside `gluetun` so proxy egress matches the Stremio VPN path

`./stremio comet doctor` verifies the pinned checkout, container health, bind
surface, gluetun network-namespace sharing, matching VPN egress IPs, and
required proxy settings. `./stremio comet probe-playback` is the proof tool: it
checks whether a playback URL stays on the Comet endpoint or redirects the
client to a provider URL. `./stremio comet log-canary` verifies that no hop
(your reverse proxy, the gateway, Comet) logs addon URL paths, which carry
debrid credentials; see [docs/comet-gateway.md](docs/comet-gateway.md#log-canary).

For the current end-to-end Tailscale/MagicDNS/Serve workflow, see
[docs/tailscale-runbook.md](docs/tailscale-runbook.md).
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

- [docs/comet-gateway.md](docs/comet-gateway.md)
- [docs/comet-patches.md](docs/comet-patches.md)
- [docs/rootless-docker.md](docs/rootless-docker.md) — optional: the few things
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

## Recommended workflow

Use the root wrapper as the normal entry point:

```bash
./stremio
```

With no arguments, `./stremio` behaves like `./stremio start`.

### What `./stremio` does

1. Checks that `uv`, `docker`, and `docker compose` are available.
2. Confirms `.env` exists and is populated.
3. Starts `gluetun` and waits for its healthcheck to pass.
4. Probes the tunnel egress IP live from inside gluetun's network namespace
   and this host's direct public IP from outside it.
5. Refuses to continue if the VPN looks unsafe:
   - the egress IP equals this host's direct public IP,
   - the egress IP matches your saved home-IP baseline,
   - `EXPECTED_VPN_IP` is set and does not match, or
   - neither the host's IP nor a baseline is available to compare against.
6. Starts Stremio inside gluetun's network namespace.
7. If `COMET_ENABLED=1`, prepares the vendored Comet runtime and starts Comet
   plus its PostgreSQL dependency inside the same gluetun network namespace.
8. Starts the watchdog as the `stremioguard-watchdog.service` systemd user unit,
   waits until it reports ready, and returns to the shell. The check that a
   user service manager is reachable runs before step 3, so protected
   services never start without a supervised watchdog.

### Container restart policy

- `stremio`, `comet`, `comet-postgres`, and `comet-gateway` use `restart: "no"` so Docker does not revive them before the verifier and validation checks have run.
- `gluetun` uses `restart: unless-stopped` so it can recover across host reboots and transient handshake failures.
- Every other third-party image (`stremthru`, `comet-gateway`'s nginx, `comet-postgres`, and the `docker compose up` gate's busybox) is pinned by digest; Dependabot proposes bumps, and Postgres majors stay manual because they need a data-directory upgrade. Comet is pinned by the generated override to the digest `./stremio comet update` promoted.
- `gluetun` is pinned by digest too, and Dependabot proposes its bumps. It is the container the kill switch lives in, and the watchdog relies on details of it (its healthcheck, `wget`, its log wording, the control-server route), so a new release is reviewed rather than picked up by whichever start happens next. `./stremio start`/`restart` best-effort pull the pinned image when it is missing; a failed or slow pull only logs a warning and gluetun boots from the image already on the host.
- Every service shares gluetun's network namespace and therefore one port space. `NAMESPACE_PORTS` in `src/stremioguard/config.py` is the registry; a test checks `docker-compose.yml` against it. Add a port there before giving a new service one.

### Useful commands

```bash
./stremio init
./stremio start
./stremio restart
./stremio stop
./stremio status
./stremio logs
./stremio check
```

Command guide:

- `./stremio init`
  Guided setup and safe re-init. Creates `.env` from `.env.example` when needed; later runs offer a redacted `.env` summary and can restart unchanged configuration without re-entering secrets. Declining reuse opens the guided editor with existing non-secret values as defaults. Generated `.stremio` files are runtime state, never a second configuration source.

- `./stremio start`
  Normal day-to-day entry point. If no Compose instance exists yet, it performs the safe first start automatically, then starts the supervised watchdog and returns to the shell. It is also the deploy step: it publishes the current `.env` and `docker-compose.yml` (see [What the stack runs from](#what-the-stack-runs-from)), so that is when an edit takes effect. A gluetun that is already running keeps its VPN server and is recreated only if its own configuration changed. A watchdog that is already running is left alone unless its unit, a forwarded setting or the published configuration changed. When `COMET_ENABLED=1`, it also prepares and starts Comet automatically.

- `./stremio restart`
  Reset/build/start flow. Runs `docker compose down --remove-orphans`, brings gluetun back up, rebuilds the local Stremio image, and starts Stremio again. When `COMET_ENABLED=1`, it also refreshes Comet runtime files and restarts Comet. It does not delete `stremio-data/`, `gluetun-data/`, or `.stremio/comet/`.

- `./stremio stop`
  Stops the watchdog unit first, then stops Stremio and Comet when enabled, so the watchdog does not immediately start them back up again. If the unit cannot be confirmed stopped, the services are still stopped and the command exits nonzero.

- `./stremio status`
  Shows gluetun health, the current public IP as seen from inside gluetun, any active lockout, the Stremio container status, and the watchdog unit's state and restart count. When `COMET_ENABLED=1`, it also shows Comet status and its observed network mode.

- `./stremio unlock`
  Shows an active lockout marker and, after confirmation, clears it without starting anything.

- `./stremio logs`
  Tails the latest host-side run log.

- `./stremio check`
  Runs the local development checks for the Python tooling in this repo.

### Logging and watchdog behavior

Each `./stremio start` creates a host-side run log under `logs/`, named like `logs/stremio-20260424-221500.log`. The startup command and background watchdog share that file, so one run captures gluetun health checks, public IP observations, container lifecycle events, drops, and periodic watchdog summaries.

Use `./stremio logs` to tail the latest run log. Crashes that happen before logging is set up land in the journal instead: `journalctl --user -u stremioguard-watchdog.service`.

The watchdog polls gluetun health and the egress IP every 10 seconds by default. Set `WATCH_INTERVAL_SECONDS` in `.env` (or for one run, `WATCH_INTERVAL_SECONDS=5 ./stremio start`) for faster checks, or a larger value for less polling.

Additional watchdog parameters:
- `PUBLIC_IP_FAILURE_THRESHOLD`: The number of consecutive failed public IP checks (returning `UNKNOWN` status) before the watchdog shuts down the stack to fail closed (default: `3`).
- `EGRESS_PROBE_INTERVAL_SECONDS`: How long a verified tunnel egress IP is trusted before the watchdog re-probes it live and re-compares it with this host's direct IP (default: `300`). This bounds leak-detection latency. Recovery after a VPN outage always re-probes immediately. Gluetun's control-server IP is only fetched once per gluetun start and goes stale after an in-tunnel reconnect, so it is only a change trigger (ignored if non-public), and a difference between it and the live egress is logged once and never stops services.
- `VPN_RECOVERY_BUDGET_SECONDS` / `VPN_RESTART_CADENCE_SECONDS`: How long the watchdog keeps restarting an unhealthy gluetun (default: `300`, every `45` seconds) before it trips the circuit breaker.
- `MAX_AUTO_STARTS_PER_HOUR`: How many times the watchdog may start the services on its own within an hour before it treats the cycle as a fault and trips the circuit breaker (default: `10`; `0` disables the limit).

What the watchdog trusts and how NordVPN resolution is bounded:

- **IP-check services:** on each path (inside gluetun and directly from this host), the first configured `IP_CHECK_URLS` endpoint that answers a global unicast (public) address is believed, with no consensus between services. Non-public answers (private, loopback, CGNAT, multicast, reserved, link-local, site-local, or zone-suffixed) count as failures and move to the next URL. A service that lies (returning any public address other than this host's) can make a real leak look `SAFE`, while one that returns this host's address for the tunnel can force a lockout. Both paths send identical HTTP request heads (`User-Agent: Wget/1.25.0`, `Accept: */*`, `Accept-Encoding: identity`, `Connection: close`), though their TLS handshakes and source addresses still differ, and the host probe reveals this host's address to the IP-check services.
- **NordVPN endpoint resolver:** when NordVPN is selected without `SERVER_HOSTNAMES`, a cached endpoint in `.stremio/nordvpn-endpoint-cache.json` is reused for 1 hour, and as a fallback after a failed live API query for at most 24 hours (ignoring future-dated, malformed, non-public, or non-regular files). Past 24 hours, the resolver returns nothing and gluetun chooses its own server.

Log summaries are decoupled from the poll cadence. A window in which something happened (an outage, an automatic start, a namespace repair, a failed IP check, a loop error or a new public IP) is summarized every `WATCHDOG_LOG_INTERVAL_SECONDS` (default 5 minutes); a quiet one only once an hour, as a heartbeat (`0` logs every tick). Warnings for a failure that persists, such as an unreachable public-IP checker, repeat at most every 5 minutes, while the fail-closed stop itself still runs on every check. All of these can live in `.env`. A value exported in your shell reaches the supervised watchdog only because `./stremio start` forwards a fixed list of known keys to `.stremio/watchdog.env`; anything else exported in the shell does not. Changing a forwarded value and rerunning `./stremio start` restarts the watchdog to apply it.

On a bad signal, the watchdog fails closed:

- **gluetun unhealthy:** it stops the protected services, copies gluetun's recent log into the run log (recreating the container deletes it), restarts gluetun every `VPN_RESTART_CADENCE_SECONDS` (widening a narrow server filter to the whole country halfway through the budget), and resumes services once gluetun is healthy and a fresh egress probe passes. If the budget runs out, it trips the circuit breaker: it writes the lockout marker `.stremio/vpn-lockout`, stops the services and gluetun, and exits with status 78.
- **credentials rejected:** providers answer `AUTH_FAILED` for a connection limit or a busy server as well as for bad credentials, so one sighting only logs a warning. Seen again after gluetun has been restarted onto another server, it trips the circuit breaker (`auth_rejected`).
- **leak verdict** (the tunnel egress equals this host's own address, the saved home baseline, or differs from `EXPECTED_VPN_IP`): it stops the protected services at once. A second verdict within 24 hours trips the circuit breaker (`egress_leak`), whether or not passing checks came between them (the 24-hour leak history is kept in memory and resets when the watchdog restarts); a leak means the kill switch did not hold, so resuming is your decision. After `PUBLIC_IP_FAILURE_THRESHOLD` consecutive *unknown* results it stops the services and keeps checking.
- **gluetun restarted on its own** (a crash, an OOM kill, a manual `docker restart`): services that joined its previous network namespace still look healthy but can reach nothing. The watchdog compares each service's start time and namespace with gluetun's and restarts the ones left behind.
- **stop/start loop:** more than `MAX_AUTO_STARTS_PER_HOUR` automatic starts trips the circuit breaker (`service_flapping`), whatever the cause.

The lockout marker records the reason and the evidence behind it (for example the log line, or how long gluetun stayed unhealthy); `./stremio status` shows both.

Restarting services never touches gluetun (`docker compose up --no-deps`), so the tunnel that was just verified is the one they join.

### What the stack runs from

`./stremio start` and `./stremio restart` publish a generation under `.stremio/`: a copy of `docker-compose.yml` (`compose.base.yml`), a normalized snapshot of `.env` (`env.snapshot`), gluetun's share of it (`gluetun.env`), the generated override, and one patch bundle per Comet image digest (`comet/bundles/`). Containers are only ever created from that published generation (lifecycle commands publish first, and the watchdog refuses to start any container from an incomplete generation missing the override, `compose.base.yml`, or `env.snapshot`), so container settings come from `env.snapshot` rather than the working tree. Before the first start, or when the generation is incomplete, read-only queries and teardown fall back to the working tree's `docker-compose.yml` and `.env`. Editing `.env`, editing `docker-compose.yml` or running `git pull` therefore changes nothing in running containers until the next start or restart, and a mistake in an edit is reported by the command you ran, not by the watchdog during a later VPN recovery. The Comet commands (`./stremio comet start`, `comet update apply|rollback`, `comet token ...`) act on the running stack, so they read the published snapshot rather than `.env`: they change the Comet image, its bundle or the token map, and never deploy a pending edit. Note as a known limit that a variable of the same name exported in the environment of the process running Compose (your shell, for `./stremio`) still takes precedence over `env.snapshot` for Compose's `${…}` interpolation.

`.env` is read by one parser, and Compose only ever sees the normalized snapshot, so the two cannot disagree about a value. Lines end at `\n`, and CRLF is accepted; any non-comment line carrying another line separator or NUL (literally or via a `\n` or `\r` escape) is refused with its line number. Optional `export`, single or double quotes, `#` after whitespace starting a comment, and the last assignment of a key winning behave as usual, except that `$` is always literal (never expanded) and the supported double-quote escapes are `\t`, `\\`, `\"` and `\$` (producing a tab, `\`, `"` and `$`, as in Compose); a `\n` or `\r` escape is refused like a literal line break, and any other escape drops its backslash, unlike Compose.

The Python code itself still runs from the checkout. Run a deployment from a checkout you do not develop in (a tagged clone or `git worktree`), so a half-finished branch is never what the boot unit starts.

Commands that start, stop or recreate containers take one lock (`.stremio/stack.lock`). The watchdog holds it for each check and stands aside while a CLI command holds it, for at most ten minutes; it keeps checking for a leak meanwhile and stops the services on a definitive verdict without waiting.

### Alerts

Set `STREMIO_ALERT_URL` in `.env` to an HTTP(S) endpoint to be told about events that otherwise only reach the run log: a lockout, a leak verdict, the fail-safe running, a watchdog that keeps failing, and gluetun restarting on its own. Each is one plain-text `POST` with ntfy-style `Title`/`Priority`/`Tags` headers (an [ntfy](https://ntfy.sh) topic URL works as is; other webhooks ignore the headers). Alerts never contain an IP address or a secret, repeat at most every 15 minutes per event, and are best-effort: delivery is not retried and a failure only logs a warning. The request leaves from this host's own connection, not through the tunnel, because an alert about a dead VPN cannot depend on the VPN.

### Watchdog supervision

`./stremio start` writes three systemd user units to `~/.config/systemd/user/` and keeps them in sync on every start:

| Unit | Role |
| :-- | :-- |
| `stremioguard-watchdog.service` | Runs the watchdog. It reports ready once it is actually watching, then sends a heartbeat every tick. |
| `stremioguard-failsafe.service` | Runs only when the watchdog unit fails for good. It writes a `watchdog_unstable` lockout (keeping any existing marker), stops the protected services, and checks with Docker that they really stopped. |
| `stremioguard.service` | Opt-in boot unit that runs `./stremio start` after Docker comes up. |

Because the watchdog runs in your user's service manager, it no longer belongs to whatever started it. Closing an SSH session or terminal, or ending an automation job, does not kill it.

What happens when the watchdog stops unexpectedly:

1. **Crash, or no heartbeat for 5 minutes** (`WatchdogSec=300`, for example from a hung Docker call): systemd restarts it after 5s, then about 10s, 20s, 40s and so on, up to 5 minutes between attempts. Each Docker call the watchdog makes is bounded on its own (`30`s for queries, `240`s for Compose mutations); host IP probes (`5`s) enforce a wall-clock deadline per URL (only the worker thread can outlive it if blocked in a DNS lookup), while `5`s alert calls and `8`s NordVPN recommendation calls have per-operation socket timeouts (DNS resolution is not pre-cancelled, and the resolver's 4 MiB cap has no separate wall-clock deadline). Under worst-case sequential timeouts or slow-success delays across a full 5-service stack (measured in `tests/test_worst_case_tick.py`: `508`–`838`s for a stalling steady-state stop, `728`–`1058`s for a first outage tick, `480`–`1080`s for a mid-outage relaxed restart, `649`–`787`s for recovery, and `815`–`1835`s for a circuit-breaker trip), a single tick exceeds `WatchdogSec=300`, so systemd kills the watchdog on timeout and restarts it. The protected services keep running during these retries, and gluetun's kill switch still blocks traffic outside the tunnel.
2. **Restart-budget limits and in-memory state:** the 24-hour leak history, the recovery budget, the auto-start count, and the auth-rejection generation count all live in memory and reset whenever the watchdog process restarts (crash, `WatchdogSec` kill, a `./stremio start` that changed its configuration, or reboot). Systemd hands over to the fail-safe unit only after the seventh start within an hour (`StartLimitBurst=6` in `StartLimitIntervalSec=3600`), so restarts spaced more than about 10 minutes apart continue indefinitely, each with fresh bounds. That bounds the time without a watchdog during a continuous loop to roughly 5 minutes for a crash loop, or roughly 35 minutes for a hang loop (each attempt waiting out the 5-minute `WatchdogSec=`). `./stremio start` and the boot unit reset the units' failed state.
3. **Exit status 78** (circuit breaker or an existing lockout): no restart. The fail-safe runs and keeps the original lockout reason.

While a lockout marker exists—or while `stremioguard-failsafe.service` is `failed` or `activating` (for example, if the fail-safe could not write the marker to disk)—`./stremio start`, the boot unit, and the watchdog itself all refuse to run (exit 78). Note that systemd forgets a failed unit state across a reboot, so a lockout whose marker could never be written to disk does not survive a host reboot. Recover deliberately with `./stremio restart`, which clears any existing lockout marker once the reset runs (even if VPN preflight fails, handing bounded recovery back to the watchdog, which writes a fresh marker if the VPN does not recover) and resets the failed units after a successful restart; or inspect and clear the marker with `./stremio unlock`.

Start at boot:

```bash
systemctl --user enable stremioguard.service
```

If you used the older `@reboot ./stremio start` cron entry or a hand-installed `stremio-vpn-watch.service`, remove them. The CLI warns while the old unit file is present. A watchdog started by a pre-systemd version is stopped automatically on the next `./stremio start`, `restart` or `stop`.

Without systemd (for example, WSL with systemd disabled), run `uv run python -m stremioguard.orchestrator start` and keep `uv run python -m stremioguard.orchestrator watchdog` running under a supervisor of your own.

### Stremio patch layer

The local Stremio image is built from a digest-pinned `tsaridas/stremio-docker` base image with a small patch layer.

- `STREMIO_APPLY_PATCHES=1`
  Keeps the compatibility fixes enabled. Turning it off restores upstream image behavior and removes the HTTPS redirect fix, local self-probe rewrite, favicon guard, and `/casting` stub.

- `STREMIO_SKIP_HW_PROBE=1`
  Prevents repeated `/device-info` requests from re-running noisy `qsv`, `nvenc`, and `vaapi` self-tests on every reconnect.

- `EXTERNAL_BASE_URL=https://your-public-domain`
  Optional. Keeps browser redirects and client-facing links on your public HTTPS origin. Leave it blank for local-only access so Stremio uses the host and port clients actually connect to.

- `INTERNAL_MEDIA_BASE_URL=http://127.0.0.1:11470`
  Keeps ffprobe and HLS self-references on loopback instead of probing back out through the reverse proxy.

- `STREMIO_HOST_PORT=11470`
  Host-side TCP port published by the generated Compose override. The guard maps each selected bind address as `<bind-address>:<STREMIO_HOST_PORT>:11470`.

- `STREMIO_BIND_ADDRS=127.0.0.1`
  Comma-separated host interfaces for gluetun's published Stremio port. Use a LAN IP plus a Tailscale IP, such as `192.168.1.10,100.64.0.10`, for Tier 1 LAN + Tailscale access without binding on every interface. Set it empty to publish no host port, or use `0.0.0.0` only when you intentionally want every interface.

If you change `STREMIO_APPLY_PATCHES` after the image has already been built, run `./stremio restart` so Docker rebuilds the image with the new build arg.

### Python runtime

The wrapper runs the Python guard through `uv`, so Typer, Loguru, and the rest of the Python environment come from `uv.lock` instead of global `pip` packages.

It performs best-effort dependency setup on apt-based WSL systems and can attempt to install `uv` and Docker if missing. Set `INSTALL_MISSING_DEPS=0` to disable automatic package installation attempts.

## Leak baseline

For an extra check, while gluetun is stopped (or has not been brought up yet) and you are on your normal home connection, run:

```bash
./stremio record-home-ip
```

This saves your non-VPN public IPv4 address to `.stremio/home-ip` (refusing if no IP-check service returns a public IPv4 address). The guard already compares the tunnel egress with this host's live direct IP; the baseline is used **only** as the fallback when that host-side lookup fails. A baseline entry that is not a small regular file (<= 256 bytes; never a symlink, FIFO, or directory) holding a public address counts as missing (`./stremio status` reports it as unusable and asks you to re-run `record-home-ip`), so it can never produce a `SAFE` verdict. Without a valid host probe or baseline, the check returns `UNKNOWN` and repeated `UNKNOWN`s stop services. The command refuses to run while gluetun is healthy, since that would record a VPN IP as home.

If your VPN endpoint has a stable IP, you can make the check stricter:

```bash
EXPECTED_VPN_IP=1.2.3.4 ./stremio start
```

## Start automatically (Persistent Boot Setup)

Run `./stremio start` once (it installs the units), then enable the boot unit:

```bash
systemctl --user enable stremioguard.service
```

It starts after your user's Docker service and runs the same `./stremio start`, so the lockout check, the VPN verification and the supervised watchdog all apply at boot. Lingering (`loginctl enable-linger $USER`) is what starts your user's service manager at boot without a login. See [Watchdog supervision](#watchdog-supervision) for how crashes are handled.

## Tests

The guard is written to be testable without calling gluetun or Docker directly:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run pyright
./stremio check
```

`tests/test_systemd_integration.py` loads the real watchdog units into your systemd user manager (under throwaway names, with short timings) to prove backoff, the start limit, the fail-safe and the heartbeat. It is opt-in: `STREMIOGUARD_SYSTEMD_TESTS=1 uv run pytest tests/test_systemd_integration.py`.

To verify the nginx gateway and Comet override patches against real containers without touching a live stack, see [docs/lab.md](docs/lab.md).

## Security notes

The primary kill switch is **gluetun's in-kernel firewall**, which is always on (`FIREWALL` is not a gluetun v3.41 setting; `docker-compose.yml` pins all 14 gluetun listener, auth, and firewall settings: `FIREWALL_ENABLED_DISABLING_IT_SHOOTS_YOU_IN_YOUR_FOOT=on`, `DNS_KEEP_NAMESERVER=off`, `HTTP_CONTROL_SERVER_ADDRESS=127.0.0.1:18080`, `HTTPPROXY=off`, `SHADOWSOCKS=off`, `PPROF_ENABLED=no`, `HEALTH_SERVER_ADDRESS=127.0.0.1:9999`, `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=/gluetun/auth/config.toml`, `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={}`, `FIREWALL_INPUT_PORTS=""`, `FIREWALL_VPN_INPUT_PORTS=""`, `FIREWALL_OUTBOUND_SUBNETS=""`, `VPN_PORT_FORWARDING=off`, and `VPN_INTERFACE=tun0`). `.env` cannot change these pins, and `./stremio start` / `restart` logs one warning per differing key without printing its value. With `network_mode: service:gluetun`, the exact egress boundary is:

- What can still leave outside `tun0`: the VPN endpoint's IP and port, and gluetun's own Docker bridge subnet (only `gluetun` is attached to that bridge—`use-stremio-start-instead` uses `network_mode: none`, and all other services share `gluetun`'s namespace; `FIREWALL_OUTBOUND_SUBNETS` is pinned to `""`). Because gluetun's firewall accepts input from its own bridge subnet, raw Comet's `0.0.0.0:8000` (including `/admin`, required on `0.0.0.0` so host `127.0.0.1:18000` healthchecks reach it through `docker-proxy`) and gluetun's DNS (`:::53`, which has no listen-address option in v3.41.3) are reachable from that bridge; no other container sits on it.
- What is blocked, and how: Docker's embedded DNS (`127.0.0.11`, which would otherwise forward outside the tunnel directly or via gluetun's own DNS forwarder) is rejected by `/iptables/post-rules.txt` (`gluetun-post-rules-v1`), which is verified at the top of gluetun's `OUTPUT` chain by `./stremio start`, `./stremio restart`, and the watchdog before it starts or resumes protected services (`./stremio comet start`, `./stremio comet update apply`, and `./stremio comet update rollback` start Comet directly and rely on the running watchdog, which holds services stopped while the block cannot be verified); raw `AF_PACKET` sockets are blocked by `cap_drop: [ALL]` (with no `NET_RAW` in `cap_add`) on every namespace service (`stremio`, `comet-gateway`, `comet-postgres`, `stremthru`, `comet`) and on `use-stremio-start-instead`.
- Consequence: single-label names (Docker service names and bare LAN hostnames) do not resolve inside gluetun's namespace.

The Python verifier is layer 2 — it catches the cases where gluetun is up but unhealthy, where the Docker DNS block is missing from `OUTPUT`, where the egress IP unexpectedly matches your home IP, or where an `EXPECTED_VPN_IP` constraint fails.

Defense-in-depth notes:

- Comet's Postgres (`comet-postgres`) requires SCRAM-SHA-256 password authentication for every TCP client (`127.0.0.1` and `::1`) via a Compose-managed `pg_hba.conf` (`hba_file=/etc/postgresql/pg_hba.conf`) and listens on `127.0.0.1` only (`listen_addresses=127.0.0.1`). The Unix socket inside the `comet-postgres` container stays `trust`, serving as the operator's recovery path and for the image's init scripts.
- `./stremio comet rotate-db-password` rotates the `comet` database password offline in single-user mode and requires the stack to be stopped (`./stremio stop`) first. Installs created before this change keep the legacy `comet` password until rotated, and `./stremio start` warns when it is still in use.

- LAN discovery from the VPN namespace (e.g., Chromecast, DLNA) is blocked and not supported: `FIREWALL_OUTBOUND_SUBNETS` is pinned to `""` in `docker-compose.yml` because any outbound subnet rule would reopen egress outside the VPN tunnel.
- The host-level WSL connection itself is no longer routed through any VPN by default. Anything outside this Docker setup uses your home connection. Choose split tunneling at the WSL/Windows layer if you want broader coverage.
- `WIREGUARD_PRIVATE_KEY` in `.env` is sensitive. The repo's `.gitignore` excludes `.env`; double-check before sharing dotfiles or backups.
- gluetun does not read `.env` directly. `./stremio` writes its share to `.stremio/gluetun.env` (mode 0600) on every start: every line except StremioGuard's own settings (`COMET_*`, `STREMIO_*`, the watchdog tunables, and the Stremio container's `CASTING_DISABLED`, `EXTERNAL_BASE_URL` and `INTERNAL_MEDIA_BASE_URL`) and the 14 gluetun keys pinned in `docker-compose.yml` (which trigger a warning without printing their values if set to another value in `.env`). StremioGuard keeps all its secrets under `COMET_`, so none of them sit in the VPN container's environment; any unpinned gluetun option you add to `.env` still reaches it.
- Container hardening (`docker-compose.yml`): every service enforces `security_opt: ["no-new-privileges:true"]`. `comet` and `stremthru` drop `ALL` capabilities with `read_only: true` and `tmpfs: [/tmp]`. `comet-gateway` drops `ALL`, adds only `CHOWN`, `SETGID`, `SETUID`, and runs `read_only: true` with `tmpfs: [/tmp, /var/cache/nginx]`. `comet-postgres` drops `ALL` and adds `CHOWN`, `DAC_READ_SEARCH`, `SETGID`, `SETUID`; `stremio` drops `ALL` and adds `CHOWN`, `DAC_OVERRIDE`, `SETGID`, `SETUID`; `use-stremio-start-instead` uses `network_mode: none` and drops `ALL`. `comet-postgres`, `stremio`, and `gluetun` keep writable root filesystems because Compose `configs:` with `content:` fail on `read_only` services (`gluetun`, `comet-postgres`) and `stremio`'s start script edits files in the image. `gluetun` keeps Docker's default capabilities plus `NET_ADMIN` because reducing them broke OpenVPN config `chown`, `/tmp/gluetun/ip` clearing on VPN restart, container restart, and ICMP health checks.
- `comet-gateway`'s healthcheck curls its loopback liveness endpoint (`http://127.0.0.1:8099/__sg_alive`, `204`, `access_log off`), proving the nginx master and a worker accept and answer without contacting Comet; no service depends on `comet-gateway`'s health status.
- Run logs in `logs/` record your home and tunnel IPs, so `logs/` must be a real owner-only directory (`0700`, never a symlink) and every run log—including rotated log files—is created at mode `0600`.
- Host state under `.stremio/` and `logs/` is owner-only (`0700`) and both roots must be real directories, never symlinks. StremioGuard creates its own files there at mode `0600` from creation (run logs including rotated ones, `.stremio/vpn-lockout`, `.stremio/home-ip`, `stack.lock` and `watchdog.instance.lock`, `tokens.lock`, the NordVPN cache, `daemon-id`, `gluetun-auth.toml`, and `docker-compose.bindings.yml`), while `.env` in the checkout root is also created and updated at mode `0600` (`init` and `write_env_settings`), and Comet's bundles and data directories under `.stremio/comet/` keep the modes their containers require behind the `0700` `.stremio/` directory.
- Comet never offers direct-torrent (P2P) streams or torznab magnet feeds here, whatever its configure page says: Stremio would play P2P torrents with the TV's or phone's own torrent engine, on its own connection, outside the VPN. Torznab is disabled (`DISABLE_TORRENT_STREAMS=True` and 404 at the guard), `StremioGuardResponseGuard` enforces removal of P2P entries (`infoHash` or `magnet:` links) from every JSON `streams` list at Comet's ASGI response boundary, and `_assert_p2p_blocked` in `stream.py` provides a structural second layer. Everything plays through debrid and Comet's proxy instead. Uncached results are marked with an amber `🔸` on their media-type line (`🔸 WEB-DL`); cached ones are unmarked.
- A Comet image whose `/app/comet` tree contains a link (symlink or hard link) or a special file (FIFO, socket, device, or unreadable directory) is refused before any of its files is read.
- Comet's own startup log printed half of every secret it masked (the TorBox key, passwords, the public API token). A required patch makes it print `********` instead; see [docs/comet-patches.md](docs/comet-patches.md).
- The gateway's access log keeps only clean public UI/health paths (`/`, `/configure`, `/static/`, `/health`, with query strings stripped) readable and masks `/comet/...`, `%`, `/..`, and all other request paths so raw Comet addon URLs, tokens, API tokens, and config blobs are not recorded (`302`, `400`, `403`, and `503` lines included). Non-addon paths under `/comet/<token>/...`, `/admin`, `/kodi/...`, and `/cometnet/...` are blocked at the gateway.
- Restarting gluetun mid-session (e.g., `docker compose restart gluetun`) leaves Stremio running but network-isolated until the watchdog's next tick stops it. Expected behavior of the netns-share model.

## Inbound access threat model

Outbound (torrent traffic) goes through gluetun's VPN. Inbound (clients reaching the streaming server and web UI) is a separate problem the repo does not solve in-stack. Stremio's streaming server has no built-in auth, so the trust boundary is whatever is in front of it.

The repo supports three deployment tiers. Stremio-side config is two `.env` lines; pre-Stremio infrastructure (DNS, certs, reverse proxy) is yours to assemble.

| Tier | What's in front of Stremio | Trust boundary |
|------|----------------------------|----------------|
| 1 | Nothing — direct LAN/Tailscale access | LAN devices + tailnet peers |
| 2 | Reverse proxy + domain, A record on a Tailscale CGNAT IP (tailnet-only) | LAN devices + tailnet peers; open internet has no route |
| 3 | Reverse proxy + publicly routable domain | whatever your proxy enforces (auth, allowlist, WAF, …) |

Tier 2 is the recommended posture for off-LAN access without exposing anything publicly: clients on your tailnet see a friendly `https://your.domain`, the open internet sees an unroutable CGNAT IP, the home WAN port is never opened. Tier 3 trades that L3 isolation for full public reachability and puts the gating burden on the proxy.

Per-tier setup steps, DNS-01 cert renewal, and verification live in [docs/secure-access.md](docs/secure-access.md). A raw nginx server-block reference for Tier 2/3 is in [docs/nginx-allowlist.conf](docs/nginx-allowlist.conf).
