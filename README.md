# Stremio VPN Guard

This folder runs Stremio through Docker Compose, behind a [gluetun](https://github.com/qdm12/gluetun) container that owns the network namespace Stremio runs inside. A small Python verifier sits on top as a defense-in-depth watchdog.

## Architecture

```
WSL2 host
└── Docker
     ├── gluetun  (qmcgaw/gluetun)        ← in-kernel firewall, owns ports
     │    └── network namespace shared by:
     └── stremio  (tsaridas/stremio-docker)

Python verifier (bin/stremio-vpn)
├── polls gluetun health (docker inspect)
├── probes egress IP via docker exec gluetun wget
└── stops stremio if either fails
```

The kill switch is gluetun's built-in firewall (`FIREWALL=on`). Traffic that does not exit through the VPN tunnel is dropped at the kernel layer, not by a Python polling loop. The verifier is layer 2: it confirms gluetun is healthy and that the egress IP is not your home IP, and stops Stremio if either check fails.

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

`init` is idempotent — re-run it to switch tiers. Start the stack through `./stremio`, which generates a local Compose override from `STREMIO_BIND_ADDRS` publishing Stremio's host port along with Comet's image pin and patched files. Ordinary `docker compose` commands work normally against the base file — `docker compose logs -f`, `ps`, and so on — and Postgres finds its real data directory either way, because that path lives in `docker-compose.yml` rather than in the generated override. Starting with plain `docker compose up` is not harmful, it just runs Comet unpinned and unpatched until the next `./stremio start`. See [docs/secure-access.md](docs/secure-access.md) for the full per-tier runbook, threat model, and verification steps.

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

The wrapper runs the Python orchestrator through `uv`, creates the project environment from `uv.lock`, ensures `gluetun` is healthy, verifies the egress IP, starts Stremio, and launches the background watchdog.

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

- Upstream source lives in `vendor/comet` and is pinned by `vendor/comet.lock.json`.
- Local Comet runtime state lives under `.stremio/comet/`.
- StremioGuard generates the Comet runtime `.env` plus mounted runtime overrides;
  it does not edit the upstream Comet checkout itself.
- The managed override files are rendered by `scripts/generate_comet_overrides.py`,
  which is also what the setup flow uses internally.
- The default `COMET_TORRENTIO_URL` stays generic (`https://torrentio.strem.fun`)
  so setup does not require pasting a secret-bearing native Torrentio addon URL
  into the root `.env`.
- `./stremio comet install` now protects Comet's `/configure` page by default so
  a shared domain does not let other users rewrite addon settings.
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
./stremio comet probe-playback --url 'http://<comet-host>:18000/.../playback/...'
./stremio comet logs
./stremio comet update [check [--deep]|apply|rollback]
./stremio comet stop
```

### Digest Pinning and Update Workflow

To ensure absolute configuration coherence and prevent upstream Comet updates from silently breaking your deployment, StremioGuard enforces a **digest-pinned model**:

1. **Digest Pinning:** After initial resolution, the stack runs Comet from a specific image digest (e.g., `g0ldyy/comet@sha256:...`) instead of a floating tag. The first resolution evaluates the current upstream `:latest` image against the managed patch suite and persists the accepted digest; the maintainer-tested lock digest is the fallback when required compatibility fails. This is a reproducibility and compatibility control, not a provenance/signature verification policy.
2. **Advisory Start-Time Checks:** Once every 24 hours, running `./stremio start` or `./stremio restart` triggers a throttled check against the upstream `:latest` registry tag. If an update is available, it prints a single notification line without blocking startup.
3. **Comet Update Suite:**
   - `./stremio comet update check`: Resolves the remote registry digest, extracts the code, compiles it in isolation, runs a mandatory container-isolated `import-smoke` check, and logs a feature diff (applied/skipped patches). Use `--deep` to run an ephemeral boot test.
   - `./stremio comet update apply`: Promotes the validated candidate digest to active state and restarts the Comet stack.
   - `./stremio comet update rollback`: Reverts to the previous active digest.

Recommended phase-1 shape:

- publish Stremio and Comet on the same Tailscale and/or LAN bind addresses
- use a server-owned debrid API key when needed
- keep Comet inside `gluetun` so proxy egress matches the Stremio VPN path

`./stremio comet doctor` verifies the pinned checkout, container health, bind
surface, gluetun network-namespace sharing, matching VPN egress IPs, and
required proxy settings. `./stremio comet probe-playback` is the proof tool: it
checks whether a playback URL stays on the Comet endpoint or redirects the
client to a provider URL.

For the current end-to-end Tailscale/MagicDNS/Serve workflow, see
[docs/tailscale-runbook.md](docs/tailscale-runbook.md).
Longer term, the project direction is to support a cleaner authenticated HTTPS
domain flow in front of Stremio/Comet so Tailscale does not have to be the
primary end-user access UX.

## Token-Managed Comet Gateway

The recommended low-friction access model is to protect Comet, not Stremio.
Users keep their own Stremio accounts, while Comet acts as the token-gated
addon, stream-discovery, and playback relay.

- Configure/admin stays at `https://comet.example.com/configure` and is
  protected by Comet's configure password.
- Addon, stream, playback, and debrid-sync routes live under
  `https://comet.example.com/comet/<token>/...`.
- Raw Comet is published only on `127.0.0.1:COMET_HOST_PORT` for local
  operator diagnostics.
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
4. Probes the public IP from inside gluetun's network namespace.
5. Refuses to continue if the VPN looks unsafe:
   - the IP matches your saved home-IP baseline, or
   - `EXPECTED_VPN_IP` is set and does not match.
6. Starts Stremio inside gluetun's network namespace.
7. If `COMET_ENABLED=1`, prepares the vendored Comet runtime and starts Comet
   plus its PostgreSQL dependency inside the same gluetun network namespace.
8. Launches the background watchdog and returns to the shell.

### Container restart policy

- `stremio`, `comet`, `comet-postgres`, and `comet-gateway` use `restart: "no"` so Docker does not revive them before the verifier and validation checks have run.
- `gluetun` uses `restart: unless-stopped` so it can recover across host reboots and transient handshake failures.
- `gluetun` tracks the `qmcgaw/gluetun:v3` release channel (not `latest` master builds). Every `./stremio start`/`restart` best-effort pulls the newest v3 release before bringing gluetun up; a failed or slow pull only logs a warning and gluetun boots from the existing local image. A bad release fails closed: the watchdog holds all services down until gluetun is healthy and the IP check passes, and rolling back is re-pinning one line in `docker-compose.yml`.

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
  Normal day-to-day entry point. If no Compose instance exists yet, it performs the safe first start automatically, then launches the watchdog in the background and returns to the shell. When `COMET_ENABLED=1`, it also prepares and starts Comet automatically.

- `./stremio restart`
  Reset/build/start flow. Runs `docker compose down --remove-orphans`, brings gluetun back up, rebuilds the local Stremio image, and starts Stremio again. When `COMET_ENABLED=1`, it also refreshes Comet runtime files and restarts Comet. It does not delete `stremio-data/`, `gluetun-data/`, or `.stremio/comet/`.

- `./stremio stop`
  Stops the watchdog first, then stops Stremio and Comet when enabled, so the background guard does not immediately start them back up again.

- `./stremio status`
  Shows gluetun health, the current public IP as seen from inside gluetun, and the Stremio container status. When `COMET_ENABLED=1`, it also shows Comet status and its observed network mode.

- `./stremio logs`
  Tails the latest host-side run log.

- `./stremio check`
  Runs the local development checks for the Python tooling in this repo.

### Logging and watchdog behavior

Each `./stremio start` creates a host-side run log under `logs/`, named like `logs/stremio-20260424-221500.log`. The startup command and background watchdog share that file, so one run captures gluetun health checks, public IP observations, container lifecycle events, drops, and periodic watchdog summaries.

Use `./stremio logs` to tail the latest run log. The background watchdog writes its PID to `.stremio/watchdog.pid`. `./stremio stop` stops the watchdog before stopping Stremio so it will not immediately restart the container.

The watchdog polls gluetun health and the egress IP every 10 seconds by default. Tune with `WATCH_INTERVAL_SECONDS=5 ./stremio start` for faster checks, or a larger value for less polling.

Additional watchdog parameters:
- `PUBLIC_IP_FAILURE_THRESHOLD`: The number of consecutive failed public IP checks (returning `UNKNOWN` status) before the watchdog shuts down the stack to fail closed (default: `3`).
- `IP_CROSSCHECK_INTERVAL_SECONDS`: The interval in seconds at which the watchdog cross-checks the Gluetun control server IP against external public IP providers (default: `300`).

Log summaries are decoupled from the poll cadence and default to every 5 minutes. Tune them with `WATCHDOG_LOG_INTERVAL_SECONDS=300 ./stremio start`. After changing either interval, restart with `./stremio stop` and `./stremio start`.

On a bad signal, the watchdog fails closed:

- gluetun unhealthy
- public IP check unsafe

In either case, it stops Stremio and waits for the next tick. There is no manual reconnect loop: gluetun's `restart: unless-stopped` policy reconnects the VPN tunnel on its own, and the watchdog starts Stremio again once gluetun reports healthy and the IP check passes.

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
  Comma-separated host interfaces for gluetun's published Stremio port. Use a LAN IP plus a Tailscale IP, such as `10.168.77.10,100.125.26.36`, for Tier 1 LAN + Tailscale access without binding on every interface. Set it empty to publish no host port, or use `0.0.0.0` only when you intentionally want every interface.

If you change `STREMIO_APPLY_PATCHES` after the image has already been built, run `./stremio restart` so Docker rebuilds the image with the new build arg.

### Python runtime

The wrapper runs the Python guard through `uv`, so Typer, Loguru, and the rest of the Python environment come from `uv.lock` instead of global `pip` packages.

It performs best-effort dependency setup on apt-based WSL systems and can attempt to install `uv` and Docker if missing. Set `INSTALL_MISSING_DEPS=0` to disable automatic package installation attempts.

## Leak baseline

For an extra check, while gluetun is stopped (or has not been brought up yet) and you are on your normal home connection, run:

```bash
./stremio record-home-ip
```

This saves your non-VPN public IP to `.stremio/home-ip`. Later, the guard refuses to run Stremio if the egress IP observed via gluetun matches that baseline. The command refuses to run while gluetun is healthy, since that would record a VPN IP as home.

If your VPN endpoint has a stable IP, you can make the check stricter:

```bash
EXPECTED_VPN_IP=1.2.3.4 ./stremio start
```

## Start automatically (Persistent Boot Setup)

To ensure that your entire StremioGuard stack (including the VPN container, Comet gateway, Comet, and the watchdog) automatically boots up upon system restart, choose one of the two standard persistence methods below:

### Option A: The Cron `@reboot` Method (Simplest & Recommended for general use)
This is the most straightforward, zero-configuration method. It does not require root (`sudo`) access, has no complex unit files, and completely avoids D-Bus session errors.

1. Open your user's cron scheduler:
   ```bash
   crontab -e
   ```
2. Add the following line at the very bottom of the file (replacing `/path/to/StremioGuard` with the absolute path to your cloned repository):
   ```text
   @reboot /path/to/StremioGuard/stremio start
   ```

---

### Option B: System-Wide Systemd Service (Most Robust / Production-Grade)
For advanced deployments where you want **automatic crash recovery** (restarts StremioGuard if it crashes) and native log management via `journalctl`. By registering it as a system-wide service that runs under your user account, we avoid any D-Bus/user-session complications.

1. Create the service definition file `/etc/systemd/system/stremio-guard.service` (replacing `<username>` with your local Linux username and `/path/to/StremioGuard` with the absolute path to your cloned repository):
   ```ini
   [Unit]
   Description=Guard Stremio behind the gluetun VPN container
   After=docker.service
   Requires=docker.service

   [Service]
   Type=forking
   User=<username>
   WorkingDirectory=/path/to/StremioGuard
   ExecStart=/path/to/StremioGuard/stremio start
   ExecStop=/path/to/StremioGuard/stremio stop
   PIDFile=/path/to/StremioGuard/.stremio/watchdog.pid
   Restart=always
   RestartSec=10
   RestartPreventExitStatus=78

   [Install]
   WantedBy=multi-user.target
   ```
2. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now stremio-guard.service
   ```
3. Monitor your service:
   ```bash
   # Check status and process tree
   sudo systemctl status stremio-guard.service

   # View active logs in real-time
   journalctl -u stremio-guard.service -f
   ```

## Tests

The guard is written to be testable without calling gluetun or Docker directly:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run pyright
./stremio check
```

## Security notes

The primary kill switch is **gluetun's in-kernel firewall** (`FIREWALL=on`). With `network_mode: service:gluetun`, Stremio has no other network egress: if the VPN tunnel is down, gluetun's iptables rules drop everything that does not exit through the tunnel, and Stremio simply has no internet. The Python verifier is layer 2 — it catches the cases where gluetun is up but unhealthy, where the egress IP unexpectedly matches your home IP, or where an `EXPECTED_VPN_IP` constraint fails.

Defense-in-depth notes:

- LAN discovery for Stremio (e.g., Chromecast, DLNA) is blocked by default. Set `FIREWALL_OUTBOUND_SUBNETS=192.168.x.0/24` in `.env` to allow your specific LAN range.
- The host-level WSL connection itself is no longer routed through any VPN by default. Anything outside this Docker setup uses your home connection. Choose split tunneling at the WSL/Windows layer if you want broader coverage.
- `WIREGUARD_PRIVATE_KEY` in `.env` is sensitive. The repo's `.gitignore` excludes `.env`; double-check before sharing dotfiles or backups.
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
