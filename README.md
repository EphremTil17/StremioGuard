# Streamio VPN Guard

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

The default `.env.example` ships with **NordVPN WireGuard** (NordLynx). Switching to any of [gluetun's 30+ supported providers](https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers) — Mullvad, ProtonVPN, Surfshark, ExpressVPN, etc. — is a one-line `VPN_SERVICE_PROVIDER` change in `.env` plus the relevant credentials. Only NordVPN is tested in this repo.

## First-time setup

Run the guided initializer:

```bash
./streamio init
```

This creates `.env` from `.env.example` if needed, offers a couple of optional Stremio toggles up front, drives `nordvpn set technology nordlynx && nordvpn connect`, captures the WireGuard private key via `sudo wg show nordlynx private-key` (sudo prompts on the TTY), runs `nordvpn disconnect`, writes the key into `.env`, and chains into `./streamio start`. Re-running `init` is idempotent: a populated `WIREGUARD_PRIVATE_KEY` skips the extraction step.

Prerequisites the initializer does **not** install for you:

- The NordVPN Linux CLI must be installed and logged in (the modern OAuth/browser-callback flow works). `init` will print a clear pointer if either check fails.
- `wireguard-tools` must be installed so `wg show` is callable: `sudo apt install wireguard-tools` (or your distro's equivalent).
- WSL2 needs `/dev/net/tun`. Modern WSL2 kernels (≥5.6) include it by default. Verify with `ls /dev/net/tun`; if missing, `sudo modprobe tun` enables it for the session.

After `init` succeeds, the host-level NordVPN CLI is no longer needed at runtime; gluetun handles the tunnel itself.

### Manual fallback

If you'd rather skip the guided flow, the equivalent manual steps:

```bash
cp .env.example .env
sudo apt install wireguard-tools
nordvpn set technology nordlynx
nordvpn connect
sudo wg show nordlynx private-key
nordvpn disconnect
```

Paste the printed key into `.env` as `WIREGUARD_PRIVATE_KEY=...`.

## First run

From this directory:

```bash
./streamio
```

The wrapper runs the Python orchestrator through `uv`, creates the project environment from `uv.lock`, ensures `gluetun` is healthy, verifies the egress IP, starts Stremio, and launches the background watchdog.

Minimum host requirements:

- `uv`
- Docker with the Compose plugin
- `/dev/net/tun` available
- A populated `.env` (see [First-time setup](#first-time-setup))

Useful first-run checks:

```bash
./streamio status
./streamio logs
./streamio stop
```

## Recommended workflow

Use the root wrapper as the normal entry point:

```bash
./streamio
```

With no arguments, `./streamio` behaves like `./streamio start`.

### What `./streamio` does

1. Checks that `uv`, `docker`, and `docker compose` are available.
2. Confirms `.env` exists and is populated.
3. Starts `gluetun` and waits for its healthcheck to pass.
4. Probes the public IP from inside gluetun's network namespace.
5. Refuses to continue if the VPN looks unsafe:
   - the IP matches your saved home-IP baseline, or
   - `EXPECTED_VPN_IP` is set and does not match.
6. Starts Stremio inside gluetun's network namespace.
7. Launches the background watchdog and returns to the shell.

### Container restart policy

- `stremio` uses `restart: "no"` so Docker does not revive it before the verifier has run.
- `gluetun` uses `restart: unless-stopped` so it can recover across host reboots and transient handshake failures.

### Useful commands

```bash
./streamio init
./streamio start
./streamio restart
./streamio stop
./streamio status
./streamio logs
./streamio check
```

Command guide:

- `./streamio init`
  Guided first-time setup. Creates `.env` from `.env.example` when needed, collects optional Stremio settings, extracts the NordVPN WireGuard key, writes it into `.env`, and then starts the stack.

- `./streamio start`
  Normal day-to-day entry point. If no Compose instance exists yet, it performs the safe first start automatically, then launches the watchdog in the background and returns to the shell.

- `./streamio restart`
  Reset/build/start flow. Runs `docker compose down --remove-orphans`, brings gluetun back up, rebuilds the local Stremio image, and starts Stremio again. It does not delete `stremio-data/` or `gluetun-data/`.

- `./streamio stop`
  Stops the watchdog first, then stops Stremio, so the background guard does not immediately start it back up again.

- `./streamio status`
  Shows gluetun health, the current public IP as seen from inside gluetun, and the Stremio container status.

- `./streamio logs`
  Tails the latest host-side run log.

- `./streamio check`
  Runs the local development checks for the Python tooling in this repo.

### Logging and watchdog behavior

Each `./streamio start` creates a host-side run log under `logs/`, named like `logs/streamio-20260424-221500.log`. The startup command and background watchdog share that file, so one run captures gluetun health checks, public IP observations, container lifecycle events, drops, and periodic watchdog summaries.

Use `./streamio logs` to tail the latest run log. The background watchdog writes its PID to `.streamio/watchdog.pid`. `./streamio stop` stops the watchdog before stopping Stremio so it will not immediately restart the container.

The watchdog polls gluetun health and the egress IP every 10 seconds by default. Tune with `WATCH_INTERVAL_SECONDS=5 ./streamio start` for faster checks, or a larger value for less polling.

Log summaries are decoupled from the poll cadence and default to every 5 minutes. Tune them with `WATCHDOG_LOG_INTERVAL_SECONDS=300 ./streamio start`. After changing either interval, restart with `./streamio stop` and `./streamio start`.

On a bad signal, the watchdog fails closed:

- gluetun unhealthy
- public IP check unsafe

In either case, it stops Stremio and waits for the next tick. There is no manual reconnect loop: gluetun's `restart: unless-stopped` policy reconnects WireGuard on its own, and the watchdog starts Stremio again once gluetun reports healthy and the IP check passes.

### Stremio patch layer

The local Stremio image is built from `tsaridas/stremio-docker:latest` with a small patch layer.

- `STREMIO_APPLY_PATCHES=1`
  Keeps the compatibility fixes enabled. Turning it off restores upstream image behavior and removes the HTTPS redirect fix, local self-probe rewrite, favicon guard, and `/casting` stub.

- `STREMIO_SKIP_HW_PROBE=1`
  Prevents repeated `/device-info` requests from re-running noisy `qsv`, `nvenc`, and `vaapi` self-tests on every reconnect.

- `EXTERNAL_BASE_URL=https://your-public-domain`
  Keeps browser redirects and client-facing links on your public HTTPS origin.

- `INTERNAL_MEDIA_BASE_URL=http://127.0.0.1:11470`
  Keeps ffprobe and HLS self-references on loopback instead of probing back out through Cloudflare or another reverse proxy.

If you change `STREMIO_APPLY_PATCHES` after the image has already been built, run `./streamio restart` so Docker rebuilds the image with the new build arg.

### Python runtime

The wrapper runs the Python guard through `uv`, so Typer, Loguru, and the rest of the Python environment come from `uv.lock` instead of global `pip` packages.

It performs best-effort dependency setup on apt-based WSL systems and can attempt to install `uv` and Docker if missing. Set `INSTALL_MISSING_DEPS=0` to disable automatic package installation attempts.

## Leak baseline

For an extra check, while gluetun is stopped (or has not been brought up yet) and you are on your normal home connection, run:

```bash
./streamio record-home-ip
```

This saves your non-VPN public IP to `.streamio/home-ip`. Later, the guard refuses to run Stremio if the egress IP observed via gluetun matches that baseline. The command refuses to run while gluetun is healthy, since that would record a VPN IP as home.

If your VPN endpoint has a stable IP, you can make the check stricter:

```bash
EXPECTED_VPN_IP=1.2.3.4 ./streamio start
```

## Start automatically

The included user service can make this feel native. It assumes the repo lives at `~/projects/streamio` (uses systemd's `%h` substitution); if it lives elsewhere, edit `WorkingDirectory` and `ExecStart` paths in the copied unit before enabling.

```bash
mkdir -p ~/.config/systemd/user
cp systemd/user/stremio-vpn-watch.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now stremio-vpn-watch.service
```

Check it with:

```bash
systemctl --user status stremio-vpn-watch.service
journalctl --user -u stremio-vpn-watch.service -f
```

## Tests

The guard is written to be testable without calling gluetun or Docker directly:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run pyright
./streamio check
```

## Security notes

The primary kill switch is **gluetun's in-kernel firewall** (`FIREWALL=on`). With `network_mode: service:gluetun`, Stremio has no other network egress: if WireGuard is down, gluetun's iptables rules drop everything that does not exit through the tunnel, and Stremio simply has no internet. The Python verifier is layer 2 — it catches the cases where gluetun is up but unhealthy, where the egress IP unexpectedly matches your home IP, or where an `EXPECTED_VPN_IP` constraint fails.

Defense-in-depth notes:

- LAN discovery for Stremio (e.g., Chromecast, DLNA) is blocked by default. Set `FIREWALL_OUTBOUND_SUBNETS=192.168.x.0/24` in `.env` to allow your specific LAN range.
- The host-level WSL connection itself is no longer routed through any VPN by default. Anything outside this Docker setup uses your home connection. Choose split tunneling at the WSL/Windows layer if you want broader coverage.
- `WIREGUARD_PRIVATE_KEY` in `.env` is sensitive. The repo's `.gitignore` excludes `.env`; double-check before sharing dotfiles or backups.
- Restarting gluetun mid-session (e.g., `docker compose restart gluetun`) leaves Stremio running but network-isolated until the watchdog's next tick stops it. Expected behavior of the netns-share model.
