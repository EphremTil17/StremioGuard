# Setup

How to install StremioGuard on a Linux host, choose an access tier and configure the VPN.

## VPN provider support

The default `.env.example` ships with **NordVPN** and supports both:

- **WireGuard / NordLynx**: recommended for performance
- **OpenVPN**: supported through NordVPN service credentials

Switching to any of [gluetun's 30+ supported providers](https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers) — Mullvad, ProtonVPN, Surfshark, ExpressVPN, etc. — is still a one-line `VPN_SERVICE_PROVIDER` change in `.env` plus the relevant credentials. Only NordVPN is tested in this repo.

## First-time setup

Before the first run on Linux, make sure these are in place:

- Docker with the Compose plugin installed and working.
- Your Linux user able to talk to Docker without sudo (for example via the `docker` group or rootless Docker). `docker ps` should work before you run `./stremio`.
- `/dev/net/tun` available on the host.
- systemd 254 or newer with a user service manager and lingering enabled for your user (`loginctl enable-linger $USER`). The watchdog runs as a systemd user service; `./stremio start` refuses to start anything without one.
- A VPN provider account and the credentials needed for your chosen setup.

Check that the TUN device exists:

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

- **Tier 1 — LAN + Tailscale only.** No public domain. Init writes `STREMIO_BIND_ADDRS=<host-LAN-IP>,<host-tailscale-IP>` when you choose both addresses and clears `EXTERNAL_BASE_URL`. LAN clients reach Stremio at `http://<host-LAN-IP>:<STREMIO_HOST_PORT>`. Tailnet clients can reach the raw Tailscale IP directly, or use Tailscale Serve HTTPS on the node's `*.ts.net` hostname (see [secure-access.md](secure-access.md#tailscale-serve-tier-1)).
- **Tier 2 / 3 — reverse-proxied behind a domain.** Init writes the selected bind addresses plus `EXTERNAL_BASE_URL=https://<your-domain>`. You provide the proxy (NPM, Caddy, Traefik, raw nginx); it upstreams to one selected host address on `STREMIO_HOST_PORT` and applies whatever access control fits your threat model. Tier 2 is tailnet-only via a Cloudflare → CGNAT DNS pivot; Tier 3 is publicly routable. The Stremio-side config is identical for both.

`init` is idempotent — re-run it to switch tiers. Start the stack through `./stremio` (plain `docker compose up` is intentionally blocked by a compose gate service so Comet never comes up unpinned or unpatched). `./stremio start` generates a local Compose override from `STREMIO_BIND_ADDRS` publishing Stremio's host port along with Comet's image pin and patched files. Ordinary inspection commands such as `docker compose logs -f` and `docker compose ps` still work normally against the base file, and Postgres finds its real data directory either way because that path lives in `docker-compose.yml` rather than in the generated override. See [secure-access.md](secure-access.md) for the full per-tier runbook, threat model, and verification steps.

For NordVPN, `init` offers two protocol paths:

- Recommended: **WireGuard / NordLynx** (for performance and instant handshakes)
- Alternative: **OpenVPN** with NordVPN manual service credentials

If you choose **WireGuard**, `init` allows you to:

- **Generate via NordVPN Access Token (recommended)**: Paste an Access Token from your [Nord Account Dashboard](https://my.nordaccount.com/dashboard/nordvpn/access-tokens/). StremioGuard queries NordVPN's API directly to retrieve your account's permanent WireGuard private key without any host routing changes or sudo requirements.
- **Paste an existing WireGuard private key**: Paste a known 44-character Base64 WireGuard key directly.

If you choose **OpenVPN**, `init` prompts for your NordVPN **service credentials** (from your Nord Account manual setup section) and writes them into `.env`.

The initializer does **not** install these for you:

- `/dev/net/tun` must exist. If `ls /dev/net/tun` finds nothing, `sudo modprobe tun` loads the module; list `tun` in `/etc/modules-load.d/` to load it at every boot.
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

## Windows (WSL2)

Linux is the primary platform. StremioGuard also runs inside a WSL2 distribution if:

- systemd is enabled in the distribution (`[boot]` `systemd=true` in `/etc/wsl.conf`), because the
  watchdog is a systemd user service;
- Docker runs inside the distribution, or Docker Desktop's WSL integration is enabled for it;
- `/dev/net/tun` exists (WSL2 kernels 5.6 and newer include it).

Only the containers go through the VPN: Windows and the rest of the distribution keep using your
home connection.
