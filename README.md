# StremioGuard

Self-hosted debrid streaming that cannot leak. StremioGuard runs [Comet](https://github.com/g0ldyy/comet)
(and, optionally, the Stremio streaming server) inside a [gluetun](https://github.com/qdm12/gluetun)
VPN container's network namespace on a Linux host. The VPN's kernel firewall is the kill switch,
and a watchdog supervised by systemd proves the tunnel continuously. The moment it cannot, every
service stops, and nothing restarts until the tunnel is proven again.

## What you get

- **No path around the tunnel.** Every service shares gluetun's network namespace, so anything
  not leaving through the VPN is dropped in the kernel. Docker's own DNS is blocked, and raw
  packet sockets are taken away.
- **A watchdog that fails closed.** It checks gluetun every 10 seconds and re-proves the egress
  IP against your home IP at least every 5 minutes. On a leak or an unprovable verdict it stops
  the services; when trust is lost for good it locks out, and only you can lift a lockout.
- **Comet, hardened.** Its image is pinned by digest, and its patches are validated before an
  update is promoted. Direct-torrent (P2P) streams are removed at Comet's response boundary, so
  every stream plays through debrid. Debrid calls go through a self-hosted
  [StremThru](https://github.com/MunifTanjim/stremthru), and Comet's Postgres requires a
  password on loopback.
- **A token gateway for your users.** Each user installs the addon from `/comet/<token>/…`;
  only addon routes get through, and tokens can be rotated or revoked. URLs carrying credentials
  are masked in the gateway's and Comet's logs, and `./stremio comet log-canary` checks every
  hop, your reverse proxy included.
- **Least privilege.** No container can gain privileges, every service but the VPN drops the
  capabilities it does not need, and Comet, StremThru and the gateway run on read-only
  filesystems. State on the host is private to your user.
- **Hands-off updates.** A daily canary validates every new Comet release against the patches and
  merges it when it passes. Merging never deploys: nothing changes until you run
  `./stremio start`.

## Architecture

```text
Linux host: Docker (rootless recommended) and systemd user services
├── gluetun ··········· VPN tunnel + kernel kill switch; owns the namespace and published ports
│   └── shared network namespace
│       ├── comet-gateway ··· nginx token gate: the address your users and reverse proxy use
│       ├── comet ··········· debrid addon, patched and digest-pinned
│       ├── stremthru ······· self-hosted debrid proxy
│       ├── comet-postgres ·· Comet's cache, loopback only
│       └── stremio ········· optional streaming server
└── systemd user units
    ├── stremioguard-watchdog ··· proves the tunnel, fails closed (exit 78 is a lockout)
    ├── stremioguard-failsafe ··· stops everything if the watchdog fails for good
    └── stremioguard ············ optional: start the stack at boot
```

## Requirements

- Linux with systemd 254 or newer and lingering enabled (`loginctl enable-linger $USER`).
- Docker with the Compose plugin, usable without `sudo`: rootless Docker
  ([notes](docs/rootless-docker.md)) or the `docker` group.
- `/dev/net/tun`.
- A VPN account. NordVPN (WireGuard or OpenVPN) is tested; gluetun's
  [30+ providers](https://github.com/qdm12/gluetun-wiki/tree/main/setup/providers) work by
  changing `VPN_SERVICE_PROVIDER`.

`./stremio` installs [uv](https://docs.astral.sh/uv/) if it is missing. WSL2 works too; see
[setup](docs/setup.md#windows-wsl2).

## Quick start

```bash
./stremio init                                   # guided setup: VPN, access tier, Comet
./stremio start                                  # prove the VPN, start services and the watchdog
./stremio status                                 # tunnel, lockout, services, watchdog
systemctl --user enable stremioguard.service     # optional: start at boot
```

`./stremio start` refuses to start anything while the VPN looks unsafe. Always go through
`./stremio`: a plain `docker compose up` is blocked on purpose.

## Everyday commands

| Command | What it does |
| :-- | :-- |
| `./stremio start` | publishes the current `.env`, proves the VPN, starts services and the watchdog |
| `./stremio stop` | stops the watchdog, then the services |
| `./stremio restart` | resets and rebuilds the stack; also the way out of a lockout |
| `./stremio status` | shows gluetun, the egress IP, any lockout, the services and the watchdog |
| `./stremio logs` | follows the current run log |
| `./stremio unlock` | shows a lockout and clears it, without starting anything |
| `./stremio comet token add\|list\|rotate\|revoke` | manages your users' gateway tokens |
| `./stremio comet update check\|apply\|rollback` | validates and promotes a new Comet image |

Every command, and what a start does step by step: [operations](docs/operations.md).

## Access

| Tier | What is in front | Who can reach it |
| :-- | :-- | :-- |
| 1 | nothing: LAN and Tailscale | LAN devices and tailnet peers |
| 2 | reverse proxy and a domain resolving to a Tailscale address | tailnet peers only; the internet has no route |
| 3 | reverse proxy and a public domain | whatever your proxy allows |

Tier 2 is the recommended way to reach the stack away from home without exposing anything.
Point a reverse proxy at the gateway port (`18001` by default), never at Comet directly. Steps
per tier: [secure access](docs/secure-access.md).

## Documentation

| Read | For |
| :-- | :-- |
| [Setup](docs/setup.md) | `init`, VPN providers, the first run, WSL2 |
| [Watchdog](docs/watchdog.md) | verdicts, lockouts and recovery, systemd supervision, alerts, boot |
| [Comet](docs/comet.md) | sources, patches, pinning and updates, the token gateway |
| [Security model](docs/security-model.md) | the exact egress boundary and every defence layer |
| [All documentation](docs/README.md) | gateway reference, patch notes, Tailscale, the test lab |
| [Changelog](docs/changelogs/README.md) | what changed in each release |

## Development

```bash
uv run pytest && uv run ruff check && uv run ruff format --check && uv run pyright
```

The default suite needs neither Docker nor systemd. The opt-in suites run real containers
(`STREMIOGUARD_DOCKER_TESTS=1`, `tests/*_docker.py` and the integration tests) and real systemd
units (`STREMIOGUARD_SYSTEMD_TESTS=1`), always under throwaway names. [The lab](docs/lab.md)
tests the gateway and the patches against real containers.

## License

[GNU General Public License v3.0](LICENSE).
