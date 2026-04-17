# Streamio VPN Guard

This folder runs Stremio through Docker Compose, with a Python NordVPN guard in front of it.

Your current topology is WSL-specific: the NordVPN CLI changes the WSL/Linux public IP, while the Windows NordVPN app and Windows-side public IP can remain separate. That makes the guard responsible for the WSL/Docker side only.

## VPN provider support

The host-level guard currently supports **NordVPN only**. Multi-provider support (ExpressVPN, Mullvad, ProtonVPN, Surfshark, etc.) is planned via a [gluetun](https://github.com/qdm12/gluetun) container migration on a future `gluetun` branch, since gluetun natively handles 30+ providers behind a single config interface.

Please **do not submit PRs adding new providers to the host-level path** — that effort is better directed at the gluetun branch, where adding a provider is typically a one-line `VPN_SERVICE_PROVIDER` env change rather than a new Python integration. PRs in the host-level path that aren't NordVPN-specific bug fixes will likely be redirected.

## First run

From this directory:

```bash
./streamio
```

The wrapper runs the Python orchestrator through `uv`, creates the project environment from `uv.lock`, verifies NordVPN and Docker, starts Stremio, and launches the background watchdog.

Minimum host requirements:

- `uv`
- Docker with the Compose plugin
- NordVPN Linux CLI installed inside WSL and logged in

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

With no arguments, `./streamio` behaves like `./streamio start`. It:

1. checks that `uv`, `nordvpn`, `docker`, and `docker compose` are available;
2. connects NordVPN with `nordvpn connect --group p2p united_states` when needed;
3. refuses to start if the VPN or public IP cannot be verified;
4. detects an empty Compose instance and runs first-time setup automatically;
5. shows the Docker Compose build/start output;
6. starts Stremio;
7. launches a background watchdog and returns to the shell.

The Compose service intentionally uses `restart: "no"` so Docker does not revive Stremio on its own before the VPN guard has run.

Useful commands:

```bash
./streamio start
./streamio restart
./streamio stop
./streamio status
./streamio logs
./streamio check
```

`restart` is the reset/build/start flow for the Compose instance. It runs `docker compose down --remove-orphans`, then `docker compose build stremio`, then `docker compose up -d stremio`. It does not delete `stremio-data/`.

`start` initializes automatically if no Compose instance exists, starts Stremio, launches the watchdog in the background, and returns to the shell.

Each `./streamio start` creates a host-side run log under `logs/`, named like `logs/streamio-20260424-221500.log`. The startup command and background watchdog share that same log file, so one run captures VPN status, public IP observations, container lifecycle events, reconnect attempts, drops, and watchdog health checks. Use `./streamio logs` to tail the latest run log. The background watchdog writes its PID to `.streamio-watchdog.pid`. `./streamio stop` stops the watchdog before stopping Stremio, so it will not immediately restart the container.

The watchdog checks NordVPN and public-IP safety every 10 seconds by default. Tune that with `WATCH_INTERVAL_SECONDS=5 ./streamio start` if you want faster checks, or a larger value if you prefer less polling. After changing the interval, restart the background watchdog with `./streamio stop` and `./streamio start`.

On a bad VPN signal, the watchdog fails closed first: it stops Stremio before trying to reconnect. It then tries `nordvpn connect --group p2p united_states` up to five times, waiting five seconds between attempts. Stremio is restarted only after NordVPN reports connected and the public-IP safety check passes. Tune this with `RECONNECT_ATTEMPTS=3` and `RECONNECT_BACKOFF_SECONDS=10`.

The wrapper runs the Python guard through `uv`, so Typer, Loguru, and the rest of the Python environment come from `uv.lock` instead of global `pip` packages. It performs best-effort dependency setup on apt-based WSL systems. It can attempt to install `uv` and ask the Python guard to install Docker if missing. NordVPN still needs the Linux CLI installed and logged in first because that depends on NordVPN's account/client flow. Set `INSTALL_MISSING_DEPS=0` to disable automatic package installation attempts.

## Leak baseline

For an extra check, disconnect NordVPN while on your normal home connection and run:

```bash
./streamio record-home-ip
```

This saves your non-VPN public IP to `.vpn-guard.home-ip`. Later, the guard refuses to run Stremio if the observed public IP matches that baseline.

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

The guard is written to be testable without calling NordVPN or Docker directly:

```bash
python3 -m unittest discover -s tests
uv run pytest
uv run ruff check
uv run ruff format --check
uv run pyright
./streamio check
```

## Security notes

The guard is a strong operational safety check, but the hardest leak prevention is still a network-level kill switch. If NordVPN's firewall/kill switch is disabled for WSL and LAN communication, a brief leak is still theoretically possible between a route change and the watchdog's next check.

Best leak-resistance options, from strongest to most convenient:

1. Run Stremio inside a VPN network namespace/container such as Gluetun, and publish ports only from that VPN container.
2. Add host firewall rules that block Docker bridge egress unless it exits through the VPN interface.
3. Use this NordVPN host watchdog and keep `WATCH_INTERVAL_SECONDS` low.

LAN discovery is usually compatible with a guarded setup, but disabling NordVPN's firewall removes a major layer of protection. Treat the guard as the native day-to-day control and add firewall or VPN-container routing if you want the most robust possible posture.

NordVPN split tunneling may help for normal Linux processes, but Docker containers often egress through bridge/NAT networking rather than a simple app process identity. Do not trust split tunneling for Docker leak prevention until you test the container path directly.
