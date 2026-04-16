# Streamio VPN Guard

This folder runs Stremio through Docker Compose, with a Python NordVPN guard in front of it.

Your current topology is WSL-specific: the NordVPN CLI changes the WSL/Linux public IP, while the Windows NordVPN app and Windows-side public IP can remain separate. That makes the guard responsible for the WSL/Docker side only.

## Recommended workflow

Start Stremio only through the guard:

```bash
bin/stremio-vpn up --watch
```

That command:

1. checks that `nordvpn`, `docker`, and `docker compose` are available;
2. connects NordVPN with `nordvpn connect --group p2p united_states` when needed;
3. refuses to start if the VPN cannot be verified;
4. starts the `stremio` Compose service;
5. keeps watching and stops Stremio if NordVPN disconnects.

The Compose service intentionally uses `restart: "no"` so Docker does not revive Stremio on its own before the VPN guard has run.

Useful commands:

```bash
bin/stremio-vpn status
bin/stremio-vpn down
bin/stremio-vpn watch
```

## Leak baseline

For an extra check, disconnect NordVPN while on your normal home connection and run:

```bash
bin/stremio-vpn record-home-ip
```

This saves your non-VPN public IP to `.vpn-guard.home-ip`. Later, the guard refuses to run Stremio if the observed public IP matches that baseline.

If your VPN endpoint has a stable IP, you can make the check stricter:

```bash
EXPECTED_VPN_IP=1.2.3.4 bin/stremio-vpn up --watch
```

## Start automatically

The included user service can make this feel native:

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
```

## Security notes

The guard is a strong operational safety check, but the hardest leak prevention is still a network-level kill switch. If NordVPN's firewall/kill switch is disabled for WSL and LAN communication, a brief leak is still theoretically possible between a route change and the watchdog's next check.

Best leak-resistance options, from strongest to most convenient:

1. Run Stremio inside a VPN network namespace/container such as Gluetun, and publish ports only from that VPN container.
2. Add host firewall rules that block Docker bridge egress unless it exits through the VPN interface.
3. Use this NordVPN host watchdog and keep `WATCH_INTERVAL_SECONDS` low.

LAN discovery is usually compatible with a guarded setup, but disabling NordVPN's firewall removes a major layer of protection. Treat the guard as the native day-to-day control and add firewall or VPN-container routing if you want the most robust possible posture.

NordVPN split tunneling may help for normal Linux processes, but Docker containers often egress through bridge/NAT networking rather than a simple app process identity. Do not trust split tunneling for Docker leak prevention until you test the container path directly.
