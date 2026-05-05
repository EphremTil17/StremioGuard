# Tailscale runbook

This runbook covers the tailnet-friendly shape for the unified StremioGuard
stack: Stremio and optional Comet both publish on the same host interfaces,
and Tailscale Serve provides the HTTPS browser-facing URLs when you want
MagicDNS names instead of raw `100.x.y.z` addresses.

## Prerequisites

- Tailscale is installed on the Linux host and connected to your tailnet.
- MagicDNS is enabled tailnet-wide.
- The client device you test from is also on the same tailnet.
- `./stremio init` or the root `.env` already sets:
  - `STREMIO_BIND_ADDRS=<host-LAN-IP>,<host-tailscale-IP>` or a single chosen address
  - `STREMIO_HOST_PORT=11470`
  - `COMET_ENABLED=1` and `COMET_HOST_PORT=18000` if Comet is in use

Quick checks:

```bash
tailscale status --self
tailscale dns status
tailscale ip -4
```

You want `MagicDNS: enabled tailnet-wide` in `tailscale dns status`.

## Raw service ports vs HTTPS

Important rule:

- Raw Stremio and Comet service ports are plain HTTP.
- Tailscale Serve is what gives you an HTTPS `*.ts.net` URL.

That means:

- `http://<tailscale-ip>:11470` is valid for Stremio
- `http://<tailscale-ip>:18000` is valid for Comet
- `https://<tailscale-ip>:11470` is wrong and usually fails with TLS
  `wrong version number`

If you want HTTPS with a MagicDNS hostname, use Tailscale Serve.

## Recommended Serve layout

If `443` is already occupied, use alternate HTTPS ports. A working pattern is:

- Stremio on `10000`
- Comet on `8443`

Example:

```bash
sudo tailscale serve --bg --https=10000 http://<host-tailscale-ip>:11470
sudo tailscale serve --bg --https=8443  http://<host-tailscale-ip>:18000
tailscale serve status
```

Expected output shape:

```text
https://<host>.<tailnet>.ts.net:10000
|-- / proxy http://<host-tailscale-ip>:11470

https://<host>.<tailnet>.ts.net:8443
|-- / proxy http://<host-tailscale-ip>:18000
```

Do not point Serve at `127.0.0.1` unless the service is actually bound there.
In this stack, Stremio and Comet normally bind only on the selected LAN and/or
Tailscale addresses, not on loopback.

## Stremio browser/open-in-app flow

If you want a browser-friendly Stremio URL over Tailscale Serve:

1. Expose Stremio with Tailscale Serve.
2. Set `EXTERNAL_BASE_URL=https://<host>.<tailnet>.ts.net:<stremio-serve-port>`
3. Restart the stack:

```bash
./stremio restart
```

Then opening the Serve URL should redirect to the Stremio web shell with a
`streamingServer=` value that matches the HTTPS Serve origin, not the raw HTTP
backend port.

## Comet configure/install flow

1. Expose Comet with Tailscale Serve, for example:

```bash
sudo tailscale serve --bg --https=8443 http://<host-tailscale-ip>:18000
```

2. Open:

```text
https://<host>.<tailnet>.ts.net:8443/configure
```

3. If configure-page protection is enabled, sign in with the Comet configure
   password from your setup flow or root `.env`.
4. Set your addon options.
5. If you want proxy playback, the configure-page field
   `debridStreamProxyPassword` must match the server-side
   `PROXY_DEBRID_STREAM_PASSWORD` in `.stremio/comet/.env`.
6. Install the generated addon into the Stremio account used by your client
   devices.

## Validation steps

Basic health:

```bash
./stremio status
./stremio comet status
./stremio comet doctor
```

Proxy-path proof:

```bash
./stremio comet probe-playback --url 'https://<host>.<tailnet>.ts.net:8443/.../playback/...'
```

You want the probe to report `proxied`, not `redirected`.

VPN egress proof:

```bash
docker exec gluetun wget -qO- https://api.ipify.org
docker exec comet   wget -qO- https://api.ipify.org
```

Those IPs should match when Comet is correctly sharing `gluetun`.

## Common failures

### `DNS_PROBE_FINISHED_NXDOMAIN`

Cause:

- MagicDNS is disabled or the client is not actually on the tailnet.

Checks:

```bash
tailscale dns status
tailscale status --self
```

### TLS `wrong version number`

Cause:

- You used `https://` directly on a raw HTTP service port such as `11470` or `18000`.

Fix:

- Use `http://<tailscale-ip>:<port>` for raw ports, or put that port behind
  Tailscale Serve and use the Serve HTTPS port instead.

### TLS `unrecognized name`

Cause:

- HTTPS was requested on a hostname/port combination Tailscale Serve was not
  actually serving yet, or the wrong port was chosen.

Fix:

- Re-check `tailscale serve status`
- Re-check that the HTTPS port is not already occupied by another service

### HTTP `502` from Tailscale Serve

Cause:

- Serve is proxying to the wrong backend target, usually `127.0.0.1` when the
  service is only bound on the LAN/Tailscale IP.

Fix:

- Point Serve at the real bound address, such as:

```bash
sudo tailscale serve --bg --https=8443 http://<host-tailscale-ip>:18000
```

### Configure page opens without a password prompt

Cause:

- You already have a valid Comet `configure_session` cookie.

Fix:

- Use a private/incognito window or clear cookies for the Serve hostname.

### `Debrid Stream Proxy Password incorrect. Streams will not be proxied.`

Cause:

- The addon config field `debridStreamProxyPassword` does not match the
  server-side `PROXY_DEBRID_STREAM_PASSWORD`.

Fix:

- Copy the exact proxy password from `.stremio/comet/.env`
- Reconfigure the addon and reinstall/update it

## Notes

- Tailscale Serve remains a host-level concern in this repo. The CLI does not
  automate it.
- The unified stack manages Docker, gluetun, Stremio, and Comet. Tailscale
  itself still lives outside that boundary.
