# Secure Access: Deployment Tiers

StremioGuard controls the container-side bind surface (`STREMIO_BIND_ADDRS`, `STREMIO_HOST_PORT`, `COMET_GATEWAY_HOST_PORT`, and `EXTERNAL_BASE_URL` / `COMET_GATEWAY_PUBLIC_BASE_URL`). DNS, certificates, and any external reverse proxy live on your host infrastructure.

| Tier | What is in front | `EXTERNAL_BASE_URL` (Stremio) | Who can reach it |
| :--- | :--- | :--- | :--- |
| 1 | Nothing (LAN / Tailscale, or Tailscale Serve) | empty (or `https://<node>.<tailnet>.ts.net:<port>` for Serve) | LAN devices + tailnet peers |
| 2 | Reverse proxy + domain resolving to a Tailscale CGNAT IP (`100.x.y.z`) | `https://<your-domain>` | Tailnet peers only (open internet has no route) |
| 3 | Reverse proxy + publicly routable domain | `https://<your-domain>` | Whatever your proxy / gateway allows |

> **Comet vs. Stremio:** For remote or shared addon access, expose **Comet's token gateway** (`COMET_GATEWAY_HOST_PORT`, default `18001`) instead of Stremio, and follow [comet-gateway.md](comet-gateway.md) for its reverse-proxy headers, body cap, and log redaction.

---

## Tier 1 — LAN + Tailscale

Set in `.env`:

```ini
STREMIO_HOST_PORT=11470
STREMIO_BIND_ADDRS=<host-LAN-IP>,<host-tailscale-IP>
EXTERNAL_BASE_URL=
```

- **Stremio auth (required across all tiers):** `./stremio start` requires `STREMIO_USERNAME` and a `STREMIO_PASSWORD` of at least 12 characters. The host port maps to the Stremio image's Basic-Auth nginx (container port `8080`). Give Stremio clients `http://USER:PASSWORD@<host-LAN-IP>:11470`. (`STREMIO_ALLOW_NO_AUTH=1` opts out with a startup warning.)
- **Raw stream gate:** Media players cannot send Basic Auth on raw stream URLs (`/<infohash>/<file>`), so `docker/stremio/gate-raw-streams.js` allows unauthenticated raw stream playback only for torrents already started through an authenticated route (`STREMIO_OPEN_RAW_STREAMS=1` restores upstream behavior).
- **Trust boundary:** Every device on the bound LAN/tailnet can reach the published ports.

### Tailscale Serve (Tier 1)

Raw service ports (`11470` for Stremio, `18001` for Comet gateway) speak plain HTTP. To get HTTPS on a `*.ts.net` MagicDNS hostname without a public domain:

1. Verify MagicDNS is active (`tailscale dns status` → `MagicDNS: enabled tailnet-wide`) and note your Tailscale IP (`tailscale ip -4`).
2. Ensure `STREMIO_BIND_ADDRS` includes `<host-tailscale-IP>` (not loopback-only, unless pointing Serve at `127.0.0.1` for an intentionally loopback-bound port).
3. Proxy HTTPS ports with Tailscale Serve:
   ```bash
   # Optional Stremio server
   sudo tailscale serve --bg --https=10000 http://<host-tailscale-ip>:11470
   # Comet token gateway (never point Serve at raw Comet :18000 for addon users)
   sudo tailscale serve --bg --https=8443  http://<host-tailscale-ip>:18001
   tailscale serve status
   ```
4. Set `EXTERNAL_BASE_URL=https://<host>.<tailnet>.ts.net:10000` (if using Stremio) and/or `COMET_GATEWAY_PUBLIC_BASE_URL=https://<host>.<tailnet>.ts.net:8443`, then run `./stremio restart`.
5. Validate with `./stremio status`, `./stremio comet doctor`, and `./stremio comet probe-playback --url '<playback-url>'` (expect `proxied`). To verify VPN egress inside Comet manually, use its Python (the Comet image has no `wget`):
   ```bash
   docker exec stremioguard-comet-1 /app/.venv/bin/python -c "import urllib.request; print(urllib.request.urlopen('https://api.ipify.org').read().decode())"
   ```

---

## Tier 2 — Reverse-Proxied Domain (Tailnet-Only)

Recommended for off-LAN access without opening a WAN port.

**Prerequisites:**
- A domain whose DNS A record points at your reverse proxy's Tailscale CGNAT IP (`100.x.y.z`), **DNS-only** (gray cloud on Cloudflare; never proxied).
- TLS issued via **DNS-01** (HTTP-01 fails because public port 80 is unreachable) using a single-zone `Zone.DNS / Edit` API token.
- Reverse proxy (Nginx Proxy Manager, Caddy, Traefik, or raw nginx) enforcing an IP allowlist (`100.64.0.0/10` + `<LAN_CIDR>`, deny all).

**In `.env` (Stremio profile):**

```ini
STREMIO_HOST_PORT=11470
STREMIO_BIND_ADDRS=<host-LAN-IP>
EXTERNAL_BASE_URL=https://<your-domain>
```

**On your reverse proxy (Stremio):**
- Upstream → `http://<host-LAN-IP>:11470`, WebSockets enabled.
- Streaming directives (NPM **Advanced** tab):
  ```nginx
  proxy_buffering         off;
  proxy_request_buffering off;
  proxy_read_timeout      1h;
  ```
- For Comet, use the gateway-specific proxy template in [comet-gateway.md](comet-gateway.md#reverse-proxy) (`access_log off;`, `client_max_body_size 64k;`, `$http_host`, cleared client-IP headers).

**Layered enforcement:** L3 isolation (unroutable CGNAT DNS record, no open WAN port) + L7 allowlist at the proxy. Note that L7 rules run *after* the TLS handshake; the CGNAT DNS pivot is what prevents public scanners from reaching port 443 via DNS.

---

## Tier 3 — Reverse-Proxied Public Domain

Same `.env` as Tier 2, except the DNS A record points at a publicly routable IP. Because L3 isolation is gone:

- **For Comet:** Always terminate at `COMET_GATEWAY_HOST_PORT` (`18001`), keep `COMET_GATEWAY_PUBLIC_CONFIGURE=0` (use SSH tunnel or a Cloudflare Access owner portal via `COMET_GATEWAY_CONFIGURE_URL`), enforce NPM log redaction + 64 KB body cap, and verify with `./stremio comet log-canary`.
- **For Stremio:** Keep `STREMIO_USERNAME` / `STREMIO_PASSWORD` enabled and gate the proxy further (WAF / IP allowlist / mTLS). Note that browser-based OIDC gates do not work for native mobile/TV Stremio clients.

Switch tiers at any time by re-running `./stremio init` (idempotent).

---

## Verification

1. **Bind surface:** `ss -tlnp | grep -E '11470|18001'` matches `STREMIO_BIND_ADDRS` (raw Comet `18000` stays `127.0.0.1` when the gateway is enabled).
2. **Stremio auth check (if enabled):**
   ```bash
   curl -i http://<host-LAN-IP>:11470/stats.json                    # expect 401
   curl -i -u USER:PASSWORD http://<host-LAN-IP>:11470/stats.json   # expect 200
   curl -i -u USER:PASSWORD https://<your-domain>/stats.json        # Tier 2: 200 on tailnet, timeout off tailnet
   ```
3. **DNS-01 renewal:** Test renewal (`certbot renew --dry-run`, `acme.sh --renew … --force`, or NPM Renew Now) before closing public port 80.

---

## Raw Nginx Reference (Stremio Only)

> **Do not use this template for Comet.** Comet requires stripping client-IP headers, disabling access logs, and capping bodies at 64 KB — see [comet-gateway.md](comet-gateway.md#reverse-proxy).

This reference server block shows host-native nginx interface pinning + L7 allowlisting for Tier 2/3 Stremio:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    # Pin to private interfaces only — never add `listen 0.0.0.0:443`.
    listen <NGINX_LAN_IP>:443 ssl;
    listen <NGINX_TS_IP>:443 ssl;
    http2 on;
    server_name <SERVER_NAME>;

    ssl_certificate     <CERT_PATH>;
    ssl_certificate_key <KEY_PATH>;

    allow 100.64.0.0/10;
    allow <LAN_CIDR>;
    deny  all;

    proxy_http_version 1.1;
    proxy_set_header   Host              $http_host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_set_header   Upgrade           $http_upgrade;
    proxy_set_header   Connection        $connection_upgrade;

    proxy_buffering         off;
    proxy_request_buffering off;
    proxy_read_timeout      1h;

    location / {
        proxy_pass http://<STREMIO_UPSTREAM>;
    }
}
```

## Common Gotchas

- **Loopback bind (`127.0.0.1`):** Fail-safe default only; unreachable from LAN, Tailscale, or Dockerized reverse proxies.
- **`0.0.0.0` bind:** Exposes the port on every interface (`docker0`, `tailscale0`, LAN). Prefer explicit interface IPs.
- **Host firewall:** Under rootless Docker, published ports enter `INPUT` (see [rootless-docker.md](rootless-docker.md)); allow only your reverse proxy's single pinned IP, and remember Tailscale's `ts-input` bypasses `ufw` unless restricted via Tailscale ACLs.
- **Default vhost fingerprinting:** Set your reverse proxy's unmatched-host default site to `404` or connection close.
- **WSL2:** Default NAT mode may need `netsh portproxy` on Windows, or opt-in `mirrored` networking in `~/.wslconfig`.
