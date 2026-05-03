# Secure access: deployment tiers

The repo's job is the **Stremio side** of inbound access — `STREMIO_BIND_ADDRS`,
`STREMIO_HOST_PORT`, and optionally `EXTERNAL_BASE_URL`. Everything else
(domain registration, DNS, certs, reverse proxy installation, network topology)
is your pre-existing infrastructure. This doc lists three tiers, what each tier
assumes you have already, and what you set in `.env` for each.

The Stremio-side config is intentionally small. Tiers differ mainly in what's
in front of Stremio.

| Tier | What's in front of Stremio | `EXTERNAL_BASE_URL` |
|------|----------------------------|---------------------|
| 1 | Nothing — direct LAN/Tailscale access | empty |
| 2 | Reverse proxy, domain only routable via your tailnet | `https://<your-domain>` |
| 3 | Reverse proxy, publicly routable domain | `https://<your-domain>` |

`STREMIO_BIND_ADDRS` controls which host interfaces publish Stremio. Use one
address for a single entry path, or a comma-separated LAN + Tailscale pair for
direct access on both networks.

## Tier 1 — LAN + Tailscale only

You already have:
- This host on a LAN.
- (Optional) Tailscale running on this host so off-LAN clients on your tailnet
  reach the host's `100.x.y.z` address.

You set in `.env`:

```ini
STREMIO_HOST_PORT=11470
STREMIO_BIND_ADDRS=<host-LAN-IP>,<host-tailscale-IP>
EXTERNAL_BASE_URL=
```

Clients reach Stremio:
- LAN device → `http://<host-LAN-IP>:11470`
- Tailscale device anywhere → `http://<host-tailscale-IP>:11470`
  (`tailscale ip -4` on this host)

Trust boundary: every device on the LAN can hit `:11470`. A compromised IoT
device on the same `192.168.x.0/24` reaches Stremio. That's what binding on
the LAN NIC means; if you don't accept it, Tier 1 isn't for you.

## Tier 2 — Tier 1 + reverse-proxied domain (tailnet-only)

Tier 1 plus a friendly hostname. The domain resolves publicly but routes only
through your tailnet — open internet sees no Stremio.

You already have:
- A domain you own.
- A reverse proxy of your choice (Nginx Proxy Manager, Caddy, Traefik, raw
  nginx — anywhere that can reach the LAN). It must do TLS termination and
  IP-based access control.
- A DNS provider that lets you point the A record at a Tailscale CGNAT IP
  (`100.x.y.z`). Cloudflare works; the record must be DNS-only (gray cloud),
  never proxied.
- A TLS cert. The A record points at a CGNAT IP, so public port 80 is
  unreachable; HTTP-01 won't work. Use DNS-01 (NPM's DNS challenge,
  `certbot --dns-cloudflare`, `acme.sh --dns dns_cf`).
- A scoped DNS API token: `Zone.DNS / Edit` for the one zone. Never a Global
  API Key.

You set in `.env`:

```ini
STREMIO_HOST_PORT=11470
STREMIO_BIND_ADDRS=<host-LAN-IP>
EXTERNAL_BASE_URL=https://<your-domain>
```

On your reverse proxy:
- Upstream → `<host-LAN-IP>:11470`.
- Access list / IP allow: `100.64.0.0/10` (Tailscale CGNAT range) and your
  LAN CIDR (`192.168.x.0/24`, `10.x.y.z/24`, whatever it is). Deny everything
  else.
- Streaming-friendly proxy directives (Stremio uses Range and long-lived
  bodies):
  ```nginx
  proxy_buffering         off;
  proxy_request_buffering off;
  proxy_read_timeout      1h;
  ```
  In NPM this lives under the proxy host's **Advanced** tab.
- Websockets enabled.

Two enforcement layers stack here:

- **L3** — Cloudflare A record is `100.x.y.z`. Public internet has no route to
  the host. The home WAN port is never opened. Primary kill switch.
- **L7** — Reverse proxy access list. Catches bare-IP scans that bypass DNS,
  and any future proxy host added without an access list. Defense in depth.

Clients reach Stremio:
- Tailnet device anywhere → `https://<your-domain>` (DNS resolves to CGNAT,
  tailnet carries the connection).
- LAN device with Tailscale → same.
- LAN device without Tailscale → run Tailscale on the device, or set up a
  local DNS rewrite (Pi-hole, AdGuard, router) that returns the proxy host's
  LAN IP for `<your-domain>` on-LAN. Repo doesn't enforce either.
- LAN device → `http://<host-LAN-IP>:11470` (Tier 1 path; still works).
- Open internet → DNS resolves to an unroutable CGNAT IP. Nothing reaches.

### TLS handshake caveat

L7 access lists run *after* the TLS handshake. Anyone scanning the proxy's IP
on 443 completes the handshake (sees the cert) before getting a 403. The L3
layer — the Cloudflare → CGNAT pivot — is what actually closes L4 for clients
who only know the domain.

## Tier 3 — Reverse-proxied with a publicly-routable domain

Same Stremio-side config as Tier 2. The difference is your side: the A record
points at your real public IP and the WAN port is open.

You already have:
- All of Tier 2, except the A record is publicly routable.
- A way to authenticate, rate-limit, or otherwise gate the proxy on the public
  side. The L3 isolation Tier 2 relies on is gone.

You set in `.env`:

```ini
STREMIO_HOST_PORT=11470
STREMIO_BIND_ADDRS=<host-LAN-IP>
EXTERNAL_BASE_URL=https://<your-domain>
```

Stremio's streaming server has no built-in auth. Whatever your proxy applies
(Authentik / Authelia via OIDC, basic auth, mTLS, IP allowlist, WAF rules) is
the only gate on the public side. Note: OIDC and CORS do not work for native
mobile Stremio — they assume a browser. Design accordingly.

## Switching tiers

`./stremio init` is idempotent — rerun it and pick a different tier to
overwrite `.env`. Going from Tier 2 back to Tier 1 just clears
`EXTERNAL_BASE_URL`; init handles that for you.

## Verification

After bringing the stack up (`./stremio restart`):

1. **Bind matches `.env`** (any tier):
   ```bash
   ss -tlnp | grep 11470
   ```
   The listener addresses should match `STREMIO_BIND_ADDRS`. If it shows only
   `127.0.0.1`, `.env` is missing `STREMIO_BIND_ADDRS` or the guard-generated
   compose override was not used. If it shows `0.0.0.0` and you didn't pick
   that, init wrote the wrong value.

2. **LAN-direct reachability** (any tier):
   ```bash
   curl -v http://<host-LAN-IP>:11470/stats.json
   ```
   200 with a JSON body. Run from a LAN device, not from this host's
   loopback.

3. **Tier 2 / 3 — domain reachability**:
   ```bash
   curl -v https://<your-domain>/stats.json
   ```
   - Tier 2 from a tailnet client → 200. From a non-tailnet client (cellular,
     no Tailscale) → connection times out. That timeout is the L3 layer
     working.
   - Tier 3 from any client → 200, gated by whatever your proxy applies.

4. **Tier 2 — proxy is the L7 gate** (proves the access list does work):
   - Temporarily detach the access list on the proxy host (NPM: set Access
     List to "Publicly Accessible").
   - Retry from a non-tailnet client. It should now load — confirming the
     access list, not L3 alone, is the gate.
   - Reattach the access list. Same client → 403.

5. **Tier 2 / 3 — DNS-01 renewal works**:
   - NPM: SSL Certificates → cert → ⋮ → Renew Now. Expiry advances ~90 days.
   - certbot: `certbot renew --dry-run`.
   - acme.sh: `acme.sh --renew -d <your-domain> --force`.
   Renewal must succeed before you trust auto-renew. HTTP-01 stops working
   the moment public port 80 is unreachable.

## Risks and gotchas

- **Loopback bind makes Stremio unreachable.** No real deployment tier uses
  `STREMIO_BIND_ADDRS=127.0.0.1`. The default is loopback purely as a fail-safe
  so an unconfigured run cannot accidentally expose anything before you run
  `./stremio init`. Init steers you away from it.
- **`0.0.0.0` is wider than you need.** It binds on every interface — LAN,
  loopback, docker0, tailscale0, future bridges. Picking the specific LAN IP
  is one rung tighter. Use `0.0.0.0` only on multi-homed hosts where every
  NIC genuinely needs to listen.
- **WSL2 LAN reachability.** On WSL2, even with the right `STREMIO_BIND_ADDRS`,
  whether the Windows LAN actually reaches the WSL2 VM depends on the WSL2
  network mode. Default NAT may need
  `netsh portproxy v4tov4 listenport=11470 connectport=11470 connectaddress=<wsl-vm-ip>`
  on the Windows host. WSL2 `mirrored` networking removes the hop but is
  opt-in via `~/.wslconfig`.
- **Cloudflare CGNAT-IP records require proxy off** (Tier 2). With proxy on
  (orange cloud), Cloudflare won't route to a `100.x.y.z` IP and may strip
  the record. Must be DNS-only.
- **Cert break window** (Tier 2 / 3 migration). Migrate from HTTP-01 to
  DNS-01 *before* you point the A record at a CGNAT IP and close public port
  80. Verify a renewal works first; otherwise the cert expires silently.
- **Tailscale outage** (Tier 2). Tailnet down → all domain access stops.
  Tier 1 paths (`http://<host-LAN-IP>:11470` direct, LAN clients with
  split-horizon DNS) still work. Tier 1 alone is unaffected.
- **Default Site fingerprinting.** Reverse proxies that fall back to a
  default vhost (NPM does) leak their identity to unmatched-hostname probes.
  Set the default to a 404 page or a closed connection.
- **API token scope.** DNS-01 needs only `Zone.DNS / Edit` on the one zone.
  Never use a Global API Key.
- **Stremio has no built-in auth.** All gating happens before Stremio. If
  you skip access control on a Tier 3 proxy, the streaming server is open.
