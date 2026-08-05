# Token-Managed Comet Gateway

The Comet gateway is the public access boundary for shared addon use. Stremio
itself is no longer the authorization layer; users can keep their own Stremio
accounts while all Comet stream discovery and playback stays behind a bearer
gateway token.

## URL Model

Management stays canonical and simple:

```text
https://comet.example.com/configure
```

That page is protected by Comet's configure password.

Addon install/query/playback routes must use the gateway prefix:

```text
https://comet.example.com/comet/<token>/<config>/manifest.json
https://comet.example.com/comet/<token>/<config>/stream/...
https://comet.example.com/comet/<token>/<config>/playback/...
```

Direct public addon paths are blocked by the gateway:

```text
https://comet.example.com/manifest.json
https://comet.example.com/<config>/manifest.json
https://comet.example.com/stream/...
https://comet.example.com/<config>/stream/...
https://comet.example.com/playback/...
https://comet.example.com/<config>/playback/...
https://comet.example.com/debrid-sync/...
```

## Why This Exists

The important privacy goal is not "host a public Stremio account." The important
goal is that TorBox and other debrid providers only see the server/VPN IP while
authorized users can still install and use the Comet addon.

The gateway helps by:

- requiring a valid token before manifest, stream, playback, or debrid-sync
  routes reach Comet
- clearing client IP headers before forwarding to Comet
- keeping Comet, Postgres, and Stremio in the gluetun network namespace
- publishing raw Comet only on `127.0.0.1:COMET_HOST_PORT` for local operator
  diagnostics

## Setup

Enable Comet and the gateway in `.env`:

```env
COMET_ENABLED=1
COMET_HOST_PORT=18000
COMET_GATEWAY_ENABLED=1
COMET_GATEWAY_HOST_PORT=18001
COMET_GATEWAY_PUBLIC_BASE_URL=https://comet.example.com
COMET_GATEWAY_TOKEN_LENGTH=8
# Alternatively, leave COMET_GATEWAY_PUBLIC_BASE_URL blank/empty to enable dynamic relative
# path resolution. The gateway and configure page will automatically resolve endpoints
# using the client browser's request window location host origin at runtime.
```

Create a shared token:

```bash
./stremio comet token add "Shared Addon"
```

The first token becomes the default token used by Comet's configure-page
copy/install buttons. You can switch the default later:

```bash
./stremio comet token use <id>
```

Treat the token like a password: anyone who has it can use the corresponding
addon path. Keep the default length or increase it; do not lower
`COMET_GATEWAY_TOKEN_LENGTH` for an internet-facing deployment. Tokens do not
expire automatically, so rotate or revoke them when a device/user no longer
needs access.


## Reverse Proxy

Point the public Comet domain to the gateway port, not the raw Comet port:

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

Replace `<SERVERIP:18001>` with the host address and
`COMET_GATEWAY_HOST_PORT` your reverse proxy can reach.

The gateway trusts the origin information the proxy supplies to construct
secure cookies and playback URLs. Do both of the following:

- restrict `COMET_GATEWAY_HOST_PORT` at the host firewall/security group so
  only the reverse proxy, LAN, or tailnet can reach it as intended;
- overwrite `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto` at the proxy.
  Do not pass client-supplied forwarded headers through unchanged.


If your proxy terminates HTTPS before forwarding to the gateway, make sure
`X-Forwarded-Proto` reaches the gateway as `https`. Nginx Proxy Manager usually
does this automatically, but custom location blocks should keep the header
explicit so Comet playback URLs stay on the public HTTPS origin.

## Token Commands

```bash
./stremio comet token add "Shared Addon"
./stremio comet token list
./stremio comet token rotate <id>
./stremio comet token revoke <id>
./stremio comet token use <id>
./stremio comet token url <id> --manifest <url>
```

The `url` command rewrites an existing Comet manifest URL to use another token.
That is the intended per-user token workflow.

## Verification

After `./stremio start`, useful checks are:

```bash
curl -i https://comet.example.com/manifest.json
curl -i https://comet.example.com/badtoken/manifest.json
curl -i https://comet.example.com/comet/<token>/<config>/manifest.json
./stremio comet gateway-logs
./stremio comet doctor
```

Expected results:

- direct public manifest/stream/playback paths return `403`
- invalid or missing gateway tokens return `403`
- valid gateway paths proxy to Comet
- `./stremio comet doctor` confirms Comet shares gluetun and egresses through
  the VPN

## Rate Limiting and Log Hygiene

The generated nginx config rate-limits abuse paths without ever throttling
authenticated playback:

- Requests carrying an invalid gateway token are rewritten to an internal
  location that rejects them in the access phase, rate-limited per client IP
  (5 r/s, burst 10). Valid tokens never enter that location, so bursty range
  requests during seeks are unaffected.
- Human-paced pages (`/configure`, `/static/`, `/health`, `/admin`, and the
  root page) are limited per client IP at 10 r/s (burst 20), which throttles
  configure-password brute force.
- Everything else falls through to a `403` limited at 5 r/s (burst 3).

Access logs record a masked request line: the entire path after `/comet/` —
the token and the base64 config blob after it, which can embed debrid API
keys — is replaced with `***`, so neither secret ever lands in `access.log`.

This applies to the generated gateway log only. Configure your external reverse
proxy to redact or avoid logging `/comet/` request paths too; it sees the token
and configuration blob before the request reaches the gateway.

## Tradeoffs

This is a pragmatic small-scale access model. Tokens in URLs are easy to share
and revoke, but they are not a full identity platform. If a token leaks, rotate
or revoke it.
