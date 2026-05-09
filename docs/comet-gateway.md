# Token-Managed Comet Gateway

The Comet gateway is the public access boundary for shared addon use. Stremio
itself is no longer the authorization layer; users can keep their own Stremio
accounts while all Comet stream discovery and playback stays behind a short
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

## Tradeoffs

This is a pragmatic small-scale access model. Tokens in URLs are easy to share
and revoke, but they are not a full identity platform. If a token leaks, rotate
or revoke it.
