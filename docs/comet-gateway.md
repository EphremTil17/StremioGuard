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

Because StremioGuard requires `CONFIGURE_PAGE_PASSWORD`, Comet mounts all Stremio
addon routes under `STREMIO_API_PREFIX=/s/<PUBLIC_API_TOKEN>`. Addon
install/query/playback routes through the gateway therefore use:

```text
https://comet.example.com/comet/<token>/s/<api>/manifest.json
https://comet.example.com/comet/<token>/s/<api>/<config>/manifest.json
https://comet.example.com/comet/<token>/s/<api>/stream/<type>/<id>.json
https://comet.example.com/comet/<token>/s/<api>/<config>/stream/<type>/<id>.json
https://comet.example.com/comet/<token>/s/<api>/<config>/playback/<hash>/<svc>/<idx>/<season>/<episode>
```

Opening `/comet/<token>` or `/comet/<token>/` answers `302` with a relative
`Location: /comet/<token>/configure` so token-scoped configure pages keep the
token in their install/copy links.

### Allowed and Blocked Routes

Under `/comet/<token>`, the gateway matches tokens byte-for-byte
(case-sensitively) and allows only the Stremio addon routes Comet actually serves
plus the token's configure page, evaluated strictly on the raw `$request_uri`
path (dot segments, empty segments, `%2F`, `%2E`, `%5C`, `\`, `;`, `#`, and
case variants are denied):

| Allowed shape under `/comet/<token>` | Comet route |
| :--- | :--- |
| `/s/<api>/manifest.json`, `/s/<api>/<config>/manifest.json` | Addon manifest |
| `/s/<api>/stream/<seg>/<seg>.json`, `/s/<api>/<config>/stream/<seg>/<seg>.json` | Stream search |
| `/s/<api>/<config>/playback/<seg>/<seg>/<seg>/<seg>/<seg>` (5 segments) | Stream playback |
| `/configure`, `/<config>/configure`, `/s/<api>/configure`, `/s/<api>/<config>/configure` | Configure page |
| `/configure/login` | Configure form login POST target |

Everything else under `/comet/<token>/` (and at top level outside the public
routes `/`, `/configure`, `/configure/...`, `/static/`, `/health`) is denied
with `403` (`503` when rate-limited) and never reaches Comet, including:

- `/s/<api>/<config>/debrid-sync/...`: blocked deliberately. If a user enables
  "scrape debrid account torrents", Comet's "Comet Sync" stream entry points at
  `debrid-sync` and returns `403` through the gateway; Comet's own
  stream-triggered account sync still runs during normal stream searches.
- `/s/<api>/torznab/api`: blocked at the gateway so token holders cannot
  query Comet's Torznab search API.
- `/s/<api>/manifest` and `/s/<api>/streams`: ChillLink routes are not Stremio
  addon routes (`./stremio comet token url` also requires `/manifest.json`).
- `/s/<api>/configure/login`: the configure form posts only to `/configure/login`.
- Unprefixed `/manifest.json`, `/stream/...`, `/playback/...`: Comet does not
  serve unprefixed addon routes when `CONFIGURE_PAGE_PASSWORD` is set.
- `/admin`, `/kodi/...`, `/cometnet/...` (including `/cometnet/ws`), `/metrics`,
  `/docs`, `/openapi.json`, and `/`: administrative, pairing, federation, or
  internal endpoints not needed by Stremio clients.

This Comet release has no `catalog`, `meta`, or `subtitles` routes. If a future
Comet update adds or changes routes, updating the gateway requires a deliberate
allowlist change in `comet_gateway.py` and re-verifying with the opt-in
integration suite (`STREMIOGUARD_DOCKER_TESTS=1 uv run pytest tests/test_gateway_integration.py`)
against the new Comet image digest.

Comet's `/admin` dashboard should be accessed directly via `COMET_HOST_PORT` on
LAN/tailnet rather than through the public gateway. Kodi pairing through the
gateway is unsupported.

## Why This Exists

The important privacy goal is not "host a public Stremio account." The important
goal is that TorBox and other debrid providers only see the server/VPN IP while
authorized users can still install and use the Comet addon.

The gateway helps by:

- requiring an exact, case-sensitive token and an allowlisted Stremio addon
  route before manifest, stream, or playback requests reach Comet
- clearing all 14 client-IP headers from Comet's `IP_PROXY_HEADERS` list
  (`CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `X-Client-IP`,
  `DO-Connecting-IP`, `Fastly-Client-IP`, `X-Cluster-Client-IP`,
  `X-Forwarded-For`, `X-Forwarded`, `Forwarded-For`, `Forwarded`,
  `X-AppEngine-User-IP`, `CF-Pseudo-IPv4`, `X-AIOStreams-User-IP`) and
  overwriting `X-Forwarded-Host` and `X-Forwarded-Prefix` on every proxied
  location so clients cannot steer Comet's client-IP or path-prefix logic
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

The first token becomes the default token used by root `/configure` copy/install
buttons (while `/comet/<token>/configure` preserves that specific token in its
copy/install links). Note that every configure page—including `/comet/<token>/configure`—sits
behind Comet's single shared configure password and embeds the default token for
root `/configure` links, so token separation holds for people who receive a
manifest link without the configure password. You can switch the default later:

```bash
./stremio comet token use <id>
```

Treat the token like a password: anyone who has it can use the corresponding
addon path. Keep the default length or increase it (minimum 8); do not lower
`COMET_GATEWAY_TOKEN_LENGTH` for an internet-facing deployment. Tokens do not
expire automatically, so rotate or revoke them when a device/user no longer
needs access.


## Reverse Proxy

Point the public Comet domain to the gateway port, not the raw Comet port:

```nginx
location / {
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Real-IP "";
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
    proxy_http_version 1.1;
    proxy_pass http://<SERVERIP:18001>$request_uri;
}
```

Replace `<SERVERIP:18001>` with the host address and
`COMET_GATEWAY_HOST_PORT` your reverse proxy can reach.

The gateway validates `Host` at server level (returning `400` if missing or
malformed) and preserves `$http_host` — including any non-default port — as both
`Host` and `X-Forwarded-Host` so Comet playback links keep the port the client
used. When your public URL uses a non-default port, set `proxy_set_header Host
$http_host;` (and `X-Forwarded-Host $http_host;`) on the reverse proxy rather
than `$host`, which strips the port. The gateway trusts the origin information
the proxy supplies to construct secure cookies and playback URLs. Do both of
the following:

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
./stremio comet gateway-reload
```

The `url` command rewrites an existing Comet Stremio manifest URL (ending in
`/manifest.json`) to use another token. That is the intended per-user token
workflow.

Token mutations (`add`, `revoke`, `rotate`, `use`) validate `tokens.json`,
re-render `nginx.conf` and `tokens.map`, and reload the running gateway before
reporting success (exiting non-zero if reload fails or the gateway's state is
unknown). `./stremio start` and `./stremio restart` also re-render `nginx.conf`
and `tokens.map`, verify `nginx -t` and the in-container sha256 of both files,
reload an already-running gateway, and recreate Comet if its mounted patch bundle
is stale (exiting `1` after starting the watchdog if any convergence check fails);
`./stremio comet gateway-reload` runs the checked gateway reload directly.

## Verification

After `./stremio start`, useful checks are:

```bash
curl -i https://comet.example.com/manifest.json
curl -i https://comet.example.com/badtoken/manifest.json
curl -i https://comet.example.com/comet/<token>/s/<api>/<config>/manifest.json
./stremio comet gateway-logs
./stremio comet doctor
./stremio comet log-canary
```

Expected results:

- direct public manifest/stream/playback paths return `403`
- invalid or missing gateway tokens return `403`
- valid gateway paths proxy to Comet
- `./stremio comet doctor` confirms Comet shares gluetun and egresses through
  the VPN
- `./stremio comet log-canary` passes on every sink

## Rate Limiting and Log Hygiene

The generated nginx config rate-limits abuse paths without ever throttling
authenticated playback:

- Requests carrying an invalid gateway token (including case-mismatched or
  percent-encoded tokens) are rewritten to an internal location that rejects
  them in the access phase with `deny all` (`403`), rate-limited by
  `gateway_auth` at 5 r/s (burst 10; excess returns `503`). Behind rootless
  Docker or a reverse proxy, every client arrives from the same address, so each
  limiter shares one bucket rather than limiting per end client IP. Valid tokens
  with allowed routes never enter a limiter, so bursty range requests during
  playback seeks are unaffected.
- Valid-token requests to disallowed routes under `/comet/<token>/...` rewrite
  to an internal access-phase location (`deny all`, `403`) rate-limited by
  `gateway_fail` at 5 r/s (burst 3; excess returns `503`).
- Human-paced public pages (`/configure`, `/static/`, `/health`, and the root
  page) share `gateway_admin` at 10 r/s (burst 20).
- Configure-password guessing has its own, much stricter bucket:
  every `POST` to `/configure/login` or `/comet/<token>/configure/login` draws
  from `gateway_login`, 6 a minute (burst 5; excess returns `503` and never
  reaches Comet). Every other request has an empty key in that zone and is
  never counted, so playback and page loads are unaffected. The bucket is
  shared by every client, so a guesser also slows your own login; a strong
  password matters more than the limit.
- Everything else falls through to `location /` (`deny all`, `403`) limited by
  `gateway_fail` at 5 r/s (burst 3; excess returns `503`).

Access logs record a masked request line: the entire path after `/comet/` —
the token and the base64 config blob after it, which can embed debrid API
keys — is replaced with `***`, any request line containing `%` or `/..`
(traversal or encoded variants) is masked to `***`, and query strings on
`/configure`, `/static/`, `/health`, and `/` are stripped so tokens, configs,
and secrets are not recorded in `access.log`.

nginx itself appends the raw request line to every error-log entry made while
serving a request, so the generated config sets `error_log … crit`: upstream
failures (`connection refused`, timeouts, resets) are logged at `[error]` and
stay out of the error log, and the masked access line records them instead
This reinforces API key management hardening across gateway services. Comet's own
per-request log is sanitized by the `api_app` override (see `comet-patches.md`).

This applies to the generated gateway and Comet logs only. Your reverse proxy
sees the full URL (token and config blob) before the gateway does and must not
log it either. For Nginx Proxy Manager, put this in the proxy host's
**Advanced** tab (NPM inserts that text at server level, after its own log
directives), keeping your existing `location /` settings:

```nginx
# Server level: NPM's Force-SSL/Block-Exploits includes `return` and read an
# uninitialized variable *before* a location is chosen, and both log the full
# request line through the server-level logs.
access_log off;
uninitialized_variable_warn off;

location / {
    access_log off;
    error_log /data/logs/proxy-host-<id>_error.log crit;
    # ... existing proxy_set_header / proxy_pass lines ...
}
```

A location-level `error_log` alone is not enough: nginx writes to every error
log defined at one level, and server-phase warnings never reach the location.
Do not edit `data/nginx/proxy_host/<id>.conf` directly; NPM regenerates it
from its database. The gateway's masked access log keeps per-request status
and timings, so nothing useful is lost.

### Log canary

```bash
./stremio comet log-canary
```

Sends a fresh random value shaped like a gateway token through the public URL
(`COMET_GATEWAY_PUBLIC_BASE_URL`, over HTTPS and, if open, plain HTTP) and
directly to Comet, then searches every sink for it: the gateway and Comet
container logs, this run's StremioGuard logs, and every file matched by
`COMET_LOG_CANARY_GLOBS` (comma-separated; point it at your reverse
proxy's logs). It prints only the canary's fingerprint and a PASS / FAIL /
UNVERIFIED line per sink, and exits 1 unless the public HTTPS probe reached
the gateway and every sink passed. A sink it cannot read, or a glob that
matches nothing, is UNVERIFIED rather than PASS. A matched path that is a
symlink or not a regular file (a FIFO, a device) is never followed or read
and makes its sink UNVERIFIED. Plain log files are read from their end, at
most the last 32 MiB (the canary was just written there); a compressed
rotated log larger than 32 MiB uncompressed makes its sink UNVERIFIED. The
same check runs as an advisory warning after `./stremio start` and
`./stremio restart`.

Logs owned by root-only runtimes (for example a rootful Docker daemon's
`json-file` logs) are outside the automated check; scan them once with root.

## Tradeoffs

This is a pragmatic small-scale access model. Tokens in URLs are easy to share
and revoke, but they are not a full identity platform. If a token is compromised, rotate
or revoke it.
