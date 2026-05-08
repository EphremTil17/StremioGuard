# Auth Proxy

This project optionally supports a small token-gated reverse proxy in front of
Stremio.

The goal is to reduce end-user friction compared with "everyone must install
Tailscale" while still avoiding a fully open public Stremio endpoint.

## What It Does

When enabled, StremioGuard runs an `nginx:alpine` container that expects a
short token in the first URL path segment:

```text
https://streamio.example.com/<token>/
```

Only requests with a valid token are proxied through to Stremio.

Each device or household can receive its own tokenized URL, managed with:

```bash
./stremio auth add "Living Room TV"
./stremio auth list
./stremio auth rotate <token-id>
./stremio auth revoke <token-id>
```

## Security Model

This is a pragmatic compromise, not a full identity platform.

It improves security by:

- removing the need to expose the raw Stremio host port as the primary remote
  entrypoint
- requiring possession of a valid URL token
- allowing easy per-device rotation/revocation
- keeping the token gate outside Stremio itself

It is **not** a substitute for:

- SSO
- per-user sessions
- fine-grained authorization
- rate-aware abuse protection at internet scale

So the intended use is:

- self-hosted, small-scale sharing
- "good enough" controlled access
- low-friction device onboarding

## Privacy Behavior

By default, the generated auth proxy configuration does **not** forward
client-origin IP headers upstream to Stremio:

- `X-Real-IP` is cleared
- `X-Forwarded-For` is cleared

It still forwards:

- `Host`
- `X-Forwarded-Proto`
- `X-Forwarded-Host`
- `X-Forwarded-Prefix`

Those are needed so the patched Stremio server can correctly derive its public
origin and preserve the tokenized path prefix in generated URLs.

## Token Prefix Preservation

One subtle issue with path-token auth is that Stremio generates its own
absolute URLs during the web flow.

If the proxy strips `/<token>/` before forwarding upstream, but the backend
does not know about that prefix, generated `streamingServer=` or callback URLs
can drop the token path and escape the protected namespace.

StremioGuard fixes that by:

- sending `X-Forwarded-Prefix: /<token>`
- teaching the patched Stremio server to include that prefix when deriving its
  external origin

So the tokenized path becomes a first-class part of the public origin instead
of a fragile proxy-only rewrite.

## Port Publishing Behavior

When `AUTH_ENABLED=1`, StremioGuard suppresses the raw Stremio host-port
publish in the generated Docker override. That means the intended remote path
is:

```text
reverse proxy -> auth proxy -> Stremio
```

instead of:

```text
reverse proxy -> either auth proxy or raw Stremio port
```

This is important because otherwise the token proxy would be only additive,
not enforced.

## Recommended Reverse Proxy Shape

Your public reverse proxy should upstream to the auth proxy host port, not the
raw Stremio port.

Example Nginx Proxy Manager / raw nginx-style location block:

```nginx
location / {
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Real-IP "";
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_connection;
    proxy_http_version 1.1;
    proxy_pass http://<SERVERIP:11471>$request_uri;
}
```

Replace:

- `<SERVERIP>` with the host address your public proxy can reach
- `11471` with your configured `AUTH_HOST_PORT` if you changed it

If you are fronting **Comet** separately, keep that as its own upstream. The
auth proxy described here protects the Stremio entrypoint, not Comet's
dedicated domain.

## Setup Flow

`./stremio init` now offers an optional auth-proxy step:

- enable token-based authenticated access
- choose the auth-proxy host port
- set the public domain used to display token URLs

After setup:

1. point your public reverse proxy at `AUTH_HOST_PORT`
2. create one or more tokens with `./stremio auth add`
3. distribute tokenized URLs, not the raw upstream

## Tradeoffs

Pros:

- simple
- revocable
- low-friction for end users
- no Tailscale app requirement for every client

Cons:

- token-in-URL model is weaker than real authn/authz
- URL leakage matters
- no user identity or session boundaries
- still requires careful reverse-proxy handling

## Long-Term Direction

This auth proxy is a transition step, not necessarily the final architecture.

The longer-term goal is a cleaner authenticated HTTPS-domain front door with a
stronger authorization story, while keeping the same self-hosted playback and
privacy properties.
