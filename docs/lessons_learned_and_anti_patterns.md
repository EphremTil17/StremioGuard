# Lessons Learned and Anti-Patterns

This file is a living ledger of local design guardrails. Review it before
changing network, proxy, auth, or Comet behavior.

---

## 1. Protect the Media Gateway, Not Hosted Stremio

### The Mistake / Issue
Putting the primary token gate in front of Stremio made account/library access
and media-relay authorization feel like the same problem.

### The Root Cause
The real privacy boundary is Comet playback and stream discovery. If a configured
Comet addon can still reach `/manifest.json`, `/stream/...`, or `/playback/...`
publicly, then a Stremio auth proxy is not the meaningful enforcement layer.

### The Core Corrective Rule
Use the token-managed Comet gateway as the public authorization boundary. Keep
management at `/configure`, but require `/comet/<token>/...` for addon install,
stream discovery, playback, and debrid-sync routes.

---

## 2. Reverse Proxy Routing Requires Host Headers

### The Mistake / Issue
Connecting to a reverse proxy by bare IP can produce a default page, `502`, or
the wrong upstream.

### The Root Cause
Reverse proxies route by HTTP `Host`. Bare IP requests do not match named proxy
hosts such as `comet.example.com`.

### The Core Corrective Rule
Test public access with the configured domain, not only the upstream IP. For the
Comet gateway, the public domain should upstream to `COMET_GATEWAY_HOST_PORT`.

---

## 3. Gateway URLs Must Preserve Their Token Prefix

### The Mistake / Issue
Comet-generated install or playback URLs can escape the protected namespace if
the gateway strips `/comet/<token>` without telling Comet about the public prefix.

### The Root Cause
Backends generate URLs from request metadata. If forwarded prefix/proto/host
headers are missing or overwritten, generated addon and playback URLs may point
at raw Comet paths.

### The Core Corrective Rule
The gateway must send `X-Forwarded-Prefix: /comet/<token>` and preserve the
client-facing protocol/host. Comet runtime overrides must use those forwarded
headers when `PUBLIC_BASE_URL` is blank.

---

## 4. Managed Patches Beat In-Container Hand Editing

### The Mistake / Issue
Patching files inside a running Docker container is fast but non-reproducible.

### The Root Cause
Container-local edits disappear on rebuild, pull, recreate, or host migration.

### The Core Corrective Rule
Generate local override files under `.stremio/comet/` and
`.stremio/comet-gateway/`, then mount them read-only through Docker Compose.

---

## 5. Comet Must Share Gluetun's Network Namespace

### The Mistake / Issue
If Comet runs outside the VPN namespace, scraping or playback can use the host
network instead of the VPN path.

### The Root Cause
Docker services do not automatically share egress. Comet must explicitly use
the `gluetun` network namespace.

### The Core Corrective Rule
Comet, Comet Postgres, and the gateway should share `gluetun`'s namespace.
`./stremio comet doctor` must verify that Comet's public egress IP matches
gluetun's public egress IP.

---

## 6. Raw Comet Must Not Be Public When Gateway Is Enabled

### The Mistake / Issue
Publishing both raw Comet and the gateway makes the token gate bypassable.

### The Root Cause
Direct raw Comet paths can serve manifest, stream, playback, and debrid-sync
requests without the gateway token.

### The Core Corrective Rule
When `COMET_GATEWAY_ENABLED=1`, publish raw Comet only on
`127.0.0.1:COMET_HOST_PORT` for operator diagnostics. Publish public Comet
access only through `COMET_GATEWAY_HOST_PORT`.

---

## 7. Nested Proxies Must Preserve Public Protocol

### The Mistake / Issue
Generated URLs can fall back to `http://` even when users connect over HTTPS.

### The Root Cause
An inner proxy can overwrite `X-Forwarded-Proto` with its own upstream scheme
instead of preserving the client-facing scheme.

---

## 8. Pyright Type Narrowing for Containment Checks

### The Mistake / Issue
Using set containment checks such as `if value not in {None, ""}` fails to narrow the type of `value` from `str | None` to `str` under Pyright, causing type-checker errors when passing `value` to functions that require a non-Optional string/integer.

### The Root Cause
Pyright's static analysis does not automatically perform type narrowing on member containment checks for sets.

### The Core Corrective Rule
Use explicit comparison operators like `if value is not None and value != ""` to narrow types from `Optional` values to concrete ones.

---

## 9. Stdin Mocks for CLI Prompts

### The Mistake / Issue
Introducing interactive CLI prompts (like deployment profile selection in `init()`) causes unit tests that run in captured output environments to crash with `OSError: pytest: reading from stdin while output is captured`.

### The Root Cause
Interactive `typer.prompt` or `click.prompt` statements attempt to read from standard input (`sys.stdin`), which is intercepted/disabled by pytest output capture.

### The Core Corrective Rule
Ensure all CLI command tests patch `typer.prompt` (or supply mocked side effects/inputs) to represent the user choice, avoiding attempts to read from real stdin during unit testing.

---

## 10. Raw Comet Base URL Sourcing

### The Mistake / Issue
Disabling the Comet gateway on a reverse-proxied setup left the deployment without a configured public base URL, as the wizard only prompted for `COMET_GATEWAY_PUBLIC_BASE_URL` when the gateway was enabled.

### The Root Cause
Raw Comet runs under a different environment variable (`COMET_PUBLIC_BASE_URL`) than the token gateway (`COMET_GATEWAY_PUBLIC_BASE_URL`).

### The Core Corrective Rule
If the gateway is disabled but the deployment is reverse-proxied, the setup wizard must prompt for and record `COMET_PUBLIC_BASE_URL` to ensure Comet runs with its correct public-facing routing prefix.

---

## 11. Robust Proxy Auto-Detection

### The Mistake / Issue
Detecting a public proxy configuration by checking interface bindings (e.g. `STREMIO_BIND_ADDRS != "127.0.0.1"`) falsely classified LAN setups as proxied and loopback-bound proxied setups as local.

### The Root Cause
Interface bindings are orthogonal to external domain routing. An NPM-proxied deployment can safely bind to `127.0.0.1`, while a private LAN binding is not internet-accessible.

### The Core Corrective Rule
Detect proxy status by parsing existing configured public URLs (`EXTERNAL_BASE_URL`, `COMET_GATEWAY_PUBLIC_BASE_URL`, or `COMET_PUBLIC_BASE_URL`). If none are present, prompt the operator explicitly instead of guessing based on IP/port bindings.
