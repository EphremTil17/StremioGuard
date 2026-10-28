# Egress Verification & Request-Path Log Hygiene

Design record for two hardening changes: tunnel-egress verification in the
watchdog, and keeping addon request paths out of every log on the request path.

## Motivation

- **Egress verification.** Gluetun's control-server `/v1/publicip/ip` is a
  snapshot fetched once per gluetun start. After an in-tunnel reconnect the exit
  IP can move within the provider's range while the snapshot keeps the old
  value. Treating any difference between that snapshot and a live probe as a
  definitive failure turned a benign reconnect into a stop/start cycle every
  cross-check interval, interrupting playback.
- **Request-path log hygiene.** Comet addon URLs carry the gateway token,
  Comet's `PUBLIC_API_TOKEN` (`/s/<token>`), and a base64 user config holding
  debrid credentials. Any component that logs a raw request path therefore
  stores those credentials. Paths were written by:
  - nginx `[error]`/`[warn]` entries, which always append the raw request line;
  - Comet's `LoguruMiddleware`, which logs `request.url.path` at a level no
    setting can silence;
  - the TLS-terminating reverse proxy in front of the gateway (see Phase 7).

  Docker `json-file` logs persist across `compose stop`/`start`; only removing
  the container clears them.
- `./stremio start` did not re-render the gateway `nginx.conf` (only token
  commands did), so gateway template changes would not deploy.

## Invariants

1. **Egress:** protected services run only while the *live* tunnel egress IP has
   been verified within the probe interval to differ from this host's direct
   public IP (live, or the recorded baseline when the live host probe fails);
   inability to verify fails closed through the existing UNKNOWN threshold.
2. **Availability:** a stale gluetun snapshot can never stop services.
3. **Log hygiene:** no hop a Comet request traverses (reverse proxy, gateway,
   Comet, container runtimes) writes a raw addon request path to a log.
4. **Control plane:** a circuit-breaker exit (78) is never auto-restarted into
   service; the lockout marker blocks the next `start`.

## Proof obligations

| Requirement | Authority | Runtime owner | Evidence |
|---|---|---|---|
| Egress ≠ host | live probe via `docker exec gluetun wget` vs host `urllib` probe | watchdog | verified egress logged; no stop on snapshot desync |
| Stale snapshot harmless | live probe (control IP only a change trigger) | watchdog | desync warning logged once, services stay up |
| No path in gateway logs | nginx `error_log … crit` + masked access log | gateway container | log canary PASS on the gateway container log |
| No path in Comet logs | `api_app` override (route template) | Comet container | log canary PASS on the Comet container log |
| No path in reverse-proxy logs | proxy config (Phase 7) | reverse proxy | log canary PASS on `COMET_LOG_CANARY_GLOBS` through the public HTTPS URL |
| No path via a tunnel/CDN edge | route the Comet host directly, or apply the same rule at the edge | edge | ingress/DNS config reviewed; re-check when a tunnel rule or proxied record is added |
| Template deploys | `CometManager.prepare_runtime` renders gateway | `./stremio start` | `nginx -T` shows `crit` |
| Regressions caught | log canary (fake token through every hop, every sink searched) | `./stremio comet log-canary`, advisory after start/restart | exit 0 only if every required probe reached and every sink PASS |
| Exit 78 terminal | lockout marker + `RestartPreventExitStatus=78` | cron/systemd | `start` refuses under lockout |

## Phase 1 — Egress verification (`config.py`, `guard.py`, `orchestrator.py`)

1. Rename `IP_CROSSCHECK_INTERVAL_SECONDS` → `EGRESS_PROBE_INTERVAL_SECONDS`
   (default 300).
2. `public_ip(*, version=None)`: bypass proxy environment variables (the
   baseline must be the *direct* IP) and skip answers of the wrong IP family, so
   an IPv6 host answer is never compared with an IPv4 egress.
3. `public_ip_assessment(log_observation, force_probe=False)`:
   - Read `control_ip` (cheap, local). A probe is **due** when `force_probe`, no
     verified egress is cached, the interval elapsed, or `control_ip` changed.
   - Not due ⇒ SAFE (egress verified less than an interval ago).
   - Due ⇒ `egress = public_ip_via_gluetun()`; None ⇒ UNKNOWN.
   - `host = public_ip(version=family(egress))`: `host == egress` ⇒
     UNSAFE_DEFINITIVE; host unknown and no valid baseline ⇒ UNKNOWN.
   - `EXPECTED_VPN_IP` mismatch or baseline match ⇒ UNSAFE_DEFINITIVE.
   - `control_ip != egress` ⇒ warn once per distinct pair (informational).
   - Only SAFE outcomes are cached, so every non-SAFE tick re-probes.
4. The recovery path calls `public_ip_assessment(force_probe=True)`: the egress
   changes exactly on reconnect.

## Phase 2 — Gateway and Comet log hygiene

1. Gateway nginx: `error_log … crit` (upstream failures log at `[error]` with
   the request line) and `upstream=… urt=… rt=…` fields in the masked access
   log, so failure diagnostics remain without paths.
2. `overrides/api_app.py` → `/app/comet/api/app.py`, `Requirement.REQUIRED`:
   log `_metrics_route(request)` (upstream's route-template helper, which also
   abstracts the `/s/<token>` prefix) instead of `request.url.path`. Fails
   closed on upstream drift; the promotion flow rejects a drifted candidate.
3. `CometManager.prepare_runtime` renders the gateway config when the gateway
   is enabled, so `./stremio start` deploys template changes.

## Phase 3 — Tests

- Guard: snapshot desync ⇒ SAFE with a single warning; egress == host ⇒ UNSAFE;
  tunnel probe failure ⇒ UNKNOWN and not cached; host failure without a valid
  baseline ⇒ UNKNOWN; baseline fallback; interval, control-change and
  `force_probe` re-probe rules; UNSAFE not cached; IP-family filtering.
- Orchestrator: recovery passes `force_probe=True`; the log canary runs as a
  post-start advisory and never fails a start.
- Gateway: `crit` error log, upstream fields in `log_format`.
- Overrides: `api_app` renders, logs the route template for a credential-shaped
  path, fails closed on unknown shapes, and is REQUIRED.
- Log canary: file (plain + gzip) and Docker sinks, UNVERIFIED for unreadable
  or unmatched sinks, optional vs required probes, and an end-to-end manager
  test with a simulated path-logging reverse proxy.

## Phase 4 — Docs

README and `.env.example` (renamed variable, egress semantics, log canary),
`docs/comet-patches.md` (`api_app`), `docs/comet-gateway.md` (logging,
reverse-proxy configuration, log canary).

## Phase 5 — Control plane

Cron `@reboot` or the systemd user unit may supervise the watchdog. The unit
ships with `RestartPreventExitStatus=78`, so a tripped breaker is not
restarted; under cron nothing restarts it, and the lockout marker blocks the
next `start` either way.

## Phase 6 — Rollout

1. `./stremio stop`, then stop gluetun
   (`docker compose -f docker-compose.yml -f .stremio/docker-compose.bindings.yml stop gluetun`).
2. `./stremio record-home-ip` (refuses while gluetun is healthy).
3. Remove the Comet and gateway containers so their log history is discarded
   (Postgres untouched).
4. `./stremio start` (renders the override bundle including `api_app` and the
   gateway config, verifies egress, starts the watchdog).
5. `./stremio comet log-canary` through the public URL.

## Phase 7 — Hops in front of the gateway

The gateway and Comet changes cover only the layers StremioGuard renders. A
TLS-terminating reverse proxy sees the full URL first and logs it by default.
Nginx Proxy Manager needs attention beyond a location-level override:

- Its Force-SSL include reads an uninitialized `$trust_forwarded_proto` and
  emits a `[warn]` with the request line on every request *before* location
  selection, so a location-level `error_log … crit` cannot suppress it, and a
  second server-level `error_log` does not replace the first (nginx writes to
  every error log defined at one level).
- Server-level `return`s (Force-SSL 301, Block Exploits 403) log through the
  server-level `access_log`.

Reproduced in a throwaway nginx with NPM's directive order: the location-only
change leaves access and error entries; adding server-level `access_log off;`
and `uninitialized_variable_warn off;` leaves none. The configuration is
applied through NPM's Advanced tab (never by editing its generated
`data/nginx/proxy_host/<id>.conf`), as documented in `docs/comet-gateway.md`.

`./stremio comet log-canary` sends a fresh random gateway-token-shaped value
through the public HTTPS URL (required), its plain-HTTP twin (optional: a
closed port answers nothing and so logs nothing), and directly to Comet inside
gluetun (a fake token never passes the gateway). It searches both container
logs, this run's StremioGuard logs, and `COMET_LOG_CANARY_GLOBS`. Unreadable or
unmatched sinks are UNVERIFIED, never PASS; only the canary's fingerprint is
printed. It runs as an advisory after start/restart; the command exits 1
unless everything passes.

### Lesson

Every hop in front of the app is in scope. Hardening the layers we render
says nothing about the proxy that terminates TLS in front of them, and clean
inner logs are not evidence that the request path goes unlogged. Map the full
client → edge → proxy → gateway → app → runtime path first, then verify the
invariant end to end through the public URL with a canary rather than per
layer by inspection.

### Credential rotation

Credentials that appeared in request paths before redaction was in place are
rotated only after the log canary passes on every sink (otherwise the new
values would be written again), and pre-redaction proxy logs are then emptied
and their rotated archives deleted.

## Residual risks (accepted)

- Egress verification latency is bounded by the probe interval (300s).
- A tunnel-side IPv6 path would not equal the host IPv4; gluetun blocks IPv6 by
  default.
- Request-context `[crit]` nginx entries still include the request line (rare
  syscall failures; `proxy_buffering off` avoids temp-file writes).
- Messages from third-party exceptions inside Comet are not sanitized.
- Under cron, a watchdog crash is not auto-restarted (services stay behind
  gluetun's kill switch; availability only).
- The addon URL is the credential by design: Stremio clients store it and sync
  it to the user's Stremio account.
- Logs of a root-only runtime (e.g. a rootful Docker daemon's `json-file` logs)
  are outside the automated canary; review them with root.
- Comet's startup banner prints a masked prefix of the proxy password
  (upstream behavior; the remaining characters keep ample entropy).

## Follow-ups

- `_pid_is_our_watchdog` matches any process whose argv contains `watchdog`
  plus `stremioguard.orchestrator` and whose cwd is the repo, so
  `./stremio stop` can signal an unrelated process that merely mentions those
  strings. Matching the PID file plus exact argv would be tighter.
- A 180s `subprocess.run` timeout on `docker compose pull gluetun` kills the
  direct child but not the compose plugin process it spawns, which can outlive
  it indefinitely.
