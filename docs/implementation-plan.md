# Implementation Plan — Hardening + Comet Image Promotion System

Status: approved design, ready for implementation (July 2026).
Origin: architectural review + design discussion. This document is the single
source of truth for the work; each phase is self-contained and can be handed
to an implementing agent as "implement Phase N of docs/implementation-plan.md".

## Ground rules for the implementing agent

- Run `./stremio check` (ruff format --check, ruff check, pyright, pytest via
  uv) before every commit. All four must pass.
- Follow the commit style skill at `.codex/skills/commit-message-style/SKILL.md`
  (subject 8–12 words; short human paragraphs on why; categorical file groups
  in backticks). One phase = one commit (or a small series within the phase).
- Tests follow the existing mocked-`Runner` pattern (see `tests/conftest.py`
  and `tests/test_guard.py`). No test may hit the network or the real Docker
  daemon. Small, focused tests close to the module changed.
- Project stance is beta: no legacy shims or compatibility layers unless a
  phase explicitly calls for a migration step. Fail closed everywhere.
- Do not modify anything under `vendor/` (managed upstream checkout).
- Preserve the public CLI surface (`./stremio ...` commands) except where a
  phase adds new subcommands.

## Phase ordering and dependencies

```
Phase 0  Hardening batch (independent small fixes)         — no deps
Phase 1  Watchdog resilience + IP-check debounce           — no deps
Phase 2  Stack publisher consolidation                     — no deps
Phase 3  Override metadata + image-source rendering        — after 2
Phase 4  Digest promotion state machine                    — after 3
Phase 5  Update commands + start-time check                — after 4
Phase 6  Validation depth (import smoke, --deep)           — after 4
Phase 7  CI canary + generator regression gate             — after 6
Phase 8  Documentation sweep                               — last
```

Phases 0, 1, 2 are independent of each other and of the promotion system;
they can be implemented and merged in any order.

---

## Phase 0 — Hardening batch

Independent fixes from the security/reliability review. Each item is one
logical commit or grouped sensibly.

### 0.1 Gateway nginx: rate-limit auth failures, mask tokens in logs, atomic writes

File: `src/stremioguard/comet_gateway.py` (`render_nginx_conf`,
`render_tokens_map`, `write_nginx_configs`).

- **Rate-limit invalid-token requests without touching valid streaming
  traffic.** Use the empty-key exemption pattern: requests whose zone key is
  an empty string are not rate limited. Add to the `http` block:

  ```nginx
  map $token_valid $auth_fail_key {
      0 $binary_remote_addr;
      1 "";
  }
  limit_req_zone $auth_fail_key zone=gateway_auth:1m rate=5r/s;
  limit_req_zone $binary_remote_addr zone=gateway_admin:1m rate=10r/s;
  ```

  Apply `limit_req zone=gateway_auth burst=10 nodelay;` inside both `/comet/…`
  token locations (valid tokens have an empty key → exempt; invalid tokens get
  throttled before the 403). Apply
  `limit_req zone=gateway_admin burst=20 nodelay;` to the
  `/configure|/static|/health|/admin` location and the `location = /` block
  (human-paced pages; throttles password brute force). Keep the existing
  `gateway_fail` zone on the fallback 403 location. Do NOT add any limit that
  counts successful token-authenticated playback requests — video players
  burst range requests during seeks.

- **Mask the token in access logs.** The current `log_format` records
  `$request`, which contains the token path segment and the base64 Comet
  config (may embed debrid API keys). Add:

  ```nginx
  map $request $request_masked {
      ~^(?<mreq_head>\S+\s/comet/)[A-Za-z0-9_-]+(?<mreq_tail>\S*) "${mreq_head}***${mreq_tail}";
      default $request;
  }
  ```

  and log `$request_masked` instead of `$request`. Note this also truncates
  the config blob from logs only when it follows the token segment — verify
  the regex against a real playback URL in a test that renders the conf and
  asserts no raw token appears in the format line.

- **Atomic, 0600 writes.** `write_nginx_configs` currently uses
  `Path.write_text` (non-atomic, umask perms). Switch both files to
  `atomic_write_text(..., mode=0o600)` from `stremioguard.env` (the nginx
  container runs as root and can read 0600 bind mounts).

Tests: extend `tests/test_comet_gateway.py` — rendered conf contains the two
new zones and the masked log format; token locations contain
`limit_req zone=gateway_auth`; rendered files are written via the atomic
helper (assert file mode 0o600 after `write_nginx_configs`).

### 0.2 Restart-policy symmetry for the Comet trio

File: `docker-compose.yml`.

Change `comet`, `comet-postgres`, `comet-gateway` from
`restart: unless-stopped` to `restart: "no"`, matching `stremio`'s rationale:
nothing that produces debrid traffic should be revived by Docker before the
verifier has run. The watchdog already auto-starts all enabled services once
gluetun is healthy and the IP check passes, so boot recovery is preserved for
users running the cron/systemd persistence options. `gluetun` stays
`unless-stopped` (it must self-recover; it is the kill switch, not the
guarded workload). Update the "Container restart policy" section of
`README.md` in Phase 8.

### 0.3 Random Postgres password

Files: `src/stremioguard/comet/manager.py` (`render_runtime_env`,
`write_runtime_env`), `src/stremioguard/publishing.py`, `docker-compose.yml`.

- Generate `POSTGRES_PASSWORD` with `secrets.token_urlsafe(18)` on first
  runtime-env render; persist it the same way the other generated passwords
  are persisted (re-read from the existing runtime env on re-render).
- Write a `.stremio/comet/postgres.env` (0600, atomic) with
  `POSTGRES_USER=comet`, `POSTGRES_PASSWORD=<generated>`, `POSTGRES_DB=comet`.
  The generated compose override adds `env_file` to `comet-postgres`;
  remove the hardcoded credentials from the base `docker-compose.yml`
  environment block. Comet's `DATABASE_URL` in the runtime env uses the same
  generated password.
- Migration: Postgres only reads env credentials at first initialization. If
  `.stremio/comet/postgres-data` already exists but no `postgres.env` does,
  the data was initialized with the legacy `comet:comet` — Comet's data is a
  disposable scrape cache, so log a clear one-time warning telling the user
  to run `./stremio comet stop`, delete `.stremio/comet/postgres-data`, and
  restart to adopt the generated password; keep using `comet` as the password
  in both files until they do (write `postgres.env` with `comet` in that
  case so behavior stays consistent). No ALTER USER automation.

Tests: `tests/test_comet.py` — new install generates a non-default password
into both files consistently; existing-data-dir path falls back to legacy
password with the warning.

### 0.4 Watchdog PID matching tightened

File: `src/stremioguard/cli/watchdog.py` (`_pid_is_our_watchdog`).

Require, in addition to the current cmdline markers, that
`Path(f"/proc/{pid}/cwd").resolve() == ROOT_DIR` (wrap in the same
OSError/PermissionError guard, returning False). This prevents
`./stremio stop` from SIGKILLing unrelated processes (e.g.
`tail -f logs/stremio-vpn-*.log | grep watchdog`) that merely mention the
marker strings in argv.

Tests: `tests/test_cli.py` — a PID whose cwd differs is not matched even with
matching cmdline (monkeypatch the /proc reads).

### 0.5 Home-IP baseline staleness warning

Files: `src/stremioguard/guard.py`, `src/stremioguard/orchestrator.py`.

Residential IPs rotate; a stale `.stremio/home-ip` silently weakens the leak
check. When `public_ip_safe` (or `preflight`) reads the baseline, check the
file mtime; if older than 30 days, emit one warning per process run
("home-IP baseline is N days old; re-run `./stremio record-home-ip` while
gluetun is stopped"). `./stremio status` also prints the baseline age.
Do not fail on staleness — it is advisory.

Tests: `tests/test_guard.py` — warning fires once for an old baseline, not at
all for a fresh one.

### 0.6 Config parsing consolidation

Files: `src/stremioguard/env.py`, `src/stremioguard/config.py`,
`src/stremioguard/guard.py`.

- `_parse_port` (config.py) and `GluetunGuard.env_port` / `env_port_value`
  (guard.py / env.py) are three implementations of the same parse. Keep ONE
  in `env.py` (`env_port_value` semantics but raising `RuntimeError` instead
  of typer-exiting; adjust callers), delete the others.
- `DEFAULT_STREMIO_HOST_PORT` is defined in `guard.py`, `config.py`, and
  `env.py`. Single home: `config.py`; import elsewhere.
- Collapse the repetitive hand-rolled int parsing inside
  `CometConfig.from_env` (COMET_HOST_PORT, token length, healthcheck
  interval, max connections) onto shared helpers
  (`env_port_value`, a new `env_int_value(env_path, key, default, *,
  minimum=None, maximum=None)`).
- Document the dotenv dialect at the top of `.env.example`: values are taken
  verbatim after the first `=`; no quoting, no inline comments, no `export`.
  (Do not switch parser libraries in this phase.)

Tests: adjust existing config/env tests; add cases for `env_int_value`
bounds.

---

## Phase 1 — Watchdog resilience + IP-check debounce

The watchdog is the component that must not die and must not cry wolf.

### 1.1 Survive transient errors in the loop

File: `src/stremioguard/orchestrator.py`.

`watch_once` currently propagates exceptions (e.g. `compose("up", ...)` has
`check=True`; `write_compose_override` can raise `RuntimeError` on a bad
mid-flight `.env` edit), and `_run_command` converts them into process exit —
silently killing layer 2.

- In `watch_stremio`, wrap the `watch_once()` call in
  `try/except Exception`: log the full traceback via
  `logger.exception(...)`, increment a `loop_error` counter, continue the
  loop. The `time.sleep` stays outside the try so a hot exception loop still
  paces itself.
- Track `consecutive_loop_errors`; at a threshold (3), attempt
  `stop_active_services()` inside its own try/except (fail closed even when
  broken), keep looping, and reset the counter on the next clean tick.
- Change the auto-start call in `watch_once` to `check=False` and let the
  next tick verify the containers actually came up.
- Add `loop_errors` to the periodic watchdog summary line.

### 1.2 IP checks: gluetun control server primary, debounced external fallback

Files: `src/stremioguard/guard.py`, `src/stremioguard/config.py`,
`docker-compose.yml` (control server is already configured at
`HTTP_CONTROL_SERVER_ADDRESS: 127.0.0.1:18080`).

Today every 10s tick shells into gluetun and hits api.ipify.org /
icanhazip.com / ifconfig.me — ~8.6k req/day from a shared VPN exit IP. Those
services throttle, and a single failed sample stops streaming mid-playback.

- Add `GluetunGuard.public_ip_via_control_server()`:
  `docker exec <gluetun> wget -qO- http://127.0.0.1:18080/v1/publicip/ip`,
  parse JSON `{"public_ip": ...}`. IMPORTANT: verify the exact route/response
  shape and auth behavior against the gluetun version actually pulled
  (`qmcgaw/gluetun:latest`; newer gluetun versions gate some control-server
  routes behind an auth config). If the endpoint returns 401/404, log once
  and fall back permanently (for the process lifetime) to the external-probe
  path.
- `public_ip_safe` resolution order: control server → external probes
  (existing `public_ip_via_gluetun`). External probes also run as a
  cross-check at most once per `IP_CROSSCHECK_INTERVAL_SECONDS` (default 300,
  env-tunable) even when the control server is answering; a mismatch between
  the two sources is logged as a warning and treated as unsafe.
- **Debounce transient unknowns, act immediately on definitive leaks.**
  Distinguish outcomes:
  - `UNSAFE_DEFINITIVE`: an IP was observed and it matches the home baseline,
    or mismatches `EXPECTED_VPN_IP` → stop services immediately (current
    behavior, unchanged).
  - `UNKNOWN`: no IP could be determined → count consecutive unknowns; only
    after `PUBLIC_IP_FAILURE_THRESHOLD` (default 3, env-tunable) consecutive
    unknowns does the watchdog stop services. Reset the counter on any
    successful observation.
  Encode this as a small enum return from a new
  `public_ip_assessment()` used by the watchdog; `preflight` keeps the strict
  single-shot behavior (a failed check at start refuses to start — starting
  is not latency-sensitive).

Config additions (`Config.from_env`): `ip_crosscheck_interval_seconds`,
`public_ip_failure_threshold`.

Tests: `tests/test_orchestrator.py` — loop survives an exception in
`watch_once`; three consecutive UNKNOWNs stop services but two do not;
definitive home-IP match stops on the first tick; control-server 401 falls
back to external probing. Use the mocked Runner to script the docker exec
responses.

---

## Phase 2 — Stack publisher consolidation

Files: `src/stremioguard/publishing.py` (grows), `src/stremioguard/guard.py`,
`src/stremioguard/comet/manager.py`.

Two independent writers currently assemble `.stremio/docker-compose.bindings.yml`
(`GluetunGuard.write_compose_override` and
`CometManager.write_stack_override_file`) via parallel input-gathering that
must stay in sync by hand, and both rewrite the file on every compose call —
so read-only commands like `status` mutate deployment state, non-atomically.

- Create a single `StackPublisher` (in `publishing.py`) that owns: gathering
  bind addresses/ports/configs, rendering (the existing
  `render_stack_compose_override`), and writing the override file via
  `atomic_write_text`. Both `GluetunGuard` and `CometManager` delegate to it.
- Only lifecycle paths regenerate the file: `preflight`/`setup`/`start`/
  `restart`/`comet install`/token changes. Read-only commands (`status`,
  `ps`, `logs`, container-id lookups, watchdog ticks that don't start
  anything) use the file as it exists on disk; if it is missing, they may
  generate it once. Concretely: split the current
  `compose()` helpers into `compose()` (no regeneration) and
  `compose_fresh()` (regenerate then run), and audit every call site for
  which one it needs. The watchdog's auto-start path uses `compose_fresh()`.
- The publisher is also where Phase 4's digest-pinned image reference will be
  rendered — keep the render signature ready to accept an explicit image
  reference for the comet service.

Tests: `tests/test_publishing.py` — both former call paths produce
byte-identical output through the publisher; `status`-style calls do not
rewrite the file (assert mtime unchanged via tmp_path); the file write is
atomic (mode/content).

---

## Phase 3 — Override metadata + image-source rendering

Files: `src/stremioguard/overrides/*` (all renderers + `bundle.py`),
`src/stremioguard/comet/manager.py`, `src/stremioguard/publishing.py`.

### 3.1 Override specs

Introduce a declarative spec per override in `overrides/bundle.py`:

```python
@dataclass(frozen=True)
class OverrideSpec:
    name: str  # "stream", "torrentio", ...
    feature: str  # user-facing: "TV-readable stream naming and gateway playback URLs"
    container_path: str  # "/app/comet/api/endpoints/stream.py"
    output_name: str  # "stream.py" (file written under state_dir)
    requirement: Requirement  # REQUIRED, REQUIRED_WHEN_GATEWAY, OPTIONAL
    render: Callable[[Path, RenderContext], str | None]
```

Current classification: `stream` → REQUIRED_WHEN_GATEWAY (forwarded-header
playback base is what makes gateway-prefixed URLs work; without the gateway
it is OPTIONAL cosmetics — encode as REQUIRED_WHEN_GATEWAY and treat as
OPTIONAL otherwise). `config`, `template` (configure page install URL) →
REQUIRED_WHEN_GATEWAY. `torrentio`, `filtering`, `formatter`,
`orchestration` (episode pack), `metadata_service` → OPTIONAL, each with an
accurate `feature` string describing what degrades.

### 3.2 Partial bundle + report

`write_override_bundle` stops raising on first failure. New behavior: attempt
every spec; collect `BundleReport(applied: list[str], skipped:
list[SkippedOverride(name, feature, reason)])`. Raise only if a spec that is
required *for this deployment shape* (gateway enabled) failed. Write a
machine-readable `bundle-manifest.json` into `state_dir` (atomic): rendered
digest inputs, applied/skipped lists, per-file output names. The compose
override generation (Phase 2 publisher) reads the manifest and mounts ONLY
the files listed as applied — a skipped override must not leave a stale file
mounted (delete stale outputs for skipped specs, as the formatter/
orchestration paths already do).

User-facing reporting: after bundle generation, log a concise feature table —
applied patches at info level; skipped ones at warning level with the
`feature` text ("episode-pack preservation disabled: <reason>").

### 3.3 Render from the image, not the vendored checkout

- Extract the existing `docker create`/`docker cp` logic from
  `validate_compatibility` into a reusable context manager in
  `comet/manager.py`:
  `extract_image_source(runner, image_ref) -> Iterator[Path]` yielding the
  copied `/app/comet` parent directory in a TemporaryDirectory, always
  removing the temp container in `finally`.
- `prepare_runtime` renders the runtime bundle from the **active image's**
  extracted source (Phase 4 defines "active"; until Phase 4 lands, use
  `self.config.image`). The vendored checkout is no longer an input to
  runtime rendering.
- Cache to avoid re-extracting on every start: skip rendering when
  `bundle-manifest.json` records the same (image digest, patch fingerprint,
  format style, episode-pack flag, gateway addon URL) tuple. The existing
  `_managed_patch_fingerprint` covers generator changes.
- `vendor/comet` demotes to a maintainer aid: `fetch_and_checkout_pinned`
  is no longer called from `prepare_runtime`/`start`; keep it behind
  `./stremio comet vendor-sync` (new hidden command) for diffing upstream
  when fixing anchors. `doctor` drops the pinned-commit assertion and
  instead asserts the running container's image digest matches the active
  digest and the mounted bundle manifest matches it too.
- `validate_compatibility` keeps its structure but now validates the exact
  artifact that will be mounted (render from image source → the same code
  path used at runtime), eliminating the vendored-vs-image coherence gap.

Tests: `tests/test_comet.py` + new `tests/test_overrides_bundle.py` — bundle
report reflects per-spec failures; gateway-enabled deployment raises when the
stream anchor is missing but proceeds (with warnings) when only optional
specs fail; manifest-driven mounts exclude skipped files; cache hit skips
re-render (assert extract not called via mocked runner).

---

## Phase 4 — Digest promotion state machine

Files: `vendor/comet.lock.json`, new `src/stremioguard/comet/state.py`,
`src/stremioguard/comet/manager.py`, `src/stremioguard/publishing.py`,
`src/stremioguard/config.py`.

### 4.1 Data model

- `comet.lock.json` (repo, maintainer-owned) gains:

  ```json
  {
    "upstream_url": "...",
    "pinned_commit": "...",
    "default_branch": "main",
    "image": "g0ldyy/comet",
    "tested_digest": "sha256:..."
  }
  ```

  `tested_digest` = last digest the maintainers validated (updated by the
  Phase 7 canary PRs). Extend `comet/lock.py` accordingly; missing
  `tested_digest` is a hard error with a clear message.

- `.stremio/comet/state.json` (local, machine-owned; atomic 0600 writes via a
  small typed wrapper in `comet/state.py`):

  ```json
  {
    "active_digest": "sha256:...",
    "previous_digest": "sha256:... | null",
    "candidate": {
      "digest": "sha256:...",
      "checked_at": "2026-07-14T00:00:00+00:00",
      "validation": {"status": "passed|failed", "report": {...}}
    } | null,
    "last_remote_check": "ISO-8601 | null"
  }
  ```

### 4.2 Compose always runs a digest

The publisher renders the comet service image as
`<image>@<active_digest>` (e.g. `g0ldyy/comet@sha256:...`). `COMET_IMAGE`
in `.env` remains supported as the repository name override; it is combined
with the active digest, never used as a floating tag at runtime. If
`state.json` is missing (pre-migration installs), fall back to resolving it
during the next `prepare_runtime` (see 4.3) — never render an unpinned
reference once state exists.

Digest resolution: after any pull, read `RepoDigests` via the existing
`_image_digest`; for remote comparison without pulling, use
`docker manifest inspect <image>:latest` and hash comparison against the
stored digest. Always compare registry manifest-list digests to
manifest-list digests (both sources above provide that form) — never mix in
image IDs.

### 4.3 Install / first-run flow

In `CometManager.install` (and `prepare_runtime` when no `state.json`
exists):

1. Pull `:latest`; resolve digest D.
2. Extract source from D; render bundle; run validation (Phase 6 stages).
3. All applicable specs pass → `active_digest = D`. Report success + applied
   feature list.
4. Only OPTIONAL specs fail → prompt (interactive) or proceed (non-tty) with
   `active_digest = D`, clearly listing degraded features; record skips in
   the bundle manifest.
5. A required-for-this-shape spec fails → fall back: pull
   `tested_digest` from the lock, validate it (must pass; if even that
   fails, abort with the compatibility diagnostic — generator bug), set
   `active_digest = tested_digest`, and tell the user: "upstream's newest
   image isn't yet supported by StremioGuard's patches; you are on the last
   maintainer-validated version; run `./stremio comet update` after updating
   StremioGuard."

### 4.4 Promotion / rollback primitives

`comet/state.py` (or manager) methods, used by Phase 5 commands:

- `check_remote() -> str | None` — resolve remote digest, update
  `last_remote_check`; returns new digest if ≠ active.
- `validate_candidate(digest) -> ValidationReport` — pull if needed, extract,
  render, validate; store under `candidate`. Never touches running services.
- `promote_candidate()` — re-validate (cheap, digest-cached), set
  `previous_digest = active_digest`, `active_digest = candidate.digest`,
  clear candidate, regenerate bundle + override, restart the comet trio.
- `rollback()` — swap active/previous, regenerate, restart. One level deep.

Tests: `tests/test_comet_state.py` — state round-trips atomically; install
fallback path selects `tested_digest` when candidate validation fails;
promote/rollback swap digests and regenerate; publisher renders
`image@digest`. All docker interactions scripted through the mocked Runner.

---

## Phase 5 — Update commands + start-time check

Files: `src/stremioguard/cli/commands/comet_core.py`,
`src/stremioguard/cli/commands/general.py`, `src/stremioguard/orchestrator.py`.

### 5.1 CLI

New typer sub-app `./stremio comet update` with:

- `check` (default when bare `update` is invoked): remote digest compare →
  if new, run candidate validation and print one of:
  - "Update available and validated → run `./stremio comet update apply`"
    (+ applied/degraded feature diff vs current)
  - "Update available but patches fail: staying on <active>; a StremioGuard
    update is needed" (+ diagnostic summary)
  - "Already up to date."
- `apply`: promote (5.1 `promote_candidate`); refuses if no validated
  candidate or validation is stale (candidate digest no longer matches
  remote — re-run check).
- `rollback`: one-step rollback with confirmation prompt.

Never auto-apply anywhere. `COMET_AUTO_UPDATE` is intentionally NOT
implemented in this plan (revisit later as opt-in).

### 5.2 Start-time advisory check

In the `start`/`restart` flow (after services are up, so it can never delay
startup), run a throttled advisory check:

- Skip entirely unless `last_remote_check` is older than 24h.
- One `docker manifest inspect` comparison; on any error (registry down, rate
  limit, no network) log at DEBUG and return — no user-visible noise, no
  effect on exit code. Wrap so no exception can escape.
- If a new digest exists: single INFO line "Comet update available — run
  `./stremio comet update`". Do NOT validate at start (validation pulls the
  image; that belongs to the explicit command).

Tests: throttle honored (no second check within 24h); registry failure is
silent; new-digest path logs the advisory and nothing else; `apply` refuses
without a validated candidate.

---

## Phase 6 — Validation depth

Files: `src/stremioguard/comet/manager.py` (validation pipeline), possibly a
new `src/stremioguard/comet/validation.py`.

Stage the compatibility validation used by install/candidate/promote:

1. **Render + compile** (existing): anchors found, output syntax-compiles.
2. **Import smoke (new, mandatory):** run the candidate image with the
   rendered overrides bind-mounted read-only at their container paths:

   ```
   docker run --rm --network none \
     -v <state>/stream.py:/app/comet/api/endpoints/stream.py:ro \
     ... (every applied override) \
     --entrypoint python <image@digest> \
     -c "import comet.api.endpoints.stream, comet.scrapers.torrentio, ..."
   ```

   Module list is derived from the bundle manifest's container paths.
   Comet's settings module may require env vars at import time — pass dummy
   values (`-e DATABASE_URL=...`, etc.) mirroring `render_runtime_env`
   keys with placeholder values; the implementer must run this once manually
   against the current image and adjust the stub env until a clean pass is
   achieved, then encode that stub in code. Any nonzero exit = validation
   failure; capture stderr into the validation report (it feeds the
   `_compatibility_diagnostic` path and the Phase 7 canary issue body).
3. **Ephemeral boot (`--deep`, optional flag on `comet update check` and
   `install`):** start a throwaway candidate container (scratch config,
   sqlite or throwaway postgres, `--network none` is NOT possible here — use
   a temporary bridge network with no published ports), wait for `/health`,
   fetch a manifest route, tear down. Never part of the default path;
   document as the paranoid pre-promotion check.

Extend `compatibility.json` cache keys to include the validation stage level,
so a compile-only pass is not mistaken for an import-verified pass.

Tests: mocked-runner sequencing of the docker run call with the right mounts
and entrypoint; failure surfaces stderr in the report; cache distinguishes
stage levels.

---

## Phase 7 — CI canary + generator regression gate

Files: `.github/workflows/comet-canary.yml`,
`.github/workflows/ci.yml` (or extend existing), small CLI entry
`python -m stremioguard.comet.validate --image <ref> [--json]` (hidden;
runs extract→render→compile→import-smoke and prints a machine-readable
report; exit code reflects pass/fail).

### 7.1 Regression gate (on push / PR)

Job steps: checkout → install uv → `./stremio check` equivalents → then, with
Docker available on the runner: pull `image@tested_digest` from the lock and
run `stremioguard.comet.validate` against it. This catches generator
regressions before merge — a change to `overrides/` that breaks against the
digest we claim to support cannot land.

### 7.2 Daily canary (schedule + workflow_dispatch)

Steps:

1. Resolve remote digest of `<image>:latest`
   (`docker buildx imagetools inspect --format '{{json .Manifest.Digest}}'`
   or `docker manifest inspect` + jq).
2. If equal to lock `tested_digest`: exit 0 (common case; no pull).
3. Else pull the new digest and run `stremioguard.comet.validate`.
4. Pass → open/refresh a PR bumping `tested_digest` in
   `vendor/comet.lock.json` (use `peter-evans/create-pull-request`; branch
   `canary/comet-<shortdigest>`; PR body embeds the JSON validation report
   and applied-feature list).
5. Fail → create or update a pinned issue titled
   "Comet upstream drift: patches fail against <shortdigest>" with the
   diagnostic output. De-duplicate by searching for an open issue with a
   marker label (`comet-canary`).

Dependabot is intentionally NOT used for this artifact: it cannot parse the
lock file, cannot run validation, and polls on a schedule just like cron —
it would only add a decoy Dockerfile and token friction. Keep Dependabot for
Python deps and actions versions.

---

## Phase 8 — Documentation sweep

Files: `README.md`, `CURRENT_PROGRESS.md`, `docs/comet-patches.md`,
`.env.example`, `docs/comet-gateway.md`.

- README: restart-policy section (0.2); watchdog behavior (thresholds, new
  env knobs from Phase 1); new `comet update` command guide; update-check
  behavior on start; digest pinning model ("StremioGuard always runs a
  validated image digest; `latest` is a candidate until promoted").
- `docs/comet-patches.md`: methodology now "rendered from the image's own
  source"; per-override feature table with requirement classes; degraded-mode
  behavior; canary/PR flow for maintainers.
- `.env.example`: dotenv dialect note (0.6); new env knobs
  (`PUBLIC_IP_FAILURE_THRESHOLD`, `IP_CROSSCHECK_INTERVAL_SECONDS`); note
  that `COMET_IMAGE` is a repo name, not a tag.
- `CURRENT_PROGRESS.md`: update mental model (StackPublisher, state.json,
  image-source rendering, vendored checkout demoted to maintainer aid).

---

## Post-implementation verification (manual, operator-run)

Not automatable in unit tests; run once on the real deployment:

1. **gluetun recreation recovery:** `docker compose up -d --force-recreate
   gluetun`, then watch that the next watchdog tick restores all services
   with working networking (netns re-attachment). If dependents keep a dead
   namespace, add `--force-recreate`-on-mismatch handling to the watchdog
   auto-start path (detect via `NetworkMode` container ID ≠ current gluetun
   ID — `doctor` already computes this for comet).
2. **Gateway rate limit:** loop 50 invalid-token requests → expect 403s then
   429/503-limited; confirm a valid-token playback stream with seeking is
   never limited.
3. **Control-server IP path:** confirm `/v1/publicip/ip` responds on the
   pulled gluetun version; if auth-gated, record the needed config in the
   README and verify the fallback engages cleanly.
4. **End-to-end update drill:** with everything on `tested_digest`, run
   `./stremio comet update check` against a genuinely newer upstream digest,
   `apply`, play a stream, then `rollback` and play again.
