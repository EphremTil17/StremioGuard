# Gateway and Override Patch Test Lab

`scripts/lab.py` verifies the nginx Comet gateway and Comet override patches against real containers without touching the live `stremioguard-*` stack, `.env`, or `.stremio/`.

## Commands

### Gateway matrix

Runs an offline `--network none` Python echo upstream (`--no-healthcheck`) as the namespace owner, joins the pinned `comet-gateway` nginx container to it via `--network container:<echo>` under the production hardening from `docker compose config --format json` (`cap_drop: [ALL]`, `cap_add: [CHOWN, SETGID, SETUID]`, `security_opt: [no-new-privileges:true]`, `read_only: true`, `tmpfs: [/tmp, /var/cache/nginx]`), sends raw HTTP probes from inside the namespace via `docker exec -i <echo>` stdin/stdout, and checks the nginx access log for secret leaks:

```sh
uv run python scripts/lab.py gateway --echo-image g0ldyy/comet@sha256:<digest>
```

Options:

- `--echo-image <ref>`: Local Comet image for the echo server. If omitted, the lab reads `active_digest` from `.stremio/comet/state.json` when present, or fails asking for `--echo-image`.
- `--ref <git-ref>`: Render `nginx.conf` and `tokens.map` from a git commit (via `git archive` into a temp directory) without modifying the working tree.
- `--gateway-image <ref>`: Override the nginx image from `docker-compose.yml`.
- `--name-prefix <prefix>`: Container and temp directory prefix (default `sglab-`, validated against `^[a-z0-9][a-z0-9-]{0,30}$`).
- `--pull`: Pull missing images (by default only local images are used).

Matrix coverage:

- Allowed addon routes (`/comet/<token>/s/<api>/manifest.json` with and without config blob, `/stream/...`, `/playback/...`, `/configure`, `/configure/login`) proxied with raw path and query unchanged, `X-Forwarded-Prefix: /comet/<token>` on token routes and none on public `/configure` and `/health`.
- `Host` with port preserved as both `Host` and `X-Forwarded-Host`, and client `X-Forwarded-For` / `CF-Connecting-IP` stripped before reaching upstream.
- Base token routes (`/comet/<token>`, `/comet/<token>/`) answering `302` with relative `Location: /comet/<token>/configure`; HTTP/1.0 without `Host` answering `400`.
- Denied routes (`403`, never proxied): `admin`, `kodi`, `torznab/api`, `debrid-sync`, `cometnet`, `/administrator`, `/kodiak`, encoded slash/dot (`%2F`, `%2E`), `..`, exact-case token mismatch, and `/__sg_alive` on the public port (`8090`).
- Loopback health listener (`127.0.0.1:8099`): `GET /__sg_alive` answers `204` without adding a line to the access log, and `GET /` answers `404`.
- Access-log masking probes and secret-leak checks for the gateway token, API token, and config blob.

### Override bundle render

Extracts `/app/comet` from a Comet image, runs `write_override_bundle` with gateway and episode-pack options enabled, compiles the generated Python files, and lists applied and skipped patches:

```sh
uv run python scripts/lab.py render --image g0ldyy/comet@sha256:<digest>
```

Options: `--name-prefix <prefix>` and `--pull`.

## Guarantees

- Every container is labeled `stremioguard.lab=1` with a `<prefix><suffix>-echo` / `<prefix><suffix>-nginx` (or `-extract`) name, no published ports, and no bridge or created Docker network (`--network none` / `container:<echo>`).
- Only disposable test tokens are generated; `.env`, `.stremio/gluetun.env`, and `.stremio/comet-gateway/` are never read (`docker compose config` runs with `--env-file /dev/null --no-env-resolution --no-interpolate` so no checkout `.env` or secret `env_file` is loaded).
- All lab containers and temporary directories are removed by exact name on normal exit, failure, or `SIGINT`/`SIGTERM`.
