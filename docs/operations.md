# Operations

The `./stremio` commands, what a start does, the container restart policy, the Stremio patch layer and the Python runtime.

## Recommended workflow

Use the root wrapper as the normal entry point:

```bash
./stremio
```

With no arguments, `./stremio` behaves like `./stremio start`.

## What `./stremio` does

1. Checks that `uv`, `docker`, and `docker compose` are available.
2. Confirms `.env` exists and is populated.
3. Starts `gluetun` and waits for its healthcheck to pass.
4. Probes the tunnel egress IP live from inside gluetun's network namespace
   and this host's direct public IP from outside it.
5. Refuses to continue if the VPN looks unsafe:
   - the egress IP equals this host's direct public IP,
   - the egress IP matches your saved home-IP baseline,
   - `EXPECTED_VPN_IP` is set and does not match, or
   - neither the host's IP nor a baseline is available to compare against.
6. If `STREMIO_ENABLED=1`, starts Stremio inside gluetun's network namespace.
7. If `COMET_ENABLED=1`, renders Comet's patch bundle from its pinned image and starts `comet-postgres`, `stremthru`, `comet`, and (when `COMET_GATEWAY_ENABLED=1`) `comet-gateway` inside gluetun's network namespace.
8. Starts the watchdog as the `stremioguard-watchdog.service` systemd user unit,
   waits until it reports ready, and returns to the shell. The check that a
   user service manager is reachable runs before step 3, so protected
   services never start without a supervised watchdog.

## Container restart policy

- `stremio`, `comet`, `stremthru`, `comet-postgres`, and `comet-gateway` use `restart: "no"` so Docker does not revive them before the verifier and validation checks have run.
- `gluetun` uses `restart: unless-stopped` so it can recover across host reboots and transient handshake failures.
- Every other third-party image (`stremthru`, `comet-gateway`'s nginx, `comet-postgres`, and the `docker compose up` gate's busybox) is pinned by digest; Dependabot proposes bumps, and Postgres majors stay manual because they need a data-directory upgrade. Comet is pinned by the generated override to the digest `./stremio comet update` promoted.
- `gluetun` is pinned by digest too, and Dependabot proposes its bumps. It is the container the kill switch lives in, and the watchdog relies on details of it (its healthcheck, `wget`, its log wording, the control-server route), so a new release is reviewed rather than picked up by whichever start happens next. `./stremio start`/`restart` best-effort pull the pinned image when it is missing; a failed or slow pull only logs a warning and gluetun boots from the image already on the host.
- Every service shares gluetun's network namespace and therefore one port space. `NAMESPACE_PORTS` in `src/stremioguard/config.py` is the registry; a test checks `docker-compose.yml` against it. Add a port there before giving a new service one.

## Useful commands

```bash
./stremio init
./stremio start
./stremio restart
./stremio stop
./stremio status
./stremio logs
./stremio check
```

Command guide:

- `./stremio init`
  Guided setup and safe re-init. Creates `.env` from `.env.example` when needed; later runs offer a redacted `.env` summary and can restart unchanged configuration without re-entering secrets. Declining reuse opens the guided editor with existing non-secret values as defaults. Generated `.stremio` files are runtime state, never a second configuration source.

- `./stremio start`
  Normal day-to-day entry point. If no Compose instance exists yet, it performs the safe first start automatically, then starts the supervised watchdog and returns to the shell. It is also the deploy step: it publishes the current `.env` and `docker-compose.yml` (see [What the stack runs from](watchdog.md#what-the-stack-runs-from)), so that is when an edit takes effect. A gluetun that is already running keeps its VPN server and is recreated only if its own configuration changed. A watchdog that is already running is left alone unless its unit, a forwarded setting or the published configuration changed. When `COMET_ENABLED=1`, it also prepares and starts Comet automatically.

- `./stremio restart`
  Reset/build/start flow. Runs `docker compose down --remove-orphans`, brings gluetun back up, rebuilds the local Stremio image, and starts Stremio again. When `COMET_ENABLED=1`, it also refreshes Comet runtime files and restarts Comet. It does not delete `stremio-data/`, `gluetun-data/`, or `.stremio/comet/`.

- `./stremio stop`
  Stops the watchdog unit first, then stops Stremio and Comet when enabled, so the watchdog does not immediately start them back up again. If the unit cannot be confirmed stopped, the services are still stopped and the command exits nonzero.

- `./stremio status`
  Shows gluetun health, the current public IP as seen from inside gluetun, any active lockout, the Stremio container status, and the watchdog unit's state and restart count. When `COMET_ENABLED=1`, it also shows Comet status and its observed network mode.

- `./stremio unlock`
  Shows an active lockout marker and, after confirmation, clears it without starting anything.

- `./stremio logs`
  Tails the latest host-side run log.

- `./stremio check`
  Runs the local development checks for the Python tooling in this repo.

## Stremio patch layer

The local Stremio image is built from a digest-pinned `tsaridas/stremio-docker` base image with a small patch layer.

- `STREMIO_APPLY_PATCHES=1`
  Keeps the compatibility fixes enabled. Turning it off restores upstream image behavior and removes the HTTPS redirect fix, local self-probe rewrite, favicon guard, and `/casting` stub.

- `STREMIO_SKIP_HW_PROBE=1`
  Prevents repeated `/device-info` requests from re-running noisy `qsv`, `nvenc`, and `vaapi` self-tests on every reconnect.

- `EXTERNAL_BASE_URL=https://your-public-domain`
  Optional. Keeps browser redirects and client-facing links on your public HTTPS origin. Leave it blank for local-only access so Stremio uses the host and port clients actually connect to.

- `INTERNAL_MEDIA_BASE_URL=http://127.0.0.1:11470`
  Keeps ffprobe and HLS self-references on loopback instead of probing back out through the reverse proxy.

- `STREMIO_HOST_PORT=11470`
  Host-side TCP port published by the generated Compose override. Maps each selected bind address as `<bind-address>:<STREMIO_HOST_PORT>:8080` (the Stremio image's Basic-Auth nginx, which proxies to internal port `11470`). Requires `STREMIO_USERNAME` and `STREMIO_PASSWORD` (12+ chars) unless `STREMIO_ALLOW_NO_AUTH=1`.

- `STREMIO_BIND_ADDRS=127.0.0.1`
  Comma-separated host interfaces for gluetun's published Stremio port. Use a LAN IP plus a Tailscale IP, such as `192.168.1.10,100.64.0.10`, for Tier 1 LAN + Tailscale access without binding on every interface. Set it empty to publish no host port, or use `0.0.0.0` only when you intentionally want every interface.

If you change `STREMIO_APPLY_PATCHES` after the image has already been built, run `./stremio restart` so Docker rebuilds the image with the new build arg.

## Python runtime

The wrapper runs the Python guard through `uv`, so Typer, Loguru, and the rest of the Python environment come from `uv.lock` instead of global `pip` packages.

If `uv` is missing, the wrapper installs it with uv's official installer, and on apt-based Linux it installs Docker (`docker.io`, through `sudo apt`) when that is missing. Set `INSTALL_MISSING_DEPS=0` to fail instead of installing anything.
