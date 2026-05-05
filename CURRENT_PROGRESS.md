# Current Progress

This project is a Stremio orchestration layer that runs Stremio behind
`gluetun`, keeps it stopped when the VPN path is unhealthy, and guides setup
for a secure network shape. The CLI entrypoint is now modular: `./stremio`
drives `src/stremioguard`, while `stremioguard.orchestrator` owns Docker
lifecycle and watchdog behavior. The optional Comet subsystem is now unified
into the same Docker product instead of being treated as a separate stack.

## Mental model

- `src/stremioguard/cli.py` is the user-facing wrapper.
- `src/stremioguard/orchestrator.py` runs the guard daemon commands.
- `src/stremioguard/guard.py` contains Docker, gluetun, and IP-safety logic.
- `src/stremioguard/init.py` and `src/stremioguard/nordvpn.py` own guided setup.
- `src/stremioguard/env.py` and `config.py` centralize configuration parsing.
- `src/stremioguard/comet.py` owns vendored Comet repo management, runtime env
  generation, doctor checks, and playback probing.
- `src/stremioguard/publishing.py` owns the shared gluetun-published service
  override generation used by both Stremio and Comet.

The project assumes Stremio itself is not an auth boundary. Security is
achieved by controlling where the service binds, what network can reach it, and
whether a reverse proxy or tailnet is in front of it.

Comet is no longer treated as "just another addon URL." In this project it is
part of the relay and compatibility story, so setup now includes optional
managed Comet patches that are generated locally and mounted into the container
at runtime instead of being hand-edited in place.

## Current network model

`STREMIO_BIND_ADDRS` is the single source of truth for host publishing.
`STREMIO_HOST_PORT` and `COMET_HOST_PORT` are separate host-side ports, but
they publish on the same host interfaces through `gluetun`.

The guard generates `.stremio/docker-compose.bindings.yml` at runtime and uses
it as a Compose override. Raw `docker compose up` does not publish the Stremio
or Comet ports by default. The intended secure default is fail-closed loopback
until `./stremio init` configures real bind addresses.

Tier 1 is LAN plus Tailscale direct access. Tier 2 is tailnet-only domain
access through a reverse proxy. Tier 3 is public reverse-proxied access. The
secure-access runbook in `docs/secure-access.md` reflects this current model.

In practice, the current proven path is:

- LAN Stremio over local HTTP
- Tailscale-facing Stremio over `tailscale serve` HTTPS
- LAN Comet over local HTTP
- Tailscale-facing Comet over `tailscale serve` HTTPS

For local clients, media ingress from the debrid/CDN side can stay WAN-in only
once and then return over LAN. For remote clients, the server still acts as a
real relay and therefore downloads once and uploads once.

## Learned behaviors

- Reverse proxies like Nginx Proxy Manager route by hostname, not bare IP.
  Bare `http://<public-ip>` or `http://<tailscale-ip>` requests may hit the
  NPM default site on port `80`.
- Disabling WAN port `80` forwarding does not affect direct Tailscale access to
  `:80`; that is local server exposure, not router forwarding.
- Stremio debrid playback can bypass the local streaming server if an addon
  returns directly playable HTTP URLs. A true relay layer is needed if the goal
  is "every media byte goes through my server."
- Comet can satisfy the relay requirement only if two things are both true:
  proxy playback is configured correctly, and Comet's outbound HTTP fetches
  share the `gluetun` VPN namespace.
- VPN egress quality matters materially for Comet. A bad VPN exit can make the
  proxy path appear broken even when the logic is correct; pinning a closer
  NordVPN city dramatically improved throughput in testing.
- Tailscale Serve solves the HTTPS requirement cleanly, but it is still a
  rough operator-facing auth model for end users. It works well as a secure
  transport, but it is not the final user-facing access story.
- Native Torrentio parity inside Comet is not automatic. Comet needed managed
  compatibility patches in three areas:
  - Torrentio resolved-result ingestion
  - episode-in-pack preservation
  - title-compatibility filtering that trusts resolved file evidence more than
    noisy outer torrent titles

## Current direction

The current direction is a unified `gluetun + Stremio + Comet` deployment. The
key thing to validate is not just addon reachability, but whether playback URLs
point back to the server in proxy-stream mode so the real media path is:

`client -> Tailscale/server -> Comet relay -> debrid provider`

That subsystem is still exposed through `./stremio comet ...` for advanced
operations, but the root `./stremio` commands now auto-manage it when
`COMET_ENABLED=1`. The vendored checkout remains under `vendor/comet`, runtime
state remains under `.stremio/comet/`, and `probe-playback` still fails if it
observes a direct provider redirect when proxy mode is expected.

Comet patching is now standardized. Override files are generated from
`src/stremioguard/comet_overrides.py` through
`scripts/generate_comet_overrides.py`, written under `.stremio/comet/`, and
mounted read-only into the running Comet container. The main managed override
areas today are:

- formatter cleanup for TV readability
- stream-name cleanup
- Torrentio scraper compatibility
- episode-pack preservation
- title-compatibility filtering

The current matching philosophy is "resolved-file-first, evidence-based
permissiveness" rather than one-off hardcoded title exceptions.

Important boundary: phase 1 proves debrid video proxy behavior only. It does
not prove that every subtitle, manifest, or auxiliary playback request stays on
the server path.

## Next phase

The next major direction is authentication and authorization in front of a
plain HTTPS domain so end users do not have to be walked through Tailscale as
the primary access UX. The likely target shape is:

`user -> HTTPS domain -> authenticated reverse proxy -> Stremio/Comet relay`

The intent is to explore secure options that preserve the relay model while
letting Nginx or another front door handle the user-facing domain and auth
layer more naturally than the current tailnet-only operator flow.

## Development preferences

- Prefer lean, modular code over compatibility layers.
- Treat this project as beta: avoid legacy shims unless they are essential.
- Prioritize security posture, tailnet-first access, and explicit trust
  boundaries.
- Favor small, focused tests close to the module being changed.
- Keep operational UX clear: good prompts, good error messages, fail closed.
- Before building custom debrid relay logic, evaluate whether Comet satisfies
  the exact proxy-stream requirement.

## Commit message preference

Use the local Codex skill at
`/home/seven/.codex/skills/commit-message-style/SKILL.md`.

In short:
- subject line: 8-12 words
- explanation section: short human paragraphs about why and what changed
- categorical section: group changed files or folders in backticks
