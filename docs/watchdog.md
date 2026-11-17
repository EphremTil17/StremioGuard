# Watchdog

How the watchdog verifies the tunnel, fails closed, logs and alerts; how systemd supervises it; what the stack runs from; the leak baseline; and starting at boot.

## Logging and watchdog behavior

Each `./stremio start` creates a host-side run log under `logs/`, named like `logs/stremio-20260424-221500.log`. The startup command and background watchdog share that file, so one run captures gluetun health checks, public IP observations, container lifecycle events, drops, and periodic watchdog summaries.

Use `./stremio logs` to tail the latest run log. Crashes that happen before logging is set up land in the journal instead: `journalctl --user -u stremioguard-watchdog.service`.

The watchdog polls gluetun health and the egress IP every 10 seconds by default. Set `WATCH_INTERVAL_SECONDS` in `.env` (or for one run, `WATCH_INTERVAL_SECONDS=5 ./stremio start`) for faster checks, or a larger value for less polling.

Additional watchdog parameters:
- `PUBLIC_IP_FAILURE_THRESHOLD`: The number of consecutive failed public IP checks (returning `UNKNOWN` status) before the watchdog shuts down the stack to fail closed (default: `3`).
- `EGRESS_PROBE_INTERVAL_SECONDS`: How long a verified tunnel egress IP is trusted before the watchdog re-probes it live and re-compares it with this host's direct IP (default: `300`). This bounds leak-detection latency. Recovery after a VPN outage always re-probes immediately. Gluetun's control-server IP is only fetched once per gluetun start and goes stale after an in-tunnel reconnect, so it is only a change trigger (ignored if non-public), and a difference between it and the live egress is logged once and never stops services.
- `VPN_RECOVERY_BUDGET_SECONDS` / `VPN_RESTART_CADENCE_SECONDS`: How long the watchdog keeps restarting an unhealthy gluetun (default: `300`, every `45` seconds) before it trips the circuit breaker.
- `MAX_AUTO_STARTS_PER_HOUR`: How many times the watchdog may start the services on its own within an hour before it treats the cycle as a fault and trips the circuit breaker (default: `10`; `0` disables the limit).

What the watchdog trusts and how NordVPN resolution is bounded:

- **IP-check services:** on each path (inside gluetun and directly from this host), the first configured `IP_CHECK_URLS` endpoint that answers a global unicast (public) address is believed, with no consensus between services. Non-public answers (private, loopback, CGNAT, multicast, reserved, link-local, site-local, or zone-suffixed) count as failures and move to the next URL. A service that lies (returning any public address other than this host's) can make a real leak look `SAFE`, while one that returns this host's address for the tunnel can force a lockout. Both paths send identical HTTP request heads (`User-Agent: Wget/1.25.0`, `Accept: */*`, `Accept-Encoding: identity`, `Connection: close`), though their TLS handshakes and source addresses still differ, and the host probe reveals this host's address to the IP-check services.
- **NordVPN endpoint resolver:** when NordVPN is selected without `SERVER_HOSTNAMES`, a cached endpoint in `.stremio/nordvpn-endpoint-cache.json` is reused for 1 hour, and as a fallback after a failed live API query for at most 24 hours (ignoring future-dated, malformed, non-public, or non-regular files). Past 24 hours, the resolver returns nothing and gluetun chooses its own server.

Log summaries are decoupled from the poll cadence. A window in which something happened (an outage, an automatic start, a namespace repair, a failed IP check, a loop error or a new public IP) is summarized every `WATCHDOG_LOG_INTERVAL_SECONDS` (default 5 minutes); a quiet one only once an hour, as a heartbeat (`0` logs every tick). Warnings for a failure that persists, such as an unreachable public-IP checker, repeat at most every 5 minutes, while the fail-closed stop itself still runs on every check. All of these can live in `.env`. A value exported in your shell reaches the supervised watchdog only because `./stremio start` forwards a fixed list of known keys to `.stremio/watchdog.env`; anything else exported in the shell does not. Changing a forwarded value and rerunning `./stremio start` restarts the watchdog to apply it.

On a bad signal, the watchdog fails closed:

- **gluetun unhealthy:** it stops the protected services, copies gluetun's recent log into the run log (recreating the container deletes it), restarts gluetun every `VPN_RESTART_CADENCE_SECONDS` (widening a narrow server filter to the whole country halfway through the budget), and resumes services once gluetun is healthy and a fresh egress probe passes. If the budget runs out, it trips the circuit breaker: it writes the lockout marker `.stremio/vpn-lockout`, stops the services and gluetun, and exits with status 78.
- **credentials rejected:** providers answer `AUTH_FAILED` for a connection limit or a busy server as well as for bad credentials, so one sighting only logs a warning. Seen again after gluetun has been restarted onto another server, it trips the circuit breaker (`auth_rejected`).
- **leak verdict** (the tunnel egress equals this host's own address, the saved home baseline, or differs from `EXPECTED_VPN_IP`): it stops the protected services at once. A second verdict within 24 hours trips the circuit breaker (`egress_leak`), whether or not passing checks came between them (the 24-hour leak history is kept in memory and resets when the watchdog restarts); a leak means the kill switch did not hold, so resuming is your decision. After `PUBLIC_IP_FAILURE_THRESHOLD` consecutive *unknown* results it stops the services and keeps checking.
- **gluetun restarted on its own** (a crash, an OOM kill, a manual `docker restart`): services that joined its previous network namespace still look healthy but can reach nothing. The watchdog compares each service's start time and namespace with gluetun's and restarts the ones left behind.
- **stop/start loop:** more than `MAX_AUTO_STARTS_PER_HOUR` automatic starts trips the circuit breaker (`service_flapping`), whatever the cause.

The lockout marker records the reason and the evidence behind it (for example the log line, or how long gluetun stayed unhealthy); `./stremio status` shows both.

Restarting services never touches gluetun (`docker compose up --no-deps`), so the tunnel that was just verified is the one they join.

## What the stack runs from

`./stremio start` and `./stremio restart` publish a generation under `.stremio/`: a copy of `docker-compose.yml` (`compose.base.yml`), a normalized snapshot of `.env` (`env.snapshot`), gluetun's share of it (`gluetun.env`), the generated override, and one patch bundle per Comet image digest (`comet/bundles/`). Containers are only ever created from that published generation (lifecycle commands publish first, and the watchdog refuses to start any container from an incomplete generation missing the override, `compose.base.yml`, or `env.snapshot`), so container settings come from `env.snapshot` rather than the working tree. Before the first start, or when the generation is incomplete, read-only queries and teardown fall back to the working tree's `docker-compose.yml` and `.env`. Editing `.env`, editing `docker-compose.yml` or running `git pull` therefore changes nothing in running containers until the next start or restart, and a mistake in an edit is reported by the command you ran, not by the watchdog during a later VPN recovery. The Comet commands (`./stremio comet start`, `comet update apply|rollback`, `comet token ...`) act on the running stack, so they read the published snapshot rather than `.env`: they change the Comet image, its bundle or the token map, and never deploy a pending edit. Note as a known limit that a variable of the same name exported in the environment of the process running Compose (your shell, for `./stremio`) still takes precedence over `env.snapshot` for Compose's `${…}` interpolation.

`.env` is read by one parser, and Compose only ever sees the normalized snapshot, so the two cannot disagree about a value. Lines end at `\n`, and CRLF is accepted; any non-comment line carrying another line separator or NUL (literally or via a `\n` or `\r` escape) is refused with its line number. Optional `export`, single or double quotes, `#` after whitespace starting a comment, and the last assignment of a key winning behave as usual, except that `$` is always literal (never expanded) and the supported double-quote escapes are `\t`, `\\`, `\"` and `\$` (producing a tab, `\`, `"` and `$`, as in Compose); a `\n` or `\r` escape is refused like a literal line break, and any other escape drops its backslash, unlike Compose.

The Python code itself still runs from the checkout. Run a deployment from a checkout you do not develop in (a tagged clone or `git worktree`), so a half-finished branch is never what the boot unit starts.

Commands that start, stop or recreate containers take one lock (`.stremio/stack.lock`). The watchdog holds it for each check and stands aside while a CLI command holds it, for at most ten minutes; it keeps checking for a leak meanwhile and stops the services on a definitive verdict without waiting.

## Alerts

Set `STREMIO_ALERT_URL` in `.env` to an HTTP(S) endpoint to be told about events that otherwise only reach the run log: a lockout, a leak verdict, the fail-safe running, a watchdog that keeps failing, and gluetun restarting on its own. Each is one plain-text `POST` with ntfy-style `Title`/`Priority`/`Tags` headers (an [ntfy](https://ntfy.sh) topic URL works as is; other webhooks ignore the headers). Alerts never contain an IP address or a secret, repeat at most every 15 minutes per event, and are best-effort: delivery is not retried and a failure only logs a warning. The request leaves from this host's own connection, not through the tunnel, because an alert about a dead VPN cannot depend on the VPN.

## Watchdog supervision

`./stremio start` writes three systemd user units to `~/.config/systemd/user/` and keeps them in sync on every start:

| Unit | Role |
| :-- | :-- |
| `stremioguard-watchdog.service` | Runs the watchdog. It reports ready once it is actually watching, then sends a heartbeat before every bounded step of a check and after every completed check. |
| `stremioguard-failsafe.service` | Runs only when the watchdog unit fails for good. It writes a `watchdog_unstable` lockout (keeping any existing marker), stops the protected services, and checks with Docker that they really stopped. |
| `stremioguard.service` | Opt-in boot unit that runs `./stremio start` after Docker comes up. |

Because the watchdog runs in your user's service manager, it no longer belongs to whatever started it. Closing an SSH session or terminal, or ending an automation job, does not kill it.

What happens when the watchdog stops unexpectedly:

1. **Crash, or no heartbeat for 5 minutes** (`WatchdogSec=300`): systemd kills it with `SIGABRT` and restarts it after 5s, then about 10s, 20s, 40s and so on, up to 5 minutes between attempts. The watchdog sends a heartbeat right before each bounded step of a check (each Docker call, each host IP probe, the NordVPN server query, each alert) and after each completed check, so a long check during an outage, a leak stop or a lockout stays supervised however many steps it takes. Every step has its own wall-clock bound: `30`s for Docker queries, `240`s for Compose mutations, `PUBLIC_IP_TIMEOUT_SECONDS` plus `2`s for each IP probe inside the tunnel and `PUBLIC_IP_TIMEOUT_SECONDS` for each host IP probe (default `8`, capped at `60`), `8`s for the NordVPN query and `5`s for an alert; the last three cover DNS, connecting, TLS and the whole response. The longest step, `240`s, leaves a 60-second margin. A step that hangs past its bound, or code that stops reaching the next step, sends nothing, and systemd kills the watchdog 5 minutes after the last heartbeat. A check that never ends stops sending heartbeats one hour after it started. After a failed check nothing is sent until the next check starts (`WATCH_INTERVAL_SECONDS` later), and after three failed checks in a row nothing is sent until one succeeds, so a watchdog that keeps failing still goes silent, is restarted, and ends with the fail-safe as described in 2. In `tests/test_worst_case_tick.py`, where every call takes its full timeout, one check takes `480`–`1884`s and the watchdog is never silent for more than `240`s (`250`s right after a failed check). Only a DNS lookup can outlive its step; it finishes in a background thread that holds no connection.
2. **Restart-budget limits and in-memory state:** the 24-hour leak history, the recovery budget, the auto-start count, and the auth-rejection generation count all live in memory and reset whenever the watchdog process restarts (crash, `WatchdogSec` kill, a `./stremio start` that changed its configuration, or reboot). Systemd hands over to the fail-safe unit only after the seventh start within an hour (`StartLimitBurst=6` in `StartLimitIntervalSec=3600`), so restarts spaced more than about 10 minutes apart continue indefinitely, each with fresh bounds. That bounds the time without a watchdog during a continuous loop to roughly 5 minutes for a crash loop, or roughly 35 minutes for a hang loop (each attempt waiting out the 5-minute `WatchdogSec=`). `./stremio start` and the boot unit reset the units' failed state.
3. **Exit status 78** (circuit breaker or an existing lockout): no restart. The fail-safe runs and keeps the original lockout reason.

While a lockout marker exists—or while `stremioguard-failsafe.service` is `failed` or `activating` (for example, if the fail-safe could not write the marker to disk)—`./stremio start`, the boot unit, and the watchdog itself all refuse to run (exit 78). Note that systemd forgets a failed unit state across a reboot, so a lockout whose marker could never be written to disk does not survive a host reboot. Recover deliberately with `./stremio restart`, which clears any existing lockout marker once the reset runs (even if VPN preflight fails, handing bounded recovery back to the watchdog, which writes a fresh marker if the VPN does not recover) and resets the failed units after a successful restart; or inspect and clear the marker with `./stremio unlock`.

Start at boot:

```bash
systemctl --user enable stremioguard.service
```

If you used the older `@reboot ./stremio start` cron entry or a hand-installed `stremio-vpn-watch.service`, remove them. The CLI warns while the old unit file is present. A watchdog started by a pre-systemd version is stopped automatically on the next `./stremio start`, `restart` or `stop`.

Without systemd, run `uv run python -m stremioguard.orchestrator start` and keep `uv run python -m stremioguard.orchestrator watchdog` running under a supervisor of your own.

## Leak baseline

For an extra check, while gluetun is stopped (or has not been brought up yet) and you are on your normal home connection, run:

```bash
./stremio record-home-ip
```

This saves your non-VPN public IPv4 address to `.stremio/home-ip` (refusing if no IP-check service returns a public IPv4 address). The guard already compares the tunnel egress with this host's live direct IP; the baseline is used **only** as the fallback when that host-side lookup fails. A baseline entry that is not a small regular file (<= 256 bytes; never a symlink, FIFO, or directory) holding a public address counts as missing (`./stremio status` reports it as unusable and asks you to re-run `record-home-ip`), so it can never produce a `SAFE` verdict. Without a valid host probe or baseline, the check returns `UNKNOWN` and repeated `UNKNOWN`s stop services. The command refuses to run while gluetun is healthy, since that would record a VPN IP as home.

If your VPN endpoint has a stable IP, you can make the check stricter:

```bash
EXPECTED_VPN_IP=1.2.3.4 ./stremio start
```

## Start automatically (Persistent Boot Setup)

Run `./stremio start` once (it installs the units), then enable the boot unit:

```bash
systemctl --user enable stremioguard.service
```

It starts after your user's Docker service and runs the same `./stremio start`, so the lockout check, the VPN verification and the supervised watchdog all apply at boot. Lingering (`loginctl enable-linger $USER`) is what starts your user's service manager at boot without a login. See [Watchdog supervision](#watchdog-supervision) for how crashes are handled.
