# Running this stack under rootless Docker

Optional, and unrelated to normal setup — `./stremio init` does not need it.
Under a rootless daemon a container escape lands on an unprivileged UID rather
than host root, which is worth something here because the stack runs
third-party application code (Comet) that this repo patches at runtime.

Install the daemon by following [Docker's rootless mode
docs](https://docs.docker.com/engine/security/rootless/); nothing about that is
specific to this project. What follows is only the parts that are.

## gluetun works, with one caveat

`--cap-add NET_ADMIN` and `--device /dev/net/tun` both work unprivileged: runc
bind-mounts the device node instead of calling `mknod`, so OpenVPN connects
normally.

WireGuard needs one addition. `/proc/sys` is read-only in a rootless container,
so `wg-quick`'s `sysctl -w net.ipv4.conf.all.src_valid_mark=1` fails. Pass it at
container creation instead, where runc applies it before the read-only remount:

```yaml
services:
  gluetun:
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
```

OpenVPN (`VPN_TYPE=openvpn`) is unaffected.

## The Comet Postgres directory has mixed ownership

Rootless Docker maps container UIDs into your subuid range: container `0`
becomes your own UID, and container `N` becomes `subuid_base + N - 1`, where
`subuid_base` is the first field for your user in `/etc/subuid`.

`.stremio/comet/postgres-data` is the one bind mount that needs care, because
it is **not** uniformly owned — the Postgres image uses one UID for the data
files and another for the directories above them. Chowning the tree to a single
UID looks right and stops Postgres from starting. Shift each one separately:

```bash
PG=.stremio/comet/postgres-data
base=$(awk -F: -v u="$USER" '$1==u{print $2; exit}' /etc/subuid)
for id in $(sudo find "$PG" -printf '%U\n' | sort -u); do
    sudo find "$PG" -uid "$id" -exec chown -h "$((base + id - 1))" {} +
done
for id in $(sudo find "$PG" -printf '%G\n' | sort -u); do
    sudo find "$PG" -gid "$id" -exec chgrp -h "$((base + id - 1))" {} +
done
```

Then confirm the *container's* view is unchanged from before the move — that is
the invariant that matters:

```bash
docker exec <postgres-container> ls -lan /var/lib/postgresql/
```

Reverse it by subtracting `base - 1` instead of adding it. Everything else the
stack bind-mounts is owned by container root, which maps to you, so a plain
`chown -R "$USER:$USER"` covers it.

## Published ports stop bypassing your firewall

A rootful daemon publishes ports with iptables DNAT, so packets reach the
container through the `FORWARD` chain — which is why a published port is often
reachable even though the host firewall was never told about it. Rootless
publishes an ordinary userspace socket, so the same traffic arrives on `INPUT`
instead.

If your firewall default-denies inbound, `COMET_GATEWAY_HOST_PORT` becomes
unreachable the moment you switch, and every container stays healthy while the
reverse-proxied path returns errors. Add an explicit rule scoped to whatever
needs to reach it, for example with ufw:

```bash
sudo ufw allow proto tcp from <proxy-subnet> to <bind-address> port <gateway-port>
```

This is worth doing deliberately rather than resenting: the rule that was never
needed before was never needed only because Docker was quietly bypassing the
firewall.

One asymmetry that saves rules: a caller that is *itself* a rootless container
reaches host ports over the loopback path and needs no rule. Only rootful
callers and external clients do.

## `.stremio/daemon-id`

Written on first start, holding the ID of the daemon the stack was created
under; `./stremio` refuses to run against a different one.

Both daemons on a host see the same bind mounts, and `docker context use` (or
sudo, which reads root's contexts rather than yours) decides which one a
command reaches. Starting the stack under the wrong daemon would point a second
Postgres at the live data directory, and `postmaster.pid` cannot detect the
first one across PID namespaces.

Delete the file to re-pin deliberately, after confirming the old stack is gone.

## After restarting the daemon, use `restart`

`systemctl --user restart docker` leaves existing containers with no network
attached. Starting one from that state produces a container with no default
route, which surfaces as an application error rather than a networking one.
`./stremio restart` recreates the containers; `./stremio start` reuses them.
