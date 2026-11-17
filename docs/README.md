# StremioGuard documentation

## Guides

| Page | Read it for |
| :-- | :-- |
| [setup.md](setup.md) | requirements, `./stremio init`, VPN providers, the first run, WSL2 |
| [operations.md](operations.md) | every `./stremio` command, what a start does, restart policy, the Stremio patch layer |
| [watchdog.md](watchdog.md) | how the tunnel is verified, failing closed, lockouts and recovery, systemd supervision, alerts, boot |
| [comet.md](comet.md) | Comet's sources and patches, digest pinning and updates, the token gateway |
| [secure-access.md](secure-access.md) | reaching the stack from outside: the three access tiers, step by step |
| [tailscale-runbook.md](tailscale-runbook.md) | Tier 1 access through Tailscale Serve |
| [rootless-docker.md](rootless-docker.md) | what differs under a rootless Docker daemon |

## Reference

| Page | Contents |
| :-- | :-- |
| [security-model.md](security-model.md) | the exact egress boundary, defence in depth, the inbound threat model |
| [comet-gateway.md](comet-gateway.md) | the gateway's URL model, routes, reverse-proxy setup, rate limits and log hygiene |
| [comet-patches.md](comet-patches.md) | each Comet patch: what it changes and why |
| [nginx-allowlist.conf](nginx-allowlist.conf) | a raw nginx server block for Tier 2 and 3 |
| [lab.md](lab.md) | testing the gateway and patches against real containers |
| [changelogs/](changelogs/README.md) | what changed in each release |

## Design notes

Plans and records of past work, kept for their reasoning:
[implementation-plan.md](implementation-plan.md),
[egress-log-hygiene-plan.md](egress-log-hygiene-plan.md),
[rtn-rank-display-evolution-plan.md](rtn-rank-display-evolution-plan.md).
