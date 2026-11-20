# StremioGuard documentation

## Guides

| Page | Read it for |
| :-- | :-- |
| [setup.md](setup.md) | requirements, `./stremio init`, VPN providers, the first run, WSL2 |
| [operations.md](operations.md) | every `./stremio` command, what a start does, restart policy, the Stremio patch layer |
| [watchdog.md](watchdog.md) | how the tunnel is verified, failing closed, lockouts and recovery, systemd supervision, alerts, boot |
| [comet.md](comet.md) | Comet's sources, digest pinning and updates, the token gateway overview |
| [secure-access.md](secure-access.md) | reaching the stack from outside: the three access tiers, Tailscale Serve, Stremio raw-nginx reference |
| [rootless-docker.md](rootless-docker.md) | what differs under a rootless Docker daemon |

## Reference

| Page | Contents |
| :-- | :-- |
| [security-model.md](security-model.md) | the exact egress boundary, container/host hardening, defence in depth, inbound threat model |
| [comet-gateway.md](comet-gateway.md) | the gateway's URL model, route allowlist, reverse-proxy setup, Cloudflare Access owner portal, rate limits, log canary |
| [comet-patches.md](comet-patches.md) | all 16 declarative Comet patches, requirements, canary validation contract, heuristics and tradeoffs |
| [lab.md](lab.md) | testing the gateway and patches against real containers (`scripts/lab.py`) |
| [test-quality.md](test-quality.md) | whether the tests would catch a bug: mutation testing, fix-site coverage, test overlap |
| [changelogs/](changelogs/README.md) | what changed in each release |
