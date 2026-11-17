# Changelogs

One file per release, named after its git tag. The changelog starts at v0.4.0; earlier releases,
up to v0.3.53, exist only as tags (`git tag -l 'v*'`).

| Release | Date | About |
| :-- | :-- | :-- |
| [v0.4.0](v0.4.0.md) | 2026-11-16 | security release: audit fixes, hardened containers, supervised watchdog, automated Comet and Stremio updates |

## Cutting a release

1. Pick the number: a breaking change to `.env`, commands or deployment bumps the minor version
   while it is 0, a new feature bumps the minor, a fix bumps the patch.
2. Write `v<version>.md` here, with an "Upgrading" section whenever the owner has to act, and add
   it at the top of the table above.
3. Set `version` in `pyproject.toml`, run `uv lock --offline`, and commit both with the release.
4. Tag the commit: `git tag -a v<version> -m "StremioGuard v<version>: <summary>"`.
