# Test quality

Line coverage says which code the suite *runs*. It does not say whether a test would fail if
that code were wrong. These three tools measure the second thing. All of them use only the
default suite (no Docker, no systemd) and leave the working tree unchanged, apart from mutmut's
`mutants/` folder, which is git-ignored.

| Tool | Question it answers | Time |
| :-- | :-- | :-- |
| `uv run mutmut run`, then `scripts/mutation_report.py` | If this code had a small bug, would any test fail? | about 15 min for two modules |
| `scripts/fix_site_coverage.py` | Before a fix, did passing tests already run the code that was wrong? | about 2 min per fix commit |
| `scripts/test_overlap.py` | Which tests run exactly the same code as another, and which are the only ones to reach some branch? | about 2 min |
| `tests/docker_fake.py` and its contract test | Does the test's Docker behave like real Docker? | about 25 s |

## Mutation testing

[mutmut](https://github.com/boxed/mutmut) makes many small deliberate bugs (mutants) in the files
listed under `only_mutate` in `[tool.mutmut]` (`pyproject.toml`) and runs the tests that reach
each one. A mutant is *killed* when a test fails, *survives* when the whole suite still passes,
and has *no tests* when no test calls the function at all.

```bash
uv run mutmut run --max-children 6            # resumable: rerun to continue
uv run python scripts/mutation_report.py      # score per module, functions by survivors
uv run python scripts/mutation_report.py --logic-only
uv run python scripts/mutation_report.py --logic-only --function stop_gluetun --diffs 20
```

To check another domain, change `only_mutate` and delete `mutants/` first.

Reading the report:

- `--logic-only` leaves out mutants that change only string literals, such as a log message or
  an error's wording. Most of those survive harmlessly.
- Some logic survivors are *equivalent*: the change has no observable effect. For example,
  dropping `mode=0o600` from `atomic_write_text` is equivalent, because `0o600` is already the
  default. Read the diff before writing a test.
- A survivor in a decision (a comparison, `and`/`or`, a fallback, `check=True`, a timeout, a
  read limit) means that behaviour is executed but nothing asserts it. Those are the ones worth
  a test.
- If mutmut stops at "Failed to run clean test", delete `mutants/` and run again. mutmut runs
  pytest inside its own process, and a resumed run can trip over state a previous run left
  behind (seen with `test_ac12e_malformed_state_exits_1_via_fail_without_traceback`).

## Fix-site coverage

```bash
uv run python scripts/fix_site_coverage.py                    # every fix: commit touching src/
uv run python scripts/fix_site_coverage.py --since v0.4.1
uv run python scripts/fix_site_coverage.py 284339d 04cc9e4
```

For each fix, the script exports the parent commit, runs its default suite under coverage, and
counts the fix's hunks whose pre-fix lines were executed. A high share means the tests ran the
defective code without asserting the property the fix restored. After an audit, the goal is
that findings land where tests *fail*, not just where they run. Hunks include refactoring that
landed with each fix, so the share is approximate.

## Test overlap

```bash
uv run python scripts/test_overlap.py --show-groups 5 --show-unique
```

Tests with identical or subset footprints are only *candidates* for removal. Two tests can run
the same path with different inputs, which is deliberate for spelling variants such as line
separators or address forms. A test is redundant only if mutation testing shows it kills no
mutant that another test does not also kill.

## Faking Docker

Tests that need Docker to *behave* use `FakeDocker` (`tests/docker_fake.py`) instead of stubbing
StremioGuard's own functions. Each container has a state (running, restarting, paused, exited,
created), queries answer from that state the way Compose does, and stops change it. So a test
judges what the code concludes from Docker, not which call it sent. A test that mocked
`container_running` hid a real bug: a crash-looping gluetun read as stopped.

```python
docker = FakeDocker(tmp_path, {"gluetun": "restarting", "comet": "running"})
docker.on_stop("gluetun", compose="comes-back")  # or "fails", "hangs"
guard = GluetunGuard(make_config(tmp_path), docker, frozen=True)
guard.stop_gluetun()
assert docker.state("gluetun") == "exited"
```

The fake's answers are a claim about Docker, so they are checked against it:
`tests/test_docker_fake_contract_docker.py` (`STREMIOGUARD_DOCKER_TESTS=1`, about 25 s) starts a
throwaway project with a container in each state, asks the guard the same questions through
real Docker and through the fake, and requires the same answers. Two assumptions in the first
draft of the fake failed that check:

- `docker compose ps` with a name that is not a service exits 1 ("no such service"); it does not
  answer "nothing running". The guard reads it as unknown, which is the safe reading.
- `compose config --services` works with the daemon down, because it only reads the files.

Moving the stop-path tests onto the fake found a gap the old script hid: the `docker stop`
fallback looked containers up with `docker compose ps -q`, so when Compose could not read the
project nothing could be stopped. The old test let `compose config` fail while `compose ps`
answered, which real Docker never does. The fallback now finds containers by Compose's labels,
and the contract test proves it against a broken Compose file and a second stack with a service
of the same name.

Rules:

- The fake fails the test on any command it does not model (`UnmodelledCommandError`), and on a
  hanging command sent without a timeout. Extend the model and the contract test together.
- `compose_unreadable=True` (every `docker compose` command fails, plain `docker` still works)
  is recorded behaviour and part of the contract.
- Injected failures (`fails`, `comes-back`, `hangs`, and `slow()` for a daemon whose next calls
  hang) cannot be produced on demand against real Docker, so they are not part of the
  contract. Keep them to plain exit codes and timeouts.
- Tests whose subject *is* the command sent, or a malformed answer from Docker (the `ps`
  parser tests), stay on exact-command `FakeRunner` scripts: there the script is the point.
- `removing` is modelled by analogy with the other states, because it is too short-lived to
  record.
- A fake that answers more conveniently than Docker inflates the mutation score. The first
  `stop_gluetun` fake listed an exited container in `ps -q`, which real Docker never does.

### Whole watchdog scenarios

The orchestrator's unit tests replace the guard's answers ("the stop worked", "gluetun is unhealthy")
with `mock.patch.object(..., autospec=True)`, which is the right way to cover its decisions; `autospec`
makes every replacement accept exactly what the real method accepts. What those tests cannot see is
the two running together, so `tests/test_watchdog_scenarios.py` runs the real orchestrator and guard
against `FakeDocker` and asserts what Docker ends up doing. The first of them found that the outage
path's `compose restart gluetun` also started the services it had just stopped; the contract test
pins that Compose behaviour, and the restart now passes `--no-deps`.

## Baseline (2026-11-19, `3dd6508`)

| Measure | Result |
| :-- | :-- |
| Default suite | 1111 passed, 70 skipped (every skip is a real-Docker or systemd test) |
| Fix sites already executed before the fix, 17 fix commits | 615 of 678 (91%) |
| Tests with an identical footprint to another test | 344, in 89 groups |
| Tests that are the only one to reach some branch | 346 |
| Mutation score, `guard.py` | 67% overall, 76% for logic mutants (740 of 968) |
| Mutation score, `comet_gateway.py` | 67% overall, 76% for logic mutants (315 of 415); `status()` has no tests |

The first run's real gaps (an untested crash-looping gluetun stop, `EXPECTED_VPN_IP`
enforcement, failed nginx reloads, the IP probe's bounds and others) and the tests that closed
them are listed in the [v0.4.3 changelog](changelogs/v0.4.3.md). After those tests, every
remaining logic survivor in the functions they cover is equivalent or only changes logging.
