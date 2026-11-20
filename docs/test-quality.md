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
