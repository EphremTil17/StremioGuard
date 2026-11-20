#!/usr/bin/env python3
"""Summarise a mutmut run: mutation score per module and the functions where mutants survive.

A mutant is a small deliberate bug (a flipped comparison, a changed constant, a
dropped argument). "Killed" means some test failed on it; "survived" means the
whole suite still passed, so that behaviour is executed but not asserted.
"No tests" means no test even reaches the mutated function.

Run the mutation pass first (scope is ``only_mutate`` in ``[tool.mutmut]``):

    uv run mutmut run --max-children 6     # resumable; rerun to continue
    uv run python scripts/mutation_report.py
    uv run python scripts/mutation_report.py --function running_services --diffs 5

Not every survivor is a gap: equivalent mutants (a change with no observable
effect, such as a log message's wording) survive by definition. Read the
diffs before writing a test.
"""

from __future__ import annotations

import argparse
import collections
import difflib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STATUS = {
    1: "killed",
    3: "killed",
    37: "killed",
    0: "survived",
    5: "no tests",
    33: "no tests",
    36: "timeout",
    -24: "timeout",
    34: "skipped",
    None: "not checked",
}
NAME = re.compile(r"^(?P<module>.+?)\.(?:x_|xǁ)(?P<func>.+)__mutmut_\d+$")


def load(mutants_dir: Path) -> list[tuple[str, str, str, str]]:
    """(mutant key, module, function, status) for every mutant mutmut recorded."""
    rows = []
    for meta in sorted(mutants_dir.rglob("*.py.meta")):
        data = json.loads(meta.read_text())
        for key, code in data.get("exit_code_by_key", {}).items():
            m = NAME.match(key)
            module, func = (m.group("module"), m.group("func")) if m else (key, "?")
            func = func.replace("ǁ", ".")  # mutmut's class-method separator
            rows.append((key, module, func, STATUS.get(code, "suspicious")))
    return rows


def _tokens(source: str) -> list[tuple[int, str]]:
    import io
    import textwrap
    import tokenize

    skip = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}
    toks = tokenize.generate_tokens(io.StringIO(textwrap.dedent(source)).readline)
    return [(t.type, t.string) for t in toks if t.type not in skip]


def classify(mutants_dir: Path, diffs: dict[str, str] | None = None) -> dict[str, str]:
    """Mutant key -> "text" when only string literals differ from the original, else "logic".

    Text-only mutants mostly alter log or error wording; a survivor there is
    usually harmless. Logic mutants change a comparison, constant, call or
    control flow, so a logic survivor is behaviour no test pins down.
    """
    import ast
    import tokenize

    string_types = {tokenize.STRING}
    for name in ("FSTRING_MIDDLE", "TSTRING_MIDDLE"):
        if hasattr(tokenize, name):
            string_types.add(getattr(tokenize, name))
    kinds: dict[str, str] = {}
    for py in sorted((mutants_dir / "src").rglob("*.py")):
        if not py.with_suffix(".py.meta").exists():
            continue
        source = py.read_text()
        lines = source.splitlines(keepends=True)
        module = ".".join(py.relative_to(mutants_dir / "src").with_suffix("").parts)
        funcs = {
            node.name: "".join(lines[node.lineno - 1 : node.end_lineno])
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and "__mutmut_" in node.name
        }
        for name, body in funcs.items():
            base, _, suffix = name.rpartition("__mutmut_")
            if suffix == "orig" or not suffix.isdigit():
                continue
            original = funcs.get(f"{base}__mutmut_orig")
            if original is None:
                continue
            a = _tokens(original.replace(f"{base}__mutmut_orig", "F", 1))
            b = _tokens(body.replace(name, "F", 1))
            # Text-only: every changed token is a string literal, or a None/comma
            # standing in for one (mutmut also swaps literals for None or drops them).
            changed = [
                tok
                for op, i1, i2, j1, j2 in difflib.SequenceMatcher(
                    None, a, b, autojunk=False
                ).get_opcodes()
                if op != "equal"
                for tok in a[i1:i2] + b[j1:j2]
            ]
            text_only = any(t[0] in string_types for t in changed) and all(
                t[0] in string_types or t[1] in {"None", ","} for t in changed
            )
            kinds[f"{module}.{name}"] = "text" if text_only else "logic"
            if diffs is not None:
                diffs[f"{module}.{name}"] = "".join(
                    line
                    for line in difflib.unified_diff(
                        original.replace(
                            f"{base}__mutmut_orig", base.split("\u01c1")[-1].removeprefix("x_"), 1
                        ).splitlines(True),
                        body.replace(
                            name, base.split("\u01c1")[-1].removeprefix("x_"), 1
                        ).splitlines(True),
                        n=1,
                    )
                    if not line.startswith(("---", "+++"))
                )
    return kinds


def score(counter: collections.Counter) -> str:
    tested = counter["killed"] + counter["survived"] + counter["timeout"]
    if not tested:
        return "  n/a"
    return f"{100 * (counter['killed'] + counter['timeout']) / tested:4.0f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--mutants", type=Path, default=REPO_ROOT / "mutants")
    parser.add_argument("--top", type=int, default=25, help="functions to list by survivors")
    parser.add_argument("--function", help="only functions whose name contains this")
    parser.add_argument("--diffs", type=int, default=0, help="show N surviving mutants' diffs")
    parser.add_argument(
        "--logic-only",
        action="store_true",
        help="ignore mutants that change only string literals (log and error wording)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if not args.mutants.is_dir():
        print(
            f"no mutmut results in {args.mutants}; run `uv run mutmut run` first", file=sys.stderr
        )
        return 1
    rows = load(args.mutants)
    diffs: dict[str, str] = {}
    kinds = classify(args.mutants, diffs)
    if args.logic_only:
        rows = [r for r in rows if kinds.get(r[0]) != "text"]
    if args.function:
        rows = [r for r in rows if args.function in r[2]]

    by_module: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    by_func: dict[tuple[str, str], collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    text_survivors: collections.Counter = collections.Counter()
    for key, module, func, status in rows:
        by_module[module][status] += 1
        by_func[(module, func)][status] += 1
        if status == "survived" and kinds.get(key) == "text":
            text_survivors[module] += 1

    if args.json:
        print(
            json.dumps(
                {
                    "modules": {m: dict(c) for m, c in by_module.items()},
                    "functions": {f"{m}:{f}": dict(c) for (m, f), c in by_func.items()},
                    "survivors": [k for k, _, _, s in rows if s == "survived"],
                },
                indent=2,
            )
        )
        return 0

    print("score = killed / (killed + survived), over mutants some test reaches\n")
    print(
        f"{'module':40} {'mutants':>7} {'killed':>7} {'survived':>8} {'no tests':>8} {'score':>6}"
    )
    for module, c in sorted(by_module.items()):
        counts = f"{sum(c.values()):7} {c['killed']:7} {c['survived']:8} {c['no tests']:8}"
        print(f"{module:40} {counts} {score(c):>6}")
    if not args.logic_only:
        for module, n in sorted(text_survivors.items()):
            print(f"  {module}: {n} survivors change only string literals (see --logic-only)")
    unchecked = sum(c["not checked"] for c in by_module.values())
    if unchecked:
        print(f"\n{unchecked} mutants not checked yet: rerun `uv run mutmut run` to continue")

    ranked = sorted(by_func.items(), key=lambda kv: (-kv[1]["survived"], -kv[1]["no tests"]))
    print(f"\nfunctions by surviving mutants (top {args.top}):")
    print(f"{'survived':>8} {'killed':>6} {'no tests':>8} {'score':>6}  function")
    for (module, func), c in ranked[: args.top]:
        if not (c["survived"] or c["no tests"]):
            break
        where = f"{module.rsplit('.', 1)[-1]}.{func}"
        print(f"{c['survived']:8} {c['killed']:6} {c['no tests']:8} {score(c):>6}  {where}")

    survivors = [k for k, _, _, s in rows if s == "survived"]
    for key in survivors[: args.diffs]:
        print(f"\n# {key} ({kinds.get(key, '?')})\n{diffs.get(key, '(diff unavailable)').rstrip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
