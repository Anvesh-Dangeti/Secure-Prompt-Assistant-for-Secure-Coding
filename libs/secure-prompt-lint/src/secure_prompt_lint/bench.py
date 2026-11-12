"""The mutation benchmark (E1): does the linter notice when a prompt loses what makes it secure?

    python -m secure_prompt_lint.bench            # the bundled 24 cases
    python -m secure_prompt_lint.bench --json     # machine-readable result
    python -m secure_prompt_lint.bench --cases my_cases.json

A *case* is a well-formed remediation prompt of nine paragraphs, in this order:
opening, explanation, handling directive, guard, classification, scope,
inert-data instruction, delimited untrusted code, output contract. Each case
also carries the expectation it is linted against (its CWE, the entities at
risk, its location, and the sentences that repair each constituent).

Every case is mutated the way a developer edits a prompt before pasting it:

* **delete one paragraph** -- each of the nine in turn;
* **genericise** -- directive and guard replaced by "Make sure the code is secure.";
* **truncate** -- keep only the opening sentence;
* **undelimit** -- keep the code but remove its untrusted-data markers.

A mutant is *failed* when the linter reports an error and *flagged* when it
reports an error or a warning. Two numbers matter: how many mutants that
remove a security constituent are caught, and how many mutants that remove
only an unchecked paragraph (explanation, classification, the code itself, the
output contract) raise a false alarm. Every failed mutant is also passed
through the fix-its, which must repair it.

The bundled cases are the 24 real findings the Secure Prompt Assistant's
scanners report on its seeded Flask fixture, with the prompts its strategy S7
generates (secrets already redacted). On them the linter scores: controls
24/24 clean; constituent mutants failed 149/168, flagged 168/168; unchecked
mutants 0/96 false alarms; every failed mutant repaired.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path

from secure_prompt_lint.engine import lint
from secure_prompt_lint.expectation import LintExpectation
from secure_prompt_lint.fixit import apply_fixes

ROLES = ("opening", "explanation", "directive", "guard", "classification", "scope", "inert-data instruction",
         "untrusted code", "output contract")
CARRIES = {"opening": "A5", "directive": "A3", "guard": "A2", "scope": "A4",
           "inert-data instruction": "B3"}   # the paragraphs whose loss the linter is meant to catch
UNCHECKED = ("explanation", "classification", "untrusted code", "output contract")   # no rule protects these
GENERIC = "Make sure the code is secure."


@dataclass(frozen=True)
class Case:
    canonical: str
    expectation: LintExpectation
    id: str = ""


def paragraphs(text: str) -> list[str]:
    parts = text.split("\n\n")
    if len(parts) != len(ROLES):
        raise ValueError(f"a benchmark prompt has {len(ROLES)} paragraphs, this one has {len(parts)}")
    return parts


def _delete(i: int) -> Callable[[list[str]], str]:
    return lambda parts: "\n\n".join(p for j, p in enumerate(parts) if j != i)


def _genericise(parts: list[str]) -> str:
    keep = [p for j, p in enumerate(parts) if ROLES[j] not in {"directive", "guard"}]
    return "\n\n".join([keep[0], GENERIC, *keep[1:]])


def _truncate(parts: list[str]) -> str:
    return parts[0]


def _undelimit(parts: list[str]) -> str:
    i = ROLES.index("untrusted code")
    code = "\n".join(parts[i].splitlines()[1:-1])           # drop the opening and closing marker lines
    return "\n\n".join([*parts[:i], code, *parts[i + 1:]])


OPERATORS: dict[str, Callable[[list[str]], str]] = {
    **{f"delete {role}": _delete(i) for i, role in enumerate(ROLES)},
    "genericise directive + guard": _genericise,
    "truncate to the opening": _truncate,
    "undelimit the code": _undelimit,
}
REMOVES_A_CONSTITUENT = [*(f"delete {role}" for role in CARRIES), "genericise directive + guard",
                         "truncate to the opening"]


def score(cases: Sequence[Case]) -> dict:
    """Lint every mutant of every case; the expectation's ``canonical`` is set to the case's prompt (rule A7)."""
    rows: dict[str, Counter] = {name: Counter() for name in OPERATORS}
    controls = 0
    for case in cases:
        exp = case.expectation if case.expectation.canonical == case.canonical else \
            LintExpectation(**{**asdict(case.expectation), "canonical": case.canonical})
        control = lint(case.canonical, exp)
        controls += control.passed and not control.warnings
        parts = paragraphs(case.canonical)
        for name, mutate in OPERATORS.items():
            mutant = mutate(parts)
            report = lint(mutant, exp)
            row = rows[name]
            row["failed"] += not report.passed
            row["flagged"] += bool(report.issues)
            for rule in sorted({i.rule for i in report.issues}):
                row[f"rule {rule}"] += 1
            if not report.passed:
                row["repaired"] += lint(apply_fixes(mutant, report, exp), exp).passed
    summary = {}
    for name, row in rows.items():
        summary[name] = {
            "failed": row["failed"],
            "flagged": row["flagged"],
            "repaired": row["repaired"],
            "rules": {k.removeprefix("rule "): v for k, v in sorted(row.items()) if k.startswith("rule ")},
        }
    unchecked = [f"delete {role}" for role in UNCHECKED]
    return {
        "findings": len(cases),
        "controls_clean": controls,
        "mutants": len(cases) * len(OPERATORS),
        "constituent": {"mutants": len(cases) * len(REMOVES_A_CONSTITUENT),
                        "failed": sum(summary[n]["failed"] for n in REMOVES_A_CONSTITUENT),
                        "flagged": sum(summary[n]["flagged"] for n in REMOVES_A_CONSTITUENT)},
        "unchecked": {"mutants": len(cases) * len(unchecked),
                      "failed": sum(summary[n]["failed"] for n in unchecked),
                      "flagged": sum(summary[n]["flagged"] for n in unchecked)},
        "by_operator": summary,
    }


# ---- the case file ------------------------------------------------------------

_EXPECTATION_FIELDS = ("cwe", "weakness_terms", "entities", "locations", "vocabulary", "max_block_lines",
                       "token_budget", "fixits")


def case_to_dict(case: Case) -> dict:
    exp = asdict(case.expectation)
    return {"id": case.id, "prompt": case.canonical,
            "expectation": {k: (list(v) if isinstance(v, tuple) else v) for k, v in exp.items()
                            if k in _EXPECTATION_FIELDS}}


def case_from_dict(data: dict) -> Case:
    raw = data["expectation"]
    exp = LintExpectation(
        bound=True, cwe=raw["cwe"], weakness_terms=tuple(raw["weakness_terms"]), entities=tuple(raw["entities"]),
        locations=tuple(raw["locations"]), vocabulary=tuple(raw["vocabulary"]),
        max_block_lines=int(raw["max_block_lines"]), token_budget=int(raw["token_budget"]),
        fixits=dict(raw["fixits"]), canonical=data["prompt"])
    return Case(data["prompt"], exp, data.get("id", ""))


def load_cases(path: str | Path | None = None) -> list[Case]:
    if path is None:
        text = resources.files("secure_prompt_lint").joinpath("data/e1_benchmark.json").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    return [case_from_dict(c) for c in data["cases"]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m secure_prompt_lint.bench", description=__doc__.split("\n")[0])
    parser.add_argument("--cases", type=Path, help="a case file (default: the bundled 24 cases)")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)
    result = score(load_cases(args.cases))
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    n = result["findings"]
    c, u = result["constituent"], result["unchecked"]
    print(f"Mutation benchmark -- {n} cases, {result['mutants']} mutants")
    print(f"  unmutated controls clean: {result['controls_clean']}/{n}")
    print(f"  mutants that remove a constituent: failed {c['failed']}/{c['mutants']}, flagged {c['flagged']}/{c['mutants']}")
    print(f"  mutants no rule covers (false alarms): failed {u['failed']}/{u['mutants']}, flagged {u['flagged']}/{u['mutants']}")
    print(f"\n  {'mutation':<34} {'failed':>7} {'flagged':>8} {'fix-its pass':>13}  rules fired")
    for name, row in result["by_operator"].items():
        rules = ", ".join(f"{r}x{k}" for r, k in row["rules"].items()) or "-"
        print(f"  {name:<34} {row['failed']:>4}/{n} {row['flagged']:>5}/{n} {row['repaired']:>9}/{row['failed']:<3}  {rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
