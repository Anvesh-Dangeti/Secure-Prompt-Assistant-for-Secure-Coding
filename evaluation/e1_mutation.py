"""E1: linter mutation sensitivity -- does the Prompt Security Linter notice when a prompt loses what makes it secure?

    python -m evaluation.e1_mutation

No model is involved, so the result is deterministic and asserted by a test
(``recorded_results.E1``). For each of the 24 real fixture findings, the S7
first message is built, then *mutated* the way a developer edits a prompt
before pasting it:

* **delete one paragraph** -- each of the nine paragraphs in turn (opening,
  explanation, directive, guard, classification, scope, inert-data
  instruction, untrusted code, output contract);
* **genericise** -- the directive and guard replaced by "Make sure the code
  is secure." (the most common real-world shortening);
* **truncate** -- keep only the opening sentence;
* **undelimit** -- the code kept, its untrusted-data markers removed.

Each mutant is linted as a developer-edited prompt bound to its finding (the
same call as ``lint-prompt --finding`` and the web interface). A mutant is
*failed* when the linter reports an error, and *flagged* when it reports an
error or a warning (A7 compares against the generated prompt).

The paragraphs no rule protects -- the explanation, the classification, the
code itself (a prompt without code leaks nothing), the output contract --
measure the other side: a linter that failed those would be crying wolf.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from app.ai.context import FindingContext, extract_context
from app.ai.linter import apply_fixes, expectation_for, lint
from app.ai.prompt_builder import build_prompt
from app.normalization.finding import NormalizedFinding

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "flask_vuln_app"
RECORDED = ROOT / "tests" / "data" / "flask_vuln_app_findings.json"   # the 24 real in-scope findings
NONCE = "0123456789abcdef"
GENERIC = "Make sure the code is secure."

# The S7 first message, paragraph by paragraph (app/ai/strategies/ours.py + base.compose).
ROLES = ("opening", "explanation", "directive", "guard", "classification", "scope", "inert-data instruction",
         "untrusted code", "output contract")
CARRIES = {"opening": "A5", "directive": "A3", "guard": "A2", "scope": "A4",
           "inert-data instruction": "B3"}   # the paragraphs whose loss the linter is meant to catch
UNCHECKED = ("explanation", "classification", "untrusted code", "output contract")   # no rule protects these


def contexts() -> list[FindingContext]:
    raw = json.loads(RECORDED.read_text(encoding="utf-8"))
    return [extract_context(NormalizedFinding(**f), FIXTURE) for f in raw]


def _paragraphs(text: str) -> list[str]:
    parts = text.split("\n\n")
    if len(parts) != len(ROLES):
        raise ValueError(f"S7 first message has {len(parts)} paragraphs, expected {len(ROLES)}")
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


def run() -> dict:
    rows: dict[str, Counter] = {name: Counter() for name in OPERATORS}
    controls = 0
    ctxs = contexts()
    for ctx in ctxs:
        canonical = build_prompt(ctx, "S7", nonce=NONCE).messages[0]
        exp = expectation_for(ctx, canonical=canonical)
        controls += lint(canonical, exp).passed and not lint(canonical, exp).warnings
        parts = _paragraphs(canonical)
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
        "findings": len(ctxs),
        "controls_clean": controls,
        "mutants": len(ctxs) * len(OPERATORS),
        "constituent": {"mutants": len(ctxs) * len(REMOVES_A_CONSTITUENT),
                        "failed": sum(summary[n]["failed"] for n in REMOVES_A_CONSTITUENT),
                        "flagged": sum(summary[n]["flagged"] for n in REMOVES_A_CONSTITUENT)},
        "unchecked": {"mutants": len(ctxs) * len(unchecked),
                      "failed": sum(summary[n]["failed"] for n in unchecked),
                      "flagged": sum(summary[n]["flagged"] for n in unchecked)},
        "by_operator": summary,
    }


def main() -> None:
    result = run()
    n = result["findings"]
    c, u = result["constituent"], result["unchecked"]
    print(f"E1 linter mutation sensitivity -- {n} real findings, S7 first message, bound lint (as lint-prompt --finding)")
    print(f"  unmutated controls clean: {result['controls_clean']}/{n}")
    print(f"  mutants that remove a constituent: failed {c['failed']}/{c['mutants']}, flagged {c['flagged']}/{c['mutants']}")
    print(f"  mutants no rule covers (false alarms): failed {u['failed']}/{u['mutants']}, flagged {u['flagged']}/{u['mutants']}")
    print(f"\n  {'mutation':<34} {'failed':>7} {'flagged':>8} {'fix-its pass':>13}  rules fired")
    for name, row in result["by_operator"].items():
        rules = ", ".join(f"{r}x{c}" for r, c in row["rules"].items()) or "-"
        print(f"  {name:<34} {row['failed']:>4}/{n} {row['flagged']:>5}/{n} {row['repaired']:>9}/{row['failed']:<3}  {rules}")


if __name__ == "__main__":
    main()
