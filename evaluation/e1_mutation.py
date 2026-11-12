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

The mutation operators and the scoring are the published benchmark
(``secure_prompt_lint.bench``); this module supplies the cases from our own
fixture. The same 24 cases ship with the library as its bundled benchmark
(exported by ``scripts/export_lint_data.py``), so anyone can reproduce E1
without this application.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_prompt_lint.bench import (CARRIES, GENERIC, OPERATORS, REMOVES_A_CONSTITUENT, ROLES, UNCHECKED, Case,
                                      score)
from secure_prompt_lint.bench import paragraphs as _paragraphs

from app.ai.context import FindingContext, extract_context
from app.ai.linter import expectation_for
from app.ai.prompt_builder import build_prompt
from app.normalization.finding import NormalizedFinding

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "flask_vuln_app"
RECORDED = ROOT / "tests" / "data" / "flask_vuln_app_findings.json"   # the 24 real in-scope findings
NONCE = "0123456789abcdef"

__all__ = ["CARRIES", "GENERIC", "NONCE", "OPERATORS", "REMOVES_A_CONSTITUENT", "ROLES", "UNCHECKED", "cases",
           "contexts", "main", "run"]


def contexts() -> list[FindingContext]:
    raw = json.loads(RECORDED.read_text(encoding="utf-8"))
    findings = [NormalizedFinding(**f) for f in raw]
    return [extract_context(f, FIXTURE, group=findings) for f in findings]


def cases() -> list[Case]:
    """One benchmark case per real finding: its S7 first message and the expectation it is linted against."""
    out = []
    for ctx in contexts():
        canonical = build_prompt(ctx, "S7", nonce=NONCE).messages[0]
        _paragraphs(canonical)          # fail early if S7's paragraph structure ever changes
        rule = ctx.rule_id.rsplit(".", 1)[-1]
        out.append(Case(canonical, expectation_for(ctx, canonical=canonical),
                        f"{ctx.tool}:{rule}:{ctx.file_path}:{ctx.symbol or ctx.start_line}"))
    return out


def run() -> dict:
    return score(cases())


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
        rules = ", ".join(f"{r}x{k}" for r, k in row["rules"].items()) or "-"
        print(f"  {name:<34} {row['failed']:>4}/{n} {row['flagged']:>5}/{n} {row['repaired']:>9}/{row['failed']:<3}  {rules}")


if __name__ == "__main__":
    main()
