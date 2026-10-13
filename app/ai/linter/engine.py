"""Run every lint rule over one prompt.

Deterministic and model-free: the same prompt always gets the same report, so
lint results are reproducible evidence, and the linter can be evaluated on its
own (E1) without any LLM.
"""

from __future__ import annotations

from dataclasses import replace

from app.ai.delimiting import split_prompt
from app.ai.linter.constituents import check_constituents
from app.ai.linter.expectation import LintExpectation, unbound_expectation
from app.ai.linter.hygiene import check_hygiene
from app.ai.linter.report import CONSTITUENTS, WARNING, LintIssue, LintReport

SHORTENED_RATIO = 0.6


def _shortening(text: str, preamble: str, present: dict, exp: LintExpectation) -> list[LintIssue]:
    """A7: compare against the prompt the tool generated, when we have it."""
    if not exp.canonical:
        return []
    canonical = lint(exp.canonical, replace(exp, canonical=None), preamble=preamble)
    lost = [r for r in CONSTITUENTS if canonical.constituents.get(r) and not present.get(r)]
    issues = []
    if lost:
        issues.append(LintIssue("A7", WARNING, "editing removed constituents the generated prompt had: "
                                + ", ".join(lost)))
    original = len(split_prompt(exp.canonical).instructions.strip())
    kept = len(split_prompt(text).instructions.strip())
    if original and kept / original < SHORTENED_RATIO:
        issues.append(LintIssue("A7", WARNING, f"the instructions were shortened to {kept * 100 // original}% of "
                                "the generated prompt; minimal edits alone raised vulnerability rates in Paper 2"))
    return issues


def lint(text: str, expectation: LintExpectation | None = None, *, preamble: str = "") -> LintReport:
    """Lint ``text`` (the first user message). ``preamble`` is a system/rules text sent before it."""
    exp = expectation or unbound_expectation()
    split = split_prompt(text)
    issues, present = check_constituents(split, preamble, exp)
    issues += _shortening(text, preamble, present, exp)
    hygiene, tokens = check_hygiene(text, preamble, split, exp)
    issues += hygiene
    order = {rule: i for i, rule in enumerate(("A5", "A1", "A2", "A3", "A4", "A6", "A7",
                                               "B1", "B2", "B3", "B4", "B5", "C1"))}
    issues.sort(key=lambda i: (i.severity == WARNING, order.get(i.rule, 99)))
    return LintReport(tuple(issues), present, tokens, exp.bound)
