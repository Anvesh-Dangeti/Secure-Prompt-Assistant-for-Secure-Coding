"""Prompt Security Linter -- the tool Paper 2 (section V-B) calls for, plus prompt-security rules.

    report = lint(prompt_text, expectation_for(ctx))       # bound to a finding
    report = lint(developer_prompt)                         # unbound
    fixed  = apply_fixes(prompt_text, report, expectation)

The rules, the engine and the fix-its are the ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), published separately so others can extend the
linter. This package adds what needs the application: binding an expectation
to a finding (``expectation_for``) and this deployment's limits.
"""

from __future__ import annotations

from secure_prompt_lint import engine as _engine
from secure_prompt_lint.fixit import apply_fixes
from secure_prompt_lint.report import CONSTITUENTS, RULES, LintIssue, LintReport

from app.ai.linter.expectation import LintExpectation, expectation_for, unbound_expectation

__all__ = ["CONSTITUENTS", "RULES", "LintExpectation", "LintIssue", "LintReport", "apply_fixes",
           "expectation_for", "lint", "unbound_expectation"]


def lint(text: str, expectation: LintExpectation | None = None, *, preamble: str = "") -> LintReport:
    """Lint ``text``; with no expectation, unbound with this deployment's limits."""
    return _engine.lint(text, expectation or unbound_expectation(), preamble=preamble)
