"""Prompt Security Linter -- the tool Paper 2 (section V-B) calls for, plus prompt-security rules.

    report = lint(prompt_text, expectation_for(ctx))       # bound to a finding
    report = lint(developer_prompt)                         # unbound
    fixed  = apply_fixes(prompt_text, report, expectation)
"""

from app.ai.linter.engine import lint
from app.ai.linter.expectation import LintExpectation, expectation_for, unbound_expectation
from app.ai.linter.fixit import apply_fixes
from app.ai.linter.report import CONSTITUENTS, RULES, LintIssue, LintReport

__all__ = ["CONSTITUENTS", "RULES", "LintExpectation", "LintIssue", "LintReport", "apply_fixes",
           "expectation_for", "lint", "unbound_expectation"]
