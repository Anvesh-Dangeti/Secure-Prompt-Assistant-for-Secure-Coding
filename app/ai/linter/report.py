"""Lint results: issues, constituent outcomes, and the score used in the evaluation.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.report`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.report import CONSTITUENTS, ERROR, RULES, WARNING, LintIssue, LintReport

__all__ = ["CONSTITUENTS", "ERROR", "RULES", "WARNING", "LintIssue", "LintReport"]
