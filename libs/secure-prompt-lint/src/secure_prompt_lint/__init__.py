"""secure-prompt-lint -- a deterministic linter for security-remediation prompts.

    from secure_prompt_lint import lint, expectation, apply_fixes

    report = lint(prompt_text)                                    # unbound: any hand-written prompt
    exp = expectation("CWE-78", entities=["host", "subprocess.check_output"], locations=["app.py", "ping_host"])
    report = lint(prompt_text, exp)                               # bound to one finding
    report.passed, report.constituent_score, report.tokens, report.issues
    fixed = apply_fixes(prompt_text, report, exp)                 # deterministic repairs, no model

The rules:

* **A1-A7** -- security constituents a remediation prompt must keep (Cicalese
  et al., arXiv:2607.15937, sections IV-B and V-B): the entity at risk, the
  condition under which the operation may proceed, the handling directive,
  the scope limit, an opening sentence that states task, weakness and location,
  no constraint stranded at the end, and no silent shortening.
* **B1-B5** -- the prompt's own security: no secrets, untrusted code delimited
  with a nonce, an inert-data instruction before it, data minimisation, and a
  warning for instruction-like text inside the code.
* **C1** -- a token budget.

No model is involved anywhere: the same prompt always gets the same report.
"""

from __future__ import annotations

from secure_prompt_lint.delimiting import INERT_INSTRUCTION, split_prompt, wrap_untrusted
from secure_prompt_lint.engine import lint
from secure_prompt_lint.expectation import LintExpectation, expectation, unbound_expectation
from secure_prompt_lint.fixit import apply_fixes
from secure_prompt_lint.report import CONSTITUENTS, ERROR, RULES, WARNING, LintIssue, LintReport
from secure_prompt_lint.rules import RuleContext, describe_rules, register_rule, unregister_rule
from secure_prompt_lint.tokens import estimate_tokens
from secure_prompt_lint.vocabulary import load_vocabulary, use_vocabulary

__version__ = "1.0.1"

__all__ = [
    "CONSTITUENTS", "ERROR", "INERT_INSTRUCTION", "RULES", "WARNING", "LintExpectation", "LintIssue", "LintReport",
    "RuleContext", "__version__", "apply_fixes", "describe_rules", "estimate_tokens", "expectation", "lint",
    "load_vocabulary", "register_rule", "split_prompt", "unbound_expectation", "unregister_rule", "use_vocabulary",
    "wrap_untrusted",
]
