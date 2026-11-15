"""The prompt templates: eleven ways of asking an AI assistant to fix one security finding.

    from secure_prompt_lint.templates import Finding, Source, build_prompt

    finding = Finding(cwe="CWE-78", file_path="app.py", code=code, window_start=12, window_end=19,
                      window_kind="function", symbol="ping_host",
                      sources=(Source("host", "the HTTP request (`request.args`)"),),
                      sinks=("subprocess.check_output",))
    plan = build_prompt(finding, "S7m")      # S0-S8, S7a or S7m
    print(plan.render())                     # what to paste, in order
    plan.lint.passed, plan.estimated_tokens

These are the templates the Secure Prompt Assistant generates and measures:

* **S0-S6** -- the prompting techniques of Tony et al. (ACM TOSEM 2025),
  adapted from generating code to repairing a scanner finding;
* **S7** -- ours: a code-specific explanation, every linted constituent, and an
  explained review turn; **S7a** -- its first message alone; **S7m** -- the
  minimal prompt, only what the linter requires;
* **S8** -- a rules file: one standing ruleset sent with every request.

Every strategy shares one security envelope (the code delimited with a nonce,
an instruction to treat it as data, a scope limit and an output contract), so
strategies differ only in their security guidance. The wording comes from the
same vocabulary table the linter checks against. No model is involved:
the same finding always gives the same prompt.

``python -m secure_prompt_lint.templates --ladder`` reproduces the static token
ladder from the 24 real findings bundled with the library.
"""

from __future__ import annotations

from secure_prompt_lint.templates.base import Explanation, Strategy, StrategyInput, compose, template_explanation
from secure_prompt_lint.templates.build import (
    BENCH_NONCE,
    PromptPlan,
    PromptRejected,
    build_prompt,
    bundled_findings,
    expectation_for,
    ladder,
)
from secure_prompt_lint.templates.finding import WINDOW_KINDS, Finding, Source
from secure_prompt_lint.templates.guidance import Guidance, all_guidance, guidance_for
from secure_prompt_lint.templates.strategies import (
    COMPARED,
    LADDER,
    PAPERS,
    RECOMMENDED,
    STRATEGIES,
    get_strategy,
)

__all__ = [
    "BENCH_NONCE", "COMPARED", "LADDER", "PAPERS", "RECOMMENDED", "STRATEGIES", "WINDOW_KINDS", "Explanation",
    "Finding", "Guidance", "PromptPlan", "PromptRejected", "Source", "Strategy", "StrategyInput", "all_guidance",
    "build_prompt", "bundled_findings", "compose", "expectation_for", "get_strategy", "guidance_for", "ladder",
    "template_explanation",
]
