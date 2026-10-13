"""Stage B -- build a remediation prompt for one finding with a chosen strategy, then lint it.

    ctx  = extract_context(finding, source_root)
    plan = build_prompt(ctx, "S7")          # developer mode: show plan.messages
    plan.lint.passed, plan.lint.constituent_score

Every prompt is linted. For S7 a failing lint means no prompt (``PromptRejected``):
our own strategy must never ship a prompt missing a constituent. For S0-S6
and S8 the report is recorded but never blocks -- the baselines are *meant*
to lack constituents, and that difference is what the evaluation measures.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.ai.context import FindingContext
from app.ai.delimiting import wrap_untrusted
from app.ai.explainer import Explanation, explain
from app.ai.guidance import guidance_for
from app.ai.linter import LintExpectation, LintReport, expectation_for, lint
from app.ai.strategies import DEFAULT_STRATEGY, StrategyInput, get_strategy
from app.ai.tokens import estimate_tokens


class PromptRejected(ValueError):
    """An enforced strategy produced a prompt that fails the linter -- nothing is emitted."""

    def __init__(self, strategy: str, report: LintReport) -> None:
        reasons = "; ".join(f"{i.rule}: {i.message}" for i in report.errors)
        super().__init__(f"{strategy} prompt rejected by the linter: {reasons}")
        self.report = report


@dataclass(frozen=True)
class PromptPlan:
    strategy: str
    system: str | None
    messages: tuple[str, ...]
    nonce: str
    explanation: Explanation
    expectation: LintExpectation
    lint: LintReport

    @property
    def estimated_tokens(self) -> int:
        """All text the tool sends (system + every user turn); model replies are extra."""
        return estimate_tokens((self.system or "") + "".join(self.messages))

    def render(self) -> str:
        """Human-readable form for developer mode: what to paste, in order."""
        out = []
        if self.system:
            out.append("=== Instructions (system / rules file) ===\n" + self.system)
        total = len(self.messages)
        for n, message in enumerate(self.messages, start=1):
            title = "Prompt" if total == 1 else f"Message {n} of {total}"
            if n > 1:
                title += " (send after the assistant replies)"
            out.append(f"=== {title} ===\n{message}")
        return "\n\n".join(out)


def build_prompt(ctx: FindingContext, strategy_id: str = DEFAULT_STRATEGY, *,
                 explanation: Explanation | None = None, nonce: str | None = None) -> PromptPlan:
    strategy = get_strategy(strategy_id)
    g = guidance_for(ctx.cwe)
    explanation = explanation or explain(ctx)
    block = wrap_untrusted(ctx.code, ctx.file_path, ctx.lines_label, nonce)
    system, messages = strategy.build(StrategyInput(ctx, g, explanation, block))
    if not messages:
        raise ValueError(f"strategy {strategy.id} produced no messages")
    expectation = expectation_for(ctx)
    report = lint(messages[0], expectation, preamble=system or "")
    if strategy.enforce_lint and not report.passed:
        raise PromptRejected(strategy.id, report)
    return PromptPlan(strategy.id, system, tuple(messages), block.nonce, explanation, expectation, report)
