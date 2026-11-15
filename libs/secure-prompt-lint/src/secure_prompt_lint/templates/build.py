"""Build a remediation prompt for one finding with a chosen strategy, then lint it.

    plan = build_prompt(finding, "S7m")
    print(plan.render())                    # what to paste, in order
    plan.lint.passed, plan.estimated_tokens

Every prompt is linted against the finding. For our strategies (S7, S7a, S7m)
a failing lint means no prompt (``PromptRejected``): they must never ship a
prompt missing a constituent. For S0-S6 and S8 the report is recorded but never
blocks -- the baselines are *meant* to lack constituents, and that difference
is what a comparison measures.

``ladder()`` reproduces the Secure Prompt Assistant's static token ladder from
the 24 real findings bundled with the library.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from statistics import median
from typing import Any

from secure_prompt_lint.delimiting import wrap_untrusted
from secure_prompt_lint.engine import lint
from secure_prompt_lint.expectation import DEFAULT_MAX_BLOCK_LINES, DEFAULT_TOKEN_BUDGET, LintExpectation
from secure_prompt_lint.report import LintReport
from secure_prompt_lint.templates import sentences
from secure_prompt_lint.templates.base import Explanation, StrategyInput, template_explanation
from secure_prompt_lint.templates.finding import Finding
from secure_prompt_lint.templates.guidance import guidance_for
from secure_prompt_lint.templates.strategies import RECOMMENDED, get_strategy
from secure_prompt_lint.tokens import estimate_tokens

#: the delimiter nonce of the bundled benchmark, so reproduced numbers match exactly
BENCH_NONCE = "0123456789abcdef"


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
    explanation: Any
    expectation: LintExpectation
    lint: LintReport

    @property
    def estimated_tokens(self) -> int:
        """All text a developer sends (system + every user turn); the model's replies are extra."""
        return estimate_tokens((self.system or "") + "".join(self.messages))

    def render(self) -> str:
        """Human-readable form: what to paste, in order."""
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


def expectation_for(ctx: Any, g: Any = None, *, max_block_lines: int = DEFAULT_MAX_BLOCK_LINES,
                    token_budget: int = DEFAULT_TOKEN_BUDGET, canonical: str | None = None) -> LintExpectation:
    """Bind the linter to a finding; its fix-its insert the sentences S7 would have had."""
    g = g or guidance_for(ctx.cwe)
    locations = [loc for loc in (ctx.symbol, ctx.file_path, ctx.file_path.rsplit("/", 1)[-1]) if loc]
    return LintExpectation(
        bound=True,
        cwe=ctx.cwe,
        weakness_terms=g.weakness_terms,
        entities=ctx.entities,
        locations=tuple(dict.fromkeys(locations)),
        vocabulary=g.vocabulary,
        max_block_lines=max_block_lines,
        token_budget=token_budget,
        fixits={
            "A1": sentences.binding(ctx, g),
            "A2": sentences.guard(ctx, g),
            "A3": sentences.directive(ctx, g),
            "A4": sentences.scope(ctx),
            "A5": sentences.opening(ctx, g),
        },
        canonical=canonical,
    )


def _plan(ctx: Any, strategy_id: str, explanation: Any, nonce: str | None,
          max_block_lines: int, token_budget: int) -> tuple[bool, PromptPlan]:
    strategy = get_strategy(strategy_id)
    g = guidance_for(ctx.cwe)
    if explanation is None:
        explanation = template_explanation(ctx, g)
    elif isinstance(explanation, str):
        explanation = Explanation(" ".join(explanation.split()), "caller")
    block = wrap_untrusted(ctx.code, ctx.file_path, ctx.lines_label, nonce)
    system, messages = strategy.build(StrategyInput(ctx, g, explanation, block))
    if not messages:
        raise ValueError(f"strategy {strategy.id} produced no messages")
    expectation = expectation_for(ctx, g, max_block_lines=max_block_lines, token_budget=token_budget)
    report = lint(messages[0], expectation, preamble=system or "")
    plan = PromptPlan(strategy.id, system, tuple(messages), block.nonce, explanation, expectation, report)
    return strategy.enforce_lint, plan


def build_prompt(ctx: Any, strategy: str = RECOMMENDED, *, explanation: Any = None, nonce: str | None = None,
                 max_block_lines: int = DEFAULT_MAX_BLOCK_LINES,
                 token_budget: int = DEFAULT_TOKEN_BUDGET) -> PromptPlan:
    """The prompt for ``ctx`` (a ``Finding``) with ``strategy``.

    ``explanation`` (text, or an object with ``.text``) replaces the template
    explanation S7 and S7a include. ``nonce`` fixes the delimiter id, for
    reproducible output; leave it out in real use.
    """
    enforced, plan = _plan(ctx, strategy, explanation, nonce, max_block_lines, token_budget)
    if enforced and not plan.lint.passed:
        raise PromptRejected(plan.strategy, plan.lint)
    return plan


# ---- the bundled findings and the token ladder ----------------------------------


def bundled_findings() -> list[tuple[str, Finding]]:
    """The 24 real findings four scanners report on the Secure Prompt Assistant's seeded Flask application."""
    text = resources.files("secure_prompt_lint").joinpath("data/findings.json").read_text(encoding="utf-8")
    return [(row["id"], Finding.from_dict(row["finding"])) for row in json.loads(text)["findings"]]


def _spread(values: list[int]) -> tuple[int, int, int]:
    """(min, median, max), the median rounded half up to a whole token."""
    return min(values), int(median(values) + 0.5), max(values)


def ladder(findings: list[Finding] | None = None, strategies: tuple[str, ...] = ("S7", "S7a", "S7m", "S2")) -> dict:
    """How small each strategy's prompt is, and whether it still passes the linter (no model involved)."""
    findings = findings if findings is not None else [f for _, f in bundled_findings()]
    first: dict[str, list[int]] = {sid: [] for sid in strategies}
    typed: dict[str, list[int]] = {sid: [] for sid in strategies}
    passed: dict[str, int] = {sid: 0 for sid in strategies}
    code: list[int] = []
    for ctx in findings:
        for sid in strategies:
            _, plan = _plan(ctx, sid, None, BENCH_NONCE, DEFAULT_MAX_BLOCK_LINES, DEFAULT_TOKEN_BUDGET)
            first[sid].append(plan.lint.tokens)
            typed[sid].append(plan.estimated_tokens)
            passed[sid] += plan.lint.passed
        code.append(estimate_tokens(wrap_untrusted(ctx.code, ctx.file_path, ctx.lines_label, BENCH_NONCE).text))
    out = {
        "findings": len(findings),
        "passes_lint": passed,
        "first_message": {sid: _spread(v) for sid, v in first.items()},
        "typed": {sid: _spread(v) for sid, v in typed.items()},       # every message the developer pastes
        "code_block": _spread(code),
    }
    if "S7a" in first and "S7m" in first:
        out["s7m_saving_vs_s7a"] = round(1 - sum(first["S7m"]) / sum(first["S7a"]), 2)
    return out
