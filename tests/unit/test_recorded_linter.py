"""The linter numbers presented at review (``recorded_results.LINTER``) are the ones the code produces.

Every strategy builds a prompt for each of the 24 real fixture findings and the
linter scores it. No model is involved: this measures the prompts, not the fixes.
"""

from __future__ import annotations

from app.ai.linter import apply_fixes, expectation_for, lint
from app.ai.prompt_builder import build_prompt
from app.ai.strategies import STRATEGIES
from evaluation.recorded_results import LINTER
from tests._ai_support import NONCE, all_contexts

CONTEXTS = all_contexts()
PLANS = {sid: [build_prompt(c, sid, nonce=NONCE) for c in CONTEXTS] for sid in STRATEGIES}


def test_recorded_over_every_real_finding() -> None:
    assert len(CONTEXTS) == LINTER["findings"]
    assert set(LINTER["by_strategy"]) == set(STRATEGIES)


def test_pass_counts_and_mean_scores_per_strategy() -> None:
    for sid, plans in PLANS.items():
        scores = [p.lint.constituent_score for p in plans]
        measured = (sum(p.lint.passed for p in plans), round(sum(scores) / len(scores), 2))
        assert measured == LINTER["by_strategy"][sid], sid


def test_s0_range_and_s7_token_range() -> None:
    s0 = [p.lint.constituent_score for p in PLANS["S0"]]
    assert (min(s0), max(s0)) == LINTER["s0_score_range"]
    s7 = [p.lint.tokens for p in PLANS["S7"]]
    assert (min(s7), max(s7)) == LINTER["s7_tokens"]


def test_fixits_repair_the_baseline() -> None:
    repaired = 0
    for ctx, plan in zip(CONTEXTS, PLANS["S0"]):
        exp = expectation_for(ctx)
        text = plan.messages[0]
        repaired += lint(apply_fixes(text, lint(text, exp), exp), exp).passed
    assert repaired == LINTER["fixits_repair_s0"]
