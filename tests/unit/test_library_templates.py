"""The published prompt templates are exactly the prompts this application generates and measured.

* the application's strategy and sentence modules re-export the library's (one source of code);
* the library's bundled findings are the 24 fixture contexts the evaluation uses;
* for every finding and every strategy, the library -- with only its own bundled data -- builds the
  same messages and the same lint report as the application;
* the library's guidance renders every template exactly as our guidance table does;
* the library's stand-alone ladder reproduces the recorded static token ladder (E5).
"""

from __future__ import annotations

import pytest
from secure_prompt_lint.templates import Finding, bundled_findings, ladder
from secure_prompt_lint.templates import guidance as lib_guidance
from secure_prompt_lint.templates import ours as lib_ours
from secure_prompt_lint.templates import sentences as lib_sentences
from secure_prompt_lint.templates import strategies as lib_strategies
from secure_prompt_lint.templates.build import BENCH_NONCE, _plan

import app.ai.sentences
from app.ai import guidance
from app.ai.prompt_builder import build_prompt
from app.ai.strategies import STRATEGIES, get_strategy
from app.ai.strategies import ours as app_ours
from app.core.config import get_settings
from evaluation.e1_mutation import NONCE, contexts
from evaluation.recorded_results import E5_STATIC

TEMPLATE_FIELDS = ("name", "explain", "risk", "directive", "guard", "mitre", "rule")


@pytest.fixture(scope="module")
def pairs() -> list:
    ctxs, bundled = contexts(), bundled_findings()
    assert len(ctxs) == len(bundled) == 24
    return list(zip(ctxs, [f for _, f in bundled], strict=True))


def test_the_application_strategies_are_the_library() -> None:
    assert STRATEGIES is lib_strategies.STRATEGIES and get_strategy is lib_strategies.get_strategy
    assert app_ours.sentences is lib_sentences and app_ours.s7m is lib_ours.s7m
    assert app.ai.sentences.opening is lib_sentences.opening and app.ai.sentences.scope is lib_sentences.scope


def test_the_bundled_findings_are_our_fixture_contexts(pairs: list) -> None:
    for ctx, finding in pairs:
        assert Finding.from_context(ctx) == finding, ctx.rule_id


def test_the_library_builds_the_same_prompts_as_the_application(pairs: list) -> None:
    assert NONCE == BENCH_NONCE
    s = get_settings()
    for ctx, finding in pairs:
        for sid in STRATEGIES:
            ours = build_prompt(ctx, sid, nonce=NONCE)
            _, published = _plan(finding, sid, None, BENCH_NONCE, s.max_context_lines, s.prompt_token_budget)
            assert (published.system, published.messages) == (ours.system, ours.messages), (ctx.rule_id, sid)
            assert published.lint.to_dict() == ours.lint.to_dict(), (ctx.rule_id, sid)


def test_the_library_guidance_renders_like_ours(pairs: list) -> None:
    for g in guidance.all_guidance():
        published = lib_guidance.guidance_for(g.cwe)
        assert (published.name, published.vocabulary, published.weakness_terms) == \
            (g.name, g.vocabulary, g.weakness_terms)
    for ctx, _ in pairs:
        g, published = guidance.guidance_for(ctx.cwe), lib_guidance.guidance_for(ctx.cwe)
        for field in TEMPLATE_FIELDS:
            assert published.render(field, ctx.slots()) == g.render(field, ctx.slots()), (ctx.rule_id, field)
    for cwe in (None, "CWE-1234"):                     # the generic wording for a weakness outside the table
        g, published = guidance.guidance_for(cwe), lib_guidance.guidance_for(cwe)
        assert published.generic and g.generic
        for field in TEMPLATE_FIELDS:
            assert published.render(field, {"symbol": "f"}) == g.render(field, {"symbol": "f"}), (cwe, field)


def test_the_stand_alone_ladder_reproduces_e5_static() -> None:
    result = ladder()
    for key in ("findings", "passes_lint", "first_message", "typed", "code_block", "s7m_saving_vs_s7a"):
        assert result[key] == E5_STATIC[key], key
