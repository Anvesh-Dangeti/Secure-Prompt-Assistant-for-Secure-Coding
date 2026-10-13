"""Strategies S0-S8: each has its defining cue, and only the security guidance varies."""

from __future__ import annotations

import pytest

from app.ai import sentences
from app.ai.delimiting import INERT_INSTRUCTION
from app.ai.guidance import all_guidance, guidance_for
from app.ai.prompt_builder import PromptRejected, build_prompt
from app.ai.strategies import STRATEGIES, get_strategy
from app.ai.strategies import ours as ours_module
from tests._ai_support import NONCE, context

SQL = context("B608")
PLANS = {sid: build_prompt(SQL, sid, nonce=NONCE) for sid in STRATEGIES}


def test_registry_is_s0_to_s8_and_only_s7_is_enforced() -> None:
    assert list(STRATEGIES) == [f"S{i}" for i in range(9)]
    assert [s.id for s in STRATEGIES.values() if s.enforce_lint] == ["S7"]
    assert get_strategy(" s5 ").id == "S5"
    with pytest.raises(ValueError, match="unknown strategy"):
        get_strategy("S9")


@pytest.mark.parametrize("sid", list(STRATEGIES))
def test_the_security_envelope_is_identical_in_every_strategy(sid: str) -> None:
    first = PLANS[sid].messages[0]
    for part in (sentences.scope(SQL), INERT_INSTRUCTION, sentences.output_contract(SQL), SQL.code,
                 f'<untrusted_code id="{NONCE}"'):
        assert part in first


def test_s0_is_direct_feedback_without_a_security_cue() -> None:
    s0 = PLANS["S0"].messages[0]
    assert sentences.scanner_report(SQL) in s0
    assert "CWE-89" not in s0 and "secure" not in s0.lower()
    assert "parameteris" not in s0


def test_each_strategy_carries_its_defining_cue() -> None:
    first = {sid: p.messages[0] for sid, p in PLANS.items()}
    assert "make sure the code is secure" in first["S1"]
    assert "CWE-89" in first["S2"] and "MITRE" in first["S2"]
    assert "OWASP secure-coding practices" in first["S3"]
    assert "Let's think step by step." in first["S4"]
    assert first["S6"].startswith("Act as a software security expert.")
    assert first["S7"].startswith("Fix the SQL injection (CWE-89) in `get_user`")


def test_rci_strategies_are_three_turn_conversations() -> None:
    assert len(PLANS["S5"].messages) == 3 and "find security problems" in PLANS["S5"].messages[1]
    assert len(PLANS["S7"].messages) == 3 and "fully removed" in PLANS["S7"].messages[1]
    assert all(len(PLANS[s].messages) == 1 for s in ("S0", "S1", "S2", "S3", "S4", "S6", "S8"))
    assert PLANS["S5"].messages[0] == PLANS["S1"].messages[0]


def test_s8_is_a_standing_ruleset_plus_the_s0_request() -> None:
    s8 = PLANS["S8"]
    assert s8.messages == PLANS["S0"].messages
    rules = [g.render("rule") for g in all_guidance()]
    assert all(rule in s8.system for rule in rules) and len(rules) == 10
    # The same ruleset for every finding -- that is what makes it a rules file.
    assert build_prompt(context("B311"), "S8").system == s8.system


def test_prompts_are_deterministic_for_a_fixed_nonce() -> None:
    again = build_prompt(SQL, "S7", nonce=NONCE)
    assert again.messages == PLANS["S7"].messages


def test_lint_scores_separate_the_strategies() -> None:
    scores = {sid: p.lint.constituent_score for sid, p in PLANS.items()}
    assert scores["S7"] == 1.0
    assert scores["S0"] < scores["S2"] < scores["S7"]


def test_s7_fails_closed_when_its_prompt_would_miss_a_constituent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ours_module.sentences, "directive", lambda ctx, g: "Fix it properly.")
    with pytest.raises(PromptRejected, match="A3"):
        build_prompt(SQL, "S7")


def test_baselines_are_recorded_not_blocked() -> None:
    plan = build_prompt(SQL, "S0")
    assert not plan.lint.passed  # recorded...
    assert plan.messages         # ...but the prompt is still produced


def test_render_shows_turn_order_and_rules_file() -> None:
    assert "Message 3 of 3 (send after the assistant replies)" in PLANS["S7"].render()
    assert PLANS["S8"].render().startswith("=== Instructions (system / rules file) ===")
    assert PLANS["S0"].render().startswith("=== Prompt ===")


@pytest.mark.parametrize("rule", ["B105", "PYSEC-2021-142", "B201", "B403"])
def test_s7_reads_well_for_non_function_findings(rule: str) -> None:
    ctx = context(rule)
    first = build_prompt(ctx, "S7").messages[0]
    g = guidance_for(ctx.cwe)
    assert first.startswith(f"Fix the {g.name} ({g.cwe})")
    assert "{" not in first.split("<untrusted_code")[0], "no unfilled template slot"
