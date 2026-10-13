"""S8 -- rules-file injection: a fixed secure-coding ruleset sent with every request.

This is how rules files work in practice (Backslash Security's product,
`.github/copilot-instructions.md`, `AGENTS.md`): one standing ruleset, the
same for every request, sent as system-level instructions, with the request
itself unchanged. Backslash reports 100% secure output with it on seeded
generation scenarios, without publishing the ruleset or re-scanning; here it
is measured on real findings under the same gates as every other strategy.

The rules come from the same guidance table as everything else (one per
scoped CWE), and the user message is exactly S0's.
"""

from __future__ import annotations

from app.ai.guidance import all_guidance
from app.ai.strategies.base import Strategy, StrategyInput
from app.ai.strategies.paper3 import s0


def ruleset() -> str:
    rules = [f"- {g.render('rule')}" for g in all_guidance() if g.texts["rule"].strip()]
    return "Follow these secure-coding rules in every change you make:\n" + "\n".join(rules)


def s8(inp: StrategyInput):
    _, messages = s0(inp)
    return ruleset(), messages


RULES_FILE = [
    Strategy("S8", "Rules file", "Backslash Security (2025); industry rules files",
             "fixed CWE ruleset as system instructions + the S0 request", s8),
]
