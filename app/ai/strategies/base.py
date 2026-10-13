"""What a prompting strategy is: a function from one finding's context to messages.

Every strategy returns an optional system text and an ordered list of user
messages. Single-turn strategies return one message; RCI returns three (ask,
critique, improve). Lab mode sends the messages in turn, appending the model's
replies; developer mode shows them in order for the developer to paste. One
definition serves both modes, so what is measured is what developers get.

The security envelope -- scope constraint, inert-data instruction, delimited
code, output contract -- is added by ``compose`` to every strategy, so the
comparison between strategies varies only the security guidance.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.ai import sentences
from app.ai.context import FindingContext
from app.ai.delimiting import INERT_INSTRUCTION, UntrustedBlock
from app.ai.explainer import Explanation
from app.ai.guidance import CweGuidance


@dataclass(frozen=True)
class StrategyInput:
    ctx: FindingContext
    guidance: CweGuidance
    explanation: Explanation
    block: UntrustedBlock


Build = Callable[[StrategyInput], tuple[str | None, list[str]]]


@dataclass(frozen=True)
class Strategy:
    id: str
    name: str
    origin: str          # where the technique comes from
    summary: str
    build: Build
    #: S7 is our claim: its prompts must pass the linter or are not produced at all.
    enforce_lint: bool = False


def compose(opening: str, body: list[str], inp: StrategyInput) -> str:
    """First user message: strategy-specific opening and body, then the constant envelope."""
    ctx = inp.ctx
    parts = [opening, *body, sentences.scope(ctx), INERT_INSTRUCTION, inp.block.text, sentences.output_contract(ctx)]
    return "\n\n".join(p.strip() for p in parts if p and p.strip())
