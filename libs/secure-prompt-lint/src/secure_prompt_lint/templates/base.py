"""What a prompting strategy is: a function from one finding's context to messages.

Every strategy returns an optional system text and an ordered list of user
messages. Single-turn strategies return one message; RCI returns three (ask,
critique, improve). An experiment sends the messages in turn, appending the
model's replies; a developer pastes them in order. One definition serves both,
so what is measured is what developers get.

The security envelope -- scope constraint, inert-data instruction, delimited
code, output contract -- is added by ``compose`` to every strategy, so the
comparison between strategies varies only the security guidance.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from secure_prompt_lint.delimiting import INERT_INSTRUCTION, UntrustedBlock
from secure_prompt_lint.templates import sentences


@dataclass(frozen=True)
class Explanation:
    """Why the finding matters, about this code. S7 and S7a include it."""

    text: str
    source: str = "template"   # "template", or whoever wrote it (a model, a person)


def template_explanation(ctx: Any, g: Any) -> Explanation:
    """The explanation from the guidance table: what flows where, then why it matters. No model involved."""
    slots = ctx.slots()
    return Explanation(f"{g.render('explain', slots)} {g.render('risk', slots)}", "template")


@dataclass(frozen=True)
class StrategyInput:
    ctx: Any                 # a Finding, or an object with the same attributes
    guidance: Any            # a Guidance, or an object with cwe, name and render()
    explanation: Any         # an Explanation, or an object with .text
    block: UntrustedBlock    # the code, delimited (wrap_untrusted)


Build = Callable[[StrategyInput], tuple[str | None, list[str]]]


@dataclass(frozen=True)
class Strategy:
    id: str
    name: str
    origin: str          # where the technique comes from
    summary: str
    build: Build
    #: our strategies must pass the linter, or no prompt is produced at all
    enforce_lint: bool = False


def compose(opening: str, body: list[str], inp: StrategyInput) -> str:
    """First user message: strategy-specific opening and body, then the constant envelope."""
    ctx = inp.ctx
    parts = [opening, *body, sentences.scope(ctx), INERT_INSTRUCTION, inp.block.text, sentences.output_contract(ctx)]
    return "\n\n".join(p.strip() for p in parts if p and p.strip())
