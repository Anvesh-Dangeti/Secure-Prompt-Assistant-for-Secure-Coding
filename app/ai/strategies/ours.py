"""Our strategies: S7 and the two token-ladder variants of it.

S7 -- explained feedback + every linted constituent + RCI:

* Paper 1: an explanation tied to the specific code beats raw scanner output;
* Paper 2: the opening sentence carries task, weakness, location and entity,
  and the guard and handling directive are stated before the code;
* Paper 3: recursive criticism and improvement was the strongest technique --
  here the critique is *explained* too: it asks about this weakness, about
  newly introduced weaknesses, and about preserved behaviour (gates 1-3).

The token ladder asks how far a prompt can shrink before it stops working:

* S7a -- S7's first message alone. RCI re-sends the whole conversation twice,
  so dropping its two turns removes most of S7's cost; this isolates that cost.
* S7m -- the minimal prompt: only what the linter requires. The opening,
  handling directive and guard (plus the entity binding when the opening does
  not already name the entity), a compact scope / inert-data / output line, and
  the same delimited code. No explanation, no classification. It deliberately
  compresses the envelope that S0-S8 share, which is the variable measured.

All three must pass the linter or no prompt is produced (fail closed): a
shorter prompt is only acceptable if it lost words, not constituents.
"""

from __future__ import annotations

from app.ai import sentences
from app.ai.linter.text import mentions
from app.ai.strategies.base import Strategy, StrategyInput, compose


def _first_message(inp: StrategyInput) -> str:
    ctx, g = inp.ctx, inp.guidance
    body = [
        f"Why it matters: {inp.explanation.text}",
        f"Required change: {sentences.directive(ctx, g)}",
        f"Condition: {sentences.guard(ctx, g)}",
        sentences.classification(ctx),
    ]
    return compose(sentences.opening(ctx, g), body, inp)


def s7(inp: StrategyInput):
    ctx, g = inp.ctx, inp.guidance
    subject = f"`{ctx.symbol}`" if ctx.symbol and ctx.window_kind in {"function", "lines"} else "the code"
    review = (f"Review your answer before it is used: is the {g.name} ({g.cwe}) fully removed, does the change "
              f"introduce any other weakness, and does {subject} keep its behaviour for valid input? "
              f"List every problem you find.")
    final = "Based on your review, give the final corrected version. " + sentences.output_contract(ctx)
    return None, [_first_message(inp), review, final]


def s7a(inp: StrategyInput):
    return None, [_first_message(inp)]


def s7m(inp: StrategyInput):
    ctx, g = inp.ctx, inp.guidance
    opening = sentences.opening(ctx, g)
    directive, guard = sentences.directive(ctx, g), sentences.guard(ctx, g)
    said = " ".join((opening, directive, guard))
    parts = [opening]
    if ctx.entities and not any(mentions(said, e) for e in ctx.entities):
        parts.append(sentences.binding(ctx, g))
    parts += [directive, guard, sentences.scope_compact(ctx), sentences.INERT_COMPACT, inp.block.text,
              sentences.output_contract_compact(ctx)]
    return None, ["\n\n".join(p.strip() for p in parts if p and p.strip())]


OURS = [
    Strategy("S7", "Explained + linted + RCI", "this project (Papers 1, 2, 3)",
             "code-specific explanation, all constituents, explained RCI", s7, enforce_lint=True),
    Strategy("S7a", "Ours, one message", "this project (token ladder)",
             "S7's first message only: no review turns", s7a, enforce_lint=True),
    Strategy("S7m", "Ours, minimal", "this project (token ladder)",
             "only the linted constituents, compact envelope", s7m, enforce_lint=True),
]
