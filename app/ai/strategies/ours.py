"""S7 -- our strategy: explained feedback + every linted constituent + RCI.

* Paper 1: an explanation tied to the specific code beats raw scanner output;
* Paper 2: the opening sentence carries task, weakness, location and entity,
  and the guard and handling directive are stated before the code;
* Paper 3: recursive criticism and improvement was the strongest technique --
  here the critique is *explained* too: it asks about this weakness, about
  newly introduced weaknesses, and about preserved behaviour (gates 1-3).

S7 is the only strategy whose prompt must pass the linter: if it does not, no
prompt is produced (fail closed), because a prompt that silently lost a
constituent is exactly the failure the linter exists to stop.
"""

from __future__ import annotations

from app.ai import sentences
from app.ai.strategies.base import Strategy, StrategyInput, compose


def s7(inp: StrategyInput):
    ctx, g = inp.ctx, inp.guidance
    body = [
        f"Why it matters: {inp.explanation.text}",
        f"Required change: {sentences.directive(ctx, g)}",
        f"Condition: {sentences.guard(ctx, g)}",
        sentences.classification(ctx),
    ]
    first = compose(sentences.opening(ctx, g), body, inp)
    subject = f"`{ctx.symbol}`" if ctx.symbol and ctx.window_kind in {"function", "lines"} else "the code"
    review = (f"Review your answer before it is used: is the {g.name} ({g.cwe}) fully removed, does the change "
              f"introduce any other weakness, and does {subject} keep its behaviour for valid input? "
              f"List every problem you find.")
    final = "Based on your review, give the final corrected version. " + sentences.output_contract(ctx)
    return None, [first, review, final]


OURS = [
    Strategy("S7", "Explained + linted + RCI", "this project (Papers 1, 2, 3)",
             "code-specific explanation, all constituents, explained RCI", s7, enforce_lint=True),
]
