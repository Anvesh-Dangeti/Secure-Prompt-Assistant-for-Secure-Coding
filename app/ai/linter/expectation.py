"""What a prompt is checked against -- the application's side of the linter.

The linter itself is the ``secure_prompt_lint`` library. This module binds it to
a finding the way only this application can: from a ``FindingContext`` (the
entities ``ast`` found, the symbol and file) and the guidance table, whose
sentences become the fix-its. A fix-it therefore inserts exactly the sentence
our own strategy S7 would have had.

*Bound* to a finding, the linter knows the exact entities, weakness and
handling-directive vocabulary. *Unbound* -- a developer's own prompt with no
finding attached -- it checks for *some* entity, weakness and directive from
the whole table, and offers advice instead of sentences.
"""

from __future__ import annotations

from secure_prompt_lint.expectation import LintExpectation
from secure_prompt_lint.expectation import unbound_expectation as _library_unbound

from app.ai import sentences
from app.ai.context import FindingContext
from app.ai.guidance import guidance_for
from app.core.config import get_settings

__all__ = ["LintExpectation", "expectation_for", "unbound_expectation"]


def expectation_for(ctx: FindingContext, canonical: str | None = None) -> LintExpectation:
    g = guidance_for(ctx.cwe)
    s = get_settings()
    locations = [loc for loc in (ctx.symbol, ctx.file_path, ctx.file_path.rsplit("/", 1)[-1]) if loc]
    return LintExpectation(
        bound=True,
        cwe=ctx.cwe,
        weakness_terms=g.weakness_terms,
        entities=ctx.entities,
        locations=tuple(dict.fromkeys(locations)),
        vocabulary=g.vocabulary,
        max_block_lines=s.max_context_lines,
        token_budget=s.prompt_token_budget,
        fixits={
            "A1": sentences.binding(ctx, g),
            "A2": sentences.guard(ctx, g),
            "A3": sentences.directive(ctx, g),
            "A4": sentences.scope(ctx),
            "A5": sentences.opening(ctx, g),
        },
        canonical=canonical,
    )


def unbound_expectation() -> LintExpectation:
    """The library's unbound expectation with this deployment's limits.

    Its vocabulary is the one exported from our guidance table
    (``scripts/export_lint_vocabulary.py``; a test keeps them equal).
    """
    s = get_settings()
    return _library_unbound(max_block_lines=s.max_context_lines, token_budget=s.prompt_token_budget)
