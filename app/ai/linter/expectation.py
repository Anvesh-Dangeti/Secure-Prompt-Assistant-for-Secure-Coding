"""What a prompt is checked against.

*Bound* to a finding, the linter knows the exact entities, weakness and
handling-directive vocabulary, and can offer the sentence that fixes each
missing constituent. *Unbound* -- a developer's own prompt with no finding
attached -- it can only check for the presence of *some* entity, weakness and
directive from the whole guidance table, and offers advice instead of sentences.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from app.ai import sentences
from app.ai.context import FindingContext
from app.ai.guidance import all_vocabulary, all_weakness_terms, guidance_for
from app.core.config import get_settings


@dataclass(frozen=True)
class LintExpectation:
    bound: bool
    cwe: str | None = None
    weakness_terms: tuple[str, ...] = ()
    entities: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    vocabulary: tuple[str, ...] = ()
    max_block_lines: int = 40
    token_budget: int = 1500
    fixits: Mapping[str, str] = field(default_factory=dict)
    canonical: str | None = None     # the generated prompt, for the no-shorten rule (A7)


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
    s = get_settings()
    return LintExpectation(
        bound=False,
        weakness_terms=all_weakness_terms(),
        vocabulary=all_vocabulary(),
        max_block_lines=s.max_context_lines,
        token_budget=s.prompt_token_budget,
    )
