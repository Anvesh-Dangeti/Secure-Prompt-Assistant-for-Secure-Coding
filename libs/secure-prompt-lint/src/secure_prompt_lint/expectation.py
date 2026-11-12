"""What a prompt is checked against.

*Bound* to a finding, the linter knows the exact entities, weakness and
handling-directive vocabulary, and can offer the sentence that fixes each
missing constituent. *Unbound* -- a developer's own prompt with no finding
attached -- it can only check for the presence of *some* entity, weakness and
directive from the whole vocabulary table, and offers advice instead of sentences.

``expectation()`` builds either kind from plain values, so the linter can be
used without the rest of the Secure Prompt Assistant: give it the CWE, the
names at risk (``host``, ``subprocess.check_output``) and where the code lives.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from secure_prompt_lint.sentences import fixits_for
from secure_prompt_lint.vocabulary import all_vocabulary, all_weakness_terms, entry_for

DEFAULT_MAX_BLOCK_LINES = 40     # data minimisation: the flagged function, not the file
DEFAULT_TOKEN_BUDGET = 1500


@dataclass(frozen=True)
class LintExpectation:
    bound: bool
    cwe: str | None = None
    weakness_terms: tuple[str, ...] = ()
    entities: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    vocabulary: tuple[str, ...] = ()
    max_block_lines: int = DEFAULT_MAX_BLOCK_LINES
    token_budget: int = DEFAULT_TOKEN_BUDGET
    fixits: Mapping[str, str] = field(default_factory=dict)
    canonical: str | None = None     # the generated prompt, for the no-shorten rule (A7)


def unbound_expectation(*, max_block_lines: int = DEFAULT_MAX_BLOCK_LINES,
                        token_budget: int = DEFAULT_TOKEN_BUDGET) -> LintExpectation:
    """A hand-written prompt with no finding attached: any known weakness and directive counts."""
    return LintExpectation(bound=False, weakness_terms=all_weakness_terms(), vocabulary=all_vocabulary(),
                           max_block_lines=max_block_lines, token_budget=token_budget)


def default_slots(entities: Iterable[str] = (), locations: Iterable[str] = ()) -> dict[str, str]:
    """Slots for the fix-it sentences, read from plain lists: the first entity is the untrusted
    value (``source``) and the second the call it reaches (``sink``); a location with a file
    extension is the ``file`` and any other location the ``symbol``."""
    entities, locations = list(entities), list(locations)
    slots = {"source": entities[0] if entities else "", "sink": entities[1] if len(entities) > 1 else ""}
    for loc in locations:
        key = "file" if "." in loc.rsplit("/", 1)[-1] and not loc.endswith(")") else "symbol"
        slots.setdefault(key, loc)
    return slots


def expectation(cwe: str | None = None, *, entities: Iterable[str] = (), locations: Iterable[str] = (),
                fixits: Mapping[str, str] | None = None, slots: Mapping[str, str] | None = None,
                canonical: str | None = None, max_block_lines: int = DEFAULT_MAX_BLOCK_LINES,
                token_budget: int = DEFAULT_TOKEN_BUDGET) -> LintExpectation:
    """Bind the linter to one finding. With no ``cwe`` the expectation is unbound.

    ``fixits`` maps a rule id (A1-A5) to the sentence that satisfies it; the
    fix-it step inserts those sentences. When it is not given they are rendered
    from the vocabulary's templates with ``slots`` (or slots read from
    ``entities`` and ``locations``). The structural rules (B2 delimiters, B3
    inert-data instruction) are repaired either way.
    """
    if not cwe:
        return unbound_expectation(max_block_lines=max_block_lines, token_budget=token_budget)
    entities, locations = tuple(entities), tuple(dict.fromkeys(locations))
    entry = entry_for(cwe)
    if fixits is None:
        fixits = fixits_for(cwe, slots if slots is not None else default_slots(entities, locations))
    return LintExpectation(
        bound=True, cwe=entry.cwe, weakness_terms=entry.weakness_terms, entities=entities,
        locations=locations, vocabulary=entry.vocabulary,
        max_block_lines=max_block_lines, token_budget=token_budget, fixits=dict(fixits), canonical=canonical,
    )
