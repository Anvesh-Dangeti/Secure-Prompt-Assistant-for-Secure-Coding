"""The sentences a fix-it inserts when a constituent is missing.

Bound to a weakness, the fix-it for each constituent rule is a sentence:

* A5 opening    -- "Fix the OS command injection (CWE-78) in `ping_host` in app.py, where `host` reaches ..."
* A1 binding    -- which value is at risk and which operation it reaches
* A3 directive  -- how the value must be handled
* A2 guard      -- when the operation may proceed
* A4 scope      -- do not change anything else

The binding, directive and guard sentences are templates from the vocabulary
table, filled with *slots*: ``source`` (the untrusted value), ``sink`` (the call
it reaches), ``origin``, ``symbol``, ``package`` and so on. A slot left empty
reads as a neutral phrase ("the untrusted value"), so a sentence stays
grammatical without inventing a detail. Slot values are identifiers the caller
supplies, never free text from the code under repair.

These are the sentences the Secure Prompt Assistant's own strategy uses, so a
repaired prompt reads like a generated one.
"""

from __future__ import annotations

import string
from collections.abc import Mapping

from secure_prompt_lint.vocabulary import VocabularyEntry, current, entry_for


class _Slots(dict):
    def __missing__(self, key: str) -> str:
        return current().slot_defaults.get(key, "")


def render(entry: VocabularyEntry, field: str, slots: Mapping[str, str] | None = None) -> str:
    """Fill one of the entry's templates; an entry without that template gives an empty string."""
    template = entry.templates.get(field)
    if not template:
        return ""
    values = _Slots({k: v for k, v in (slots or {}).items() if v})
    values.setdefault("cwe", entry.cwe)
    return string.Formatter().vformat(template, (), values).strip()


def _location(slots: Mapping[str, str]) -> str:
    file, symbol = slots.get("file"), slots.get("symbol")
    if symbol and file:
        return f"`{symbol}` in {file}"
    return f"`{symbol}`" if symbol else (file or "the marked code")


def fixits_for(cwe: str | None, slots: Mapping[str, str] | None = None) -> dict[str, str]:
    """Rule id -> the sentence that satisfies it, for a weakness and the given slots."""
    slots = dict(slots or {})
    entry = entry_for(cwe)
    source, sink, symbol = slots.get("source"), slots.get("sink"), slots.get("symbol")
    clause = (f", where `{source}` reaches `{sink}`" if source and sink else
              f", where `{source}` is used unsafely" if source else
              f", in the call to `{sink}`" if sink else "")
    out = {"A5": f"Fix the {entry.name} ({entry.cwe}) in {_location(slots)}{clause}."}
    binding = render(entry, "explain", slots)
    entities = [e for e in (source, sink) if e]
    if binding and entities and not any(e in binding for e in entities):
        binding = f"The flagged code is `{entities[0]}`. {binding}"
    for rule, text in (("A1", binding), ("A3", render(entry, "directive", slots)),
                       ("A2", render(entry, "guard", slots))):
        if text:
            out[rule] = text
    out["A4"] = (f"Change only the code between the markers: do not rename `{symbol}`, do not modify anything "
                 f"else in the file, and keep its behaviour for valid input." if symbol else
                 "Change only the code between the markers and do not modify anything else in the file.")
    return out
