"""Per-CWE remediation guidance: the vocabulary table, read as sentence templates.

One table feeds both sides. The handling directive a prompt states and the
vocabulary the linter checks that directive against come from the same entry,
so a generated prompt and the check that validates it cannot disagree.

Per weakness the templates are:

* ``explain``   -- what flows where, in this code       (the explanation; binding sentence)
* ``risk``      -- why it matters                       (the explanation)
* ``directive`` -- *how* to fix it                      (S7; the linter's rule A3)
* ``guard``     -- *when* the operation may proceed     (S7; the linter's rule A2)
* ``mitre``     -- MITRE CWE's mitigation, paraphrased  (S2)
* ``rule``      -- a finding-independent standing rule  (S8's rules file)

Slots such as ``{source}`` and ``{sink}`` are filled from the finding; an empty
slot reads as a neutral phrase, never as a raw brace. ``use_vocabulary()``
swaps the table, which re-words every prompt and every check together.
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from dataclasses import dataclass

from secure_prompt_lint.sentences import _Slots
from secure_prompt_lint.vocabulary import GENERIC, _bundled, canonical, current


@dataclass(frozen=True)
class Guidance:
    cwe: str
    texts: Mapping[str, str]        # "name" plus the sentence templates
    vocabulary: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    generic: bool = False

    def render(self, field: str, slots: Mapping[str, str] | None = None) -> str:
        """Fill one template with ``slots``; a template the table lacks reads as an empty string."""
        values = _Slots({k: v for k, v in (slots or {}).items() if v})
        values.setdefault("cwe", self.cwe)
        return string.Formatter().vformat(self.texts.get(field, ""), (), values).strip()

    @property
    def name(self) -> str:
        return self.render("name")

    @property
    def weakness_terms(self) -> tuple[str, ...]:
        """Lower-case ways of naming this weakness: CWE id, name, aliases."""
        terms = [self.cwe.lower(), self.name.lower(), *self.aliases]
        return tuple(dict.fromkeys(t for t in terms if t and t != GENERIC))


def guidance_for(cwe: str | None) -> Guidance:
    """The guidance for ``cwe``; a weakness outside the table gets the generic wording."""
    key = canonical(cwe)
    entry = current().entries.get(key or "")
    if entry is not None:
        return Guidance(entry.cwe, {"name": entry.name, **entry.templates}, entry.vocabulary, entry.aliases)
    generic = current().generic or _bundled().generic
    return Guidance(key or GENERIC, dict(generic), (), (), True)


def all_guidance() -> list[Guidance]:
    """Every entry of the table, in table order (S8's standing ruleset)."""
    return [guidance_for(cwe) for cwe in current().entries]
