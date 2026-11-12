"""The per-CWE words the constituent rules look for.

For each weakness the table holds:

* ``name`` and ``aliases`` -- ways a prompt can name the weakness (rule A5:
  "SQL injection", "SQLi", "CWE-89");
* ``vocabulary`` -- stems of the handling directive (rule A3: "parameteris",
  "allowlist", "shell=false"). Matching is case-insensitive and anchored at a
  word start, so a stem covers its inflections ("parameterised") without
  matching inside another word ("salt" is not satisfied by "unsalted").

``cwe_aliases`` folds child CWEs into the entry that covers them (CWE-259, a
hard-coded password, is checked as CWE-798). The bundled table covers the ten
weaknesses the Secure Prompt Assistant scopes; ``use_vocabulary()`` swaps in
another table of the same shape, which is how a study extends the linter to new
CWEs without touching code.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path

GENERIC = "an unclassified weakness"
TEMPLATE_FIELDS = ("explain", "directive", "guard")


class VocabularyError(ValueError):
    """The vocabulary table is malformed."""


@dataclass(frozen=True)
class VocabularyEntry:
    cwe: str
    name: str
    aliases: tuple[str, ...]
    vocabulary: tuple[str, ...]
    #: sentence templates the fix-its insert: "explain" (A1), "directive" (A3), "guard" (A2)
    templates: Mapping[str, str] = field(default_factory=dict)

    @property
    def weakness_terms(self) -> tuple[str, ...]:
        """Lower-case ways of naming this weakness: CWE id, name, aliases."""
        terms = [self.cwe.lower(), self.name.lower(), *self.aliases]
        return tuple(dict.fromkeys(t for t in terms if t and t != GENERIC))


@dataclass(frozen=True)
class Vocabulary:
    entries: dict[str, VocabularyEntry]
    cwe_aliases: dict[str, str]
    slot_defaults: dict[str, str] = field(default_factory=dict)


def _strings(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise VocabularyError(f"{where} must be a list of non-empty strings")
    return tuple(v.strip().lower() for v in value)


def parse_vocabulary(data: object) -> Vocabulary:
    if not isinstance(data, dict) or not isinstance(data.get("weaknesses"), dict):
        raise VocabularyError("the vocabulary must be an object with a 'weaknesses' mapping")
    entries = {}
    for cwe, raw in data["weaknesses"].items():
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"].strip():
            raise VocabularyError(f"{cwe}: needs a non-empty 'name'")
        vocab = _strings(raw.get("vocabulary", []), f"{cwe}.vocabulary")
        if not vocab:
            raise VocabularyError(f"{cwe}: a weakness needs at least one handling-directive term")
        templates = raw.get("templates", {})
        if not isinstance(templates, dict) or not all(
                k in TEMPLATE_FIELDS and isinstance(v, str) for k, v in templates.items()):
            raise VocabularyError(f"{cwe}.templates must map {', '.join(TEMPLATE_FIELDS)} to strings")
        entries[cwe] = VocabularyEntry(cwe, raw["name"].strip(), _strings(raw.get("aliases", []), f"{cwe}.aliases"),
                                       vocab, dict(templates))
    maps = {}
    for name in ("cwe_aliases", "slot_defaults"):
        value = data.get(name, {})
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
            raise VocabularyError(f"'{name}' must map strings to strings")
        maps[name] = dict(value)
    return Vocabulary(entries, maps["cwe_aliases"], maps["slot_defaults"])


def load_vocabulary(path: str | Path | None = None) -> Vocabulary:
    """Load a vocabulary table (JSON). Without a path, the bundled table."""
    if path is None:
        text = resources.files("secure_prompt_lint").joinpath("data/cwe_vocabulary.json").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    return parse_vocabulary(json.loads(text))


_active: Vocabulary | None = None


@lru_cache(maxsize=1)
def _bundled() -> Vocabulary:
    return load_vocabulary()


def current() -> Vocabulary:
    return _active or _bundled()


def use_vocabulary(vocabulary: Vocabulary | None) -> None:
    """Make ``vocabulary`` the table every later expectation is built from (``None``: the bundled one)."""
    global _active
    _active = vocabulary


def canonical(cwe: str | None) -> str | None:
    if not cwe:
        return None
    cwe = cwe.strip().upper()
    return current().cwe_aliases.get(cwe, cwe)


def entry_for(cwe: str | None) -> VocabularyEntry:
    """The entry for ``cwe``. An unknown CWE gets one with no directive vocabulary:
    rule A3 then reports the directive as unverifiable rather than passing it."""
    key = canonical(cwe)
    entry = current().entries.get(key or "")
    if entry is not None:
        return entry
    label = key or GENERIC
    return VocabularyEntry(label, f"{label} weakness" if key else GENERIC, (), ())


def all_vocabulary() -> tuple[str, ...]:
    return tuple(sorted({term for e in current().entries.values() for term in e.vocabulary}))


def all_weakness_terms() -> tuple[str, ...]:
    return tuple(sorted({term for e in current().entries.values() for term in e.weakness_terms}))
