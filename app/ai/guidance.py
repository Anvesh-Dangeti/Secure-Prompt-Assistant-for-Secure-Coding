"""Per-CWE remediation guidance (``app/mapping/data/cwe_guidance.yaml``).

One table feeds the Explainer, the prompt strategies and the linter, so the
sentence a prompt uses to state its handling directive and the vocabulary the
linter checks that directive against come from the same entry.

Templates are trusted project data; slot values are identifiers extracted by
``ast`` or package metadata, never free text from the scanned repository.
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.mapping.mapper import DATA_DIR, canonical_cwe

GUIDANCE_FILE = DATA_DIR / "cwe_guidance.yaml"
TEXT_FIELDS = ("name", "explain", "risk", "directive", "guard", "mitre", "rule")

# What a slot reads as when the context could not supply it. Neutral wording
# keeps the sentence grammatical without inventing a detail.
SLOT_DEFAULTS = {
    "source": "the untrusted value",
    "origin": "outside the program",
    "sink": "the vulnerable call",
    "target": "the value",
    "base": "the intended directory",
    "symbol": "the marked code",
    "package": "the package",
    "version": "the pinned version",
    "fixed": "a fixed version",
    "vulns": "the published advisories",
    "cwe": "this CWE",
}


class GuidanceDataError(ValueError):
    """The guidance table is malformed -- a configuration error, never ignored."""


class _Slots(dict):
    def __missing__(self, key: str) -> str:
        return SLOT_DEFAULTS.get(key, "")


@dataclass(frozen=True)
class CweGuidance:
    cwe: str
    texts: Mapping[str, str]
    vocabulary: tuple[str, ...]
    aliases: tuple[str, ...]
    generic: bool

    def render(self, field: str, slots: Mapping[str, str] | None = None) -> str:
        values = _Slots({k: v for k, v in (slots or {}).items() if v})
        values.setdefault("cwe", self.cwe)
        return string.Formatter().vformat(self.texts[field], (), values).strip()

    @property
    def name(self) -> str:
        return self.render("name")

    @property
    def weakness_terms(self) -> tuple[str, ...]:
        """Lower-case ways of naming this weakness: CWE id, name, aliases."""
        terms = [self.cwe.lower(), self.name.lower(), *self.aliases]
        return tuple(dict.fromkeys(t for t in terms if t and t != "an unclassified weakness"))


def _entry(cwe: str, raw: object, generic: bool) -> CweGuidance:
    if not isinstance(raw, dict):
        raise GuidanceDataError(f"{cwe}: entry must be a mapping")
    texts = {}
    for field in TEXT_FIELDS:
        value = raw.get(field)
        if not isinstance(value, str) or (not value.strip() and field != "rule"):
            raise GuidanceDataError(f"{cwe}: '{field}' must be a non-empty string")
        texts[field] = value
    lists = {}
    for field in ("vocabulary", "aliases"):
        values = raw.get(field, [])
        if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
            raise GuidanceDataError(f"{cwe}: '{field}' must be a list of strings")
        lists[field] = tuple(v.strip().lower() for v in values)
    if not generic and not lists["vocabulary"]:
        raise GuidanceDataError(f"{cwe}: a scoped CWE needs a handling-directive vocabulary")
    return CweGuidance(cwe, texts, lists["vocabulary"], lists["aliases"], generic)


def load_guidance(path: Path = GUIDANCE_FILE) -> tuple[dict[str, CweGuidance], CweGuidance]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("guidance"), dict):
        raise GuidanceDataError("cwe_guidance.yaml must contain a 'guidance' mapping")
    entries = {}
    for cwe, raw in data["guidance"].items():
        if canonical_cwe(str(cwe)) != cwe:
            raise GuidanceDataError(f"{cwe}: guidance must be keyed by canonical CWE")
        entries[str(cwe)] = _entry(str(cwe), raw, generic=False)
    return entries, _entry("generic", data.get("generic"), generic=True)


@lru_cache(maxsize=1)
def _table() -> tuple[dict[str, CweGuidance], CweGuidance]:
    return load_guidance()


def guidance_for(cwe: str | None) -> CweGuidance:
    entries, generic = _table()
    canonical = canonical_cwe(cwe)
    if canonical in entries:
        return entries[canonical]
    return CweGuidance(canonical or "an unclassified weakness", generic.texts, (), (), True)


def all_guidance() -> list[CweGuidance]:
    """Every scoped entry, in file order -- the S8 standing ruleset."""
    return list(_table()[0].values())


def all_vocabulary() -> tuple[str, ...]:
    return tuple(sorted({term for g in all_guidance() for term in g.vocabulary}))


def all_weakness_terms() -> tuple[str, ...]:
    return tuple(sorted({term for g in all_guidance() for term in g.weakness_terms}))
