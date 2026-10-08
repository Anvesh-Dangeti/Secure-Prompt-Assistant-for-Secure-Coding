"""Classify normalised findings: canonical CWE, OWASP 2021 category, scope.

Precedence for the CWE, most specific first:
    1. a documented rule-level override (rule_overrides.yaml ``rules``)
    2. the CWE the tool reported
    3. the tool's documented default (Gitleaks -> 798, pip-audit -> 1395)
then canonicalised through ``aliases``.

OWASP comes from our own table for the canonical CWE; only when we have no
row do we fall back to the tool's own OWASP 2021 tag. CVEs are never invented
here -- they arrive only from pip-audit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.normalization.finding import NormalizedFinding

DATA_DIR = Path(__file__).resolve().parent / "data"
_CWE_ID = re.compile(r"^CWE-\d{1,5}$")
_OWASP_ID = re.compile(r"^A(0[1-9]|10)$")


class MappingDataError(ValueError):
    """A mapping data file is malformed; refuse to classify with bad tables."""


@dataclass(frozen=True)
class MappingTables:
    owasp_names: dict[str, str]
    cwe_to_owasp: dict[str, str]
    aliases: dict[str, str]
    alias_reasons: dict[str, str]
    scoped: frozenset[str]
    tool_defaults: dict[str, str]
    rule_overrides: dict[str, str]
    override_reasons: dict[str, str]


def _load_yaml(path: Path) -> dict:
    # safe_load: a data file must never be able to construct Python objects.
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise MappingDataError(f"{path.name}: top level must be a mapping")
    return data


def _check_cwe(value: object, where: str) -> str:
    if not isinstance(value, str) or not _CWE_ID.match(value):
        raise MappingDataError(f"{where}: invalid CWE id {value!r}")
    return value


def load_tables(data_dir: Path = DATA_DIR) -> MappingTables:
    core = _load_yaml(data_dir / "cwe_owasp.yaml")
    over = _load_yaml(data_dir / "rule_overrides.yaml")

    owasp_names = {str(k): str(v) for k, v in (core.get("owasp_2021") or {}).items()}
    for key in owasp_names:
        if not _OWASP_ID.match(key):
            raise MappingDataError(f"owasp_2021: invalid category {key!r}")

    cwe_to_owasp: dict[str, str] = {}
    for cwe, cat in (core.get("cwe_to_owasp") or {}).items():
        _check_cwe(cwe, "cwe_to_owasp")
        if cat not in owasp_names:
            raise MappingDataError(f"cwe_to_owasp: {cwe} -> unknown category {cat!r}")
        cwe_to_owasp[cwe] = cat

    aliases, alias_reasons = {}, {}
    for cwe, spec in (core.get("aliases") or {}).items():
        _check_cwe(cwe, "aliases")
        if not isinstance(spec, dict):
            raise MappingDataError(f"aliases: {cwe} must be a mapping")
        aliases[cwe] = _check_cwe(spec.get("canonical"), f"aliases.{cwe}")
        alias_reasons[cwe] = str(spec.get("reason", "")).strip()
    for cwe, target in aliases.items():
        # Checked after the table is complete, so entry order cannot hide a chain.
        if target in aliases:
            raise MappingDataError(f"aliases: {cwe} maps to another alias; chains are not allowed")

    scoped = frozenset(_check_cwe(c, "scoped") for c in (core.get("scoped") or []))
    for cwe in scoped:
        if cwe not in cwe_to_owasp:
            raise MappingDataError(f"scoped CWE {cwe} has no OWASP mapping")

    tool_defaults = {
        str(tool): _check_cwe((spec or {}).get("cwe"), f"tool_defaults.{tool}")
        for tool, spec in (over.get("tool_defaults") or {}).items()
    }
    rule_overrides, override_reasons = {}, {}
    for rule, spec in (over.get("rules") or {}).items():
        rule_overrides[str(rule)] = _check_cwe((spec or {}).get("cwe"), f"rules.{rule}")
        override_reasons[str(rule)] = str((spec or {}).get("reason", "")).strip()

    return MappingTables(
        owasp_names, cwe_to_owasp, aliases, alias_reasons, scoped,
        tool_defaults, rule_overrides, override_reasons,
    )


@lru_cache(maxsize=1)
def tables() -> MappingTables:
    return load_tables()


def canonical_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return tables().aliases.get(cwe, cwe)


def owasp_label(category: str | None) -> str | None:
    return tables().owasp_names.get(category) if category else None


def classify(finding: NormalizedFinding) -> NormalizedFinding:
    """Fill ``cwe``, ``owasp``, ``in_scope`` and ``mapping_note`` in place."""
    t = tables()
    notes: list[str] = []

    if finding.rule_id in t.rule_overrides:
        chosen = t.rule_overrides[finding.rule_id]
        if finding.cwe_reported and finding.cwe_reported != chosen:
            notes.append(f"rule override {finding.cwe_reported}->{chosen}")
    elif finding.cwe_reported:
        chosen = finding.cwe_reported
    else:
        chosen = t.tool_defaults.get(finding.tool)
        if chosen:
            notes.append(f"tool default {chosen}")

    canonical = canonical_cwe(chosen)
    if chosen and canonical != chosen:
        notes.append(f"alias {chosen}->{canonical}")

    category = t.cwe_to_owasp.get(canonical or "")
    if category is None and finding.owasp_reported in t.owasp_names:
        category = finding.owasp_reported
        notes.append("OWASP from tool tag")

    finding.cwe = canonical
    finding.owasp = category
    finding.in_scope = (canonical or "") in t.scoped
    finding.mapping_note = "; ".join(notes) or None
    return finding
