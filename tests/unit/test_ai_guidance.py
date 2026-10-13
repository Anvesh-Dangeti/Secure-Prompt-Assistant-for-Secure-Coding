"""The guidance table: complete for the scope, and consistent with the linter that checks it."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ai.guidance import GuidanceDataError, all_guidance, guidance_for, load_guidance
from app.ai.linter.constituents import GUARD_RE
from app.ai.linter.text import contains_any
from app.mapping.mapper import tables


def test_every_scoped_cwe_has_guidance() -> None:
    assert {g.cwe for g in all_guidance()} == set(tables().scoped)


@pytest.mark.parametrize("g", all_guidance(), ids=lambda g: g.cwe)
def test_each_entry_satisfies_its_own_lint_rules(g) -> None:  # noqa: ANN001
    # A fix-it sentence that failed its own rule would make --fix loop forever.
    assert contains_any(g.render("directive"), g.vocabulary), "directive must use the CWE's vocabulary (A3)"
    assert GUARD_RE.search(g.render("guard")), "guard must state a condition (A2)"
    assert g.render("rule"), "S8 needs a standing rule"
    assert g.cwe.lower() in g.weakness_terms and g.name.lower() in g.weakness_terms


def test_unknown_cwe_falls_back_to_generic_without_vocabulary() -> None:
    g = guidance_for("CWE-918")
    assert g.generic and g.vocabulary == ()
    assert g.render("directive") == "Apply the standard mitigation for CWE-918 to the marked code."


def test_aliases_resolve_to_the_canonical_entry() -> None:
    assert guidance_for("CWE-259").cwe == "CWE-798"
    assert guidance_for("CWE-489").cwe == "CWE-94"


def test_missing_slots_read_as_neutral_words_never_braces() -> None:
    text = guidance_for("CWE-89").render("explain", {})
    assert "{" not in text and "the untrusted value" in text


@pytest.mark.parametrize("body, message", [
    ("guidance: []\n", "'guidance' mapping"),
    ("guidance:\n  CWE-259: {name: x}\n", "canonical"),
    ("guidance:\n  CWE-89: {name: x}\n", "'explain'"),
    ("guidance:\n  CWE-89: {name: a, explain: a, risk: a, directive: a, guard: a, mitre: a, rule: a}\n",
     "vocabulary"),
])
def test_malformed_tables_fail_loudly(tmp_path: Path, body: str, message: str) -> None:
    path = tmp_path / "g.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(GuidanceDataError, match=message):
        load_guidance(path)
