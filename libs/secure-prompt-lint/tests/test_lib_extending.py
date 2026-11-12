"""Extending the linter: custom rules, another vocabulary, and the bundled benchmark."""

from __future__ import annotations

import json

import pytest

from secure_prompt_lint import (WARNING, LintIssue, describe_rules, expectation, lint, load_vocabulary,
                                register_rule, unregister_rule, use_vocabulary)
from secure_prompt_lint.bench import OPERATORS, load_cases, score
from secure_prompt_lint.vocabulary import VocabularyError, parse_vocabulary


def test_a_custom_rule_runs_after_the_built_ins() -> None:
    @register_rule("X1", "names the web framework")
    def framework(ctx):  # noqa: ANN001, ANN202
        return [] if "flask" in ctx.instructions.lower() else [LintIssue("X1", WARNING, "no framework named")]

    try:
        report = lint("Fix the SQL injection in app.py.")
        assert report.issues[-1].rule == "X1"
        assert lint("Fix the SQL injection in the Flask app.py.").failed("X1") is False
        assert "X1" in describe_rules()
    finally:
        unregister_rule("X1")
    assert not lint("Fix the SQL injection in app.py.").failed("X1")


def test_built_in_ids_are_reserved() -> None:
    with pytest.raises(ValueError, match="built-in"):
        register_rule("A1", "shadowing")
    with pytest.raises(ValueError, match="alphanumeric"):
        register_rule("bad id!", "spaces")


def test_a_custom_rule_cannot_report_a_built_in_id() -> None:
    @register_rule("X2", "misbehaves")
    def bad(ctx):  # noqa: ANN001, ANN202
        return [LintIssue("A1", WARNING, "pretending")]

    try:
        with pytest.raises(ValueError, match="built-in rule id"):
            lint("Fix it.")
    finally:
        unregister_rule("X2")


def test_another_vocabulary_extends_the_linter_to_a_new_cwe(tmp_path) -> None:  # noqa: ANN001
    table = {"weaknesses": {"CWE-601": {"name": "open redirect", "aliases": ["open redirect"],
                                        "vocabulary": ["allowlist of redirect targets", "relative path"]}}}
    path = tmp_path / "vocab.json"
    path.write_text(json.dumps(table), encoding="utf-8")
    try:
        use_vocabulary(load_vocabulary(path))
        exp = expectation("CWE-601", entities=["next_url"], locations=["views.py"])
        prompt = ("Fix the open redirect (CWE-601) in views.py, where `next_url` is used unsafely. Redirect only "
                  "if `next_url` is in the allowlist of redirect targets. Do not modify anything else.")
        assert lint(prompt, exp).passed
    finally:
        use_vocabulary(None)
    assert expectation("CWE-601").vocabulary == ()          # back to the bundled table


@pytest.mark.parametrize("bad", [
    {}, {"weaknesses": []}, {"weaknesses": {"CWE-1": {"name": ""}}},
    {"weaknesses": {"CWE-1": {"name": "x", "vocabulary": []}}},
    {"weaknesses": {"CWE-1": {"name": "x", "vocabulary": ["y"], "templates": {"other": "z"}}}},
    {"weaknesses": {}, "cwe_aliases": {"CWE-2": 3}},
])
def test_a_malformed_vocabulary_is_refused(bad) -> None:  # noqa: ANN001
    with pytest.raises(VocabularyError):
        parse_vocabulary(bad)


def test_the_bundled_benchmark_reproduces_the_published_numbers() -> None:
    cases = load_cases()
    result = score(cases)
    assert result["findings"] == 24 and result["controls_clean"] == 24
    assert result["mutants"] == 24 * len(OPERATORS) == 288
    assert result["constituent"] == {"mutants": 168, "failed": 149, "flagged": 168}
    assert result["unchecked"] == {"mutants": 96, "failed": 0, "flagged": 0}
    assert all(row["repaired"] == row["failed"] for row in result["by_operator"].values())


def test_the_bundled_benchmark_carries_no_secret() -> None:
    # Every control passes clean, which includes rule B1 (no secret-like value) on all 24 prompts.
    assert all(not lint(c.canonical, c.expectation).failed("B1") for c in load_cases())
