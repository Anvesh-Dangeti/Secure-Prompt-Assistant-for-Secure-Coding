"""The E1 numbers presented at review (``recorded_results.E1``) are the ones the linter produces today.

No model is involved: every mutant of every real finding's S7 prompt is linted
again on each test run, so a linter change that moves a number fails here.
"""

from __future__ import annotations

from evaluation.e1_mutation import OPERATORS, run
from evaluation.recorded_results import E1

RESULT = run()


def test_headline_numbers() -> None:
    assert RESULT["findings"] == E1["findings"] and RESULT["controls_clean"] == E1["controls_clean"]
    assert RESULT["constituent"] == E1["constituent"]
    assert RESULT["unchecked"] == E1["unchecked"]


def test_every_operator() -> None:
    assert set(E1["by_operator"]) == set(OPERATORS)
    for name, (failed, flagged) in E1["by_operator"].items():
        row = RESULT["by_operator"][name]
        assert (row["failed"], row["flagged"]) == (failed, flagged), name


def test_whatever_fails_is_repaired_by_its_fix_its() -> None:
    for name, row in RESULT["by_operator"].items():
        assert row["repaired"] == row["failed"], name


def test_no_rule_fires_on_what_no_rule_covers() -> None:
    for name in ("delete explanation", "delete classification", "delete untrusted code", "delete output contract"):
        assert RESULT["by_operator"][name]["rules"] == {}, name
