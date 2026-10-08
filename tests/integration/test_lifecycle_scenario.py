"""The Review 3 lifecycle demonstration, asserted step by step with the real scanners.

If this passes, ``python scripts/demo_lifecycle.py`` shows exactly these numbers.
"""

from __future__ import annotations

import pytest

from app.scanners import all_scanners
from evaluation.lifecycle_scenario import run_scenario

pytestmark = [
    pytest.mark.scanners,
    pytest.mark.skipif(not all(s.is_available() for s in all_scanners()), reason="scanners not installed"),
]

KEYS = ("NEW", "STILL_OPEN", "RESOLVED", "REGRESSION", "SUPPRESSED", "UNVERIFIED")
EXPECTED = {
    #                          NEW STILL RES REG SUP UNV   status
    "v1-baseline":            ((24, 0, 0, 0, 0, 0), "COMPLETED"),
    "v2-fix-sqli":            ((4, 19, 3, 0, 2, 0), "COMPLETED"),
    "v3-refactor":            ((0, 23, 0, 0, 2, 0), "COMPLETED"),   # reformat + nosec: no change at all
    "v4-revert":              ((0, 23, 0, 3, 2, 0), "COMPLETED"),
    "v5-secret-gitleaks-down": ((0, 24, 1, 0, 2, 1), "PARTIAL"),    # gitleaks finding kept open
    "v6-gitleaks-back":       ((0, 24, 1, 0, 2, 0), "COMPLETED"),
}


def test_scenario_produces_the_documented_lifecycle() -> None:
    results = run_scenario()
    assert [r.step.label for r in results] == list(EXPECTED)
    for r in results:
        counts, status = EXPECTED[r.step.label]
        assert tuple(r.summary.lifecycle[k] for k in KEYS) == counts, r.step.label
        assert r.summary.status == status, r.step.label

    by_label = {r.step.label: r for r in results}
    assert {c.rule for c in by_label["v1-baseline"].suppressed} == {"B403", "B404"}
    resolved_v2 = {c.cwe for c in by_label["v2-fix-sqli"].changes if c.to_status == "RESOLVED"}
    new_v2 = {c.cwe for c in by_label["v2-fix-sqli"].changes if c.to_status == "NEW"}
    assert resolved_v2 == {"CWE-89"} and new_v2 == {"CWE-78"}
    assert {c.cwe for c in by_label["v4-revert"].changes if c.to_status == "REGRESSION"} == {"CWE-89"}
    (kept,) = [c for c in by_label["v5-secret-gitleaks-down"].changes if c.unverified]
    assert kept.tool == "gitleaks" and kept.to_status == "STILL_OPEN"
    assert [c.tool for c in by_label["v6-gitleaks-back"].changes if c.to_status == "RESOLVED"] == ["gitleaks"]
