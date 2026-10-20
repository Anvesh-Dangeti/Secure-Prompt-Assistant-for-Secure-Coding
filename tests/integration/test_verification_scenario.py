"""The Review 4 verification demonstration, asserted step by step with the real scanners.

If this passes, ``python scripts/demo_verify.py`` shows exactly these verdicts.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models import Verification
from app.db.session import session_scope
from app.scanners import all_scanners
from evaluation.recorded_results import VERIFICATION
from evaluation.verification_scenario import run_scenario

pytestmark = [
    pytest.mark.scanners,
    pytest.mark.skipif(not all(s.is_available() for s in all_scanners()), reason="scanners not installed"),
]


def test_scenario_produces_the_documented_verdicts() -> None:
    results = [r for r in run_scenario() if r.verdict]
    assert [r.step.label for r in results] == list(VERIFICATION)
    with session_scope() as s:
        rows = {r.id: r for r in s.scalars(select(Verification))}
    for r in results:
        verdict, gate, group = VERIFICATION[r.step.label]
        assert (r.verdict, r.failed_gate, len(rows[r.verification_id].target)) == (verdict, gate, group), \
            r.step.label

    by_label = {r.step.label: r for r in results}
    # The stub silenced every scanner (gate 1 passes) -- only the structural gate catches it.
    stub = rows[by_label["v2-stub-ping"].verification_id]
    assert [g["status"] for g in stub.gates] == ["PASS", "PASS", "FAIL", "NOT_APPLICABLE"]
    # The real fix leaves only Bandit's LOW advisories: warnings, not a rejection.
    real = rows[by_label["v3-fix-ping"].verification_id]
    assert all(w.startswith("warning LOW: bandit B60") for w in real.gates[1]["items"])
    # Re-verification after a rejected commit compares with the last scan the weakness was seen in.
    assert rows[by_label["v6-remove-route"].verification_id].before_scan_id == \
        rows[by_label["v5-fix-sql-new-route"].verification_id].before_scan_id
