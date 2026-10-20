"""Lab mode end to end on the real fixture: real scanners, real behaviour tests, recorded model answers.

Asserts ``recorded_results.LAB_REPLAYS``, so the replays shown at the review
produce exactly these verdicts. Needs the scanners and .tools/fixture.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.ai.providers import ReplayProvider
from app.cli import zip_directory
from app.core.scratch import scratch_dir
from app.db.models import TrackedFinding
from app.db.session import init_db, session_scope
from app.sandbox.lab import prepare_baseline, run_lab_trial
from app.scan_service import scan_zip
from app.scanners import all_scanners
from app.verification.gates.gate3b_tests import fixture_python
from evaluation.lifecycle_scenario import FIXTURE
from evaluation.recorded_results import FIXTURE_BEHAVIOUR_TESTS, LAB_REPLAYS

REPLAYS = FIXTURE.parents[1] / "evaluation" / "replays"

pytestmark = [
    pytest.mark.scanners,
    pytest.mark.skipif(not all(s.is_available() for s in all_scanners()), reason="scanners not installed"),
    pytest.mark.skipif(fixture_python() is None, reason="fixture test environment not installed"),
]


def test_recorded_replays_produce_the_documented_verdicts() -> None:
    init_db()
    with scratch_dir("t-") as work:
        zip_directory(FIXTURE, work / "fixture.zip")
        scan_zip("lab-fixture", work / "fixture.zip")
    with session_scope() as s:
        ids = {t.rule_id: t.id for t in s.scalars(select(TrackedFinding)) if t.rule_id in {"B608", "B602"}}

    baseline = prepare_baseline(FIXTURE)
    assert baseline.tests is not None and baseline.tests.detail.startswith(f"{FIXTURE_BEHAVIOUR_TESTS} passed")
    assert set(LAB_REPLAYS) == {p.stem for p in REPLAYS.glob("*.json")}
    for name, (rule, verdict, gate) in LAB_REPLAYS.items():
        with session_scope() as s:
            row = run_lab_trial(s, ids[rule], FIXTURE, "S7", ReplayProvider.from_file(REPLAYS / f"{name}.json"),
                                baseline=baseline)
            failed = next((g["gate"] for g in row.gates if g["status"] in {"FAIL", "UNVERIFIED"}), None)
            assert (row.verdict.value, failed) == (verdict, gate), name
            if verdict == "VERIFIED_RESOLVED":
                assert row.gates[3]["detail"].startswith(f"{FIXTURE_BEHAVIOUR_TESTS} passed"), name
