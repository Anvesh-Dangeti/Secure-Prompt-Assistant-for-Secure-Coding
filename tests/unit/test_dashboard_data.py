"""Dashboard read models over a real database built by real scans (stand-in scanners)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import TrackedFinding
from app.db.session import init_db, session_scope
from app.intelligence.tracking import suppress
from app.verification.service import verify
from dashboard import data
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, write_app


@pytest.fixture
def project(tmp_path: Path) -> int:
    init_db()
    code = write_app(tmp_path / "code")
    first = scan("demo", code)                                       # 3 findings: B608, B602, semgrep SQLi
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    second = scan("demo", code)                                      # SQLi resolved (2 findings)
    with session_scope() as s:
        b608 = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).one()
        verify(s, b608.id, second.scan_id)
        b602 = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B602")).one()
        suppress(s, b602.id, "accepted risk for the demo")
    return first.project_id


def test_projects(project: int) -> None:
    (p,) = data.projects()
    assert (p.id, p.name, p.source_type, p.scans) == (project, "demo", "zip", 2)


def test_overview_counts(project: int) -> None:
    o = data.overview(project)
    assert o.states == {"NEW": 0, "STILL_OPEN": 0, "RESOLVED": 2, "REGRESSION": 0, "SUPPRESSED": 1}
    assert sum(o.open_by_severity.values()) == 0 and list(o.open_by_severity) == list(data.SEVERITIES)
    assert o.verdicts["VERIFIED_RESOLVED"] == 1
    assert o.latest.id == 2 and o.latest.findings == 1
    assert {r["scanner"] for r in o.scanner_runs} == {"bandit", "semgrep"}
    assert data.overview(9999) is None


def test_tracked_filters_and_order(project: int) -> None:
    rows = data.tracked(project)
    assert [r.status for r in rows] == ["RESOLVED", "RESOLVED", "SUPPRESSED"]    # lifecycle order
    assert {r.rule for r in data.tracked(project, states=["RESOLVED"])} == {"B608", "tainted-sql-string"}
    assert [r.rule for r in data.tracked(project, severities=["HIGH"], tools=["bandit"])] == ["B602"]
    b608 = next(r for r in rows if r.rule == "B608")
    assert b608.verdict == "VERIFIED_RESOLVED" and b608.label == f"#{b608.id} MEDIUM B608 app.py:12"


def test_scan_history_transitions(project: int) -> None:
    first, second = data.scan_history(project)
    assert first.transitions["NEW"] == 3 and first.findings == 3
    assert second.transitions["RESOLVED"] == 2 and second.transitions["STILL_OPEN"] == 1
    assert second.scanners == {"bandit": "OK", "semgrep": "OK"}
    assert {r["scanner"] for r in data.scanner_runs(second.id)} == {"bandit", "semgrep"}


def test_finding_detail(project: int) -> None:
    b608 = next(r for r in data.tracked(project) if r.rule == "B608")
    detail = data.finding_detail(b608.id)
    assert detail.evidence.snippet.startswith("cursor.execute") and detail.evidence.cwe == "CWE-89"
    assert [(e.from_status, e.to_status) for e in detail.events] == [(None, "NEW"), ("NEW", "RESOLVED")]
    (v,) = detail.verifications
    assert v.verdict == "VERIFIED_RESOLVED" and [g["gate"] for g in v.gates] == ["1", "2", "3a", "3b"]
    assert data.verifications(b608.id) == detail.verifications
    b602 = next(r for r in data.tracked(project) if r.rule == "B602")
    assert data.finding_detail(b602.id).suppressed_reason == "accepted risk for the demo"
    assert data.finding_detail(9999) is None
