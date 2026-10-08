"""Persisted lifecycle tracking, driven by synthetic scan results (no real scanners).

These are the "findings are never falsely marked resolved" tests the brief
asks for: scanner crash, timeout, missing tool, unparseable file and an
unpinned dependency must all leave an open finding open.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import LifecycleEvent, LifecycleState, Project, Scan, ScanStatus, SourceType, ToolStatus, \
    TrackedFinding
from app.db.session import init_db, session_scope
from app.intelligence.fingerprint import assign_fingerprints
from app.intelligence.tracking import TrackingError, suppress, unsuppress, update_tracking
from app.main import create_app
from app.normalization.finding import NormalizedFinding
from app.pipeline import TreeScan
from app.scanners.base import ScannerResult
from tests._support import TEST_API_KEY


def _finding(tool: str = "bandit", rule: str = "B602", path: str = "app.py", snippet: str = "x()",
             package: str | None = None) -> NormalizedFinding:
    return NormalizedFinding(tool=tool, rule_id=rule, message="m", file_path=path, start_line=1, end_line=1,
                             severity="HIGH", snippet=snippet, package=package,
                             vuln_id=rule if package else None)


SQLI = _finding(rule="B608", snippet='execute("..." % x)')
CMD = _finding(rule="B602", snippet="check_output(cmd, shell=True)")
DEP = _finding(tool="pip-audit", rule="PYSEC-1", path="requirements.txt", snippet="pyyaml==5.3", package="pyyaml")


def _tree(*findings: NormalizedFinding, failed: dict[str, ToolStatus] | None = None,
          blind: dict[str, set[str]] | None = None) -> TreeScan:
    failed, blind = failed or {}, blind or {}
    copies = [NormalizedFinding(**{k: v for k, v in vars(f).items()}) for f in findings]
    assign_fingerprints(copies)
    results = []
    for tool in ("bandit", "pip-audit"):
        status = failed.get(tool, ToolStatus.OK)
        mine = [f for f in copies if f.tool == tool]
        results.append(ScannerResult(tool, status, mine if status == ToolStatus.OK else [],
                                     unverified_scopes=blind.get(tool, set())))
    return TreeScan(results)


def _scan(tree: TreeScan) -> dict[str, int]:
    init_db()
    with session_scope() as s:
        project = s.scalars(select(Project).where(Project.name == "p")).first()
        if project is None:
            project = Project(name="p", source_type=SourceType.ZIP)
            s.add(project)
            s.flush()
        scan = Scan(project_id=project.id, source_type=SourceType.ZIP, status=ScanStatus.COMPLETED)
        s.add(scan)
        s.flush()
        return update_tracking(s, scan, tree)


def _states() -> dict[str, str]:
    with session_scope() as s:
        return {t.rule_id: t.status.value for t in s.scalars(select(TrackedFinding))}


def test_full_lifecycle_new_open_resolved_regression() -> None:
    assert _scan(_tree(SQLI, CMD))["NEW"] == 2
    assert _scan(_tree(SQLI, CMD))["STILL_OPEN"] == 2
    assert _scan(_tree(CMD))["RESOLVED"] == 1
    assert _states() == {"B608": "RESOLVED", "B602": "STILL_OPEN"}
    counts = _scan(_tree(SQLI, CMD))
    assert counts["REGRESSION"] == 1
    with session_scope() as s:
        t = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).one()
        assert t.regression_count == 1
        assert [e.to_status.value for e in t.events] == ["NEW", "STILL_OPEN", "RESOLVED", "REGRESSION"]


@pytest.mark.parametrize("failure", [ToolStatus.ERROR, ToolStatus.TIMEOUT, ToolStatus.NOT_INSTALLED])
def test_scanner_failure_never_resolves(failure: ToolStatus) -> None:
    _scan(_tree(SQLI, CMD))
    counts = _scan(_tree(failed={"bandit": failure}))   # bandit "found nothing" because it failed
    assert counts["RESOLVED"] == 0 and counts["UNVERIFIED"] == 2
    assert _states() == {"B608": "NEW", "B602": "NEW"}
    with session_scope() as s:
        assert all(e.unverified for e in s.scalars(select(LifecycleEvent)).all()[-2:])


def test_tool_missing_from_scan_entirely_never_resolves() -> None:
    _scan(_tree(SQLI))
    tree = _tree()
    tree.results = [r for r in tree.results if r.tool != "bandit"]
    assert _scan(tree)["RESOLVED"] == 0


def test_unparseable_file_never_resolves() -> None:
    _scan(_tree(SQLI))
    counts = _scan(_tree(blind={"bandit": {"file:app.py"}}))
    assert counts["RESOLVED"] == 0 and counts["UNVERIFIED"] == 1


def test_unpinned_dependency_never_resolves() -> None:
    _scan(_tree(DEP))
    counts = _scan(_tree(blind={"pip-audit": {"package:pyyaml"}}))
    assert counts["RESOLVED"] == 0 and _states()["PYSEC-1"] == "NEW"
    # Pinned again to a fixed version and audited: now it really is resolved.
    assert _scan(_tree())["RESOLVED"] == 1


def test_suppressed_findings_are_kept_and_never_counted_as_new_or_regression() -> None:
    _scan(_tree(SQLI))
    with session_scope() as s:
        tid = s.scalars(select(TrackedFinding)).one().id
        suppress(s, tid, "test fixture data, not reachable")
    assert _scan(_tree(SQLI))["SUPPRESSED"] == 1
    assert _scan(_tree())["RESOLVED"] == 0          # disappears: still SUPPRESSED, not resolved
    counts = _scan(_tree(SQLI))                      # reappears: not a regression
    assert counts["REGRESSION"] == 0 and counts["NEW"] == 0
    assert _states() == {"B608": "SUPPRESSED"}
    with session_scope() as s:
        unsuppress(s, tid)
    assert _scan(_tree(SQLI))["STILL_OPEN"] == 1


def test_suppress_requires_a_reason() -> None:
    _scan(_tree(SQLI))
    with session_scope() as s:
        tid = s.scalars(select(TrackedFinding)).one().id
        with pytest.raises(TrackingError):
            suppress(s, tid, "   ")


def test_suppress_via_api() -> None:
    _scan(_tree(SQLI))
    with session_scope() as s:
        tid, pid = (lambda t: (t.id, t.project_id))(s.scalars(select(TrackedFinding)).one())
    auth = {"X-API-Key": TEST_API_KEY}
    with TestClient(create_app()) as client:
        assert client.post(f"/api/v1/tracked/{tid}/suppress", json={"reason": "x"}, headers=auth).status_code == 422
        assert client.post(f"/api/v1/tracked/{tid}/suppress", json={"reason": "ok"}).status_code == 401
        r = client.post(f"/api/v1/tracked/{tid}/suppress", json={"reason": "false positive"}, headers=auth)
        assert r.status_code == 200 and r.json()["status"] == "SUPPRESSED"
        listing = client.get(f"/api/v1/projects/{pid}/findings?state=SUPPRESSED", headers=auth).json()
        assert [t["id"] for t in listing] == [tid]
        detail = client.get(f"/api/v1/tracked/{tid}", headers=auth).json()
        assert [e["to_status"] for e in detail["events"]] == ["NEW", "SUPPRESSED"]
        assert client.post("/api/v1/tracked/9999/suppress", json={"reason": "abc"}, headers=auth).status_code == 404
    assert LifecycleState.SUPPRESSED.value == "SUPPRESSED"
