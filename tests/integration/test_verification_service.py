"""Developer-mode verification through the real scan -> persist -> verify path (stand-in scanners)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import BlindSpot, SymbolSnapshot, ToolStatus, TrackedFinding, Verdict
from app.db.session import init_db, session_scope
from app.main import create_app
from app.verification import snapshots
from app.verification.service import NotVerifiable, VerificationNotFound, history, verify
from tests._support import TEST_API_KEY
from tests._verify_support import PING_BODY, SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, write_app

AUTH = {"X-API-Key": TEST_API_KEY}
FIXED = TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED)


def _tracked(rule: str) -> int:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == rule)).first().id


def _verify(tracked_id: int, scan_id: int | None = None):
    with session_scope() as s:
        row = verify(s, tracked_id, scan_id)
        return row.verdict, row.reason, {g["gate"]: g["status"] for g in row.gates}, row


@pytest.fixture
def code(tmp_path: Path) -> Path:
    init_db()
    return write_app(tmp_path / "code")


def test_good_fix_is_verified_and_recorded(code: Path) -> None:
    scan("p", code)
    target = _tracked("B608")
    write_app(code, FIXED)
    after = scan("p", code)
    verdict, reason, gates, row = _verify(target, after.scan_id)
    assert verdict == Verdict.VERIFIED_RESOLVED and reason is None
    assert gates == {"1": "PASS", "2": "PASS", "3a": "PASS", "3b": "NOT_APPLICABLE"}
    assert sorted(row.target) == ["bandit B608 app.py:12", "semgrep tainted-sql-string app.py:12"]
    assert (row.before_scan_id, row.after_scan_id) == (1, after.scan_id)
    with session_scope() as s:
        assert [h.verdict for h in history(s, target)] == [Verdict.VERIFIED_RESOLVED]


def test_snapshots_are_facts_not_code(code: Path) -> None:
    scan("p", code)
    with session_scope() as s:
        rows = {(r.file_path, r.symbol): r for r in s.scalars(select(SymbolSnapshot))}
        assert set(rows) == {("app.py", "get_user"), ("app.py", "ping_host")}
        snap = rows[("app.py", "get_user")]
        assert (snap.kind, snap.state, snap.signature) == ("function", "PRESENT", "()")
        assert snap.decorators == ["app.route('/user')"]
        stored = " ".join(str(getattr(snap, c.name)) for c in SymbolSnapshot.__table__.columns)
    assert "execute" not in stored and "SELECT" not in stored          # no function body is ever stored


def test_stubbed_function_is_rejected_by_gate_3a(code: Path) -> None:
    scan("p", code)
    target = _tracked("B602")
    write_app(code, TOY_APP.replace(PING_BODY, "    pass\n"))
    verdict, reason, gates, _ = _verify(target, scan("p", code).scan_id)
    assert verdict == Verdict.FIX_REJECTED and gates["1"] == "PASS" and gates["3a"] == "FAIL"
    assert "stub" in reason


def test_deleted_function_is_tracked_through_carried_snapshots(code: Path) -> None:
    scan("p", code)
    target = _tracked("B602")
    write_app(code, TOY_APP.split('\n\n@app.route("/ping")')[0] + "\n")
    after = scan("p", code)
    _, reason, gates, _ = _verify(target, after.scan_id)
    assert gates["3a"] == "FAIL" and "no longer defined" in reason
    with session_scope() as s:
        snap = s.scalars(select(SymbolSnapshot).where(SymbolSnapshot.scan_id == after.scan_id,
                                                      SymbolSnapshot.symbol == "ping_host")).one()
        assert snap.state == "MISSING"


def test_scanner_down_is_unverified(code: Path) -> None:
    scan("p", code)
    target = _tracked("B608")
    write_app(code, FIXED)
    verdict, _, gates, _ = _verify(target, scan("p", code, semgrep=ToolStatus.TIMEOUT).scan_id)
    assert verdict == Verdict.UNVERIFIED and gates["1"] == "UNVERIFIED" and gates["2"] == "UNVERIFIED"


def test_persisted_blind_spot_makes_absence_unverified(code: Path) -> None:
    scan("p", code)
    target = _tracked("B608")
    write_app(code, FIXED)
    after = scan("p", code, blind={"file:app.py"})
    with session_scope() as s:
        assert [(b.tool, b.scope_key) for b in s.scalars(select(BlindSpot))] == [("semgrep", "file:app.py")]
    verdict, _, gates, _ = _verify(target, after.scan_id)
    assert verdict == Verdict.UNVERIFIED and gates["1"] == "UNVERIFIED"


def test_reverification_compares_with_the_last_scan_the_finding_was_seen_in(code: Path) -> None:
    scan("p", code)                                                         # scan 1: SQLi present
    target = _tracked("B608")
    write_app(code, FIXED + '\n\ndef cleanup(name):\n    import os\n    os.system("rm " + name)\n')
    second = scan("p", code)                                                # scan 2: fixed, but new os.system
    assert _verify(target, second.scan_id)[2]["2"] == "FAIL"
    write_app(code, FIXED)
    third = scan("p", code)                                                 # scan 3: follow-up commit
    verdict, _, _, row = _verify(target, third.scan_id)
    assert verdict == Verdict.VERIFIED_RESOLVED and row.before_scan_id == 1


def test_not_verifiable_and_not_found(code: Path) -> None:
    first = scan("p", code)
    target = _tracked("B608")
    with session_scope() as s:
        with pytest.raises(NotVerifiable, match="no 'before'"):
            verify(s, target, first.scan_id)
        with pytest.raises(VerificationNotFound):
            verify(s, 9999)
    other = scan("q", code)
    with session_scope() as s:
        with pytest.raises(VerificationNotFound, match="scan not found"):
            verify(s, target, other.scan_id)


def test_snapshot_failure_never_fails_the_scan(code: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("bug")

    scan("p", code)
    target = _tracked("B608")
    write_app(code, FIXED)
    monkeypatch.setattr(snapshots, "capture", boom)
    after = scan("p", code)
    assert after.status == "COMPLETED"
    verdict, _, gates, _ = _verify(target, after.scan_id)
    assert gates["3a"] == "UNVERIFIED" and verdict == Verdict.UNVERIFIED


def test_api_verify_and_history(code: Path) -> None:
    scan("p", code)
    target = _tracked("B608")
    write_app(code, FIXED)
    after = scan("p", code)
    with TestClient(create_app()) as client:
        assert client.post(f"/api/v1/tracked/{target}/verify").status_code == 401
        r = client.post(f"/api/v1/tracked/{target}/verify", headers=AUTH)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["verdict"] == "VERIFIED_RESOLVED" and body["after_scan_id"] == after.scan_id
        assert [g["gate"] for g in body["gates"]] == ["1", "2", "3a", "3b"]
        assert client.post("/api/v1/tracked/9999/verify", headers=AUTH).status_code == 404
        assert client.post(f"/api/v1/tracked/{target}/verify?scan_id=1", headers=AUTH).status_code == 409
        rows = client.get(f"/api/v1/tracked/{target}/verifications", headers=AUTH).json()
        assert [h["verdict"] for h in rows] == ["VERIFIED_RESOLVED"]
        assert client.get("/api/v1/tracked/9999/verifications", headers=AUTH).status_code == 404
