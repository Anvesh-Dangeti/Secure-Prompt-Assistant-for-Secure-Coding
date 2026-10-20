"""Security properties of verification: it executes nothing in developer mode, and is not a lab over HTTP."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import TrackedFinding, Verdict
from app.db.session import init_db, session_scope
from app.main import create_app
from app.verification.service import verify
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, write_app


def test_developer_mode_verification_never_starts_a_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    init_db()
    code = write_app(tmp_path / "code")
    scan("p", code)
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    after = scan("p", code)

    def no_processes(*_a: object, **_k: object) -> None:
        raise AssertionError("verification tried to start a process")

    monkeypatch.setattr(subprocess, "Popen", no_processes)
    with session_scope() as s:
        target = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).first().id
        row = verify(s, target, after.scan_id)
        assert row.verdict == Verdict.VERIFIED_RESOLVED
        assert row.gates[3] == {"gate": "3b", "title": "fixture tests", "status": "NOT_APPLICABLE",
                                "detail": "developer mode never executes repository code", "items": []}


def test_the_api_offers_no_lab_mode_and_no_code_execution() -> None:
    paths = create_app().openapi()["paths"]
    routes = {(method.upper(), path) for path, ops in paths.items() for method in ops}
    verification = {(m, p) for m, p in routes if "verif" in p}
    assert verification == {("POST", "/api/v1/tracked/{tracked_id}/verify"),
                            ("GET", "/api/v1/tracked/{tracked_id}/verifications")}
    assert not any(word in p for _, p in routes for word in ("lab", "propose", "apply", "pytest", "sandbox"))
