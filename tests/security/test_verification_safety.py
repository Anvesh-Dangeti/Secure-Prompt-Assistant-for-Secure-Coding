"""Security properties of verification: nothing executes in developer mode; lab mode is fenced and CLI-only."""

from __future__ import annotations

import subprocess
import sys
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


def test_gate_3b_runs_fenced_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The one path that executes model-written code: isolated interpreter, -P, pinned config, no secrets."""
    from app.core.config import get_settings
    from app.core.paths import is_within
    from app.core.subprocess_runner import ToolResult, _child_env
    from app.verification.gates import gate3b_tests

    seen: dict = {}

    def fake_run_tool(args, *, cwd, timeout, extra_env=None, **_kw):  # noqa: ANN001, ANN202
        seen.update(args=list(args), cwd=cwd, timeout=timeout, env=_child_env(extra_env), extra=extra_env)
        return ToolResult(tuple(args), 0, "1 passed in 0.01s", "", 0.1, False, False)

    monkeypatch.setattr(gate3b_tests, "run_tool", fake_run_tool)
    monkeypatch.setattr(gate3b_tests, "fixture_python", lambda: Path(sys.executable))
    scratch = get_settings().scratch_root
    code, work, tests = scratch / "code", scratch / "work", tmp_path / "app_tests"
    for d in (code, work, tests):
        d.mkdir(parents=True)
    (tests / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")

    assert gate3b_tests.run_fixture_tests(code, tests, work).status.value == "PASS"
    args = seen["args"]
    assert args[1] == "-P"                                     # no working-directory module shadowing
    assert args[args.index("-c") + 1].startswith(str(work))    # pytest config pinned to the copied tests
    assert is_within(seen["cwd"], scratch)
    assert set(seen["extra"]) == {"PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"}
    assert seen["extra"]["PYTHONPATH"] == str(code)
    assert not [k for k in seen["env"] if k.upper().startswith("SPA_")]   # the API key never reaches the child
    assert seen["timeout"] == get_settings().fixture_test_timeout_seconds
