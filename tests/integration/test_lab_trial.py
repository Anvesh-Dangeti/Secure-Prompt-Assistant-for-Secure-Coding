"""Lab-mode trials with a scripted model and stand-in scanners: every verdict, and gate 3b's fences."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.ai.providers import ScriptedProvider, TemplateProvider
from app.db.models import Scan, ToolStatus, TrackedFinding, Verdict
from app.db.session import init_db, session_scope
from app.sandbox import lab
from app.sandbox.lab import LabError, prepare_baseline, run_lab_trial
from app.verification.gates import GateResult, GateStatus
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, scanners, write_app

GOOD = ('@app.route("/user")\ndef get_user():\n    user_id = request.args.get("id")\n'
        '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n    return "ok"')
STUB = '@app.route("/user")\ndef get_user():\n    pass'
NEW_WEAKNESS = GOOD.replace('    return "ok"', '    subprocess.check_output("logger " + user_id, shell=True)\n'
                                               '    return "ok"')


def model(code: str | None = None, final: str | None = None) -> ScriptedProvider:
    """S7 is three turns: answer, critique, final (schema-constrained) answer."""
    final = final if final is not None else json.dumps({"code": code, "imports": [], "summary": "fixed"})
    return ScriptedProvider(["first attempt", "no problems found", final])


class RunnerSpy:
    """Stands in for gate 3b's runner and records what it was asked to run."""

    def __init__(self, status: GateStatus = GateStatus.PASS) -> None:
        self.status, self.runs = status, []

    def __call__(self, code_root: Path, tests_dir: object, work: Path) -> GateResult:
        self.runs.append((code_root / "app.py").read_text(encoding="utf-8"))
        return GateResult("3b", "fixture tests", self.status, f"spy {self.status.value}")


@pytest.fixture
def code(tmp_path: Path) -> Path:
    init_db()
    root = write_app(tmp_path / "code")
    scan("lab", root)
    return root


def _target() -> int:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).first().id


def trial(code: Path, provider, **kw):  # noqa: ANN001, ANN201
    with session_scope() as s:
        row = run_lab_trial(s, _target(), code, "S7", provider, scanners=scanners(), **kw)
        return row.verdict, {g["gate"]: g["status"] for g in row.gates}, row.reason, row


def test_good_fix_is_verified_and_tests_run_twice(code: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spy = RunnerSpy()
    monkeypatch.setattr(lab, "run_fixture_tests", spy)
    verdict, gates, _, row = trial(code, model(GOOD))
    assert verdict == Verdict.VERIFIED_RESOLVED and gates == {"1": "PASS", "2": "PASS", "3a": "PASS", "3b": "PASS"}
    assert len(spy.runs) == 2 and "% user_id" in spy.runs[0] and SQL_FIXED in spy.runs[1]   # pristine, then patched
    assert (row.strategy, row.provider, row.model, row.calls) == ("S7", "scripted", "scripted", 3)
    assert row.prompt_tokens > 0 and row.proposal["summary"] == "fixed"
    assert row.before_scan_id is None and row.after_scan_id is None          # scratch copies, not project scans


def test_model_code_never_runs_after_a_failed_gate(code: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spy = RunnerSpy()
    monkeypatch.setattr(lab, "run_fixture_tests", spy)
    verdict, gates, reason, _ = trial(code, model(STUB))
    assert verdict == Verdict.FIX_REJECTED and gates["3a"] == "FAIL" and gates["3b"] == "NOT_RUN"
    verdict, gates, reason, _ = trial(code, model(NEW_WEAKNESS))
    assert verdict == Verdict.FIX_REJECTED and gates["2"] == "FAIL" and gates["3b"] == "NOT_RUN"
    assert len(spy.runs) == 2 and all("% user_id" in run for run in spy.runs)    # only the pristine baselines ran


def test_crashed_scanner_after_the_fix_is_unverified(code: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spy = RunnerSpy()
    monkeypatch.setattr(lab, "run_fixture_tests", spy)
    baseline = prepare_baseline(code, scanners())
    with session_scope() as s:
        row = run_lab_trial(s, _target(), code, "S7", model(GOOD), scanners=scanners(semgrep=ToolStatus.TIMEOUT),
                            baseline=baseline)
        assert row.verdict == Verdict.UNVERIFIED
        assert [g["status"] for g in row.gates] == ["UNVERIFIED", "UNVERIFIED", "PASS", "NOT_RUN"]
    assert len(spy.runs) == 1


def test_unusable_or_missing_answers(code: Path) -> None:
    verdict, gates, reason, row = trial(code, model(final="here is my fix: ..."), run_tests=False)
    assert verdict == Verdict.FIX_REJECTED and "malformed" in reason and set(gates.values()) == {"NOT_RUN"}
    assert row.proposal is None
    verdict, _, reason, _ = trial(code, ScriptedProvider([]), run_tests=False)
    assert verdict == Verdict.ERROR and reason.startswith("provider")


def test_3b_without_a_trustworthy_baseline_is_unverified(code: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab, "run_fixture_tests", RunnerSpy(GateStatus.FAIL))
    verdict, gates, reason, _ = trial(code, model(GOOD))
    assert verdict == Verdict.UNVERIFIED and gates["3b"] == "UNVERIFIED" and "unmodified code" in reason
    verdict, gates, _, _ = trial(code, model(GOOD), run_tests=False)
    assert verdict == Verdict.UNVERIFIED and gates["3b"] == "UNVERIFIED"


def test_no_behaviour_tests_means_unverified(code: Path) -> None:
    verdict, gates, reason, _ = trial(code, model(GOOD))           # the toy app has no <name>_tests/ directory
    assert verdict == Verdict.UNVERIFIED and gates["3b"] == "UNVERIFIED" and "no behaviour tests" in reason


def test_lab_never_touches_the_project_or_the_source(code: Path) -> None:
    before = (code / "app.py").read_bytes()
    with session_scope() as s:
        scans = s.scalar(select(func.count(Scan.id)))
        states = {t.id: t.status for t in s.scalars(select(TrackedFinding))}
    trial(code, model(GOOD), run_tests=False)
    assert (code / "app.py").read_bytes() == before
    with session_scope() as s:
        assert s.scalar(select(func.count(Scan.id))) == scans
        assert {t.id: t.status for t in s.scalars(select(TrackedFinding))} == states


def test_harness_problems_are_errors_not_verdicts(code: Path) -> None:
    with pytest.raises(LabError, match="generates"):
        trial(code, TemplateProvider())
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))      # --source no longer has the finding
    with pytest.raises(LabError, match="does not reproduce"):
        trial(code, model(GOOD), run_tests=False)
