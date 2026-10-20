"""Dashboard actions: validated wrappers over the CLI's services (stand-in scanners, no model)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app import pipeline
from app.ai.linter import lint
from app.ai.service import bound_expectation, context_for_tracked
from app.core.config import get_settings
from app.db.models import LifecycleState, TrackedFinding
from app.db.session import init_db, session_scope
from dashboard import actions
from dashboard.actions import ActionError
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scanners, write_app


@pytest.fixture
def code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    init_db()
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    root = write_app(tmp_path / "code")
    actions.scan_checkout("demo", str(root))
    return root


def _id(rule: str) -> int:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == rule)).first().id


def test_checkout_path_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = tmp_path / "repo"
    good.mkdir()
    assert actions.checkout_path(f'  "{good}"  ') == good.resolve()
    (tmp_path / "file.py").write_text("x = 1\n", encoding="utf-8")
    scratch = get_settings().scratch_root / "inside"
    scratch.mkdir(parents=True)
    for bad, message in [("", "absolute path"), ("relative/dir", "absolute path"), (str(tmp_path / "nope"), "not a"),
                         (str(tmp_path / "file.py"), "not a directory"), (str(scratch), "scratch"),
                         ("C:\\x\x00y", "invalid")]:
        with pytest.raises(ActionError, match=message):
            actions.checkout_path(bad)
    monkeypatch.setenv("SPA_DASHBOARD_SOURCE_ROOT", str(tmp_path / "allowed"))
    get_settings.cache_clear()
    with pytest.raises(ActionError, match="SPA_DASHBOARD_SOURCE_ROOT"):
        actions.checkout_path(str(good))


def test_rescan_and_verify_loop(code: Path) -> None:
    target = _id("B608")
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    summary, verdict = actions.rescan_and_verify(target, str(code))
    assert summary.status == "COMPLETED" and summary.lifecycle["RESOLVED"] == 2
    assert verdict.verdict == "VERIFIED_RESOLVED" and verdict.after_scan_id == summary.scan_id
    with pytest.raises(ActionError, match="no 'before'"):
        actions.verify_against(target, 1)
    with pytest.raises(ActionError, match="no tracked finding"):
        actions.rescan_and_verify(9999, str(code))


def test_scan_checkout_refuses_bad_project_names(code: Path) -> None:
    with pytest.raises(ActionError, match="project name"):
        actions.scan_checkout("../evil", str(code))


def test_suppression_needs_a_reason(code: Path) -> None:
    target = _id("B602")
    with pytest.raises(ActionError, match="reason"):
        actions.suppress_finding(target, "  x ")
    actions.suppress_finding(target, "accepted risk")
    with session_scope() as s:
        assert s.get(TrackedFinding, target).status == LifecycleState.SUPPRESSED
    actions.unsuppress_finding(target)
    with pytest.raises(ActionError, match="not suppressed"):
        actions.unsuppress_finding(target)


def test_prompt_for(code: Path) -> None:
    view = actions.prompt_for(_id("B608"), str(code), "S7")
    assert view.strategy == "S7" and view.report["passed"] and view.tokens > 0 and view.warning is None
    assert "get_user" in view.rendered and "untrusted" in view.rendered.lower()
    with pytest.raises(ActionError, match="unknown strategy"):
        actions.prompt_for(_id("B608"), str(code), "S99")
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))      # checkout moved on since the scan
    assert actions.prompt_for(_id("B608"), str(code), "S1").warning


def test_lint_text_matches_the_cli_rules(code: Path) -> None:
    target = _id("B608")
    prompt = actions.prompt_for(target, str(code), "S7").rendered
    shortened = "Fix the SQL injection in app.py."
    view = actions.lint_text(shortened, target, str(code))
    assert not view.report["passed"] and False in view.report["constituents"].values()
    with session_scope() as s:
        cli_report = lint(shortened, bound_expectation(context_for_tracked(s, target, code))).to_dict()
    assert view.report == cli_report                                 # one definition for CLI and dashboard
    fixed = actions.lint_text(shortened, target, str(code), fix=True)
    assert fixed.fixed and fixed.fixed_report["constituent_score"] > view.report["constituent_score"]
    assert actions.lint_text(prompt).report["bound"] is False        # unbound lint needs no finding
    with pytest.raises(ActionError, match="paste"):
        actions.lint_text("   ")
    with pytest.raises(ActionError, match="too large"):
        actions.lint_text("x" * (256 * 1024 + 1))
