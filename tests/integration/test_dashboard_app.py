"""The dashboard, driven headlessly: the access gate, every page, and the developer-mode loop in the UI."""

from __future__ import annotations

from pathlib import Path

import pytest
import streamlit.config
from sqlalchemy import select

from app import pipeline
from app.core.config import get_settings
from app.db.models import LifecycleState, TrackedFinding
from app.db.session import init_db, session_scope
from dashboard import auth
from tests._dashboard_support import PAGES, all_text, button, page, signed_in, started
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, scanners, write_app


@pytest.fixture(autouse=True)
def fast_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    init_db()


@pytest.fixture
def code(tmp_path: Path) -> Path:
    root = write_app(tmp_path / "code")
    scan("demo", root)
    return root


def _status(rule: str) -> LifecycleState:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == rule)).first().status


# ---- the gate -------------------------------------------------------------------


def test_wrong_key_shows_nothing_and_locks_out() -> None:
    at = started()
    for attempt in range(auth.MAX_FAILURES):
        at.text_input(key="spa_key_input").input(f"wrong-{attempt}")
        at.button(key="spa_sign_in").click().run()
        assert not at.radio                                   # no page, no project list
    assert "Too many wrong keys" in all_text(at.error)
    assert not at.text_input                                  # the form is gone for this session


def test_no_key_configured_means_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_API_KEY", "")
    get_settings.cache_clear()
    at = started()
    assert "dashboard is disabled" in all_text(at.error) and not at.text_input and not at.radio


def test_refuses_to_serve_unless_bound_to_loopback() -> None:
    previous = streamlit.config.get_option("server.address")
    streamlit.config.set_option("server.address", "0.0.0.0")
    try:
        at = started()
    finally:
        streamlit.config.set_option("server.address", previous)
    assert "Refusing to serve" in all_text(at.error) and not at.text_input


def test_sign_out() -> None:
    at = signed_in()
    at.button(key="spa_sign_out").click().run()
    assert at.text_input(key="spa_key_input") and not at.radio


# ---- pages ------------------------------------------------------------------------


def test_every_page_renders(code: Path) -> None:
    at = signed_in()
    for name in PAGES:
        page(at, name)
        assert at.header[0].value == name
    page(at, "Overview")
    assert {m.label: m.value for m in at.metric}["HIGH"] == "2"      # B602 + semgrep SQLi are HIGH


def test_first_run_scans_a_checkout_into_a_new_project(tmp_path: Path) -> None:
    root = write_app(tmp_path / "fresh")
    at = signed_in()
    assert "No project yet" in all_text(at.info)
    at.text_input(key="scan_path").input(str(root))
    next(t for t in at.text_input if t.label == "Project name").input("fresh")
    button(at, "Scan").click().run()
    assert not at.exception
    assert at.selectbox(key="spa_project").value.name == "fresh"


def test_prompt_and_lint_page(code: Path) -> None:
    at = page(signed_in(), "Prompt & lint")
    at.text_input(key="spa_checkout_path_input").input(str(code))
    at.button(key="build_prompt").click().run()
    assert not at.exception
    assert "get_user" in at.code[0].value or "ping_host" in at.code[0].value
    assert "Lint of this prompt: PASS" in all_text(at.success)

    at.text_area(key="edited_prompt").input("Fix the SQL injection in app.py.")
    at.button(key="lint").click().run()
    assert "Lint of your prompt: FAIL" in all_text(at.error)
    assert "MISSING" in all_text(at.dataframe)
    at.button(key="fix").click().run()
    assert any("untrusted" in c.value.lower() or "parameter" in c.value.lower() for c in at.code)


def test_bad_checkout_path_is_reported_not_raised(code: Path) -> None:
    at = page(signed_in(), "Prompt & lint")
    at.text_input(key="spa_checkout_path_input").input("relative/path")
    at.button(key="build_prompt").click().run()
    assert "No prompt was built." in all_text(at.error) and "absolute path" in all_text(at.text)


def test_rescan_and_verify_in_the_ui(code: Path) -> None:
    at = page(signed_in(), "Verification")
    picker = at.selectbox(key="verify_pick")
    picker.set_value(next(o for o in picker.options if "B608" in o)).run()
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    at.text_input(key="spa_checkout_path_input").input(str(code))
    at.button(key="rescan_verify").click().run()
    assert not at.exception
    assert "verdict VERIFIED_RESOLVED" in all_text(at.success)
    assert "Verification #1: VERIFIED_RESOLVED" in all_text(at.success)
    assert "developer mode never executes repository code" in all_text(at.dataframe)


def test_suppression_needs_a_reason(code: Path) -> None:
    at = page(signed_in(), "Findings")
    picker = at.selectbox(key="findings_pick")
    picker.set_value(next(o for o in picker.options if "B602" in o)).run()
    at.button(key="suppress").click().run()
    assert "Not suppressed." in all_text(at.error) and _status("B602") != LifecycleState.SUPPRESSED
    at.text_input(key="suppress_reason").input("accepted risk: internal tool")
    at.button(key="suppress").click().run()
    assert _status("B602") == LifecycleState.SUPPRESSED
