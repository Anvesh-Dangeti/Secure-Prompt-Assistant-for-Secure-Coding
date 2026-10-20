"""Gate 3b's test runner, end to end with a real child process (this interpreter stands in for .tools/fixture)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.verification.gates import GateStatus
from app.verification.gates.gate3b_tests import behaviour_tests_for, run_fixture_tests

CALC = "def add(a, b):\n    return a + b\n"
TESTS = '''\
import os

from calc import add


def test_add():
    assert add(2, 3) == 5


def test_the_child_sees_no_application_secrets():
    assert not [k for k in os.environ if k.startswith("SPA_")]
'''


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SPA_FIXTURE_PYTHON", sys.executable)
    get_settings.cache_clear()
    scratch = get_settings().scratch_root
    code, work = scratch / "code" / "calc_app", scratch / "work"
    code.mkdir(parents=True)
    work.mkdir(parents=True)
    (code / "calc.py").write_text(CALC, encoding="utf-8")
    tests = tmp_path / "calc_app_tests"
    tests.mkdir()
    (tests / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tests / "test_calc.py").write_text(TESTS, encoding="utf-8")
    return code, tests, work


def test_passing_tests_pass(setup) -> None:  # noqa: ANN001
    code, tests, work = setup
    result = run_fixture_tests(code, tests, work)
    assert result.status == GateStatus.PASS and "2 passed" in result.detail


def test_broken_behaviour_fails_and_names_the_test(setup) -> None:  # noqa: ANN001
    code, tests, work = setup
    (code / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    result = run_fixture_tests(code, tests, work)
    assert result.status == GateStatus.FAIL and "1 failed" in result.detail
    assert any("test_add" in item for item in result.items)


def test_a_hanging_fix_fails_on_the_timeout(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    code, tests, work = setup
    monkeypatch.setenv("SPA_FIXTURE_TEST_TIMEOUT_SECONDS", "5")
    get_settings.cache_clear()
    (code / "calc.py").write_text("def add(a, b):\n    while True:\n        pass\n", encoding="utf-8")
    result = run_fixture_tests(code, tests, work)
    assert result.status == GateStatus.FAIL and "within 5s" in result.detail


def test_missing_pieces_are_unverified_never_pass(setup, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    code, tests, work = setup
    assert run_fixture_tests(code, None, work).status == GateStatus.UNVERIFIED
    (tests / "test_calc.py").unlink()
    assert "no tests" in run_fixture_tests(code, tests, work).detail
    monkeypatch.setenv("SPA_FIXTURE_PYTHON", str(tests / "no-such-python.exe"))
    monkeypatch.setattr("app.verification.gates.gate3b_tests.PROJECT_ROOT", tests)   # no .tools/fixture either
    get_settings.cache_clear()
    assert "not installed" in run_fixture_tests(code, tests, work).detail


def test_behaviour_tests_directory_convention(tmp_path: Path) -> None:
    (tmp_path / "app_tests").mkdir()
    assert behaviour_tests_for(tmp_path / "app") is None       # no pytest.ini: not a test suite
    (tmp_path / "app_tests" / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    assert behaviour_tests_for(tmp_path / "app") == (tmp_path / "app_tests").resolve()
