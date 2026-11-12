"""The related-function evidence (``recorded_results.RELATED``) is recomputed from the committed E2 pilot rows."""

from __future__ import annotations

import json

from evaluation.recorded_results import RELATED
from evaluation.related_functions import FIXTURE, PILOT, call_map, run


def test_recorded_numbers_are_reproduced() -> None:
    assert run() == RELATED


def test_the_callers_are_real_calls_in_the_fixture() -> None:
    app_py = (FIXTURE / "app.py").read_text(encoding="utf-8")
    register = app_py[app_py.index("def register"):]
    assert "hash_password(" in register and "make_reset_token(" in register
    assert call_map()["hash_password"] == ["register"]


def test_a_verified_lab_fix_always_ran_the_behaviour_tests() -> None:
    # The claim "no verified fix broke its caller" rests on this: VERIFIED needs gate 3b to pass.
    trials = json.loads(PILOT.read_text(encoding="utf-8"))["trials"]
    assert all(t["gate"] is None for t in trials if t["verdict"] == "VERIFIED_RESOLVED")
    tests = (FIXTURE.parent / "flask_vuln_app_tests" / "test_behaviour.py").read_text(encoding="utf-8")
    assert 'client.post("/register"' in tests


def test_call_map_ignores_self_calls_and_undefined_names(tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "m.py").write_text("def a():\n    a()\n    print(1)\n    b()\n\ndef b():\n    return 1\n",
                                   encoding="utf-8")
    assert call_map(tmp_path) == {"b": ["a"]}
