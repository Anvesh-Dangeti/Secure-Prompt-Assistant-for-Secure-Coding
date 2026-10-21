"""The E2 pilot numbers presented at review are the ones in the committed per-trial results.

The pilot needs the local model, so the tests cannot re-run it. They check
that the stored summary is recomputed exactly from the per-trial rows, and that
every number on a slide (``recorded_results.E2_PILOT``) equals that summary.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from app.ai.strategies import STRATEGIES
from evaluation.e2_strategies import NO_USABLE_FIX, summarise
from evaluation.recorded_results import E2_PILOT

RESULTS = Path(__file__).resolve().parents[2] / "evaluation" / "results"
PILOT = json.loads((RESULTS / "e2_pilot.json").read_text(encoding="utf-8"))
STRICT = json.loads((RESULTS / "e2_pilot_strict_imports.json").read_text(encoding="utf-8"))


def test_every_cell_ran_exactly_once() -> None:
    cells = Counter((t["seed"], t["strategy"]) for t in PILOT["trials"])
    assert len(cells) == E2_PILOT["trials"] == len(PILOT["trials"]) and set(cells.values()) == {1}
    assert {s for _, s in cells} == set(STRATEGIES)


def test_the_stored_summary_is_recomputed_from_the_trials() -> None:
    assert summarise(PILOT["trials"]) == PILOT["summary"]


def test_the_slide_numbers_equal_the_results_file() -> None:
    for sid, (verified, applicable, esr, tokens) in E2_PILOT["by_strategy"].items():
        row = PILOT["summary"][sid]
        assert (row["verified"], row["applicable"], row["esr"]) == (verified, applicable, esr), sid
        assert row["prompt_tokens"] + row["completion_tokens"] == tokens, sid
    assert sum(t["verdict"] == "VERIFIED_RESOLVED" for t in PILOT["trials"]) == E2_PILOT["verified"]
    rejected = Counter(t["gate"] for t in PILOT["trials"] if t["verdict"] != "VERIFIED_RESOLVED")
    assert dict(rejected) == E2_PILOT["failed_at"]


def test_the_dependency_story() -> None:
    bumps = [t for t in PILOT["trials"] if t["cwe"] == "CWE-1395"]
    assert len(bumps) == E2_PILOT["dependency_bumps_rejected"]
    assert all(t["verdict"] == "FIX_REJECTED" and t["gate"] == "1" for t in bumps)


def test_the_run_is_tied_to_a_model_and_settings() -> None:
    model = PILOT["model"]
    assert model["model"] == E2_PILOT["model"] and model["digest"].startswith(E2_PILOT["digest"])
    assert model["options"]["temperature"] == 0.0 and model["options"]["seed"] == 42
    assert set(PILOT["scanners"]) == {"semgrep", "bandit", "gitleaks", "pip-audit"}


def test_the_first_run_is_kept_as_the_disclosed_artifact() -> None:
    replies = [t for t in STRICT["trials"] if t["gate"] == NO_USABLE_FIX]
    assert len(replies) == E2_PILOT["strict_imports_reply_failures"]
    assert all("not an import statement" in t["reason"] for t in replies)
