"""The live token-ladder numbers (``recorded_results.E5``) equal the committed E5 trial rows.

The run needs the local model, so the test asserts against the committed
results file -- the same arrangement as the E2 pilot.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from app.ai.strategies import LADDER
from evaluation.e2_strategies import summarise
from evaluation.recorded_results import E2_PILOT, E5

RESULTS = Path(__file__).resolve().parents[2] / "evaluation" / "results"
RUN = json.loads((RESULTS / "e5_tokens.json").read_text(encoding="utf-8"))
FIRST = json.loads((RESULTS / "e5_tokens_attempt1.json").read_text(encoding="utf-8"))


def test_every_cell_ran_exactly_once() -> None:
    cells = Counter((t["seed"], t["strategy"]) for t in RUN["trials"])
    assert len(cells) == E5["trials"] == len(RUN["trials"]) and set(cells.values()) == {1}
    assert {s for _, s in cells} == set(E5["by_strategy"]) == {"S2", "S7", *LADDER}


def test_the_stored_summary_is_recomputed_from_the_trials() -> None:
    assert summarise(RUN["trials"]) == RUN["summary"]


def test_the_recorded_numbers_equal_the_results_file() -> None:
    for sid, (verified, applicable, esr, tokens) in E5["by_strategy"].items():
        row = RUN["summary"][sid]
        assert (row["verified"], row["applicable"], row["esr"]) == (verified, applicable, esr), sid
        assert row["prompt_tokens"] + row["completion_tokens"] == tokens, sid
        assert row["verified_per_1k_tokens"] == E5["verified_per_1k_tokens"][sid], sid
        assert round(tokens / row["trials"]) == E5["tokens_per_trial"][sid], sid
        assert row["failed_at"] == E5["failed_at"][sid], sid


def test_the_ladder_claim() -> None:
    per_1k = E5["verified_per_1k_tokens"]
    assert per_1k["S7m"] == max(per_1k.values())                 # the minimal prompt is the most efficient
    assert E5["by_strategy"]["S7m"][0] >= E5["by_strategy"]["S7"][0]   # and verifies no fewer fixes than S7
    assert E5["tokens_per_trial"]["S7"] > 5 * E5["tokens_per_trial"]["S7m"]


def test_finding_23_is_fixed_for_every_rung_of_ours() -> None:
    deps = {t["strategy"]: t["verdict"] == "VERIFIED_RESOLVED" for t in RUN["trials"] if t["cwe"] == "CWE-1395"}
    assert deps == E5["dependency_verified"]


def test_same_model_and_settings_as_the_pilot() -> None:
    model = RUN["model"]
    assert model["model"] == E5["model"] == E2_PILOT["model"]
    assert model["digest"].startswith(E5["digest"]) and E5["digest"] == E2_PILOT["digest"]
    assert model["options"]["temperature"] == 0.0 and model["options"]["seed"] == 42
    assert set(RUN["scanners"]) == {"semgrep", "bandit", "gitleaks", "pip-audit"}


def test_the_rerun_is_disclosed_and_was_an_infrastructure_failure() -> None:
    errors = [t for t in FIRST["trials"] if t["verdict"] == "ERROR"]
    assert len(errors) == E5["infrastructure_reruns"]
    assert all(t["reason"].startswith("provider:") for t in errors)
    rerun = {(t["seed"], t["strategy"]) for t in errors}
    same = [t for t in FIRST["trials"] if (t["seed"], t["strategy"]) not in rerun]
    kept = [t for t in RUN["trials"] if (t["seed"], t["strategy"]) not in rerun]
    assert same == kept     # every other cell is the first attempt, unchanged
