"""The static token-ladder numbers (``recorded_results.E5_STATIC``) are the ones the prompt builder produces today.

No model is involved: every rung of the ladder is rebuilt for every real finding
on each test run, so a prompt change that moves a token count fails here.
"""

from __future__ import annotations

from evaluation.e5_tokens import run
from evaluation.recorded_results import E5_STATIC

RESULT = run()


def test_recorded_numbers_are_reproduced() -> None:
    assert RESULT == {**E5_STATIC, "first_message": RESULT["first_message"], "typed": RESULT["typed"]}
    assert {k: tuple(v) for k, v in RESULT["first_message"].items()} == E5_STATIC["first_message"]
    assert {k: tuple(v) for k, v in RESULT["typed"].items()} == E5_STATIC["typed"]


def test_every_rung_of_ours_keeps_every_constituent() -> None:
    n = RESULT["findings"]
    assert RESULT["passes_lint"]["S7"] == RESULT["passes_lint"]["S7a"] == RESULT["passes_lint"]["S7m"] == n


def test_the_ladder_goes_down() -> None:
    median = {sid: spread[1] for sid, spread in RESULT["typed"].items()}
    assert median["S7"] > median["S7a"] > median["S7m"]
    # the code block is a floor no prompt variant can go below
    assert RESULT["code_block"][1] < median["S7m"]
