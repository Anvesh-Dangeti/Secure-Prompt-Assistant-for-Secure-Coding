"""Structural, factual and plain-language checks on the final-review deck.

Builds the deck into a temporary file, then checks the slide order, that the
work since the mid-semester review gets the most presented slides, that every
number shown is the recorded, test-asserted value from
evaluation/recorded_results.py, that the presented slides stay free of internal
codes, and that the team slide gives no shares or ranks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from pptx.util import Inches  # noqa: E402

import build_final_deck as deck  # noqa: E402
from evaluation.recorded_results import (  # noqa: E402
    E1, E2_PILOT, E5, E5_STATIC, FIXTURE, RELATED, TESTS_AT_SUBMISSION,
)

SLIDE_W, SLIDE_H = Inches(13.333), Inches(7.5)
JARGON = [r"\bS[0-8]\b", r"\bS7[am]\b", r"\b[ABC][1-7]\b", r"\b3[ab]\b", r"\bB\d{3}\b", r"STRIDE", r"SARIF",
          r"\bRCI\b", r"PYSEC", r"\bESR\b", r"\bE[1-5]\b", r"VERIFIED_RESOLVED", r"FIX_REJECTED", r"(?i)fingerprint",
          r"(?i)constituent", r"(?i)mutation", r"(?i)normalis", r"(?i)(?<![-\w])lint(er|ing|ed)?\b",
          r"(?i)\bstrateg(y|ies)\b", r"(?i)\bgates?\b"]


@pytest.fixture(scope="module")
def prs(tmp_path_factory):  # noqa: ANN001, ANN201
    return deck.build(tmp_path_factory.mktemp("deck") / "final.pptx")


def _text(slide) -> str:  # noqa: ANN001
    out = []
    for shape in slide.shapes:
        if shape.has_text_frame:
            out.append(shape.text_frame.text)
        if shape.has_table:
            out.extend(cell.text for row in shape.table.rows for cell in row.cells)
        if shape.has_chart:
            out.extend(shape.chart.plots[0].categories)
    return "\n".join(out)


def _tag(slide) -> str:  # noqa: ANN001
    return _text(slide).splitlines()[0]


def test_slide_order(prs) -> None:  # noqa: ANN001
    expected = ["Building a Prompt Assistant", "Someone has to check them", "the scanners decide",
                "what we add", "Where we stood at the mid-sem review", "Three questions from the panel",
                "a sixth of the tokens", "the part we cannot cut", "judged against the whole app",
                "broke the code that calls it", "free, open library", "re-run our checker results",
                "flaw in our own prompts", "share one server", "same standard", "Friday release",
                "All 12 project requirements", "Four things we learned", "what comes next", "Thank you",
                "Words we use", "each do part of the job", "All nine ways of asking", "Each prompt size in full",
                "Questions we expect", "what each of us worked on", "If the video does not play"]
    assert len(prs.slides) == len(expected) == len(deck.BUILDERS)
    for i, fragment in enumerate(expected):
        assert fragment in _text(prs.slides[i]), f"slide {i + 1} missing {fragment!r}"


def test_work_since_midsem_has_most_presented_slides(prs) -> None:  # noqa: ANN001
    tags = [_tag(prs.slides[n - 1]) for n in deck.PRESENTED]
    since = tags.count(deck.SINCE)
    assert since >= 11 and since > tags.count(deck.RECAP) + tags.count(deck.WRAP), tags
    assert all(_tag(prs.slides[n - 1]) == deck.APPENDIX for n in range(21, len(prs.slides) + 1))


def test_presented_slides_use_plain_language(prs) -> None:  # noqa: ANN001
    for n in deck.PRESENTED:
        text = _text(prs.slides[n - 1])
        for pattern in JARGON:
            assert not re.search(pattern, text), f"slide {n}: {pattern} in {text[:120]!r}"


def test_page_numbers_follow_the_slide_order(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        if n in (1, 20):
            continue
        numbers = [s.text_frame.text for s in slide.shapes if s.has_text_frame and s.text_frame.text == str(n)]
        assert numbers, f"slide {n} has no page number {n}"


def test_midsem_recap_numbers(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[4])
    by = E2_PILOT["by_strategy"]
    assert f"{FIXTURE['detected']} / {FIXTURE['seeded']}" in text
    assert f"{E1['constituent']['flagged']} / {E1['constituent']['mutants']}" in text
    assert f"{by['S2'][0]} vs {by['S7'][0]}" in text and f"{by['S7'][3] / by['S2'][3]:.1f}×" in text


def test_token_ladder_numbers(prs) -> None:  # noqa: ANN001
    slide = prs.slides[6]
    text = _text(slide)
    chart = next(s.chart for s in slide.shapes if s.has_chart)
    per, by = E5["tokens_per_trial"], E5["by_strategy"]
    values = dict(zip(chart.plots[0].categories, chart.plots[0].series[0].values, strict=True))
    assert values == {f"{deck.LADDER[k]} · {by[k][0]}/10 fixed": per[k] for k in ("S7", "S7a", "S2", "S7m")}
    assert f"{by['S7m'][0]} / 10" in text and f"{per['S7'] / per['S7m']:.1f}×" in text
    parts = _text(prs.slides[7])
    for key in ("S7", "S7a", "S7m"):
        assert f"~{E5_STATIC['typed'][key][1]}" in parts
    assert f"about {E5_STATIC['code_block'][1]} tokens" in parts


def test_related_functions_numbers(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[9])
    assert f"{RELATED['caller_broken_by_a_verified_fix']} / {RELATED['verified_on_helpers_with_callers']}" in text
    assert str(RELATED["scanner_clean_but_behaviour_broken"]) in text
    assert str(sum(RELATED["module_wide_breaks"].values())) in text
    assert f"{RELATED['trials_on_helpers_with_callers']} times" in text


def test_library_slides(prs) -> None:  # noqa: ANN001
    library, rerun = _text(prs.slides[10]), _text(prs.slides[11])
    assert deck.LIBRARY_URL in library and "MIT" in library
    c, u = E1["constituent"], E1["unchecked"]
    assert f"{c['flagged']} / {c['mutants']}" in rerun and f"{u['flagged']} / {u['mutants']}" in rerun
    assert f"{c['mutants'] + u['mutants'] + E1['controls_clean']} edited prompts" in rerun


def test_flaw_and_team_server_slides(prs) -> None:  # noqa: ANN001
    flaw = _text(prs.slides[12])
    assert f"× {E2_PILOT['dependency_bumps_rejected']}" in flaw and "5.3.1" in flaw and "5.4" in flaw
    assert all(E5["dependency_verified"][k] for k in ("S7", "S7a", "S7m"))
    server = _text(prs.slides[13])
    for command in ("spa connect", "spa scan", "spa prompt", "spa verify"):
        assert command in server
    assert "never uploaded" in server and "never runs your code" in server


def test_key_claims_present(prs) -> None:  # noqa: ANN001
    everything = "\n".join(_text(s) for s in prs.slides)
    for claim in [f"{TESTS_AT_SUBMISSION}", f"{FIXTURE['detected']} / {FIXTURE['seeded']} planted bugs",
                  "Copilot Autofix", "What we don't claim", "never decided by the AI", "EM26MTECH14009",
                  "CS26MTECH13007", "EM26MTECH11001"]:
        assert claim in everything, f"missing claim: {claim}"
    assert str(TESTS_AT_SUBMISSION) in _text(prs.slides[14])


def test_requirements_has_all_twelve(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[16])
    assert len(deck.REQUIREMENTS) == 12
    for req, how in deck.REQUIREMENTS:
        assert req in text and how in text


def test_team_slide_gives_no_shares_or_ranks(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[25])
    assert "%" not in text and not re.search(r"(?i)\blead", text)
    for name, roll, role, areas in deck.CONTRIBUTIONS:
        assert name in text and roll in text and role in text
        assert [area for area, _ in areas] == ["Research & design", "Build", "Evaluation", "Delivery"]
    lengths = [sum(len(words) for _, words in areas) for *_, areas in deck.CONTRIBUTIONS]
    assert max(lengths) - min(lengths) <= 25, lengths   # descriptions of similar length


def test_everything_on_canvas(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        for shape in slide.shapes:
            assert shape.left >= 0 and shape.top >= 0, f"slide {n}"
            assert shape.left + shape.width <= SLIDE_W + 10 and shape.top + shape.height <= SLIDE_H + 10, f"slide {n}"


def test_no_emoji_and_author(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        assert not [ch for ch in _text(slide) if ord(ch) > 0x2800], f"slide {n}"
    assert prs.core_properties.author == prs.core_properties.last_modified_by == "TEAM-3"
