"""Structural, factual and plain-language checks on the final-review deck.

Builds the deck into a temporary file, then checks the slide order, that the
three panel questions each have their slide, that every number shown is the
recorded, test-asserted value from evaluation/recorded_results.py, and that the
presented slides stay free of internal codes.
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
from evaluation.recorded_results import E1, E5, E5_STATIC, FIXTURE, RELATED, TESTS_FINAL  # noqa: E402

SLIDE_W, SLIDE_H = Inches(13.333), Inches(7.5)
JARGON = [r"\bS[0-8]\b", r"\bS7[am]\b", r"\b[ABC][1-7]\b", r"\b3[ab]\b", r"\bB\d{3}\b", r"STRIDE", r"SARIF",
          r"\bRCI\b", r"PYSEC", r"\bESR\b", r"\bE[1-5]\b", r"VERIFIED_RESOLVED", r"FIX_REJECTED", r"(?i)fingerprint",
          r"(?i)constituent", r"(?i)mutation", r"(?i)normalis"]


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


def test_slide_order(prs) -> None:  # noqa: ANN001
    expected = ["Building a Prompt Assistant", "Nobody checks it", "each do part of the job",
                "what we built from it", "the scanners decide", "a complete fix request", "guards itself",
                "Four things our tool does", "fooled the scanners", "the checker notices", "changes the result",
                "a sixth of the tokens", "judged across the whole app", "now an open library",
                "with its own scanners", "Friday release", "All 12 project requirements", "what comes next",
                "Thank You", "Words we use", "All nine ways of asking", "What each prompt size costs",
                "Questions we expect", "Who did what", "If the video does not play",
                "as the verification page shows it"]
    assert len(prs.slides) == len(expected) == len(deck.BUILDERS)
    for i, fragment in enumerate(expected):
        assert fragment in _text(prs.slides[i]), f"slide {i + 1} missing {fragment!r}"


def test_the_three_panel_questions_have_their_slides(prs) -> None:  # noqa: ANN001
    labels = [_text(s).splitlines()[0] for s in prs.slides]
    for n in (1, 2, 3):
        assert sum(label.startswith(f"PANEL QUESTION {n}") for label in labels) == 1, labels


def test_presented_slides_use_plain_language(prs) -> None:  # noqa: ANN001
    for n in deck.PRESENTED:
        text = _text(prs.slides[n - 1])
        for pattern in JARGON:
            assert not re.search(pattern, text), f"slide {n}: {pattern} in {text[:120]!r}"


def test_page_numbers_follow_the_slide_order(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        if n in (1, 19):
            continue
        numbers = [s.text_frame.text for s in slide.shapes if s.has_text_frame and s.text_frame.text == str(n)]
        assert numbers, f"slide {n} has no page number {n}"


def test_token_ladder_numbers(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[11])
    chart = next(s.chart for s in prs.slides[11].shapes if s.has_chart)
    values = dict(zip(chart.plots[0].categories, chart.plots[0].series[0].values, strict=True))
    per = E5["tokens_per_trial"]
    assert values == {deck.LADDER[k]: per[k] for k in ("S7", "S7a", "S2", "S7m")}
    assert f"{E5['by_strategy']['S7m'][0]} / 10" in text
    assert f"~{E5_STATIC['typed']['S7m'][1]}" in text and f"~{E5_STATIC['code_block'][1]}" in text
    assert f"{per['S7'] / per['S7m']:.1f}×" in text


def test_related_functions_numbers(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[12])
    assert f"0 / {RELATED['verified_on_helpers_with_callers']}" in text
    assert str(RELATED["scanner_clean_but_behaviour_broken"]) in text
    assert str(sum(RELATED["module_wide_breaks"].values())) in text


def test_library_slide(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[13])
    assert deck.LIBRARY_URL in text and "MIT" in text
    c, u = E1["constituent"], E1["unchecked"]
    assert f"{c['flagged']} / {c['mutants']}" in text and f"{u['flagged']} / {u['mutants']}" in text


def test_key_claims_present(prs) -> None:  # noqa: ANN001
    everything = "\n".join(_text(s) for s in prs.slides)
    for claim in [f"{TESTS_FINAL} automated tests", f"{FIXTURE['detected']} / {FIXTURE['seeded']} planted bugs",
                  "Copilot Autofix", "What we do not claim", "never decided by the AI", "pip-audit",
                  "EM26MTECH14009", "CS26MTECH13007", "EM26MTECH11001"]:
        assert claim in everything, f"missing claim: {claim}"


def test_requirements_table_has_all_twelve(prs) -> None:  # noqa: ANN001
    text = _text(prs.slides[16])
    assert len(deck.REQUIREMENTS) == 12
    for i, (req, _) in enumerate(deck.REQUIREMENTS, start=1):
        assert req in text and str(i) in text


def test_everything_on_canvas(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        for shape in slide.shapes:
            assert shape.left >= 0 and shape.top >= 0, f"slide {n}"
            assert shape.left + shape.width <= SLIDE_W + 10 and shape.top + shape.height <= SLIDE_H + 10, f"slide {n}"


def test_no_emoji_and_author(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        assert not [ch for ch in _text(slide) if ord(ch) > 0x2800], f"slide {n}"
    assert prs.core_properties.author == prs.core_properties.last_modified_by == "TEAM-3"
