"""Structural, factual and plain-language checks on the simplified mid-semester deck.

Builds the deck into a temporary file, then checks the seven sections the panel
asked for, layout and house style, that every result shown is the recorded,
test-asserted value from evaluation/recorded_results.py, and that the presented
slides stay free of internal codes (strategy ids, lint-rule ids, gate 3a/3b).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from pptx.enum.shapes import MSO_SHAPE_TYPE  # noqa: E402
from pptx.util import Inches  # noqa: E402

import build_midsem_v2_deck as deck  # noqa: E402
import build_review2_deck as style  # noqa: E402
from evaluation.recorded_results import E1, E2_PILOT, FIXTURE, TESTS, VERIFICATION  # noqa: E402

SLIDE_W, SLIDE_H = Inches(13.333), Inches(7.5)
UNNUMBERED = {1, 14}                     # title and thank-you
PRESENTED = range(2, 14)                 # the content slides shown before the thank-you
JARGON = [r"\bS[0-8]\b", r"\b[ABC][1-7]\b", r"\b3[ab]\b", r"\bB\d{3}\b", r"STRIDE", r"SARIF", r"\bRCI\b",
          r"PYSEC", r"\bESR\b", r"\bE[1-4]\b", r"VERIFIED_RESOLVED", r"FIX_REJECTED", r"(?i)fingerprint",
          r"(?i)constituent", r"(?i)mutation", r"(?i)normalis"]


@pytest.fixture(scope="module")
def prs(tmp_path_factory):  # noqa: ANN001, ANN201
    return deck.build(tmp_path_factory.mktemp("deck") / "midsem_v2.pptx")


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


def _rows(slide) -> list[list[str]]:  # noqa: ANN001
    table = next(s.table for s in slide.shapes if s.has_table)
    return [[c.text for c in row.cells] for row in list(table.rows)[1:]]


def test_the_seven_sections_the_panel_asked_for_in_order(prs) -> None:  # noqa: ANN001
    labels = [_text(s).splitlines()[0] for s in prs.slides]
    sections = ["1 · PROBLEM STATEMENT", "2 · STATE OF THE ART", "3 · ARCHITECTURE", "4 · THREAT MODEL",
                "5 · WHAT IS NEW", "6 · DEMO OF THE EXISTING WORK", "7 · NEXT TWO WEEKS"]
    positions = [next(i for i, label in enumerate(labels) if label.startswith(section)) for section in sections]
    assert positions == sorted(positions), labels


def test_slide_order(prs) -> None:  # noqa: ANN001
    expected = ["Building a Prompt Assistant", "Nobody checks it", "each do part of the job",
                "what we built from it", "the scanners decide", "a complete fix request", "guards itself",
                "Four things our tool does", "fooled the scanners", "the checker notices", "Friday release",
                "changes the result", "from a working system to evidence", "Thank You", "Words we use",
                "All nine ways of asking", "Questions we expect", "If the video does not play",
                "as the verification page shows it"]
    assert len(prs.slides) == len(expected)
    for i, fragment in enumerate(expected):
        assert fragment in _text(prs.slides[i]), f"slide {i + 1} missing {fragment!r}"


def test_presented_slides_use_plain_language(prs) -> None:  # noqa: ANN001
    for n in PRESENTED:
        text = _text(prs.slides[n - 1])
        for pattern in JARGON:
            assert not re.search(pattern, text), f"slide {n}: internal term {pattern!r} on a presented slide"


def test_no_presenter_labels_and_short_notes_on_every_slide(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        assert "Presenter" not in _text(slide), f"slide {n}"
        spoken = slide.notes_slide.notes_text_frame.text.strip()
        assert spoken, f"slide {n} has no speaker notes"
        assert len(spoken) <= 800, f"slide {n}: notes too long ({len(spoken)} characters)"


def test_every_shape_is_on_canvas(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        for shape in slide.shapes:
            if shape.left is None:
                continue
            assert shape.left >= 0 and shape.top >= 0, f"slide {n}"
            assert shape.left + shape.width <= SLIDE_W and shape.top + shape.height <= SLIDE_H, f"slide {n}"


def test_tables_are_not_covered_by_later_shapes(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        shapes = list(slide.shapes)
        for i, shape in enumerate(shapes):
            if not shape.has_table:
                continue
            top, bottom = shape.top, shape.top + shape.height
            for later in shapes[i + 1:]:
                if later.shape_type not in (MSO_SHAPE_TYPE.AUTO_SHAPE, MSO_SHAPE_TYPE.PICTURE) or later.left is None:
                    continue
                overlap = (min(bottom, later.top + later.height) - max(top, later.top)) / 914400
                horizontal = later.left < shape.left + shape.width and later.left + later.width > shape.left
                assert not (horizontal and overlap > 0.02), f"slide {n}: table covered by {overlap:.2f}in"


def test_numbers_fonts_palette_and_author(prs) -> None:  # noqa: ANN001
    fonts = {style.DISPLAY, style.BODY, style.MONO, None}
    colours = {str(c) for c in style.PALETTE}
    for n, slide in enumerate(prs.slides, start=1):
        if n not in UNNUMBERED:
            assert re.search(rf"^{n}$", _text(slide), re.M), f"slide {n} lacks its number"
        frames = [s.text_frame for s in slide.shapes if s.has_text_frame]
        frames += [c.text_frame for s in slide.shapes if s.has_table for r in s.table.rows for c in r.cells]
        for tf in frames:
            for para in tf.paragraphs:
                for run in para.runs:
                    assert run.font.name in fonts, f"slide {n}: font {run.font.name}"
                    rgb = run.font.color.rgb if run.font.color and run.font.color.type else None
                    assert rgb is None or str(rgb) in colours, f"slide {n}: colour {rgb}"
    assert prs.core_properties.author == "TEAM-3" and prs.core_properties.last_modified_by == "TEAM-3"


def test_the_prompt_example_is_what_the_linter_says(prs) -> None:  # noqa: ANN001
    ex = deck.prompt_example()
    assert ex["full"].passed and ex["repaired"].passed and not ex["short"].passed
    text = _text(prs.slides[9])
    for report in (ex["full"], ex["short"], ex["repaired"]):
        assert f"{'PASS' if report.passed else 'FAIL'} · {report.constituent_score:.0%}" in text
    assert deck.SHORT_PROMPT in text
    assert ex["parts"]["opening"].replace("`", "") in _text(prs.slides[5])


def test_the_checker_numbers_are_the_recorded_ones(prs) -> None:  # noqa: ANN001
    from evaluation.e1_mutation import REMOVES_A_CONSTITUENT, run

    text = _text(prs.slides[9])
    c, u = E1["constituent"], E1["unchecked"]
    assert f"{c['flagged']} / {c['mutants']}" in text and f"0 / {u['mutants']}" in text
    assert f"{c['failed']} / {c['failed']}" in text                     # "repaired": every failed prompt
    result = run()
    assert sum(result["by_operator"][name]["repaired"] for name in REMOVES_A_CONSTITUENT) == c["failed"]
    assert f"{E1['by_operator']['undelimit the code'][1]} of {E1['findings']}" in text


def test_the_verdict_counts_are_the_recorded_ones(prs) -> None:  # noqa: ANN001
    verdicts = [v for v, _, _ in VERIFICATION.values()]
    text = _text(prs.slides[8])
    assert f"We scripted {len(VERIFICATION)} test commits" in text
    for verdict, word in (("VERIFIED_RESOLVED", "verified"), ("FIX_REJECTED", "rejected"),
                          ("UNVERIFIED", "unverified")):
        assert f"{verdicts.count(verdict)} {word}" in text
    rejected_by = {gate for v, gate, _ in VERIFICATION.values() if v == "FIX_REJECTED"}
    assert rejected_by == {"1", "2", "3a"}                              # "one by each of the 3 checks"


def test_the_results_chart_and_table_are_the_recorded_ones(prs) -> None:  # noqa: ANN001
    by = E2_PILOT["by_strategy"]
    chart = next(s.chart for s in prs.slides[11].shapes if s.has_chart)
    names = {name: sid for sid, name in deck.WAYS.items()}
    values = chart.plots[0].series[0].values
    for name, value in zip(chart.plots[0].categories, values, strict=True):
        assert by[names[name]][0] == value, name
    assert list(values) == sorted(values, reverse=True)
    for cells in _rows(prs.slides[15]):
        verified, applicable, esr, tokens = by[cells[0]]
        assert cells[2:] == [f"{verified} / {applicable}", f"{esr:.1f}", f"{tokens:,}"], cells[0]
    text = _text(prs.slides[11])
    assert f"{FIXTURE['detected']} / {FIXTURE['seeded']}" in text
    assert f"{by['S7'][3] / by['S2'][3]:.1f}×" in text
    assert "A pilot" in text                                         # never presented as a ranking


def test_screenshots_are_embedded(prs) -> None:  # noqa: ANN001
    for name in deck.SCREENSHOTS:
        assert (deck.IMG / name).is_file(), f"missing docs/img/{name}"
    pictures = {n: sum(s.shape_type == MSO_SHAPE_TYPE.PICTURE for s in slide.shapes)
                for n, slide in enumerate(prs.slides, start=1)}
    assert pictures[11] == 1 and pictures[18] == 2 and pictures[19] == 1
    assert "screenshot missing" not in "\n".join(_text(s) for s in prs.slides)


def test_key_claims_present(prs) -> None:  # noqa: ANN001
    everything = "\n".join(_text(s) for s in prs.slides)
    for claim in [f"{TESTS} automated tests", "Copilot Autofix", "Effective Safety Rate", "No plugin",
                  "REJECTED", "UNVERIFIED", "SSRF", "prompt injection", "18 Nov", "What we do not claim"]:
        assert claim in everything, f"missing claim: {claim}"


def test_no_emoji(prs) -> None:  # noqa: ANN001
    for n, slide in enumerate(prs.slides, start=1):
        assert not [ch for ch in _text(slide) if ord(ch) > 0x2800], f"slide {n}"
