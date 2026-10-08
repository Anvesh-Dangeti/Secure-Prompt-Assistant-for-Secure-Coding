#!/usr/bin/env python3
"""
Build the Review 2 presentation deck.

Content comes from docs/review2_slides.md; the visual design is lifted from the
Review 1 ideation deck (Secure_Prompt_Assistant_Ideation.pptx) so the two read
as one series. Every geometry value below was measured out of that file --
see the DESIGN SYSTEM block.

Usage (must be the Python that has python-pptx installed):
    python scripts/build_review2_deck.py
    python scripts/build_review2_deck.py --out path/to/deck.pptx

Requires: python-pptx==1.0.2
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
    from pptx.oxml.ns import qn
    from pptx.util import Emu, Inches, Pt
except ImportError:  # pragma: no cover
    sys.exit(
        "python-pptx is required.\n"
        "    pip install python-pptx==1.0.2\n"
        "Note: on this machine that is the Python 3.12 install, not the MSYS python."
    )

# ==========================================================================
# DESIGN SYSTEM -- measured from Secure_Prompt_Assistant_Ideation.pptx
# ==========================================================================

SLIDE_W, SLIDE_H = 13.333, 7.5          # inches (16:9)

NAVY = RGBColor(0x0B, 0x1E, 0x39)       # headlines, table header, dark slides
TEAL = RGBColor(0x17, 0xB8, 0xA6)       # section labels, badges, affirmatives
SLATE = RGBColor(0x5B, 0x6B, 0x7F)      # body copy, slide numbers
INK = RGBColor(0x13, 0x20, 0x2E)        # table body text
MIST = RGBColor(0xF5, 0xF7, 0xFA)       # content slide background
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
PALE = RGBColor(0xAF, 0xC0, 0xD6)       # secondary text on navy
BORDER = RGBColor(0xDF, 0xE5, 0xEC)     # table cell borders
DEEP1 = RGBColor(0x13, 0x2A, 0x4D)      # title-slide outer circle
DEEP2 = RGBColor(0x1B, 0x3B, 0x66)      # title-slide middle circle

PALETTE = {NAVY, TEAL, SLATE, INK, MIST, WHITE, PALE, BORDER, DEEP1, DEEP2}

DISPLAY = "Cambria"   # headlines, labels, card titles
BODY = "Calibri"      # body copy, tables, captions
MONO = "Consolas"     # architecture diagram

# layout grid (inches)
MARGIN_X = 0.60
LABEL_Y, LABEL_H = 0.42, 0.35
HEAD_Y, HEAD_H = 0.75, 0.90
CONTENT_Y = 1.95
CONTENT_W = 12.10
CARD_X = (0.60, 4.70, 8.80)
CARD_W = 3.85
ROW_PITCH = 1.55          # stacked-row vertical pitch
ROW_Y0 = 1.90
CALLOUT_Y, CALLOUT_H = 6.55, 0.60
NUM_X, NUM_Y = 12.43, 7.00

# tick glyphs -- plain text, never emoji (emoji render inconsistently in PowerPoint)
YES, NO, PARTIAL = "✓", "×", "~"

_warnings: list[str] = []


# ==========================================================================
# helpers
# ==========================================================================

def add_slide(prs: Presentation, bg: RGBColor = MIST):
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = bg
    return slide


def textbox(slide, x, y, w, h, *, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    return tf


def write(tf, text, *, font=BODY, size=12, bold=False, color=SLATE,
          align=PP_ALIGN.LEFT, space_after=0, para=None, line_spacing=None):
    """Write one paragraph. Pass para=<existing> to append a run instead."""
    p = para if para is not None else (
        tf.paragraphs[0] if not tf.paragraphs[0].runs and not tf.paragraphs[0].text
        else tf.add_paragraph()
    )
    p.alignment = align
    p.space_after = Pt(space_after)
    if line_spacing:
        p.line_spacing = line_spacing
    run = p.add_run()
    run.text = text
    run.font.name = font
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    return p


def section_label(slide, text):
    tf = textbox(slide, MARGIN_X, LABEL_Y, 10.00, LABEL_H)
    write(tf, text.upper(), font=DISPLAY, size=13, bold=True, color=TEAL)


def headline(slide, text, *, size=32, color=NAVY, h=HEAD_H):
    """Pass h= for a headline that legitimately needs two lines."""
    tf = textbox(slide, MARGIN_X, HEAD_Y, 11.80, h)
    write(tf, text, font=DISPLAY, size=size, bold=True, color=color, line_spacing=1.05)
    _check_fit(text, 11.80, h, size, f"headline: {text[:40]}")


def slide_number(slide, n):
    tf = textbox(slide, NUM_X, NUM_Y, 0.50, 0.30)
    write(tf, str(n), size=10, color=SLATE, align=PP_ALIGN.RIGHT)


def badge(slide, x, y, size, label, *, shape=MSO_SHAPE.OVAL, fill=TEAL,
          label_color=WHITE, label_size=None):
    shp = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(size), Inches(size))
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    shp.line.fill.background()
    shp.shadow.inherit = False
    tf = shp.text_frame
    tf.word_wrap = False
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    write(tf, label, font=DISPLAY, size=label_size or max(11, int(size * 16)),
          bold=True, color=label_color, align=PP_ALIGN.CENTER)
    return shp


def stacked_row(slide, index, num, title, body, *, y0=ROW_Y0, pitch=ROW_PITCH,
                title_size=18, body_size=13.5):
    """The slide-2 pattern: teal badge, bold title, muted body."""
    y = y0 + index * pitch
    badge(slide, 0.70, y, 0.85, num, shape=MSO_SHAPE.ROUNDED_RECTANGLE, label_size=15)
    tf = textbox(slide, 1.85, y - 0.02, 10.60, 0.40)
    write(tf, title, font=DISPLAY, size=title_size, bold=True, color=NAVY)
    tf = textbox(slide, 1.85, y + 0.38, 10.50, 0.80)
    write(tf, body, size=body_size, color=SLATE, line_spacing=1.15)
    _check_fit(body, 10.50, 0.80, body_size, f"row body: {title[:30]}")


def card(slide, col, y, num, title, body, *, h=2.15, body_size=11.5):
    x = CARD_X[col]
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(x), Inches(y), Inches(CARD_W), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = WHITE
    shp.line.fill.background()
    shp.shadow.inherit = False
    badge(slide, x + 0.30, y + 0.30, 0.75, num, label_size=14)
    tf = textbox(slide, x + 0.30, y + 1.15, 3.25, 0.35)
    write(tf, title, font=DISPLAY, size=16, bold=True, color=NAVY)
    tf = textbox(slide, x + 0.30, y + 1.50, 3.25, h - 1.70)
    # space_after on every paragraph, including the first -- otherwise the first
    # two bullets run together and read as one block.
    for line in (body if isinstance(body, list) else [body]):
        write(tf, line, size=body_size, color=SLATE, space_after=6, line_spacing=1.1)
    return shp


def callout(slide, text, *, emphasis=False, y=CALLOUT_Y, h=CALLOUT_H, size=12.5):
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(MARGIN_X), Inches(y), Inches(CONTENT_W), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = NAVY if emphasis else WHITE
    shp.line.fill.background()
    shp.shadow.inherit = False
    tf = textbox(slide, MARGIN_X + 0.30, y, CONTENT_W - 0.60, h, anchor=MSO_ANCHOR.MIDDLE)
    write(tf, text, size=size, bold=emphasis, color=WHITE if emphasis else NAVY,
          line_spacing=1.1)
    _check_fit(text, CONTENT_W - 0.60, h, size, f"callout: {text[:40]}")
    return shp


def mono_block(slide, text, *, y=CONTENT_Y, h=4.30, size=11):
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(MARGIN_X), Inches(y), Inches(CONTENT_W), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = WHITE
    shp.line.fill.background()
    shp.shadow.inherit = False
    tf = textbox(slide, MARGIN_X + 0.35, y + 0.20, CONTENT_W - 0.70, h - 0.40)
    for i, line in enumerate(text.strip("\n").split("\n")):
        # Highlight the annotated steps so the eye lands on what changed.
        emphasised = "<--" in line or line.strip().startswith("Gate")
        write(tf, line or " ", font=MONO, size=size,
              color=NAVY if emphasised else SLATE, bold=emphasised,
              space_after=0, line_spacing=1.0)


def _set_cell_borders(cell, color=BORDER, width_pt=1.0):
    """python-pptx exposes no border API, so write the a:ln* elements directly."""
    tc_pr = cell._tc.get_or_add_tcPr()
    for tag in ("a:lnL", "a:lnR", "a:lnT", "a:lnB"):
        for existing in tc_pr.findall(qn(tag)):
            tc_pr.remove(existing)
    for tag in ("a:lnL", "a:lnR", "a:lnT", "a:lnB"):
        ln = tc_pr.makeelement(qn(tag), {"w": str(int(width_pt * 12700)), "cap": "flat",
                                         "cmpd": "sng", "algn": "ctr"})
        solid = ln.makeelement(qn("a:solidFill"), {})
        clr = solid.makeelement(qn("a:srgbClr"), {"val": f"{color}"})
        solid.append(clr)
        ln.append(solid)
        tc_pr.insert(0, ln)


def data_table(slide, header, rows, col_widths, *, y=CONTENT_Y, row_h=0.55,
               header_pt=12, body_pt=11, bold_rows=(), first_col_bold=False):
    """Navy header, transparent body, hairline borders -- matches ideation slide 7."""
    n_rows, n_cols = len(rows) + 1, len(header)
    total_h = row_h * n_rows
    gfx = slide.shapes.add_table(n_rows, n_cols, Inches(MARGIN_X), Inches(y),
                                 Inches(sum(col_widths)), Inches(total_h))
    table = gfx.table

    # Strip PowerPoint's default banded-blue table style.
    tbl_pr = table._tbl.find(qn("a:tblPr"))
    if tbl_pr is not None:
        for attr in ("firstRow", "bandRow", "firstCol", "lastRow", "lastCol", "bandCol"):
            tbl_pr.attrib.pop(attr, None)
        for style in tbl_pr.findall(qn("a:tableStyleId")):
            tbl_pr.remove(style)

    for i, w in enumerate(col_widths):
        table.columns[i].width = Inches(w)
    for r in range(n_rows):
        table.rows[r].height = Inches(row_h)

    # Columns that hold only tick glyphs get centred headers, so the header
    # sits over its column of ticks rather than hugging the left border.
    tick_cols = {
        c for c in range(1, n_cols)
        if rows and all(r[c] in (YES, NO, PARTIAL) for r in rows)
    }

    def fill_cell(cell, text, *, bold, color, size, fill, center=False):
        cell.fill.solid()
        if fill is None:
            cell.fill.background()
        else:
            cell.fill.fore_color.rgb = fill
        cell.vertical_anchor = MSO_ANCHOR.MIDDLE
        cell.margin_left = cell.margin_right = Inches(0.10)
        cell.margin_top = cell.margin_bottom = Inches(0.03)
        tf = cell.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.alignment = (PP_ALIGN.CENTER
                       if center or text in (YES, NO, PARTIAL)
                       else PP_ALIGN.LEFT)
        run = p.add_run()
        run.text = text
        run.font.name = BODY
        run.font.size = Pt(size)
        run.font.bold = bold
        # Affirmative ticks read teal and bold; negatives recede to slate.
        # Note: negatives use SLATE rather than the near-white BORDER -- at
        # BORDER they vanish on a projector and the rows read as empty/broken
        # rather than as "this tool does not do it".
        if text == YES:
            run.font.color.rgb = TEAL
            run.font.bold = True
        elif text in (NO, PARTIAL):
            run.font.color.rgb = SLATE
        else:
            run.font.color.rgb = color
        _set_cell_borders(cell)

    for c, text in enumerate(header):
        fill_cell(table.cell(0, c), text, bold=True, color=WHITE, size=header_pt,
                  fill=NAVY, center=c in tick_cols)

    for r, row in enumerate(rows, start=1):
        emphasise = (r - 1) in bold_rows
        for c, text in enumerate(row):
            fill_cell(
                table.cell(r, c), text,
                bold=emphasise and (c == 0 or first_col_bold and c == 0),
                color=NAVY if emphasise else INK,
                size=body_pt, fill=None,
            )
    _check_table_fit(rows, col_widths, row_h, body_pt)
    return table


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text.strip()


# ==========================================================================
# overflow guard -- crude, but catches the obvious breakages before PowerPoint does
# ==========================================================================

def _chars_per_line(width_in: float, pt: float) -> float:
    # ~0.50 em average advance width for Calibri/Cambria at body sizes.
    return max(1.0, (width_in * 72.0) / (pt * 0.50))


def _check_fit(text, width_in, height_in, pt, label):
    if not text:
        return
    lines = max(1, -(-len(text) // int(_chars_per_line(width_in, pt))))
    needed = lines * (pt * 1.25) / 72.0
    if needed > height_in * 1.08:
        _warnings.append(
            f"  overflow? {label}  needs ~{needed:.2f}in in a {height_in:.2f}in box"
        )


def _check_table_fit(rows, col_widths, row_h, pt):
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            if len(text) > 2:
                _check_fit(text, col_widths[c] - 0.20, row_h, pt, f"table r{r+1}c{c+1}")


# ==========================================================================
# SLIDES
# ==========================================================================

def slide_01_title(prs):
    s = add_slide(prs, NAVY)
    for x, y, d, col in ((9.40, 1.10, 3.60, DEEP1), (10.00, 1.70, 2.40, DEEP2),
                         (10.55, 2.25, 1.30, TEAL)):
        shp = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
        shp.fill.solid()
        shp.fill.fore_color.rgb = col
        shp.line.fill.background()
        shp.shadow.inherit = False

    tf = textbox(s, 0.70, 2.15, 8.20, 0.40)
    write(tf, "SECURE SOFTWARE ENGINEERING · REVIEW 2",
          font=DISPLAY, size=13, bold=True, color=TEAL)

    tf = textbox(s, 0.70, 2.60, 8.60, 1.90)
    write(tf, "Building a Prompt Assistant", font=DISPLAY, size=40, bold=True, color=WHITE)
    write(tf, "for Secure Coding", font=DISPLAY, size=40, bold=True, color=WHITE)

    tf = textbox(s, 0.70, 4.55, 7.80, 0.90)
    write(tf, "Revised scope, literature review and competitive landscape",
          size=16, color=PALE, line_spacing=1.2)

    students = [
        ("Student 1 : Anvesh Dangeti", "Roll no: EM26MTECH14009", 0.70),
        ("Student 2 : Sai Prakash Nayak", "Roll no: EM26MTECH11001", 3.57),
        ("Student 3 : Dhananjay Kumar", "Roll no: CS26MTECH13007", 6.44),
    ]
    for name, roll, x in students:
        tf = textbox(s, x, 6.34, 2.60, 0.46)
        write(tf, name, size=12, bold=True, color=PALE)
        tf = textbox(s, x, 6.74, 2.60, 0.38)
        write(tf, roll, size=12, bold=True, color=PALE)

    notes(s, """
Review 2 - 19 September 2026. Fifteen minutes.

Open by framing this as: the panel gave us four action items, and answering the
first one changed the project. Do not bury that - lead with it on slide 3.

Timing: 12 presented slides at roughly 70 seconds each. Slides 3, 4, 7 and 9 are
the load-bearing ones. If you run short, cut slides 10 and 11, never those four.
Slides 14 and 15 are appendix - only go there if the panel presses.
""")


def slide_02_action_items(prs):
    s = add_slide(prs)
    section_label(s, "Review 1 action items")
    headline(s, "Four questions, four answers")
    data_table(
        s,
        ["#", "Action item", "Where it is answered"],
        [
            ["1", "Research existing prompt assistants",
             "related_tools.md  —  6 tool categories surveyed"],
            ["2", "Finalize language scope",
             "Python only  —  with measured justification"],
            ["3", "Finalize vulnerability scope",
             "10 CWEs, covering 7 OWASP categories"],
            ["4", "Conduct literature review",
             "3 assigned papers + 12 supporting works  →  5 research gaps"],
            ["5", "Update project scope",
             "13 changes to the architecture and plan"],
        ],
        [0.70, 4.60, 6.80],
        row_h=0.62, body_pt=12.5,
    )
    callout(s, "Every decision in this deck traces to a paper finding or an existing "
               "tool's limitation.")
    slide_number(s, 2)
    notes(s, """
Say: "We'll take these in order, but the honest place to start is action item 1 -
because what we found there changed the project."

Keep this slide short. It is a roadmap, not a result.
""")


def slide_03_uncomfortable(prs):
    s = add_slide(prs)
    section_label(s, "Existing solutions")
    headline(s, "The loop we proposed at Review 1 already ships")
    stacked_row(s, 0, "01", "GitHub Copilot Autofix — generally available since August 2024",
                "CodeQL raises an alert → an LLM drafts a fix → CodeQL re-runs to "
                "validate it. GitHub's own slogan: “found means fixed.”")
    stacked_row(s, 1, "02", "It is not a prototype — it is measured and shipping",
                "Covers 90%+ of alert types in JavaScript, TypeScript, Java and Python. "
                "Fixes land 3× faster overall — 7× for XSS, 12× for SQL injection.")
    stacked_row(s, 2, "03", "So we are no longer claiming that loop as our contribution",
                "The real question became: what do these tools genuinely not do? "
                "That is the rest of this deck.")
    callout(s, "We would rather tell you this than have you find it.", emphasis=True)
    slide_number(s, 3)
    notes(s, """
MOST IMPORTANT SLIDE - do not rush it.

Say: "We'd rather tell you this than have you find it. Our Review 1 pitch was
'closed-loop verification.' That's a shipped GitHub product. So the real question
became: what do these tools genuinely NOT do?"

If asked "isn't this just Copilot Autofix?":
No, and we opened with that. Autofix hides its prompt, validates only against the
default query suite, uses one scanner, and doesn't check the fix preserved
functionality. We measure nine prompting strategies against real findings, verify
against three gates, and track identity across commits. We're not claiming better
fixes than GPT-4 - we're claiming a measurement nobody has made.
""")


def slide_04_matrix(prs):
    s = add_slide(prs)
    section_label(s, "Competitive landscape")
    headline(s, "Three empty columns")
    data_table(
        s,
        ["Capability", "Copilot\nAutofix", "Snyk\nCode", "Semgrep\nAssistant",
         "Defect\nDojo", "Backslash\nRules", "Raw\nChatGPT", "Ours"],
        [
            # Backslash scores freshly *generated* code against seeded scenarios --
            # it never remediates a finding in a repository. "gen-time" states that
            # precisely; a bare NO would overstate the gap.
            ["Scanner-grounded findings", "CodeQL", YES, YES, "500+", "gen-time", NO, "4 tools"],
            ["Independent re-scan verification", "limited", PARTIAL, PARTIAL, NO, NO, NO, YES],
            ["Fix introduced nothing new", PARTIAL, NO, NO, NO, NO, NO, YES],
            ["Fix preserved functionality", NO, NO, NO, NO, NO, NO, YES],
            ["Cross-commit lifecycle", NO, NO, NO, YES, NO, NO, YES],
            ["Prompt strategy measured", NO, NO, NO, NO, NO, NO, YES],
            ["Open / reproducible / local LLM", NO, NO, "partial", YES, NO, NO, YES],
        ],
        [3.30, 1.30, 1.15, 1.35, 1.25, 1.30, 1.20, 1.25],
        row_h=0.52, header_pt=10, body_pt=10.5,
        bold_rows=(2, 3, 4, 5),
    )
    callout(s, "DefectDojo has lifecycle without AI. Copilot Autofix has AI without "
               "lifecycle. Nobody has joined them.", emphasis=True)
    slide_number(s, 4)
    notes(s, """
MOST IMPORTANT SLIDE. Point at the four bold rows.

Say: "Every tool hides its prompt. Nobody checks the fix still works. And the one
tool that does finding lifecycle properly has no AI at all."

The four bold rows are the contribution. Everything else on this slide is context.

The Backslash column is the newest and the most pointed: their whole product IS a
prompt - a CWE rules file claimed to score 100% - yet the ruleset is unpublished,
there is no independent re-scan, and nothing checks the code still runs. We added
their technique to our registry as S8 and will measure it under all three gates.

If asked why not CodeQL, since all three papers use it:
It's the strongest citation anchor, so we've wired it as an optional adapter for
the evaluation chapter. It needs a database build per scan, too slow for the
interactive loop. Semgrep and Bandit give two independent engines with sub-second
scans and an agreement metric.
""")


def slide_05_papers(prs):
    s = add_slide(prs)
    section_label(s, "Academic literature")
    headline(s, "Three papers, three findings we build on")
    stacked_row(
        s, 0, "01", "Yan et al. — Guiding AI to Fix Its Own Flaws  (arXiv 2506.23034)",
        "Raw scanner output is weak feedback. “Explained feedback” — scanner output "
        "enriched by an LLM into contextualised guidance — substantially improves repair; "
        ">98% of those explanations validated as correct.   →  We split our AI layer into two stages.")
    stacked_row(
        s, 1, "02", "Cicalese et al. — The Language of Security  (arXiv 2607.15937)",
        "12,960 prompt permutations, 40,230 code solutions. Python was vulnerable in 40.95% "
        "of snippets vs Java 8.82% and C 0.78%. Constituents that bind entities to constraints "
        "are the security-critical ones.   →  We chose Python, and built the linter they called for.")
    stacked_row(
        s, 2, "03", "Tony et al. — Prompting Techniques for Secure Code Generation  (ACM TOSEM)",
        "Seven prompting techniques over 150 tasks. RCI cut weakness density 77.55% on GPT-4. "
        "Persona prompting was worse than no security instruction at all.   "
        "→  We implement all seven, plus two of our own, as a measurable registry.")
    slide_number(s, 5)
    notes(s, """
One sentence per paper, then move. The detail lives in docs/literature_review.md.

The arrow at the end of each row is the point - each paper changed a specific
component, not just the bibliography.
""")


def slide_06_language(prs):
    s = add_slide(prs)
    section_label(s, "Action item 2 — language scope")
    headline(s, "One language: Python")
    data_table(
        s,
        ["Evidence", "Source"],
        [
            ["40.95% of LLM-generated Python was vulnerable — vs Java 8.82%, C 0.78%",
             "Paper 2, Table II"],
            ["Java snippets failed static analysis 86.81% of the time",
             "Paper 2, §IV-A"],
            ["Bandit is Python-only; Semgrep's Python ruleset is its most mature; "
             "pip-audit is Python", "tooling"],
            ["Every benchmark we need (LLMSecEval, SecurityEval, SecCodePLT) is Python",
             "Papers 1–3"],
        ],
        [9.10, 3.00],
        row_h=0.70, body_pt=12.5,
    )
    tf = textbox(s, MARGIN_X, 5.05, CONTENT_W, 0.90)
    write(tf, "Python is where LLM-generated code is measurably least secure, and the only "
              "language where all four of our scanners work.",
          font=DISPLAY, size=17, bold=True, color=NAVY, line_spacing=1.15)
    callout(s, "Stretch, not promised: one JavaScript run as a validity check — exactly how "
               "Paper 3 generalised its Python findings to C.")
    slide_number(s, 6)
    notes(s, """
Say: "One language: Python. It is where LLM-generated code is measurably least
secure - 40.95% vulnerable versus 8.82% for Java and 0.78% for C - it is the only
language where all four of our scanners work, and it is the language of every
benchmark we want to compare against."

If pressed on why not add a second language: the professor asked for depth over
breadth, and Java is the worst possible second choice given the 86.81% analysis
failure rate.
""")


def slide_07_cwes(prs):
    s = add_slide(prs)
    section_label(s, "Action item 3 — vulnerability scope")
    headline(s, "8 core CWEs + 2 supporting → 7 of 10 OWASP categories")
    tf = textbox(s, MARGIN_X, 1.72, CONTENT_W, 0.30)
    write(tf, "Selection rule:  MITRE Top 25  ∩  OWASP Top 10  ∩  measured prevalence in "
              "LLM-generated Python  ∩  scanner-detectable",
          size=11.5, bold=True, color=TEAL)
    data_table(
        s,
        ["CWE", "Name", "OWASP", "Why this one"],
        [
            ["78", "OS Command Injection", "A03 Injection",
             "Most frequent in LLM code — and resisted every prompting technique"],
            ["798 / 259", "Hard-coded Credentials", "A07 Auth Failures",
             "Top-4 prevalent; RCI cut it 21→5; found by two independent tools"],
            ["94 / 215", "Flask debug / misconfig", "A05 Misconfiguration",
             "54 → 3 under RCI — the largest measured prompting effect"],
            ["330", "Insecure Randomness", "A02 Crypto Failures",
             "One of the four most prevalent CWEs in LLM-generated Python"],
            ["89", "SQL Injection", "A03 Injection", "MITRE Top 25; the canonical case"],
            ["79", "Cross-Site Scripting", "A03 Injection",
             "MITRE Top 25; LLMSecEval input-validation tasks"],
            ["22", "Path Traversal", "A01 Access Control",
             "MITRE Top 25; the worked repair example in Paper 1"],
            ["502", "Unsafe Deserialization", "A08 Integrity Failures",
             "MITRE Top 25; Bandit detects pickle and yaml.load"],
            ["327 / 328", "Weak Cryptography", "A02 Crypto Failures",
             "High-confidence detection; crisp, verifiable fix"],
            ["1395 + CVEs", "Vulnerable Dependency", "A06 Components",
             "via pip-audit — the only place CVE mapping is honest"],
        ],
        [1.15, 2.85, 2.20, 5.90],
        # 11 rows at 0.40 ends exactly at 6.48, clearing the callout at 6.55.
        y=2.08, row_h=0.40, header_pt=11, body_pt=10.5,
        bold_rows=(0, 1, 2, 3),
    )
    callout(s, "Not covered, deliberately:  A04 Insecure Design — static analysis "
               "structurally cannot detect it.", y=6.55, h=0.52, size=12)
    slide_number(s, 7)
    notes(s, """
MOST IMPORTANT SLIDE for the scope question.

Say: "The top four rows are the four CWEs Paper 3 measured as most prevalent in
LLM-generated Python. CWE-78 is in scope BECAUSE no prompting technique fixes it -
that's an open problem, which makes it a better research target than a solved one."

If told ten still sounds like a lot:
Eight are core, two come free from dependency and config scanning. Each gets
exactly one seeded instance in our fixture with recorded ground truth, so we can
compute real precision and recall. Ten CWEs by nine strategies is ninety runs per
model arm - tractable locally. We'd rather defend ten with evidence than claim
thirty without.
""")


def slide_08_contribution(prs):
    s = add_slide(prs)
    section_label(s, "Revised direction")
    headline(s, "What we now claim")
    tf = textbox(s, MARGIN_X, 1.70, CONTENT_W, 0.95)
    write(tf, "An open, reproducible testbed that measures which prompting strategy produces "
              "scanner-verified secure fixes — under triple-gate verification, with "
              "cross-commit regression tracking.",
          font=DISPLAY, size=19, bold=True, color=NAVY, line_spacing=1.15)
    data_table(
        s,
        ["", "Review 1", "Review 2"],
        [
            ["Contribution", "closed-loop verification",
             "measured prompting strategy + stricter verification"],
            ["Languages", "unspecified", "Python"],
            ["Vulnerabilities", "all of OWASP Top 10", "10 CWEs / 7 categories"],
            ["Scanners", "3", "4  (Bandit restored)"],
            ["Prompts", "one, implicit", "9, compared"],
            ["Verification", "1 gate", "3 gates"],
            ["Fix application", "manual only", "+ sandboxed auto-apply"],
            ["Evaluation", "own fixture", "+ LLMSecEval, SecurityEval, OWASP PyGoat"],
        ],
        [2.60, 4.00, 5.50],
        y=2.85, row_h=0.47, body_pt=11.5,
    )
    slide_number(s, 8)
    notes(s, """
Read the claim sentence out loud, slowly. It is the thesis statement of the project.

Then walk the right-hand column of the table - that is what changed.

If asked what's genuinely novel in one sentence:
Nobody has measured which prompting technique produces scanner-verified fixes on
real repository findings, and nobody checks whether the fix broke the program -
even though the literature documents LLMs renaming functions secure_* without
changing them.
""")


def slide_09_gate3(prs):
    s = add_slide(prs)
    section_label(s, "Verification")
    # Deliberately a two-line headline: it is the sharpest sentence in the deck
    # and shortening it would blunt it.
    headline(s, "A fix that deletes the vulnerable code passes any scanner-only check",
             size=28, h=1.05)
    tf = textbox(s, MARGIN_X, 1.85, CONTENT_W, 0.28)
    write(tf, "Documented - and now measured: prior methods degrade Effective Safety Rate "
              "by 14-54%  (SecCoderX, 2026)", size=12.5, bold=True, color=TEAL)

    evidence = [
        ("Paper 3 §7.4(vi)", "LLM output contains “calls to undeclared methods that did "
                                  "not exist within the code's scope” — annotated "
                                  "“securely verify the user session.”"),
        ("Paper 3 §7.4(vii)", "Functions renamed secure_ping(), secure_upload_file() — "
                                   "“the actual implementation within these methods remains "
                                   "unaltered.”"),
        ("GitHub", "Copilot Autofix's single-file suggestions can break the build."),
    ]
    for i, (src, text) in enumerate(evidence):
        y = 2.22 + i * 0.52
        tf = textbox(s, MARGIN_X, y, 2.05, 0.30)
        write(tf, src, font=DISPLAY, size=12, bold=True, color=TEAL)
        tf = textbox(s, 2.75, y, 9.95, 0.48)
        write(tf, text, size=12, color=SLATE, line_spacing=1.1)

    data_table(
        s,
        ["Gate", "Check", "Fails when"],
        [
            ["1", "Target finding's fingerprint is absent from the rescan",
             "the weakness is still present"],
            ["2", "No new findings at equal-or-higher severity",
             "the fix introduced a new weakness"],
            ["3", "Function preserved — AST parses, module imports, tests pass",
             "the fix deleted the code or broke the build"],
        ],
        [0.90, 6.40, 4.80],
        # 4 rows at 0.54 ends at 5.98, clearing the callout at 6.08.
        y=3.82, row_h=0.54, body_pt=11.5,
        bold_rows=(2,),
    )
    callout(s, "All three must pass.  Any failure → FIX_REJECTED, with the reason recorded. "
               "Paper 3 observes this failure mode; its own methodology cannot penalise it.",
            emphasis=True, y=6.08, h=0.60)
    slide_number(s, 9)
    notes(s, """
MOST IMPORTANT SLIDE for novelty. This is the sharpest thing we have.

Say: "Everyone checks whether the scanner stopped complaining. Nobody checks
whether the code still works. Paper 3 documents LLMs renaming a function secure_
and leaving the body unchanged - under a scanner-only criterion that's a perfect
score."

The 14-54% is the strongest number we have. SecCoderX (NUS, arXiv 2602.07422)
measures Effective Safety Rate - code that is both functionally correct AND secure -
and finds prior secure-generation methods DEGRADE it by 14 to 54%. Between one in
seven and one in two "security improvements" break working code. That turns "fake
fixes happen" from an anecdote into a rate.

Gate 3 is cheap to build and no existing tool has it. Lean on that.

If asked whether "scanner says it's gone" is a weak definition of secure:
Yes, and we say so in the threat-model section. Our claim is precisely: the scanner
no longer detects this weakness, the fix introduced nothing new, and the code still
runs - strictly stronger than what's published, and we don't overclaim beyond it.
""")


def slide_10_architecture(prs):
    s = add_slide(prs)
    section_label(s, "System architecture")
    headline(s, "Where the changes land")
    # Column-aligned by hand: the branch connectors sit at columns 4 and 28,
    # so the two paths line up under their own pipes in a monospace face.
    mono_block(s, """
    Repository (GitHub / ZIP)
    |
    Semgrep . Bandit . Gitleaks . pip-audit           <-- Bandit restored
    |
    Normalise (SARIF) -> Map CWE/OWASP -> Fingerprint + lifecycle
    |
    Stage A:  EXPLAINER      contextualised explanation    <-- Paper 1
    |
    Stage B:  PROMPT BUILDER   x  strategy S0-S8           <-- Paper 3 + S8
    |
    PROMPT SECURITY LINTER     constituents present?       <-- Paper 2
    |
    +-----------------------+
    |                       |
  manual                sandboxed worktree apply
    |                       |
    |                       rescan -> Gate 1 . Gate 2 . Gate 3
    |                       |
    +---> VERIFIED_RESOLVED / FIX_REJECTED -> dashboard
""", y=1.90, h=4.45, size=11.5)
    callout(s, "Design rule, unchanged from Review 1: the LLM explains and drafts. "
               "It never decides fix status.", y=6.50, h=0.58)
    slide_number(s, 10)
    notes(s, """
Do not read the diagram. Point at the three arrows on the right - those are the
three new components, one per paper.

Then say the design rule out loud: the LLM explains and drafts, it never decides
fix status. That was right at Review 1 and the triple gate now enforces it harder.

Cuttable if running short.
""")


def slide_11_gaps(prs):
    s = add_slide(prs)
    section_label(s, "Research gaps & evaluation")
    headline(s, "Five gaps, and how we measure against them")
    data_table(
        s,
        ["Gap", "What is missing in the literature", "Our answer"],
        [
            ["G1", "Prompting techniques never tested on real scanner findings in real repos",
             "Strategy registry applied to live findings"],
            ["G2", "Verification is single-shot; cannot detect a fake fix", "Triple gate"],
            ["G3", "Paper 2's prompt linter does not exist", "We build it"],
            ["G4", "No study tracks finding identity across commits",
             "Fingerprint + lifecycle"],
            ["G5", "No reproducible open-model repair pipeline",
             "Local model, temp 0.0, pinned weights"],
        ],
        [0.80, 6.70, 4.60],
        row_h=0.50, body_pt=11.5,
    )
    detail = [
        ("Evaluation targets",
         "LLMSecEval (150 prompts)  ·  SecurityEval (130 samples)  ·  "
         "OWASP PyGoat  ·  our own fixture with ground truth"),
        ("Metrics",
         "Effective Safety Rate — correct AND secure (SecCoderX's metric)  ·  weakness "
         "count / rate / density (Paper 3's units)  ·  remediation rate per strategy  ·  "
         "regression and functional-break rates  ·  inter-scanner agreement (Cohen's κ)"),
    ]
    for i, (label, text) in enumerate(detail):
        y = 4.75 + i * 0.68
        tf = textbox(s, MARGIN_X, y, 2.40, 0.30)
        write(tf, label, font=DISPLAY, size=12.5, bold=True, color=TEAL)
        tf = textbox(s, 3.10, y, 9.60, 0.62)
        write(tf, text, size=11.5, color=SLATE, line_spacing=1.1)

    callout(s, "Built-in sanity check: if our harness reproduces “RCI best, persona "
               "worst”, the harness itself is validated before we trust our own result.",
            emphasis=True, y=6.30, h=0.58)
    slide_number(s, 11)
    notes(s, """
The sanity check at the bottom is worth saying explicitly - it shows we thought
about whether our own measurement instrument is trustworthy, which is the kind of
thing a panel rewards.

Cuttable if running short, but try to keep the sanity-check line.
""")


def slide_12_status(prs):
    s = add_slide(prs)
    section_label(s, "Status")
    headline(s, "Where we are")
    card(s, 0, CONTENT_Y, "01", "Done since Review 1", [
        "3 papers analysed in depth, 14 supporting works, 5 research gaps",
        "7 existing tools surveyed; contribution repositioned",
        "Scope locked: 1 language, 10 CWEs, 4 scanners, 9 strategies, 3 gates",
        "Working demo: Semgrep + Bandit scanning a seeded fixture, normalised "
        "output with CWE/OWASP mapping",
    ], h=3.55)
    card(s, 1, CONTENT_Y, "02", "Next two weeks", [
        "Phase 1 Foundation: config, secure logging, DB models, safe subprocess",
        "Phase 2 Scanner layer: 4 scanners behind one interface, SARIF normalisation",
        "Phase 3 Repository: SSRF-safe clone, zip-slip-safe extraction, "
        "vulnerable fixture with ground truth",
    ], h=3.55)
    card(s, 2, CONTENT_Y, "03", "Questions for the panel", [
        "Is the repositioned contribution sufficiently novel, given Copilot "
        "Autofix exists?",
        "Is 10 CWEs right — or narrow further to the 4 most prevalent?",
        "Add CodeQL as a third SAST engine for evaluation, accepting the "
        "runtime cost?",
    ], h=3.55)
    callout(s, "Demo available now:   python scripts/demo_scan.py fixtures/vuln_demo   "
               "—  11 findings, 5 OWASP categories, 8/8 ground-truth recall, 4/4 tests passing.")
    slide_number(s, 12)
    notes(s, """
End on the questions card - hand the floor back to the panel deliberately.

If there is time and a laptop, run the demo live. It takes about two seconds:
    python scripts/demo_scan.py fixtures/vuln_demo

Two defects worth mentioning if asked what we learned building it:
1. Bandit embeds line numbers in its code snippet, which leaked into fingerprints -
   a 12-line insertion that touched nothing turned 9 of 11 findings into false
   RESOLVED plus false NEW. Fixed; now 11/11 stable.
2. Bandit reports hard-coded credentials as CWE-259, the child of CWE-798. Without
   canonicalisation, two tools finding one weakness count as two. Paper 3 makes the
   same point.
Saying "we found this by testing it" plays well.
""")


def slide_13_thanks(prs):
    s = add_slide(prs, NAVY)
    for x, y, d, col in ((9.40, 1.10, 3.60, DEEP1), (10.00, 1.70, 2.40, DEEP2),
                         (10.55, 2.25, 1.30, TEAL)):
        shp = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
        shp.fill.solid()
        shp.fill.fore_color.rgb = col
        shp.line.fill.background()
        shp.shadow.inherit = False
    tf = textbox(s, 0.70, 3.05, 8.60, 1.10)
    write(tf, "Thank You", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.20, 8.20, 0.60)
    write(tf, "Questions welcome — the three on the previous slide are ours for you.",
          size=16, color=PALE)
    notes(s, "Appendix slides 14 to 16 hold prepared answers. Jump there only if pressed.")


def _qa_row(slide, index, question, answer, *, y0=1.85, pitch=1.18):
    y = y0 + index * pitch
    tf = textbox(slide, MARGIN_X, y, CONTENT_W, 0.32)
    write(tf, question, font=DISPLAY, size=14, bold=True, color=NAVY)
    tf = textbox(slide, MARGIN_X + 0.25, y + 0.34, CONTENT_W - 0.25, 0.78)
    write(tf, answer, size=11.5, color=SLATE, line_spacing=1.12)


def slide_14_appendix_a(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions  (1 of 3)")
    headline(s, "Prepared answers", size=28)
    _qa_row(s, 0, "“Isn't this just Copilot Autofix?”",
            "No, and we opened with that. Autofix hides its prompt, validates only against the "
            "default query suite, uses one scanner, and doesn't check the fix preserved "
            "functionality. We measure nine prompting strategies against real findings, verify "
            "against three gates, and track identity across commits.")
    _qa_row(s, 1, "“Why not use CodeQL, since all three papers do?”",
            "It is the strongest citation anchor, so it is wired as an optional adapter for the "
            "evaluation chapter. It needs a database build per scan — too slow for the "
            "interactive loop. Semgrep and Bandit give two independent engines with sub-second "
            "scans and an agreement metric.")
    _qa_row(s, 2, "“Ten CWEs still sounds like a lot.”",
            "Eight are core, two come free from dependency and config scanning. Each gets one "
            "seeded instance in our fixture with recorded ground truth, so precision and recall "
            "are computable. Ten CWEs × nine strategies is ninety runs per model arm — "
            "tractable locally.")
    _qa_row(s, 3, "“What if the local 7B model produces bad fixes?”",
            "Then that is the result — and it is gap G5, which nobody has measured. We also "
            "run a hosted free-tier arm, so we report open versus proprietary on scanner-verified "
            "repair. A negative result on the local arm is still a publishable finding.")
    slide_number(s, 14)
    notes(s, "Appendix. Do not present unless the panel asks one of these directly.")


def slide_15_appendix_b(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions  (2 of 3)")
    headline(s, "Prepared answers", size=28)
    _qa_row(s, 0, "“How do you handle false positives?”",
            "A SUPPRESSED lifecycle state — human-marked, tracked, never deleted, and excluded "
            "from new and regression counts. Plus the inter-tool agreement metric between Semgrep "
            "and Bandit measures the disagreement rather than hiding it.")
    _qa_row(s, 1, "“Isn't ‘scanner says it's gone’ a weak definition of secure?”",
            "Yes, and we say so in the threat-model section. Our claim is precisely: the scanner "
            "no longer detects this weakness, the fix introduced nothing new, and the code still "
            "runs — strictly stronger than what is published, and we do not overclaim beyond it.")
    _qa_row(s, 2, "“What is genuinely novel here — in one sentence?”",
            "Nobody has measured which prompting technique produces scanner-verified fixes on real "
            "repository findings, and nobody checks whether the fix broke the program — even "
            "though the literature documents LLMs renaming functions secure_* without changing them.")
    _qa_row(s, 3, "“What did you actually learn building the demo?”",
            "Two real defects. Bandit embeds line numbers in its code snippet, which leaked into "
            "fingerprints — an insertion that touched nothing turned 9 of 11 findings into false "
            "RESOLVED plus false NEW. And Bandit reports hard-coded credentials as CWE-259, the "
            "child of CWE-798, so without canonicalisation two tools finding one weakness count as two.")
    slide_number(s, 15)
    notes(s, "Appendix. The last row is a good answer to any 'what have you built' probe.")


def slide_16_appendix_c(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions  (3 of 3)")
    headline(s, "Prepared answers", size=28)
    _qa_row(s, 0, "“Isn't this what Backslash or Cursor rules already do?”",
            "They ship a CWE rules file and report 100% — on seeded code-generation scenarios, with "
            "no published ruleset, no independent re-scan, no functional check and no cross-commit "
            "tracking. We added their technique to the registry as S8 and measure it on real scanner "
            "findings under all three gates. If it holds up that is a result; if it does not, a bigger one.")
    _qa_row(s, 1, "“Why not train the model, like SafeCodeX?”",
            "Different axis. SafeCodeX (NUS, arXiv 2602.07422) changes the model with online "
            "reinforcement learning — it needs weights and GPUs. We change the prompt: inference-time, "
            "black-box, works on a repository we do not own. We adopt their Effective Safety Rate "
            "metric, and their finding that prior methods degrade ESR by 14-54% is why gate 3 exists.")
    slide_number(s, 16)
    notes(s, """
Appendix. Both answers cover sources the panel supplied after the deck was first
built, so they are the likeliest new questions.

Backslash row: the differentiator is generation versus remediation. They score code
the model just wrote; we fix a finding a scanner raised in a real repository.

SafeCodeX row: do not get drawn into defending why we are not doing RL. Ten weeks
and 8 GB of VRAM is the honest answer, and the prompt axis is the deployable one.
""")


BUILDERS = [
    slide_01_title, slide_02_action_items, slide_03_uncomfortable, slide_04_matrix,
    slide_05_papers, slide_06_language, slide_07_cwes, slide_08_contribution,
    slide_09_gate3, slide_10_architecture, slide_11_gaps, slide_12_status,
    slide_13_thanks, slide_14_appendix_a, slide_15_appendix_b,
    slide_16_appendix_c,
]


def build(out_path: Path) -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(SLIDE_W)
    prs.slide_height = Inches(SLIDE_H)
    for builder in BUILDERS:
        builder(prs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    return prs


def main() -> int:
    default_out = (Path(__file__).resolve().parents[2]
                   / "Secure_Prompt_Assistant_Review2.pptx")
    parser = argparse.ArgumentParser(description="Build the Review 2 deck")
    parser.add_argument("--out", type=Path, default=default_out)
    args = parser.parse_args()

    build(args.out)

    print(f"  built {len(BUILDERS)} slides -> {args.out}")
    if _warnings:
        print(f"\n  {len(_warnings)} possible layout issue(s):")
        for w in _warnings:
            print(w)
    else:
        print("  no layout warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
