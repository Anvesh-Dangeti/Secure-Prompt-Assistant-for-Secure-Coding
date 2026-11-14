#!/usr/bin/env python3
"""
Build the final-review deck (submission Sunday 15 November 2026).

The deck is written for a reader who has not seen the project before: every
headline is the takeaway, the words are plain, and internal codes stay off the
presented slides. It has three parts, marked by a tag in the top-left corner:

* MID-SEM RECAP  - the problem, how the tool works, where we stood on 30 October
* SINCE MID-SEM  - the panel's three questions and the work that answered them
* WRAP-UP        - requirements, what we learned, limits and next steps

Every number comes from evaluation/recorded_results.py, which the test suite
asserts, so the deck can be rebuilt at any time and stay correct.

Usage:
    python scripts/build_final_deck.py
    python scripts/build_final_deck.py --out path/to/deck.pptx
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from PIL import Image  # noqa: E402
from pptx import Presentation  # noqa: E402
from pptx.chart.data import CategoryChartData  # noqa: E402
from pptx.dml.color import RGBColor  # noqa: E402
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_TICK_LABEL_POSITION, XL_TICK_MARK  # noqa: E402
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE  # noqa: E402
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN  # noqa: E402
from pptx.util import Inches, Pt  # noqa: E402

from evaluation.recorded_results import (  # noqa: E402
    E1, E2_PILOT, E5, E5_STATIC, FIXTURE, RELATED, SELF_SCAN, TESTS_AT_SUBMISSION,
)

# --------------------------------------------------------------------------- design system
SLIDE_W, SLIDE_H = 13.333, 7.5
MX = 0.6                                   # side margin
CW = SLIDE_W - 2 * MX                      # content width

INK = RGBColor(0x1B, 0x2B, 0x34)           # dominant deep slate
INK2 = RGBColor(0x26, 0x40, 0x4B)          # cards on dark slides
TINT = RGBColor(0xEE, 0xF3, 0xF2)          # card tint on white
GREEN = RGBColor(0x1A, 0x9E, 0x77)         # the one accent: ours, verified, pass
GREEN_TINT = RGBColor(0xE2, 0xF3, 0xEC)
CORAL = RGBColor(0xD1, 0x49, 0x5B)         # only for fail / rejected / the problem
CORAL_TINT = RGBColor(0xFA, 0xE7, 0xEA)
GREY = RGBColor(0x5B, 0x6B, 0x73)          # captions and secondary text
SOFT = RGBColor(0xA9, 0xB8, 0xBC)          # neutral bars
PALE = RGBColor(0xC9, 0xD6, 0xD3)          # secondary text on dark slides
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

HEAD, BODY, MONO = "Cambria", "Calibri", "Consolas"

RECAP, SINCE, WRAP, APPENDIX = "MID-SEM RECAP", "SINCE MID-SEM", "WRAP-UP", "APPENDIX"

IMG = ROOT / "docs" / "img"
SCREENSHOTS = ("midsem_overview.png", "midsem_lint.png", "midsem_verification.png")
LIBRARY_URL = "github.com/Anvesh-Dangeti/secure-prompt-lint"
REPO_URL = "github.com/Anvesh-Dangeti/Secure-Prompt-Assistant-for-Secure-Coding"
PACKAGES_AUDITED = 35                      # pip-audit over the app's frozen environment (docs/evaluation.md)
TRUST_BOUNDARIES = 10                      # docs/threat_model.md

TEAM = (("Anvesh Dangeti", "EM26MTECH14009"),
        ("Dhananjay Kumar", "CS26MTECH13007"),
        ("Muday Saiprakash Nayak", "EM26MTECH11001"))

# Plain names for the prompt sizes on the token ladder (no internal ids on presented slides).
LADDER = {"S7": "Full prompt + 2 review rounds", "S7a": "One message", "S2": "Bug-specific advice",
          "S7m": "Minimal prompt"}
WAYS = {"S0": "No security hint (baseline)", "S1": "Just say “be secure”", "S2": "Bug-specific advice",
        "S3": "Full secure-coding checklist", "S4": "“Think step by step”",
        "S5": "“Review and improve your answer”", "S6": "“Act as a security expert”",
        "S7": "Ours: explain + checked prompt + review", "S8": "Security rules file"}


# --------------------------------------------------------------------------- primitives
def new_slide(prs, dark: bool = False):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    fill = s.background.fill
    fill.solid()
    fill.fore_color.rgb = INK if dark else WHITE
    return s


def text(s, x, y, w, h, paras, *, size=16, color=INK, bold=False, font=BODY, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, spacing=1.0, after=0, italic=False):
    """A text box. `paras` is a string, or a list of paragraphs; a paragraph is a string or a list of
    (text, {size, color, bold, font, italic}) runs."""
    box = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = anchor
    _fill_paras(tf, [paras] if isinstance(paras, str) else paras, size=size, color=color, bold=bold, font=font,
                align=align, spacing=spacing, after=after, italic=italic)
    return box


def _fill_paras(tf, paras, *, size, color, bold, font, align, spacing, after, italic=False):
    for i, para in enumerate(paras):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = spacing
        p.space_after = Pt(after)
        for run_text, fmt in (para if isinstance(para, list) else [(para, {})]):
            r = p.add_run()
            r.text = run_text
            f = r.font
            f.name = fmt.get("font", font)
            f.size = Pt(fmt.get("size", size))
            f.bold = fmt.get("bold", bold)
            f.italic = fmt.get("italic", italic)
            f.color.rgb = fmt.get("color", color)


def shape(s, kind, x, y, w, h, fill=None, corner=0.10):
    shp = s.shapes.add_shape(kind, Inches(x), Inches(y), Inches(w), Inches(h))
    if fill is None:
        shp.fill.background()
    else:
        shp.fill.solid()
        shp.fill.fore_color.rgb = fill
    shp.line.fill.background()
    shp.shadow.inherit = False
    if kind == MSO_SHAPE.ROUNDED_RECTANGLE:
        shp.adjustments[0] = min(0.5, corner / min(w, h))
    return shp


def card(s, x, y, w, h, fill=TINT):
    return shape(s, MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h, fill)


def inside(shp, label, *, size=14, color=WHITE, bold=True, font=BODY, align=PP_ALIGN.CENTER):
    tf = shp.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    _fill_paras(tf, [label], size=size, color=color, bold=bold, font=font, align=align, spacing=1.0, after=0)
    return shp


PILL_STYLE = {"pass": (GREEN, WHITE), "fail": (CORAL, WHITE), "neutral": (TINT, INK), "dark": (INK2, WHITE),
              "quiet": (TINT, GREY)}


def pill_width(label, size=12):
    return 0.34 + len(label) * size * 0.0079


def pill(s, x, y, label, kind="pass", size=12, h=0.36):
    fill, color = PILL_STYLE[kind]
    w = pill_width(label, size)
    shp = shape(s, MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h, fill, corner=h / 2)
    inside(shp, label, size=size, color=color)
    return w


def circle(s, x, y, d, label, fill=INK, color=WHITE, size=14, font=BODY):
    return inside(shape(s, MSO_SHAPE.OVAL, x, y, d, d, fill), label, size=size, color=color, font=font)


def arrow(s, x, y, w=0.34, h=0.26, color=SOFT, down=False):
    return shape(s, MSO_SHAPE.DOWN_ARROW if down else MSO_SHAPE.RIGHT_ARROW, x, y, w, h, color)


def tag(s, part):
    kind = {SINCE: "pass", RECAP: "neutral", WRAP: "neutral", APPENDIX: "quiet"}[part]
    pill(s, MX, 0.42, part, kind, size=11.5, h=0.34)


def headline(s, words, dark=False):
    text(s, MX, 0.86, CW, 0.95, words, size=30, bold=True, font=HEAD, color=WHITE if dark else INK)


def subline(s, words, y=1.55):
    text(s, MX, y, CW, 0.45, words, size=15, color=GREY)


def page(s, n, dark=False):
    text(s, SLIDE_W - MX - 0.5, 7.02, 0.5, 0.3, str(n), size=11, color=PALE if dark else GREY, align=PP_ALIGN.RIGHT)


def notes(s, words):
    s.notes_slide.notes_text_frame.text = " ".join(words.split())


def callout(s, y, paras, h=0.82, fill=TINT, size=15):
    card(s, MX, y, CW, h, fill)
    text(s, MX + 0.3, y, CW - 0.6, h, paras, size=size, anchor=MSO_ANCHOR.MIDDLE, spacing=1.05)


def stat_h(s, x, y, w, h, big, label, sub="", *, color=GREEN, fill=TINT, big_w=1.6, big_size=30, pill_kind=None):
    """A card with the big number on the left and its meaning on the right."""
    card(s, x, y, w, h, fill)
    if pill_kind:
        pw = pill_width(big, 13)
        pill(s, x + 0.25 + max(0.0, (big_w - pw) / 2), y + h / 2 - 0.2, big, pill_kind, size=13, h=0.4)
    else:
        text(s, x + 0.25, y, big_w, h, big, size=big_size, bold=True, font=HEAD, color=color,
             anchor=MSO_ANCHOR.MIDDLE)
    paras = [[(label, {"bold": True, "size": 15, "color": INK})]]
    if sub:
        paras.append([(sub, {"size": 13, "color": GREY})])
    text(s, x + 0.25 + big_w + 0.2, y + 0.1, w - big_w - 0.7, h - 0.2, paras, anchor=MSO_ANCHOR.MIDDLE,
         spacing=1.02, after=2)


def stat_v(s, x, y, w, h, big, label, sub="", *, color=GREEN, fill=TINT, big_size=40):
    """A card with the big number on top."""
    card(s, x, y, w, h, fill)
    text(s, x + 0.28, y + 0.2, w - 0.56, 0.8, big, size=big_size, bold=True, font=HEAD, color=color)
    paras = [[(label, {"bold": True, "size": 15, "color": INK})]]
    if sub:
        paras.append([(sub, {"size": 13, "color": GREY})])
    text(s, x + 0.28, y + 1.05, w - 0.56, h - 1.2, paras, spacing=1.02, after=3)


def picture(s, name, x, y, w, crop=(0.0, 0.0, 0.0, 0.0)):
    """Insert a screenshot at width w, cropped (left, top, right, bottom fractions), keeping its aspect."""
    path = IMG / name
    left, top, right, bottom = crop
    if not path.exists():
        shp = card(s, x, y, w, w * 0.45)
        inside(shp, f"[{name}]", size=12, color=GREY)
        return w * 0.45
    px_w, px_h = Image.open(path).size
    h = w * (px_h * (1 - top - bottom)) / (px_w * (1 - left - right))
    pic = s.shapes.add_picture(str(path), Inches(x), Inches(y))
    pic.crop_left, pic.crop_top, pic.crop_right, pic.crop_bottom = left, top, right, bottom
    pic.width, pic.height = Inches(w), Inches(h)
    pic.line.color.rgb = RGBColor(0xD5, 0xDF, 0xDD)
    pic.line.width = Pt(0.75)
    return h


def bar_chart(s, x, y, w, h, categories, values, colors):
    data = CategoryChartData()
    data.categories = categories
    data.add_series("value", values)
    chart = s.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(x), Inches(y), Inches(w), Inches(h), data).chart
    chart.has_legend = False
    chart.has_title = False
    chart.font.name = BODY
    chart.font.size = Pt(14)
    chart.font.color.rgb = INK
    plot = chart.plots[0]
    plot.gap_width = 45
    plot.vary_by_categories = False
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.font.size = Pt(15)
    labels.font.bold = True
    labels.font.color.rgb = INK
    labels.number_format = "#,##0"
    labels.number_format_is_linked = False
    labels.position = XL_LABEL_POSITION.OUTSIDE_END
    for i, color in enumerate(colors):
        fill = plot.series[0].points[i].format.fill
        fill.solid()
        fill.fore_color.rgb = color
    cat = chart.category_axis
    cat.reverse_order = True
    cat.major_tick_mark = XL_TICK_MARK.NONE
    cat.format.line.fill.background()
    cat.tick_labels.font.size = Pt(14)
    cat.tick_labels.font.color.rgb = INK
    val = chart.value_axis
    val.minimum_scale = 0
    val.maximum_scale = max(values) * 1.22
    val.has_major_gridlines = False
    val.major_tick_mark = XL_TICK_MARK.NONE
    val.tick_label_position = XL_TICK_LABEL_POSITION.NONE
    val.format.line.fill.background()
    return chart


def table(s, x, y, col_w, header, rows, *, row_h=0.46, size=13, header_size=13, bold_rows=(), highlight_col=None):
    n_rows, n_cols = len(rows) + 1, len(header)
    gt = s.shapes.add_table(n_rows, n_cols, Inches(x), Inches(y), Inches(sum(col_w)), Inches(row_h * n_rows))
    tbl = gt.table
    tbl.first_row = True
    tbl.horz_banding = False
    for j, cw in enumerate(col_w):
        tbl.columns[j].width = Inches(cw)
    for i in range(n_rows):
        tbl.rows[i].height = Inches(row_h)
    for i in range(n_rows):
        for j in range(n_cols):
            cell = tbl.cell(i, j)
            cell.margin_left = cell.margin_right = Inches(0.1)
            cell.margin_top = cell.margin_bottom = Inches(0.04)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if i == 0:
                cell.fill.fore_color.rgb = GREEN if j == highlight_col else INK
                value, fmt = header[j], {"bold": True, "color": WHITE, "size": header_size}
            else:
                cell.fill.fore_color.rgb = GREEN_TINT if j == highlight_col else (WHITE if i % 2 else TINT)
                value = rows[i - 1][j]
                fmt = {"bold": (i - 1) in bold_rows, "color": INK, "size": size}
            tf = cell.text_frame
            tf.word_wrap = True
            _fill_paras(tf, [[(value, fmt)]], size=size, color=INK, bold=False, font=BODY,
                        align=PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER, spacing=1.0, after=0)
    return tbl


# --------------------------------------------------------------------------- part 1 · mid-sem recap
def slide_title(prs, n):
    s = new_slide(prs, dark=True)
    text(s, 0.8, 1.35, 9.0, 0.4, "FINAL REVIEW  ·  SECURE SOFTWARE ENGINEERING  ·  IIT HYDERABAD", size=13,
         bold=True, color=GREEN)
    text(s, 0.8, 1.85, 8.6, 2.0, ["Building a Prompt Assistant", "for Secure Coding"], size=44, bold=True,
         font=HEAD, color=WHITE, spacing=0.95)
    text(s, 0.8, 3.95, 8.3, 1.1, "We find security bugs, help developers ask their AI assistant for a safe fix, "
                                 "and then check that fix ourselves, without trusting the AI.",
         size=19, color=PALE, spacing=1.12)
    text(s, 0.8, 5.15, 8.0, 0.4, "TEAM-3  ·  final submission, 15 November 2026", size=13, color=PALE)
    # The deck's motif, previewed: the verdicts the tool gives.
    for i, (label, kind) in enumerate((("24 issues found", "dark"), ("prompt check: PASS", "pass"),
                                       ("fake fix: REJECTED", "fail"), ("real fix: VERIFIED", "pass"))):
        pill(s, 9.9, 1.95 + i * 0.72, label, kind, size=14, h=0.46)
    for i, (name, roll) in enumerate(TEAM):
        x = 0.8 + i * 3.4
        text(s, x, 6.2, 3.3, 0.35, name, size=15, bold=True, color=WHITE)
        text(s, x, 6.56, 3.3, 0.3, roll, size=12, color=PALE)
    notes(s, """Final review, TEAM-3. One sentence: developers ask AI assistants to fix security bugs; our tool helps
    them ask well, with as few tokens as possible, and then proves without trusting the AI whether the fix worked.""")


def slide_problem(prs, n):
    s = new_slide(prs)
    tag(s, RECAP)
    headline(s, "AI writes security fixes. Someone has to check them")
    for i, (big, label, body, source) in enumerate((
        ("40.95%", "of AI-written Python code had a security flaw",
         "Java 8.82% and C 0.78% in the same study, so we focus on Python.", "Cicalese et al. (Paper 2)"),
        ("1 / 10", "safe answers from GPT-4o for a plain request",
         "With security instructions, the best model got 10 / 10. How you ask matters.", "Backslash Security, 2025"),
        ("14–54%", "of safe, working code lost by earlier “secure” methods",
         "A fix can remove the bug by breaking the code. That is not a fix.", "SecCoderX, 2026"),
    )):
        x = MX + i * 4.125
        card(s, x, 1.95, 3.85, 3.05)
        text(s, x + 0.3, 2.15, 3.3, 0.8, big, size=44, bold=True, font=HEAD, color=CORAL)
        text(s, x + 0.3, 3.0, 3.3, 0.7, label, size=16, bold=True, spacing=1.0)
        text(s, x + 0.3, 3.72, 3.3, 0.8, body, size=14, color=GREY, spacing=1.05)
        text(s, x + 0.3, 4.6, 3.3, 0.3, source, size=11, color=GREY, italic=True)
    card(s, MX, 5.35, CW, 1.25, GREEN_TINT)
    circle(s, MX + 0.3, 5.62, 0.7, "?", fill=GREEN, size=24, font=HEAD)
    text(s, MX + 1.3, 5.35, CW - 1.6, 1.25,
         "Our questions: how should a developer ask the AI for a fix, and how can we tell whether the fix really "
         "worked, without trusting the AI?", size=18, bold=True, anchor=MSO_ANCHOR.MIDDLE, spacing=1.05)
    page(s, n)
    notes(s, """Developers already paste scanner warnings into an AI assistant and accept the answer. Three facts: AI
    Python is often insecure; the wording of the request changes the result a lot; and some secure fixes simply
    break the code. Nobody checks the fix independently. That is our project.""")


def slide_how(prs, n):
    s = new_slide(prs)
    tag(s, RECAP)
    headline(s, "How it works: the scanners decide, never the AI")
    steps = (("Connect", "a GitHub link or a ZIP file"),
             ("Scan", "4 free scanners: code, secrets, libraries"),
             ("Label", "bug type and an ID that survives edits"),
             ("Write the prompt", "explain the bug, then ask for a precise fix"),
             ("Check the prompt", "make sure no safety instruction is missing"),
             ("Verify the fix", "scan again and run 3 checks"))
    for i, (title, body) in enumerate(steps):
        x0 = MX + i * 2.03
        circle(s, x0 + 0.59, 1.95, 0.72, str(i + 1), fill=GREEN if i == 5 else INK, size=18, font=HEAD)
        if i < 5:
            arrow(s, x0 + 1.79, 2.18, 0.34, 0.26)
        text(s, x0, 2.85, 1.9, 0.4, title, size=16, bold=True, align=PP_ALIGN.CENTER)
        text(s, x0, 3.27, 1.9, 0.85, body, size=13.5, color=GREY, align=PP_ALIGN.CENTER, spacing=1.02)
    for i, (title, body, color) in enumerate((
        ("Developer mode: the product",
         "The developer pastes our prompt into their own AI assistant (Copilot or any other), commits the fix, and "
         "our tool checks it again. No AI runs inside our tool.", GREEN),
        ("Lab mode: for our experiments",
         "A small AI model on our own computer writes fixes to a copy of the test app, so we can compare ways of "
         "asking under exactly the same checks.", INK))):
        x = MX + i * 6.15
        card(s, x, 4.35, 5.95, 1.6)
        text(s, x + 0.3, 4.5, 5.35, 0.4, title, size=17, bold=True, color=color)
        text(s, x + 0.3, 4.92, 5.35, 0.95, body, size=14, color=INK, spacing=1.05)
    card(s, MX, 6.15, CW, 0.66)
    text(s, MX + 0.3, 6.15, 1.9, 0.66, "A fix is marked", size=16, bold=True, anchor=MSO_ANCHOR.MIDDLE)
    pill(s, MX + 2.15, 6.3, "VERIFIED", "pass", size=13)
    text(s, MX + 3.55, 6.15, CW - 3.8, 0.66, "only if the bug is gone, nothing new appeared, and the code still works.",
         size=16, anchor=MSO_ANCHOR.MIDDLE)
    page(s, n)
    notes(s, """Six steps. The important rule: the AI only explains and drafts; the same scanners run again and three
    checks decide. Developer mode is the product; lab mode is how we run controlled experiments.""")


def slide_exists(prs, n):
    s = new_slide(prs)
    tag(s, RECAP)
    headline(s, "What tools already do, and what we add")
    card(s, MX, 1.95, 4.65, 4.45)
    text(s, MX + 0.3, 2.15, 4.05, 0.45, "Already exists", size=18, bold=True)
    text(s, MX + 0.3, 2.7, 4.05, 3.5, [
        [("GitHub Copilot Autofix ", {"bold": True}),
         ("(since August 2024) scans, asks an AI for a fix and scans again. We do not claim that loop.", {})],
        [("Research papers ", {"bold": True}),
         ("compare ways of asking on newly written code, not on fixes to real projects.", {})],
        [("Bug trackers ", {"bold": True}), ("follow findings across scans, but use no AI.", {})],
    ], size=15, color=INK, spacing=1.08, after=12)
    text(s, 5.65, 1.95, 7.0, 0.45, "What we add", size=18, bold=True, color=GREEN)
    for i, (title, body) in enumerate((
        ("We measure which way of asking works", "9 ways of asking the AI, on the same bugs, judged by the same checks"),
        ("We check the developer's prompt", "if a safety instruction is cut out, it is flagged and put back"),
        ("We don't take the AI's word", "3 checks: bug gone, nothing new, code still works"),
        ("We remember every bug", "each bug keeps its ID across commits: fixed, still open, or back again"))):
        y = 2.55 + i * 0.97
        circle(s, 5.65, y, 0.6, str(i + 1), fill=GREEN, size=16, font=HEAD)
        text(s, 6.5, y - 0.03, 6.2, 0.38, title, size=16, bold=True)
        text(s, 6.5, y + 0.36, 6.2, 0.5, body, size=14, color=GREY)
    text(s, MX, 6.6, CW, 0.3, "The full comparison table is in the appendix.", size=12, color=GREY)
    page(s, n)
    notes(s, """The closest product is Copilot Autofix, and we say so. What is new is measuring the prompt, checking the
    prompt, three independent checks on every fix, and tracking each bug across commits.""")


def slide_midsem(prs, n):
    s = new_slide(prs)
    tag(s, RECAP)
    headline(s, "Where we stood at the mid-sem review")
    by = E2_PILOT["by_strategy"]
    ratio = by["S7"][3] / by["S2"][3]
    tiles = (
        (f"{FIXTURE['detected']} / {FIXTURE['seeded']}", "planted bugs found by the scanners",
         f"{FIXTURE['findings']} issues reported in our test app; {FIXTURE['true_positive_findings']} are real", None),
        ("REJECTED", "a fake fix fooled the scanners, not our checks",
         "an emptied function hides the bug; our structure check notices", "fail"),
        (f"{E1['constituent']['flagged']} / {E1['constituent']['mutants']}",
         "removed safety parts caught by our prompt checker",
         f"and {E1['unchecked']['flagged']} false alarms on {E1['unchecked']['mutants']} harmless edits", None),
        (f"{by['S2'][0]} vs {by['S7'][0]}", "fixes verified out of 10: bug-specific advice vs our full prompt",
         f"a pilot of {E2_PILOT['trials']} fixes; ours used {ratio:.1f}× the tokens", None),
    )
    for i, (big, label, sub, kind) in enumerate(tiles):
        col, row = i % 2, i // 2
        stat_h(s, MX + col * 6.15, 1.95 + row * 1.68, 5.95, 1.5, big, label, sub, big_w=1.95, big_size=30,
               pill_kind=kind)
    callout(s, 5.45, [[("This raised the panel's three questions. ", {"bold": True}),
                       ("How low can the token cost go? Does a fix break the code around it? What can others build "
                        "on?", {})]], h=1.05, fill=GREEN_TINT, size=16)
    page(s, n)
    notes(s, """Mid-sem in one slide. The pilot result was honest: our full prompt did not win, and it was expensive.
    That, and the panel's questions, set the work for the last two weeks.""")


# --------------------------------------------------------------------------- part 2 · since mid-sem
def slide_divider(prs, n):
    s = new_slide(prs, dark=True)
    tag(s, SINCE)
    text(s, MX, 1.0, CW, 1.4, "Three questions from the panel, and what we built to answer them", size=36,
         bold=True, font=HEAD, color=WHITE, spacing=1.0)
    for i, (q, a) in enumerate((("How low can the token cost go?", "a ladder of shorter prompts, measured"),
                                ("Does fixing one function break the code around it?",
                                 "four safeguards, and evidence from 90 fixes"),
                                ("What can others build on?", "our prompt checker, published as an open library"))):
        x = MX + i * 4.1
        card(s, x, 2.75, 3.9, 2.25, INK2)
        circle(s, x + 0.3, 3.0, 0.55, str(i + 1), fill=GREEN, size=16, font=HEAD)
        text(s, x + 0.3, 3.72, 3.3, 0.7, q, size=17, bold=True, color=WHITE, spacing=1.0)
        text(s, x + 0.3, 4.42, 3.3, 0.5, a, size=14, color=PALE, spacing=1.0)
    line = s.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(1.0), Inches(5.86), Inches(10.15), Inches(5.86))
    line.line.color.rgb = SOFT
    line.line.width = Pt(1.5)
    for i, (date, what) in enumerate((("30 Oct", "mid-sem review: the three questions"),
                                      ("12 Nov", "shorter prompts measured, checker published, tool hardened"),
                                      ("13 Nov", "a shared server for whole teams"),
                                      ("15 Nov", "final submission"))):
        x = 0.9 + i * 3.05
        circle(s, x, 5.75, 0.22, "", fill=GREEN)
        text(s, x, 6.08, 2.85, 0.32, date, size=14, bold=True, color=WHITE)
        text(s, x, 6.4, 2.85, 0.6, what, size=12.5, color=PALE, spacing=1.0)
    page(s, n, dark=True)
    notes(s, """Everything from here on is new since the mid-sem review: one part per panel question, then a team
    server, the security of our own tool, and the new demo video.""")


def slide_tokens(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "A short prompt: same fixes, a sixth of the tokens")
    subline(s, "Tokens are the word-pieces an AI model reads and charges for. Same local AI model, same 10 bugs, "
               "same checks.")
    order = ("S7", "S7a", "S2", "S7m")
    per, by = E5["tokens_per_trial"], E5["by_strategy"]
    cats = [f"{LADDER[k]} · {by[k][0]}/10 fixed" for k in order]
    bar_chart(s, 0.45, 2.1, 7.95, 3.75, cats, [per[k] for k in order],
              [SOFT, SOFT, SOFT, GREEN])
    text(s, MX, 5.82, 7.6, 0.3, "Tokens per fix attempt, whole conversation", size=12, color=GREY)
    for i, (big, label, sub) in enumerate((
        (f"{by['S7m'][0]} / 10", "fixes verified with the minimal prompt", f"the full prompt: {by['S7'][0]} / 10"),
        (f"{per['S7'] / per['S7m']:.1f}×", "fewer tokens than the full prompt",
         f"{per['S7m']} vs {per['S7']:,} per attempt"),
        ("0", "tokens used by our tool", "prompts come from templates"))):
        stat_h(s, 8.65, 2.1 + i * 1.27, 4.08, 1.12, big, label, sub, big_w=1.5, big_size=28)
    callout(s, 6.15, "The review rounds were the cost: each one sends the whole conversation again. Every shorter "
                     "prompt still passes our checker, so nothing that keeps it safe was cut.", h=0.78, size=14)
    page(s, n)
    notes(s, f"""The panel asked how low token use can go. We built two smaller versions of our prompt and measured them
    with the same local model, bugs and checks. The minimal prompt verified {by['S7m'][0]} of 10 at about {per['S7m']}
    tokens per attempt; the full prompt {by['S7'][0]} of 10 at about {per['S7']:,}. Pilot scale: one model, 10 bugs,
    one try each.""")


def slide_token_parts(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "Where the tokens go, and the part we cannot cut")
    st = E5_STATIC
    subline(s, f"Typical number of tokens the developer pastes, measured over our {st['findings']} real findings.")
    code = st["code_block"][1]
    scale = 7.4 / st["typed"]["S7"][1]
    for i, (key, name, sub, color) in enumerate((
        ("S7", "Full prompt", "3 messages: explain, fix, 2 review rounds", SOFT),
        ("S7a", "One message", "the explanation and the fix request", RGBColor(0x7F, 0x9C, 0xA2)),
        ("S7m", "Minimal prompt", f"{round(st['s7m_saving_vs_s7a'] * 100)}% shorter than one message", GREEN))):
        y = 2.2 + i * 0.98
        text(s, MX, y, 2.75, 0.75, [[(name, {"bold": True, "size": 16})], [(sub, {"size": 12, "color": GREY})]],
             anchor=MSO_ANCHOR.MIDDLE, spacing=1.0, after=2)
        tokens = st["typed"][key][1]
        inside(shape(s, MSO_SHAPE.RECTANGLE, 3.5, y + 0.08, code * scale, 0.6, INK), "code", size=12)
        shape(s, MSO_SHAPE.RECTANGLE, 3.5 + code * scale, y + 0.08, (tokens - code) * scale, 0.6, color)
        text(s, 3.5 + tokens * scale + 0.15, y, 1.6, 0.75, f"~{tokens}", size=18, bold=True, font=HEAD,
             anchor=MSO_ANCHOR.MIDDLE)
    shape(s, MSO_SHAPE.RECTANGLE, 3.5, 5.18, 0.22, 0.22, INK)
    text(s, 3.82, 5.12, 4.4, 0.35, f"the code to fix: about {code} tokens, cannot be cut", size=13, color=GREY)
    shape(s, MSO_SHAPE.RECTANGLE, 8.35, 5.18, 0.22, 0.22, SOFT)
    text(s, 8.67, 5.12, 4.0, 0.35, "the request around the code", size=13, color=GREY)
    card(s, MX, 5.62, 5.95, 1.25, GREEN_TINT)
    text(s, MX + 0.3, 5.72, 5.35, 1.1, [[("What the minimal prompt keeps", {"bold": True, "color": GREEN})],
                                        [("what and where · the risky input · when it may run · how to fix it · "
                                          "change nothing else", {})]], size=14, spacing=1.05, after=4)
    card(s, 6.75, 5.62, 5.95, 1.25)
    text(s, 7.05, 5.72, 5.35, 1.1, [[("What it drops", {"bold": True})],
                                    [("the long explanation and the review rounds; the checker confirms no safety "
                                      "part was lost", {})]], size=14, spacing=1.05, after=4)
    page(s, n)
    notes(s, """The code itself is the floor, about 54 tokens for a typical finding. Everything else is the request.
    The minimal prompt keeps the five safety parts the checker requires and drops the long explanation and the
    review rounds.""")


def slide_safeguards(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "A fix is judged against the whole app")
    subline(s, "The panel asked: if we fix one function, can the code that uses it break? Four safeguards, each "
               "catching what the one before can miss.")
    for i, (title, body) in enumerate((
        ("The prompt sets the rules", "keep the function's name, inputs and behaviour; change nothing else"),
        ("The whole app is scanned again", "a new weakness anywhere in the app means the fix is rejected"),
        ("The structure is compared", "same inputs and routes, not emptied, the file still loads"),
        ("The app's own tests run", "on a copy of the fixed app, including the code that calls the fix"))):
        y = 2.3 + i * 0.95
        circle(s, MX, y, 0.62, str(i + 1), fill=INK, size=17, font=HEAD)
        text(s, MX + 0.85, y - 0.03, 6.3, 0.38, title, size=16, bold=True)
        text(s, MX + 0.85, y + 0.36, 6.3, 0.5, body, size=14, color=GREY)
    card(s, 8.0, 2.3, 4.73, 3.55)
    text(s, 8.3, 2.45, 4.2, 0.4, "Where each safeguard runs", size=16, bold=True)
    text(s, 10.35, 2.95, 1.1, 0.3, "Developer", size=12.5, bold=True, color=GREY, align=PP_ALIGN.CENTER)
    text(s, 11.45, 2.95, 1.1, 0.3, "Lab", size=12.5, bold=True, color=GREY, align=PP_ALIGN.CENTER)
    for i, (name, dev) in enumerate((("Prompt rules", True), ("Scan again", True), ("Structure check", True),
                                     ("App's own tests", False))):
        y = 3.4 + i * 0.58
        text(s, 8.3, y, 2.0, 0.4, name, size=14, anchor=MSO_ANCHOR.MIDDLE)
        for j, on in enumerate((dev, True)):
            text(s, 10.35 + j * 1.1, y, 1.1, 0.4, "✓" if on else "–", size=18, bold=True,
                 color=GREEN if on else GREY, align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    text(s, 8.0, 6.0, 4.73, 0.8, "Developer mode never runs the code it scans: that code is untrusted. Its tests "
                                 "belong in the developer's own build pipeline.", size=12.5, color=GREY, spacing=1.05)
    page(s, n)
    notes(s, """Four safeguards. The first three also run in developer mode; the app's own tests run only in lab mode,
    on a copy, because the scanned code is untrusted. Details are in docs/related_functions.md.""")


def slide_callers(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "No accepted fix broke the code that calls it")
    r = RELATED
    subline(s, f"Evidence from our {E2_PILOT['trials']} recorded lab fixes.")
    inside(shape(s, MSO_SHAPE.ROUNDED_RECTANGLE, 1.75, 2.2, 3.2, 0.8, INK), "Sign-up page  (calls both helpers)",
           size=15)
    arrow(s, 2.35, 3.08, 0.32, 0.5, down=True)
    arrow(s, 4.05, 3.08, 0.32, 0.5, down=True)
    for x, name in ((0.75, "Password hashing"), (3.55, "Reset-token maker")):
        inside(shape(s, MSO_SHAPE.ROUNDED_RECTANGLE, x, 3.68, 2.6, 0.8, GREEN_TINT), name, size=15, color=INK)
    text(s, MX, 4.7, 5.8, 1.0,
         f"We asked for fixes to the two helpers {r['trials_on_helpers_with_callers']} times. "
         f"{r['verified_on_helpers_with_callers']} fixes were accepted, and each was checked against the sign-up "
         "page that calls them.", size=14, color=INK, spacing=1.05)
    for i, (big, label, sub, color) in enumerate((
        (f"{r['caller_broken_by_a_verified_fix']} / {r['verified_on_helpers_with_callers']}",
         "accepted fixes broke the sign-up page", "the code around the fix kept working", GREEN),
        (f"{r['scanner_clean_but_behaviour_broken']}", "fixes passed every scanner but broke the app",
         "our behaviour tests caught all of them", CORAL),
        (f"{sum(r['module_wide_breaks'].values())}", "one-function edits broke the whole file",
         f"all rejected; {r['module_wide_breaks']['file_no_longer_parses']} without running any code", CORAL))):
        stat_h(s, 6.75, 2.1 + i * 1.18, 5.98, 1.05, big, label, sub, color=color, big_w=1.55, big_size=28)
    callout(s, 5.85, [[("What we don't claim: ", {"bold": True}),
                       ("a change in what a function returns is caught only by running tests, and a fix that needs "
                        "several functions changed is reported, never silently accepted.", {})]], h=0.95, size=14)
    page(s, n)
    notes(s, """No verified fix broke the function that calls the fixed helper. Seven fixes that every scanner accepted
    broke behaviour and were caught by the app's tests; four edits broke the whole file and were rejected.""")


def slide_library(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "Our prompt checker is now a free, open library")
    subline(s, "At mid-sem we said others could build on our prompt checker. It is now published on its own, and "
               "our tool uses the same code.")
    for i, (title, body) in enumerate((("13 rules", "safety parts, clean prompts, token budget"),
                                       ("Fix-its", "puts the missing sentences back"),
                                       ("Extend it", "add rules or bug types without editing it"),
                                       ("Command line", "can stop a build when a prompt fails"),
                                       ("A benchmark", "288 edited prompts reproduce our results"),
                                       ("Open problems", "a list of where to start next"))):
        col, row = i % 3, i // 3
        x, y = MX + col * 2.78, 2.2 + row * 1.45
        card(s, x, y, 2.62, 1.3)
        text(s, x + 0.25, y + 0.18, 2.15, 0.4, title, size=17, bold=True, color=GREEN)
        text(s, x + 0.25, y + 0.6, 2.15, 0.65, body, size=13.5, color=GREY, spacing=1.02)
    card(s, 9.05, 2.2, 3.68, 2.75, INK)
    text(s, 9.3, 2.38, 3.2, 0.3, "Install in one line", size=13, bold=True, color=PALE)
    text(s, 9.3, 2.75, 3.2, 1.0, ["pip install git+https://", "github.com/Anvesh-Dangeti/", "secure-prompt-lint"],
         size=12.5, font=MONO, color=WHITE, spacing=1.0)
    text(s, 9.3, 3.85, 3.2, 1.0, ["MIT licence · free", "needs no other packages", "Python 3.10 or newer"],
         size=13, color=PALE, spacing=1.05)
    card(s, MX, 5.35, CW, 1.0, GREEN_TINT)
    text(s, MX + 0.3, 5.35, CW - 0.6, 1.0,
         [[(LIBRARY_URL, {"font": HEAD, "bold": True, "size": 22, "color": GREEN}),
           ("   open to anyone who wants to continue this research", {"size": 15})]], anchor=MSO_ANCHOR.MIDDLE)
    page(s, n)
    notes(s, f"""At mid-sem we said the checker would be what others can build on. It is now a stand-alone library at
    {LIBRARY_URL}; our tool imports it, so there is one copy of that code. It ships a benchmark that reproduces our
    numbers and a list of open research problems.""")


def slide_reproduce(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "Anyone can re-run our checker results")
    subline(s, "The checker reads a prompt before it is sent to any AI, and says what is missing.")
    card(s, MX, 2.2, 7.1, 2.75, INK)
    lines = (("$ secure-prompt-lint prompt.txt --cwe CWE-78 ...", PALE, False),
             ("FAIL   20%   ~52 tokens        exit 1", CORAL, True),
             ("", PALE, False),
             ("$ secure-prompt-lint prompt.txt ... --fix -o fixed.txt", PALE, False),
             ("$ secure-prompt-lint fixed.txt ...", PALE, False),
             ("PASS  100%   ~253 tokens       exit 0", GREEN, True))
    text(s, MX + 0.35, 2.45, 6.5, 2.4, [[(line or " ", {"color": color, "bold": strong})] for line, color, strong in lines],
         size=14, font=MONO, spacing=1.15)
    text(s, MX, 5.05, 7.1, 0.4, "The one-line prompt from our demo, checked outside our tool.", size=13, color=GREY)
    c, u = E1["constituent"], E1["unchecked"]
    stat_h(s, 8.0, 2.2, 4.73, 1.3, f"{c['flagged']} / {c['mutants']}",
           "prompts with a safety part removed were caught", color=GREEN, big_w=1.95, big_size=28)
    stat_h(s, 8.0, 3.65, 4.73, 1.3, f"{u['flagged']} / {u['mutants']}", "false alarms on harmless edits",
           color=GREEN, big_w=1.95, big_size=28)
    text(s, 8.0, 5.05, 4.73, 0.7, f"{c['mutants'] + u['mutants'] + E1['controls_clean']} edited prompts in all, "
                                  "re-created with one command.", size=13, color=GREY, spacing=1.05)
    callout(s, 5.95, "No AI is involved in these numbers: the same input always gives the same result.", h=0.7,
            size=15)
    page(s, n)
    notes(s, """The one-line prompt from the demo fails with four safety parts missing; the fix-its put them back and
    it passes. The benchmark command reproduces the full experiment in a few seconds.""")


def slide_flaw(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "The pilot found a flaw in our own prompts. We fixed it")
    subline(s, "Our own checks found it, not the AI. This is why every fix is verified independently.")
    bumps = E2_PILOT["dependency_bumps_rejected"]
    card(s, MX, 2.2, 5.8, 3.25, CORAL_TINT)
    text(s, MX + 0.3, 2.38, 2.0, 0.45, "Before", size=20, bold=True, font=HEAD, color=CORAL)
    pill(s, MX + 1.75, 2.42, f"REJECTED × {bumps}", "fail", size=13)
    text(s, MX + 0.3, 3.05, 5.2, 1.4, f"For an outdated library, our prompt named only one fix version. All {bumps} "
                                      "library upgrades in the pilot stopped one version short: 5.3.1, when 5.4 was "
                                      "needed.", size=16, spacing=1.08)
    text(s, MX + 0.3, 4.5, 5.2, 0.85, [[("5.3.1", {"font": HEAD, "bold": True, "size": 36, "color": CORAL}),
                                       ("    what the AI upgraded to", {"size": 14, "color": GREY})]],
         anchor=MSO_ANCHOR.MIDDLE)
    arrow(s, 6.55, 3.62, 0.42, 0.36, color=GREEN)
    card(s, 7.1, 2.2, 5.63, 3.25, GREEN_TINT)
    text(s, 7.4, 2.38, 2.0, 0.45, "After", size=20, bold=True, font=HEAD, color=GREEN)
    pill(s, 8.6, 2.42, "VERIFIED", "pass", size=13)
    text(s, 7.4, 3.05, 5.05, 1.4, "The prompt now lists every known problem with that library and the one version "
                                  "that fixes them all. In the new run, every one of our prompt sizes verified the "
                                  "upgrade.", size=16, spacing=1.08)
    text(s, 7.4, 4.5, 5.05, 0.85, [[("5.4", {"font": HEAD, "bold": True, "size": 36, "color": GREEN}),
                                   ("    the version the prompt now names", {"size": 14, "color": GREY})]],
         anchor=MSO_ANCHOR.MIDDLE)
    callout(s, 5.75, "A small wording gap cost every upgrade. Measuring real fixes, not just reading prompts, is what "
                     "found it.", h=0.9, size=15)
    page(s, n)
    notes(s, """In the pilot every library-upgrade fix was rejected because the model upgraded to 5.3.1 when 5.4 was
    required. Our prompt quoted only the first fix version. Now it names the highest fix across all known problems,
    and every rung of our ladder verified the upgrade.""")


def slide_team_server(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "A whole team can share one server")
    subline(s, "At Review 3 the panel asked how a developer would really use the tool. Each developer runs one small "
               "command; the scanning happens on one shared server.")
    card(s, MX, 2.35, 3.75, 2.95)
    text(s, MX + 0.25, 2.5, 3.3, 0.4, "Developer's computer", size=16, bold=True)
    for i, (cmd, what) in enumerate((("spa connect", "link the project"), ("spa scan", "upload and scan"),
                                     ("spa prompt", "get a fix prompt"), ("spa verify", "check the fix"))):
        y = 3.05 + i * 0.52
        text(s, MX + 0.25, y, 1.6, 0.4, cmd, size=14, bold=True, font=MONO, anchor=MSO_ANCHOR.MIDDLE)
        text(s, MX + 1.85, y, 1.85, 0.4, what, size=13, color=GREY, anchor=MSO_ANCHOR.MIDDLE)
    text(s, 4.35, 2.95, 1.3, 0.55, ["project files", "no secrets"], size=12, color=GREY, align=PP_ALIGN.CENTER,
         spacing=1.0)
    arrow(s, 4.55, 3.55, 0.9, 0.5, color=GREEN)
    card(s, 5.65, 2.35, 3.0, 2.95, INK)
    text(s, 5.9, 2.5, 2.6, 0.4, "Shared server", size=16, bold=True, color=WHITE)
    text(s, 5.9, 3.05, 2.6, 2.1, ["4 scanners", "bug history", "prompt checker", "the 3 checks"], size=14,
         color=PALE, spacing=1.0, after=8)
    for i, words in enumerate(("Each project has its own access key; other projects see nothing",
                               "Secret files such as .env are never uploaded",
                               "The server never runs your code",
                               "Keys expire and can be withdrawn")):
        y = 2.35 + i * 0.75
        circle(s, 8.95, y + 0.05, 0.42, "✓", fill=GREEN, size=14)
        text(s, 9.55, y, 3.18, 0.7, words, size=14, spacing=1.0, anchor=MSO_ANCHOR.MIDDLE)
    callout(s, 5.7, "The same pattern teams already use for scanning services: install once, connect once, then scan "
                    "and verify from the project folder.", h=0.9, size=15)
    page(s, n)
    notes(s, """Built after the final sprint, on 13 November. The spa command is small and uses only Python's standard
    library. Each token belongs to one project; another project's token gets nothing, and a revoked token is
    refused. Details: docs/deployment.md.""")


def slide_own_security(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "We held our own tool to the same standard")
    for i, (big, label, sub, color) in enumerate((
        (str(SELF_SCAN["pip-audit"]), "vulnerable libraries", f"all {PACKAGES_AUDITED} packages checked", GREEN),
        (str(SELF_SCAN["bandit_low"]), "low-severity notes in our code", "all in the one place allowed to start "
                                                                          "programs", INK),
        (str(TESTS_AT_SUBMISSION), "automated tests", "including attacks: bad links, booby-trapped ZIP files, "
                                                       "prompt injection", GREEN),
        (str(TRUST_BOUNDARIES), "trust boundaries", "each with a control and a test", INK))):
        stat_v(s, MX + i * 3.075, 1.95, 2.9, 2.3, big, label, sub, color=color)
    for i, (title, body) in enumerate((
        ("Removed, not patched", "We retired the old dashboard: the new web interface does everything it did, and "
                                 "its library pin was blocking a security update."),
        ("The AI's answer is never trusted", "No prompt can make injection impossible, so the scanners and the "
                                             "checks decide, never the AI."))):
        x = MX + i * 6.15
        card(s, x, 4.45, 5.95, 1.35)
        text(s, x + 0.3, 4.55, 5.35, 1.2, [[(title, {"bold": True, "size": 16})], [(body, {})]], size=14,
             spacing=1.05, after=4)
    callout(s, 6.0, "A tool that reads untrusted code is a target itself: it needs a key, serves only this computer "
                    "or a keyed team server, and never runs the code it scans.", h=0.85, size=14)
    page(s, n)
    notes(s, """Our four scanners over our own code leave only 3 low-severity notes, all in the one wrapper that starts
    the scanners. pip-audit over every installed package finds nothing. The threat model has ten boundaries, each
    with a test. Full model: docs/threat_model.md.""")


def slide_demo(prs, n):
    s = new_slide(prs)
    tag(s, SINCE)
    headline(s, "Demo: one developer's Friday release")
    card(s, MX, 1.95, 5.45, 1.32)
    text(s, MX + 0.3, 1.95, 4.85, 1.32, "Rahul must ship helpdesk-portal tomorrow. The team rule: nothing ships "
                                        "without a clean security scan.", size=15, anchor=MSO_ANCHOR.MIDDLE,
         spacing=1.05)
    text(s, MX, 3.35, 5.45, 0.35, f"helpdesk-portal is our test app with {FIXTURE['seeded']} planted bugs, under a "
                                  "realistic name.", size=12, color=GREY)
    picture(s, "midsem_overview.png", MX, 3.78, 5.45, crop=(0.04, 0.0, 0.08, 0.35))
    for i, (title, body) in enumerate((
        ("Scan", f"4 scanners find {FIXTURE['findings']} issues; a false alarm is marked, not deleted"),
        ("Ask in three sizes", "full, one message, minimal: all pass the checker"),
        ("Shorten it", "the checker says FAIL; one click puts the parts back"),
        ("The checker on its own", "the open library, in a terminal"),
        ("Fake fix, then real fix", "scanners quiet but REJECTED; then VERIFIED"),
        ("A fix that adds a risk elsewhere", "REJECTED; later the bug comes back after a merge"))):
        y = 1.95 + i * 0.7
        circle(s, 6.4, y + 0.05, 0.48, str(i + 1), fill=GREEN, size=14, font=HEAD)
        text(s, 7.05, y, 5.68, 0.34, title, size=15, bold=True)
        text(s, 7.05, y + 0.32, 5.68, 0.34, body, size=13, color=GREY)
    callout(s, 6.25, "Recorded video, about 8½ minutes. Every number in it was measured twice and can be "
                     "reproduced.", h=0.62, size=14)
    page(s, n)
    notes(s, """Play the video now. Rahul and helpdesk-portal are a story; the app is our seeded test application, and
    the video caption says so. If the video fails, the backup slides in the appendix walk the same steps.""")


# --------------------------------------------------------------------------- part 3 · wrap-up
REQUIREMENTS = (
    ("Scan with open-source scanners", "Semgrep, Bandit, Gitleaks, pip-audit"),
    ("Identify weaknesses", f"{FIXTURE['detected']} / {FIXTURE['seeded']} planted bugs found"),
    ("Map to OWASP, CWE, CVE", "every finding; CVE only for libraries"),
    ("A fix prompt for each finding", "11 ways of asking; ours always pass"),
    ("Give it to Copilot or another AI", "copy and paste; no plugin needed"),
    ("Apply the secure change", "the developer's AI, or ours in lab mode"),
    ("Re-run the scanners", "the same scanners, independently"),
    ("Check the bug is gone", "check 1, never decided by the AI"),
    ("Check nothing new was added", "check 2, across the whole app"),
    ("Verification and dashboard", "3 checks, web dashboard, full history"),
    ("Test on OWASP cases and apps", "our seeded app + a public vulnerable app"),
    ("GitHub with regular check-ins", "commits per phase; the library public too"),
)


def slide_requirements(prs, n):
    s = new_slide(prs)
    tag(s, WRAP)
    headline(s, "All 12 project requirements are met")
    for i, (req, how) in enumerate(REQUIREMENTS):
        col, row = i % 4, i // 4
        x, y = MX + col * 3.06, 1.95 + row * 1.33
        card(s, x, y, 2.92, 1.2)
        circle(s, x + 0.2, y + 0.2, 0.38, "✓", fill=GREEN, size=13)
        text(s, x + 0.7, y + 0.14, 2.1, 0.98, [[(req, {"bold": True, "size": 14})],
                                              [(how, {"size": 12, "color": GREY})]], spacing=0.98, after=3)
    callout(s, 6.0, "Beyond the brief: shorter prompts measured, an open checker library, a team server, and a "
                    "structure check that catches fake fixes every scanner accepts.", h=0.85, fill=GREEN_TINT, size=15)
    page(s, n)
    notes(s, "The twelve requirements from the project brief, and where each is met.")


def slide_learned(prs, n):
    s = new_slide(prs)
    tag(s, WRAP)
    headline(s, "Four things we learned")
    for i, (title, body) in enumerate((
        ("How you ask matters, but shorter can be as good",
         "the minimal prompt matched the best result with a sixth of the full prompt's tokens"),
        ("Scanners alone can be fooled",
         f"{RELATED['scanner_clean_but_behaviour_broken']} fixes passed every scanner and still broke the app; "
         "structure and behaviour checks caught them"),
        ("A prompt can be checked before it is sent",
         "every removed safety part was caught, with no false alarms"),
        ("The AI should never grade its own work",
         "our verdicts come only from scanning again and checking; that is how we found our own prompt flaw"))):
        col, row = i % 2, i // 2
        x, y = MX + col * 6.15, 1.95 + row * 2.0
        card(s, x, y, 5.95, 1.8)
        text(s, x + 0.3, y + 0.2, 0.75, 0.9, str(i + 1), size=40, bold=True, font=HEAD, color=GREEN)
        text(s, x + 1.15, y + 0.25, 4.55, 1.45, [[(title, {"bold": True, "size": 18})],
                                                 [(body, {"size": 14, "color": GREY})]], spacing=1.03, after=6)
    callout(s, 6.05, [[("The scanners and the checks decide whether a fix worked. The AI never does.",
                        {"bold": True})]], h=0.75, size=16)
    page(s, n)
    notes(s, "Four lessons, each backed by a number earlier in the deck.")


def slide_limits(prs, n):
    s = new_slide(prs)
    tag(s, WRAP)
    headline(s, "What it cannot do yet, and what comes next")
    for col, (title, mark, fill, items) in enumerate((
        ("Limits we state", "!", CORAL, ("One test app and one small local AI model: differences, not a ranking",
                                          "A weakness no scanner detects cannot be found or verified",
                                          "Developer mode never runs the code, so behaviour is checked in lab mode",
                                          "The checker matches patterns; it does not understand grammar",
                                          "Python only")),
        ("Next steps", "→", GREEN, ("More apps and bugs, several models, repeated runs",
                                     "Check that a fix keeps what its callers expect",
                                     "Measure which checker rules predict a verified fix",
                                     "Run lab fixes in an isolated container",
                                     "More languages, through the library's extension points")))):
        x = MX + col * 6.15
        card(s, x, 1.95, 5.95, 4.0)
        text(s, x + 0.3, 2.1, 5.3, 0.45, title, size=18, bold=True)
        for i, item in enumerate(items):
            y = 2.7 + i * 0.64
            circle(s, x + 0.3, y + 0.04, 0.4, mark, fill=fill, size=13)
            text(s, x + 0.9, y, 4.8, 0.6, item, size=15, spacing=1.0, anchor=MSO_ANCHOR.MIDDLE)
    callout(s, 6.15, "Every limit is written down in the report and the repository, next to the result it affects.",
            h=0.66, size=14)
    page(s, n)
    notes(s, "Close on the limits we state openly and on the next steps. Then thank the panel.")


def slide_thanks(prs, n):
    s = new_slide(prs, dark=True)
    text(s, 0.8, 1.7, 10.0, 1.2, "Thank you", size=56, bold=True, font=HEAD, color=WHITE)
    text(s, 0.8, 2.95, 10.0, 0.5, "Questions welcome", size=22, color=PALE)
    text(s, 0.8, 4.0, 11.5, 1.0, [[("Code:  ", {"bold": True, "color": WHITE}), (REPO_URL, {})],
                                  [("Prompt checker library:  ", {"bold": True, "color": WHITE}), (LIBRARY_URL, {})]],
         size=15, color=PALE, spacing=1.1, after=6)
    for i, (name, roll) in enumerate(TEAM):
        x = 0.8 + i * 3.4
        text(s, x, 6.2, 3.3, 0.35, name, size=15, bold=True, color=WHITE)
        text(s, x, 6.56, 3.3, 0.3, roll, size=12, color=PALE)
    notes(s, "Appendix follows: words we use, full tables, prepared answers, the team, and the demo backup.")


# --------------------------------------------------------------------------- appendix
def slide_glossary(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "Words we use")
    terms = (("CWE", "a standard ID for a type of bug, e.g. CWE-89 is SQL injection"),
             ("OWASP Top 10", "the ten main web-application risk groups, e.g. A03 Injection"),
             ("CVE", "the ID of a known problem in one version of a library"),
             ("Scanner", "a free tool that reads code and reports likely bugs"),
             ("Prompt", "the request a developer types into an AI assistant"),
             ("Token", "a word-piece; AI models read, count and charge by tokens"),
             ("Prompt checker", "checks a prompt still has its safety parts; also a library"),
             ("Fix-it", "a missing sentence the checker can put back"),
             ("Bug ID", "identifies a bug by rule, file and code, not line number"),
             ("Bug states", "new · still open · fixed · came back · false alarm (kept)"),
             ("The 3 checks", "bug gone · nothing new at the same or higher severity · code still works"),
             ("Developer / lab mode", "the developer's AI writes the fix / a local model, for experiments"),
             ("Shared server", "one server for a team; developers connect with the spa command"),
             ("Prompt injection", "text hidden in code that tries to give the AI new instructions"))
    for i, (term, meaning) in enumerate(terms):
        col, row = i // 7, i % 7
        x, y = MX + col * 6.15, 1.95 + row * 0.67
        text(s, x, y, 2.1, 0.6, term, size=14, bold=True, color=GREEN)
        text(s, x + 2.15, y, 3.8, 0.62, meaning, size=13, color=INK, spacing=1.0)
    page(s, n)
    notes(s, "Appendix. Use it if a term comes up in questions.")


def slide_tools(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "Existing tools each do part of the job")
    yes, part, no = "✓", "~", "✗"
    table(s, MX, 1.95, [4.0, 1.35, 1.75, 1.35, 1.3, 1.1, 1.25],
          ["What it does", "Copilot Autofix", "Snyk / Semgrep AI", "DefectDojo", "Backslash rules", "Plain ChatGPT",
           "Our tool"],
          [["Finds bugs with real security scanners", yes, yes, yes, part, no, yes],
           ["Checks the fix again with the scanners", part, part, no, no, no, yes],
           ["Checks the fix did not break the code", no, no, no, no, no, yes],
           ["Follows each bug across commits", no, no, yes, no, no, yes],
           ["Tests and checks the prompt itself", no, no, no, no, no, yes]],
          row_h=0.62, size=15, header_size=12.5, highlight_col=6)
    text(s, MX, 5.85, CW, 0.3, f"{yes}  yes        {part}  partly        {no}  no", size=13, color=GREY)
    page(s, n)
    notes(s, """Copilot Autofix is the closest: it finds, fixes and re-scans, but hides its prompt and does not check that
    the code still works. DefectDojo tracks findings but has no AI. Backslash sells a rules file nobody re-checks.""")


def slide_pilot(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "All nine ways of asking, with their cost")
    by = E2_PILOT["by_strategy"]
    rows = [[WAYS[k], f"{v} / {a}", f"{tok:,}"] for k, (v, a, _rate, tok) in by.items()]
    table(s, MX, 1.95, [6.5, 2.8, 2.8], ["Way of asking", "Fixes passing all 3 checks", "Tokens for 10 fixes"], rows,
          row_h=0.42, size=13, bold_rows=(list(by).index("S2"), list(by).index("S7")))
    f = E2_PILOT["failed_at"]
    callout(s, 6.25, f"Where rejected fixes stopped: bug still there ×{f['1']}, structure check ×{f['3a']}, behaviour "
                     f"tests ×{f['3b']}. One local model ({E2_PILOT['model']}), temperature 0, one try per bug.",
            h=0.66, size=13)
    page(s, n)
    notes(s, f"Appendix. Model digest {E2_PILOT['digest']}, seed 42, the same checks for every way of asking.")


def slide_ladder(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "Each prompt size in full")
    st, by, per = E5_STATIC, E5["by_strategy"], E5["tokens_per_trial"]
    rows = [[LADDER[k], f"{st['passes_lint'][k]} / {st['findings']}", f"~{st['typed'][k][1]}",
             f"{by[k][0]} / {by[k][1]}", f"{per[k]:,}", f"{E5['verified_per_1k_tokens'][k]:.2f}"]
            for k in ("S7", "S7a", "S7m", "S2")]
    table(s, MX, 1.95, [3.4, 1.7, 1.9, 1.5, 1.75, 1.85],
          ["Prompt", "Passes the checker", "Tokens pasted (typical)", "Verified", "Tokens per attempt",
           "Verified per 1,000 tokens"], rows, row_h=0.56, size=14, header_size=12.5, bold_rows=(2,))
    parts = sorted(st["s7_parts"].items(), key=lambda kv: -kv[1])
    callout(s, 5.0, "Where the full prompt's first message spends its tokens (typical): "
                    + ", ".join(f"{name} {tok}" for name, tok in parts) + ".", h=0.95, size=13)
    callout(s, 6.1, f"Checker results are over our {st['findings']} real findings; verified fixes are the live run "
                    "over the 10 planted bugs. One run first hit a model-server timeout and was re-run.", h=0.78,
            size=13)
    page(s, n)
    notes(s, f"Appendix. Same model, settings and checks as the pilot ({E5['model']}, digest {E5['digest']}).")


def slide_answers(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "Questions we expect")
    paras = []
    for q, a in (
        ("If the minimal prompt is as good, why keep the long one?",
         "On our small model the review rounds bought nothing, but stronger assistants may use the explanation. "
         "Both pass the checker; the developer chooses. This is a pilot, not a ranking."),
        ("Why not run the project's own tests in developer mode?",
         "The scanned code is untrusted: running it on our side would let it do anything. Its tests belong in the "
         "developer's own build pipeline; our verdict says that check was not run."),
        ("Why publish the checker separately?",
         "So others can use and extend it without our whole tool, and reproduce our numbers with its benchmark. Our "
         "tool imports the same library."),
        ("Your own full prompt did not win the pilot. What is new?",
         "The test bench that measures ways of asking on real fixes with independent checks, the checker, and the "
         "minimal prompt, the most token-efficient way we measured."),
        ("Does the team server see our code?",
         "Only the files the developer uploads, with secret files left out. It scans them, never runs them, and "
         "each project's key sees only that project.")):
        paras.append([(q, {"bold": True, "size": 15, "color": GREEN})])
        paras.append([(a, {"size": 13.5, "color": INK})])
    text(s, MX, 1.95, CW, 4.9, paras, spacing=1.03, after=7)
    page(s, n)
    notes(s, "Appendix. Present only if asked.")


# The team, described by area. Every member has the same shape: role, then four short lines.
CONTRIBUTIONS = (
    ("Anvesh Dangeti", "EM26MTECH14009", "Architecture, prompt and verification layers",
     (("Research & design", "reviewed existing tools, shaped the scope, designed the architecture and threat model"),
      ("Build", "scanner and intake layers, the prompt layer and checker, the verification engine"),
      ("Evaluation", "the shorter prompt sizes; fixed the library-version flaw the pilot found"),
      ("Delivery", "the open checker library, the repository, review decks and reports"))),
    ("Dhananjay Kumar", "CS26MTECH13007", "Research, security testing and hardening",
     (("Research & design", "literature review of the assigned and professor-supplied papers; research gaps"),
      ("Build", "the comparison of existing tools; ways of asking grounded in the papers"),
      ("Evaluation", "attack tests for repository intake: unsafe links and malicious ZIP files"),
      ("Delivery", "security hardening of our own tool: self-scan, dependency audit, threat-model review"))),
    ("Muday Saiprakash Nayak", "EM26MTECH11001", "Test applications, web interface and evaluation",
     (("Research & design", "the seeded test app, one planted bug per bug type, and its answer key"),
      ("Build", "the web dashboard and interface; the behaviour tests used in lab mode"),
      ("Evaluation", "the checker experiment, the pilot, the token runs and the related-function evidence"),
      ("Delivery", "validation on a public vulnerable app, the recorded results, dress rehearsals"))),
)


def slide_team(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "The team, and what each of us worked on")
    for i, (name, roll, role, areas) in enumerate(CONTRIBUTIONS):
        x = MX + i * 4.1
        card(s, x, 1.95, 3.9, 4.55)
        text(s, x + 0.3, 2.1, 3.3, 0.42, name, size=18, bold=True, font=HEAD)
        text(s, x + 0.3, 2.52, 3.3, 0.3, roll, size=12, color=GREY)
        text(s, x + 0.3, 2.86, 3.3, 0.62, role, size=14, bold=True, color=GREEN, spacing=1.0)
        paras = []
        for area, words in areas:
            paras.append([(area, {"bold": True, "size": 12.5, "color": INK})])
            paras.append([(words, {"size": 12.5, "color": GREY})])
        text(s, x + 0.3, 3.55, 3.3, 2.9, paras, spacing=1.0, after=2)
    text(s, MX, 6.62, CW, 0.3, "All three of us took part in design discussions, review preparation and question "
                               "rehearsal. Details: CONTRIBUTIONS.md and the contributions document.", size=12,
         color=GREY)
    page(s, n)
    notes(s, "Appendix. Each member's areas of work, in the same form.")


def slide_backup(prs, n):
    s = new_slide(prs)
    tag(s, APPENDIX)
    headline(s, "If the video does not play")
    picture(s, "midsem_overview.png", MX, 1.95, 5.95, crop=(0.04, 0.0, 0.04, 0.35))
    picture(s, "midsem_lint.png", 6.75, 1.95, 5.95)
    picture(s, "midsem_verification.png", MX, 4.95, 7.6)
    text(s, 8.5, 4.95, 4.23, 1.7, [[("Top: ", {"bold": True}),
                                    ("the overview page, and the checker on a shortened prompt with the sentences "
                                     "that repair it.", {})],
                                   [("Bottom: ", {"bold": True}),
                                    ("the fake fix. The scanners went quiet, but the structure check rejects it.", {})]],
         size=13, color=INK, spacing=1.05, after=6)
    page(s, n)
    notes(s, "Appendix. Walk these screens if the recorded video cannot be played.")


BUILDERS = [
    slide_title,          # 1   part 1 · mid-sem recap
    slide_problem,        # 2
    slide_how,            # 3
    slide_exists,         # 4
    slide_midsem,         # 5
    slide_divider,        # 6   part 2 · since mid-sem
    slide_tokens,         # 7   panel question 1
    slide_token_parts,    # 8
    slide_safeguards,     # 9   panel question 2
    slide_callers,        # 10
    slide_library,        # 11  panel question 3
    slide_reproduce,      # 12
    slide_flaw,           # 13
    slide_team_server,    # 14
    slide_own_security,   # 15
    slide_demo,           # 16
    slide_requirements,   # 17  part 3 · wrap-up
    slide_learned,        # 18
    slide_limits,         # 19
    slide_thanks,         # 20
    slide_glossary,       # 21  appendix
    slide_tools,          # 22
    slide_pilot,          # 23
    slide_ladder,         # 24
    slide_answers,        # 25
    slide_team,           # 26
    slide_backup,         # 27
]
PRESENTED = range(2, 20)


def build(out_path: Path) -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(SLIDE_W)
    prs.slide_height = Inches(SLIDE_H)
    for n, builder in enumerate(BUILDERS, start=1):
        builder(prs, n)
    props = prs.core_properties
    props.author = props.last_modified_by = "TEAM-3"
    props.title = "Building a Prompt Assistant for Secure Coding — final review"
    props.subject = props.keywords = props.comments = ""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    return prs


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the final-review deck")
    parser.add_argument("--out", type=Path, default=ROOT.parent / "Secure_Prompt_Assistant_Final_Review.pptx")
    args = parser.parse_args()
    missing = [name for name in SCREENSHOTS if not (IMG / name).exists()]
    build(args.out)
    print(f"  built {len(BUILDERS)} slides -> {args.out}")
    if missing:
        print(f"  MISSING screenshots (placeholders used): {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
