#!/usr/bin/env python3
"""
Build the final-review deck (submission Sunday 15 November 2026).

It tells the whole project in plain language, in the style of the mid-semester
deck: every headline is the takeaway, internal codes stay off the presented
slides. Three new slides answer the panel's mid-semester questions:

* how low can the token usage go?                      -> the token ladder (E5)
* does fixing one function break the code around it?   -> the four layers and the evidence
* what can others use to continue the research?        -> the secure-prompt-lint library

The story slides that did not change are the mid-semester builders, re-used
with their section labels and page numbers adapted. Every number comes from
evaluation/recorded_results.py, which the test suite asserts. Content is
mirrored in docs/final_slides.md.

Usage:
    python scripts/build_final_deck.py
    python scripts/build_final_deck.py --out path/to/deck.pptx
"""

from __future__ import annotations

import argparse
import re
import sys
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from pptx import Presentation  # noqa: E402
from pptx.chart.data import CategoryChartData  # noqa: E402
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_TICK_LABEL_POSITION, XL_TICK_MARK  # noqa: E402
from pptx.enum.text import PP_ALIGN  # noqa: E402
from pptx.util import Inches, Pt  # noqa: E402

import build_midsem_v2_deck as v2  # noqa: E402
import build_review2_deck as base  # noqa: E402
from build_midsem_deck import TEAM, _arrow  # noqa: E402
from build_review2_deck import (  # noqa: E402
    BODY, CONTENT_W, DISPLAY, INK, MARGIN_X, MONO, NAVY, PALE, SLATE, TEAL, WHITE,
    add_slide, badge, callout, data_table, notes, textbox, write,
)
from build_review4_deck import _circles, _white_box  # noqa: E402
from evaluation.recorded_results import E1, E2_PILOT, E5, E5_STATIC, FIXTURE, RELATED, TESTS_FINAL  # noqa: E402

LIBRARY_URL = "github.com/Anvesh-Dangeti/secure-prompt-lint"
SCREENSHOTS = v2.SCREENSHOTS
IMG = v2.IMG
# Plain names for the strategies on the token ladder (no strategy ids on presented slides).
LADDER = {"S7": "Full prompt + 2 review rounds", "S7a": "One message", "S7m": "Minimal prompt",
          "S2": "Bug-specific advice"}

_PRS: list[Presentation] = []


def _number(slide) -> None:
    """Page number = the slide's actual position, so re-used builders number correctly here."""
    prs = _PRS[0]
    base.slide_number(slide, list(prs.slides).index(slide) + 1)


def _label(slide, text: str) -> None:
    base.section_label(slide, re.sub(r"^\d+ · ", "", text))


@contextmanager
def _adapted_midsem_builders():
    """While this deck is built, the re-used mid-semester builders number pages by position, drop their
    mid-semester section numbers and show the final test count. Restored afterwards, so building this deck
    never changes the mid-semester deck."""
    saved = v2.slide_number, v2.section_label, v2.TESTS
    v2.slide_number = lambda slide, _n: _number(slide)
    v2.section_label = _label
    v2.TESTS = TESTS_FINAL          # the architecture slide's footer shows the test count
    try:
        yield
    finally:
        v2.slide_number, v2.section_label, v2.TESTS = saved


def headline(slide, text):
    v2.headline(slide, text)


def _replace_notes(slide, text: str) -> None:
    slide.notes_slide.notes_text_frame.text = text.strip()


# ==========================================================================
# SLIDES
# ==========================================================================

def slide_title(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 2.05, 8.40, 0.40)
    write(tf, "SECURE SOFTWARE ENGINEERING · FINAL REVIEW", font=DISPLAY, size=13, bold=True, color=TEAL)
    tf = textbox(s, 0.70, 2.50, 8.60, 1.90)
    write(tf, "Building a Prompt Assistant", font=DISPLAY, size=40, bold=True, color=WHITE)
    write(tf, "for Secure Coding", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.45, 8.30, 1.00)
    write(tf, "We find security bugs, help the developer ask their AI assistant for a safe fix, "
              "and then check the fix ourselves.", size=17, color=PALE, line_spacing=1.2)
    for i, (name, roll, _) in enumerate(TEAM):
        x = 0.70 + i * 2.95
        tf = textbox(s, x, 6.25, 2.80, 0.36)
        write(tf, name, size=12, bold=True, color=WHITE)
        tf = textbox(s, x, 6.59, 2.80, 0.30)
        write(tf, roll, size=11, color=PALE)
    notes(s, """
TEAM-3 · final review. One sentence: "Developers ask AI assistants to fix security bugs. Our tool helps them ask
well - with as few tokens as possible - and then proves, without trusting the AI, whether the fix worked."
""")


def _bar_chart(slide, x, y, w, h, categories, values, highlight, *, number_format="#,##0", font=12.5):
    data = CategoryChartData()
    data.categories = categories
    data.add_series("value", values)
    chart = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(x), Inches(y), Inches(w), Inches(h),
                                   data).chart
    chart.has_legend = False
    chart.has_title = False
    chart.font.name = BODY
    chart.font.size = Pt(font)
    chart.font.color.rgb = INK
    plot = chart.plots[0]
    plot.gap_width = 55
    plot.vary_by_categories = False
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.font.size = Pt(13)
    labels.font.bold = True
    labels.font.color.rgb = NAVY
    labels.number_format = number_format
    labels.number_format_is_linked = False
    labels.position = XL_LABEL_POSITION.OUTSIDE_END
    for i, cat in enumerate(categories):
        fill = plot.series[0].points[i].format.fill
        fill.solid()
        fill.fore_color.rgb = TEAL if cat == highlight else NAVY
    cat_axis = chart.category_axis
    cat_axis.reverse_order = True
    cat_axis.major_tick_mark = XL_TICK_MARK.NONE
    cat_axis.format.line.fill.background()
    cat_axis.has_major_gridlines = False
    val = chart.value_axis
    val.minimum_scale = 0
    val.maximum_scale = max(values) * 1.25
    val.has_major_gridlines = False
    val.major_tick_mark = XL_TICK_MARK.NONE
    val.tick_label_position = XL_TICK_LABEL_POSITION.NONE
    val.format.line.fill.background()
    return chart


def slide_tokens(prs):
    s = add_slide(prs)
    _label(s, "Panel question 1 · How low can the tokens go?")
    headline(s, "A minimal prompt: as many fixes, a sixth of the tokens")
    order = ("S7", "S7a", "S2", "S7m")
    per = E5["tokens_per_trial"]
    tf = textbox(s, MARGIN_X, 1.85, 7.30, 0.34)
    write(tf, "Tokens per fix attempt, whole conversation (live run, local AI model)", font=DISPLAY, size=14,
          bold=True, color=NAVY)
    _bar_chart(s, 0.60, 2.22, 7.30, 3.10, [LADDER[k] for k in order], [per[k] for k in order], LADDER["S7m"])
    by = E5["by_strategy"]
    tf = textbox(s, MARGIN_X, 5.36, 7.30, 0.36)
    write(tf, "Verified, out of 10:  " + "  ·  ".join(
        f"{LADDER[k].split(' +')[0].lower()} {by[k][0]}" for k in order), size=12.5, color=SLATE)
    st = E5_STATIC
    for i, (big, title, body) in enumerate((
        (f"{by['S7m'][0]} / 10", "verified, minimal prompt",
         f"the full prompt: {by['S7'][0]} / 10, at {per['S7'] / per['S7m']:.1f}× the tokens"),
        (f"~{st['typed']['S7m'][1]}", "tokens pasted (typical)",
         f"one message; the full prompt is ~{st['typed']['S7'][1]} over three"),
        (f"~{st['code_block'][1]}", "tokens of code: the floor",
         "the code to repair cannot be cut; everything else is the request"),
        ("0", "tokens spent by our tool", "it writes the prompt from templates; no AI runs in it"),
    )):
        v2._stat(s, 8.20, 1.92 + i * 1.03, 4.50, big, title, body, big_w=1.30, big_size=22)
    callout(s, "The review rounds are where the tokens go: each one re-sends the whole conversation. Every shorter "
               "prompt still passes our checker, so nothing that makes it safe was cut.",
            y=5.90, h=0.92, size=13)
    _number(s)
    notes(s, f"""
The panel asked how low the token usage can go. We built two smaller versions of our prompt and measured them
with the same local model, bugs and checks: one message without the review rounds, and the minimal prompt that
keeps only what our checker requires. The minimal prompt verified {by['S7m'][0]}/10 at about {per['S7m']} tokens per
attempt; the full one {by['S7'][0]}/10 at about {per['S7']:,}. Pilot scale: one model, 10 bugs, one try each.
Likely question: "Then why keep the full prompt?" - it is still there for weaker assistants; the developer chooses.
""")


def slide_callers(prs):
    s = add_slide(prs)
    _label(s, "Panel question 2 · Does a fix break the code around it?")
    headline(s, "A fix is judged across the whole app")
    layers = (("The prompt fixes the contract", "keep the function's name and behaviour; change nothing else"),
              ("The whole app is rescanned", "a new weakness anywhere else means the fix is rejected"),
              ("The structure is checked", "same inputs and routes, not emptied, file still parses: callers "
                                           "keep working"),
              ("The app's own tests run", "on a copy of the fixed app (lab mode), including the callers"))
    for i, (title, body) in enumerate(layers):
        v2._step(s, 0.60, 1.95 + i * 0.86, 6.30, str(i + 1), title, body)
    r = RELATED
    for i, (big, title, body) in enumerate((
        (f"0 / {r['verified_on_helpers_with_callers']}", "verified fixes broke a caller",
         "fixes to two helpers that the register page calls"),
        (f"{r['scanner_clean_but_behaviour_broken']}", "fixes fooled every scanner",
         "but broke the app; the tests caught them"),
        (f"{sum(r['module_wide_breaks'].values())}", "one-function edits broke the whole file",
         "all rejected; two were caught without running any code"),
    )):
        v2._stat(s, 7.25, 1.98 + i * 1.12, 5.45, big, title, body, big_w=1.35, big_size=24)
    callout(s, "What we do not claim: a change in what a return value means is only caught by running tests, and a "
               "fix that needs several functions changed is reported, never silently accepted.",
            emphasis=True, y=5.62, h=0.92, size=13)
    _number(s)
    notes(s, """
The panel asked whether fixing one function breaks related functions or workflows. Four layers protect them;
the first three also run in developer mode. Evidence from our 90 recorded lab fixes: no verified fix broke a
function that calls the fixed one; 7 fixes that every scanner accepted broke behaviour and were caught; 4 edits that
broke the whole file were rejected. Details: docs/related_functions.md.
Likely question: "Why not run the tests in developer mode too?" - the repository is untrusted input; running it is
the developer's own CI, and our verdict says the behaviour check was not run.
""")


def slide_library(prs):
    s = add_slide(prs)
    _label(s, "Panel question 3 · What can others build on?")
    headline(s, "Our prompt checker is now an open library")
    items = (("13 rules", "safety parts, prompt hygiene, token budget"),
             ("Fix-its", "put the missing sentences back"),
             ("Extend it", "add rules or new bug types without editing it"),
             ("Command line", "exit codes can block a CI job"),
             ("A benchmark", "288 edited prompts reproduce our numbers"),
             ("Open problems", "a list of where to start next"))
    for i, (title, body) in enumerate(items):
        col, row = divmod(i, 3)
        x, y = 0.60 + col * 2.95, 1.90 + row * 1.12
        v2._titled_box(s, x, y, 2.80, 1.00, title, body, title_size=14, body_size=12)
    tf = textbox(s, 6.70, 1.86, 6.00, 0.34)
    write(tf, "The one-line prompt from the demo, checked in a terminal", font=DISPLAY, size=13.5, bold=True,
          color=NAVY)
    shp = _white_box(s, 6.70, 2.24, 6.00, 2.55)
    shp.fill.fore_color.rgb = WHITE
    tf = textbox(s, 6.90, 2.38, 5.65, 2.30)
    for line, strong in (("$ secure-prompt-lint prompt.txt --cwe CWE-78 ...", False),
                         ("FAIL  ...  ~52 tokens                exit 1", True),
                         ("", False),
                         ("$ secure-prompt-lint prompt.txt ... --fix -o fixed.txt", False),
                         ("$ secure-prompt-lint fixed.txt ...", False),
                         ("PASS  ...  ~253 tokens               exit 0", True)):
        write(tf, line or " ", font=MONO, size=11.5, color=NAVY if strong else SLATE, bold=strong,
              space_after=0, line_spacing=1.05)
    v2._titled_box(s, 6.70, 4.95, 6.00, 0.95, "Open source, free, no dependencies",
                   f"{LIBRARY_URL} · MIT licence · Python 3.10+", body_size=12.5)
    c = E1["constituent"]
    u = E1["unchecked"]
    callout(s, f"On {c['mutants'] + u['mutants'] + 24} edited prompts, every prompt that lost a safety part was "
               f"flagged ({c['flagged']} / {c['mutants']}) and nothing else was ({u['flagged']} / {u['mutants']} "
               "false alarms). Anyone can re-run this with one command.",
            emphasis=True, y=6.08, h=0.80, size=13)
    _number(s)
    notes(s, f"""
At mid-sem we said the checker would be our contribution others can build on. It is now a stand-alone library,
published at {LIBRARY_URL}, and our tool uses it as its single copy of that code. It ships the benchmark that
reproduces our numbers and a RESEARCH file with the open problems: a real grammar parser, whether each rule
predicts a verified fix, more languages and bug types.
""")


def slide_own_security(prs):
    s = add_slide(prs)
    _label(s, "Security of our own tool")
    headline(s, "We checked our own tool with its own scanners")
    for i, (big, title, body) in enumerate((
        ("0", "libraries with known vulnerabilities", "all 35 packages of the app, checked with pip-audit"),
        ("3", "low-severity notes in our code", "all in the one place allowed to start programs"),
        (f"{TESTS_FINAL}", "automated tests", "including attack tests: unsafe links, malicious archives, "
                                              "injected prompts, web attacks"),
        ("10", "trust boundaries", "each with a control and a test"),
    )):
        col, row = divmod(i, 2)
        v2._stat(s, 0.60 + col * 6.20, 1.95 + row * 1.25, 5.90, big, title, body, big_w=1.30, big_size=26)
    v2._titled_box(s, 0.60, 4.55, 5.90, 1.30, "Removed, not patched",
                   "We retired our old dashboard once the new web interface did everything it did. Its library "
                   "pin had blocked a security update.", body_size=12.5)
    v2._titled_box(s, 6.80, 4.55, 5.90, 1.30, "Stated, not hidden",
                   "No prompt can make injection impossible, so the AI's answer is never trusted: the scanners "
                   "and checks decide.", body_size=12.5)
    callout(s, "A tool that scans untrusted code is itself a target: it only serves this computer, needs a key, and "
               "never runs the code it scans.", y=6.08, h=0.78, size=13)
    _number(s)
    notes(s, """
Phase 9 hardening. Our four scanners over our own code: only 3 low-severity notes, all in the subprocess wrapper.
pip-audit over every installed package: none with a known vulnerability. Retiring the old Streamlit dashboard
removed a pin that blocked the Pillow security update. Full model: docs/threat_model.md.
""")


def slide_demo(prs):
    s = add_slide(prs)
    _label(s, "Demo")
    headline(s, "Demo: one developer's Friday release")
    v2._titled_box(s, 0.60, 1.85, 5.30, 1.42, "The story",
                   "Rahul must ship helpdesk-portal tomorrow. The team rule: nothing ships without a clean "
                   "security scan.", body_size=13.5)
    tf = textbox(s, 0.60, 3.36, 5.30, 0.30)
    write(tf, f"helpdesk-portal is our test app with {FIXTURE['seeded']} planted bugs, under a realistic name.",
          size=11.5, color=SLATE)
    v2.picture(s, "midsem_overview.png", 0.60, 3.78, 5.30, crop=(0.04, 0.0, 0.08, 0.35))
    for i, (title, body) in enumerate((
        ("Scan", f"4 scanners find {FIXTURE['findings']} issues; a false alarm is marked, not deleted"),
        ("Ask, in three sizes", "full, one message, minimal: all pass the checker"),
        ("Shorten it", "the checker says FAIL; one click puts the parts back"),
        ("The checker on its own", "the open library, in a terminal"),
        ("Fake fix, then real fix", "scanners quiet but REJECTED; then VERIFIED"),
        ("A fix that adds a risk elsewhere", "REJECTED, then the bug comes back after a merge"),
    )):
        v2._step(s, 6.35, 1.90 + i * 0.70, 6.35, str(i + 1), title, body)
    callout(s, "Recorded video, about 8½ minutes, run on our own test app. Every number in it was measured twice "
               "and can be reproduced.", emphasis=True, y=6.32, h=0.56, size=13.5)
    _number(s)
    notes(s, """
Play the video now. Rahul and helpdesk-portal are a story; the app is our seeded test application, and the video
caption says so. The new scenes answer the panel: three prompt sizes (tokens), the checker as a library (others can
build on it), and a fix rejected for a new risk elsewhere in the app (code around the fix).
If the video fails: the demo backup slides in the appendix walk the same steps.
""")


REQUIREMENTS = (
    ("Scan with open-source scanners", "Semgrep, Bandit, Gitleaks, pip-audit"),
    ("Identify weaknesses", f"{FIXTURE['detected']} / {FIXTURE['seeded']} planted bugs found"),
    ("Map to OWASP, CWE, CVE", "every finding; CVE only for libraries"),
    ("A remediation prompt per finding", "11 ways of asking; ours always pass the checker"),
    ("Give it to Copilot or another assistant", "any assistant: copy and paste, no plugin"),
    ("Apply the secure change", "the developer's assistant; or a local model in lab mode"),
    ("Re-run the scanners", "the same scanners, independently"),
    ("Verify the original bug is gone", "check 1, never decided by the AI"),
    ("Verify nothing new was introduced", "check 2, across the whole app"),
    ("A verification mechanism and dashboard", "3 checks, web dashboard, full history"),
    ("Test on OWASP cases and vulnerable apps", "our seeded app + a public vulnerable app"),
    ("Maintain on GitHub with regular check-ins", "per-phase commits; the library public too"),
)


def slide_requirements(prs):
    s = add_slide(prs)
    _label(s, "Requirements")
    headline(s, "All 12 project requirements are met")
    half = len(REQUIREMENTS) // 2
    for col in range(2):
        rows = [[str(col * half + i + 1), req, how]
                for i, (req, how) in enumerate(REQUIREMENTS[col * half:(col + 1) * half])]
        gfx_x = 0.60 + col * 6.15
        table = data_table(s, ["#", "Requirement", "How it is met"], rows, [0.40, 2.55, 2.95], y=1.85, row_h=0.62,
                           header_pt=12, body_pt=11)
        table_shape = s.shapes[-1]
        table_shape.left = Inches(gfx_x)
    callout(s, "Beyond the brief: the token ladder, the published checker library, and a structure check that "
               "catches fake fixes every scanner accepts.", emphasis=True, y=6.30, h=0.58, size=13)
    _number(s)
    notes(s, "The twelve requirements from the project brief, and where each is met. Ask for any one to be shown.")


def slide_limits(prs):
    s = add_slide(prs)
    _label(s, "Limitations and future work")
    headline(s, "What it cannot do yet, and what comes next")
    v2._titled_box(s, 0.60, 1.85, 5.95, 4.20, "Limits we state",
                   "• One seeded app and one small local AI model: our results show differences, not a ranking.\n"
                   "• A weakness no scanner detects cannot be found or verified.\n"
                   "• Developer mode never runs the code, so behaviour is checked only in lab mode.\n"
                   "• The checker matches patterns; it does not parse grammar.\n"
                   "• Python only.", body_size=15.5)
    v2._titled_box(s, 6.75, 1.85, 5.95, 4.20, "Next steps",
                   "• More apps and bugs, several models, repeated runs.\n"
                   "• A check that a fix keeps its callers' expectations, and the callers named in the prompt.\n"
                   "• Measure which checker rules predict a verified fix.\n"
                   "• Run lab fixes in an isolated container.\n"
                   "• More languages, through the library's extension points.", body_size=15.5)
    callout(s, "The scanners and the checks decide whether a fix worked. The AI never does.", emphasis=True,
            y=6.25, h=0.62, size=14)
    _number(s)
    notes(s, "Close on the design rule. Then thank the panel and take questions.")


def slide_thanks(prs):
    v2.slide_14_thanks(prs)
    _replace_notes(prs.slides[-1], "Appendix: glossary, full results, prepared answers, contributions, demo backup.")


def slide_full_pilot(prs):
    s = add_slide(prs)
    _label(s, "Appendix — strategy pilot in full")
    headline(s, "All nine ways of asking, with their token cost")
    by = E2_PILOT["by_strategy"]
    rows = [[sid, v2.WAYS[sid], f"{v} / {a}", f"{esr:.1f}", f"{tok:,}"] for sid, (v, a, esr, tok) in by.items()]
    data_table(s, ["Id", "Way of asking", "Passed all checks", "Rate", "Tokens (10 fixes)"], rows,
               [0.75, 5.20, 2.20, 1.30, 2.65], y=1.80, row_h=0.42, header_pt=12, body_pt=12.5,
               bold_rows=(list(by).index("S2"), list(by).index("S7")))
    failed = E2_PILOT["failed_at"]
    callout(s, f"Where the rejected fixes stopped: check 1 ×{failed['1']}, check 3 static ×{failed['3a']}, check 3 "
               f"behaviour tests ×{failed['3b']}. All {E2_PILOT['dependency_bumps_rejected']} library upgrades stopped "
               "one version short (5.3.1; 5.4 was needed); our prompt now names the right version.",
            y=6.12, h=0.78, size=12.5)
    _number(s)
    notes(s, f"Appendix. Model {E2_PILOT['model']} (digest {E2_PILOT['digest']}), temperature 0, seed 42.")


def slide_full_ladder(prs):
    s = add_slide(prs)
    _label(s, "Appendix — token ladder in full")
    headline(s, "What each prompt size costs and achieves")
    st, by, per = E5_STATIC, E5["by_strategy"], E5["tokens_per_trial"]
    rows = [[sid, LADDER[sid], f"{st['passes_lint'][sid]} / {st['findings']}", f"{st['typed'][sid][1]}",
             f"{by[sid][0]} / {by[sid][1]}", f"{per[sid]:,}", f"{E5['verified_per_1k_tokens'][sid]:.2f}"]
            for sid in ("S7", "S7a", "S7m", "S2")]
    data_table(s, ["Id", "Prompt", "Passes checker", "Tokens pasted (typical)", "Verified", "Tokens per attempt",
                   "Verified per 1k tokens"], rows, [0.75, 3.10, 1.55, 1.90, 1.25, 1.75, 1.80], y=1.85, row_h=0.50,
               header_pt=11.5, body_pt=12.5, bold_rows=(2,))
    parts = st["s7_parts"]
    callout(s, "Where the full prompt's first message spends its tokens (typical): " + ", ".join(
        f"{name} {tok}" for name, tok in sorted(parts.items(), key=lambda kv: -kv[1])) + ".",
        y=4.65, h=0.95, size=12.5)
    callout(s, "Checker pass counts are over the 24 real findings; verified fixes are the live run over the 10 planted "
               "bugs, after the version-naming fix. One run first hit a model-server timeout and was re-run.",
            y=5.80, h=0.90, size=12)
    _number(s)
    notes(s, f"Appendix. Same model, settings and checks as the pilot ({E5['model']}, digest {E5['digest']}).")


def slide_answers(prs):
    s = add_slide(prs)
    _label(s, "Appendix — prepared answers")
    headline(s, "Questions we expect")
    for i, (q, a) in enumerate((
        ("“If the minimal prompt is as good, why keep the long one?”",
         "On our small model the review rounds bought nothing, but stronger assistants may use the explanation. "
         "Both pass the checker; the developer picks. The result is a pilot, not a ranking."),
        ("“Why not run the project's own tests in developer mode?”",
         "The scanned repository is untrusted: running it on our side would let it run anything. Its tests belong "
         "in the developer's CI; our verdict says that check was not run instead of pretending it passed."),
        ("“Why publish the checker separately?”",
         "So others can use and extend it without our whole tool, and reproduce our numbers with its benchmark. Our "
         "tool imports the same library, so there is only one copy of that code."),
        ("“Your own way of asking did not win the pilot. What is new?”",
         "The test bench that measures ways of asking on real fixes with independent checks, the checker, and now "
         "the minimal prompt, which was the most token-efficient way measured."),
    )):
        base._qa_row(s, i, q, a)
    _number(s)
    notes(s, "Appendix. Present only if asked.")


def slide_contributions(prs):
    s = add_slide(prs)
    _label(s, "Appendix — individual contributions")
    headline(s, "Who did what")
    rows = [["Anvesh Dangeti", "EM26MTECH14009", "Team lead, lead developer", "60%",
             "scope and architecture; scanner, lifecycle, prompt and verification layers; token ladder; the library"],
            ["Dhananjay Kumar", "CS26MTECH13007", "Research, security testing, hardening", "20%",
             "literature and tool survey; attack test cases; security review of our own tool"],
            ["Muday Saiprakash Nayak", "EM26MTECH11001", "Fixtures, interface, evaluation", "20%",
             "seeded test app and its tests; web dashboard; experiments and recorded results"]]
    data_table(s, ["Member", "Roll number", "Role", "Share", "Main contributions"], rows,
               [2.30, 1.85, 2.45, 0.80, 4.70], y=1.90, row_h=0.95, header_pt=12, body_pt=12)
    callout(s, "Full details and phase ownership: CONTRIBUTIONS.md in the repository and the contributions document.",
            y=5.95, h=0.62, size=13)
    _number(s)
    notes(s, "Appendix. The split is the one stated in the Review 3 submission.")


def slide_backup_1(prs):
    v2.slide_18_backup(prs)


def slide_backup_2(prs):
    v2.slide_19_backup(prs)


BUILDERS = [
    slide_title,                                     # 1
    v2.slide_02_problem,                             # 2  problem
    v2.slide_03_sota_tools,                          # 3  state of the art: tools
    v2.slide_04_sota_research,                       # 4  state of the art: research
    v2.slide_05_how_it_works,                        # 5  architecture
    v2.slide_06_prompt,                              # 6  the prompt
    v2.slide_07_threat_model,                        # 7  threat model
    v2.slide_08_usps,                                # 8  what is new
    v2.slide_09_fake_fix,                            # 9  the fake fix
    v2.slide_10_checker,                             # 10 the checker
    v2.slide_12_results,                             # 11 strategy pilot
    slide_tokens,                                    # 12 panel question 1
    slide_callers,                                   # 13 panel question 2
    slide_library,                                   # 14 panel question 3
    slide_own_security,                              # 15 our own security
    slide_demo,                                      # 16 demo
    slide_requirements,                              # 17 the 12 requirements
    slide_limits,                                    # 18 limitations and future work
    slide_thanks,                                    # 19
    v2.slide_15_glossary,                            # 20 appendix
    slide_full_pilot,                                # 21
    slide_full_ladder,                               # 22
    slide_answers,                                   # 23
    slide_contributions,                             # 24
    slide_backup_1,                                  # 25
    slide_backup_2,                                  # 26
]
PRESENTED = range(2, 19)


def build(out_path: Path) -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(base.SLIDE_W)
    prs.slide_height = Inches(base.SLIDE_H)
    _PRS[:] = [prs]
    with _adapted_midsem_builders():
        for builder in BUILDERS:
            builder(prs)
    # Re-used builders wrote mid-semester notes; keep them short and current.
    _replace_notes(prs.slides[10], f"""
Left: 10 planted bugs x 9 ways of asking = {E2_PILOT['trials']} fixes by a local 7B model, each re-scanned and checked.
Teal is ours. Honest reading: ours did not win the pilot - bug-specific advice was best; ours spent extra tokens on
review rounds. That is what led to the token ladder on the next slide.
""")
    props = prs.core_properties
    props.author = props.last_modified_by = "TEAM-3"
    props.title = "Building a Prompt Assistant for Secure Coding — final review"
    props.subject = props.keywords = props.comments = ""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    return prs


def main() -> int:
    default_out = ROOT.parent / "Secure_Prompt_Assistant_Final_Review.pptx"
    parser = argparse.ArgumentParser(description="Build the final-review deck")
    parser.add_argument("--out", type=Path, default=default_out)
    args = parser.parse_args()
    missing = [name for name in SCREENSHOTS if not (IMG / name).exists()]
    build(args.out)
    print(f"  built {len(BUILDERS)} slides -> {args.out}")
    if missing:
        print(f"  MISSING screenshots (placeholders used): {', '.join(missing)}")
    if base._warnings:
        print(f"\n  {len(base._warnings)} possible layout issue(s):")
        for w in base._warnings:
            print(w)
    else:
        print("  no layout warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
