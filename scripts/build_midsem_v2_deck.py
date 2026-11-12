#!/usr/bin/env python3
"""
Build the plain-language mid-semester review deck (Friday 30 October 2026).

Same seven sections as build_midsem_deck.py -- problem statement, state of
the art, architecture, threat model, USPs, demo, next two weeks -- rewritten
so that every slide explains itself: each headline states the takeaway in
plain English, internal codes (strategy ids, lint-rule ids, gate numbers such
as 3a/3b, scanner rule ids) stay off the presented slides, and the terms that
remain are defined on the glossary slide in the appendix.

The design system is imported from build_review2_deck.py and the helpers from
build_review4_deck.py / build_midsem_deck.py, so the series stays visually
identical. Every result number comes from evaluation/recorded_results.py; the
prompt example and its lint scores are computed here by the real prompt
builder and linter on the ping_host finding from the demo. Content is mirrored
in docs/midsem_v2_slides.md.

Usage:
    python scripts/build_midsem_v2_deck.py
    python scripts/build_midsem_v2_deck.py --out path/to/deck.pptx
"""

from __future__ import annotations

import argparse
import re
import sys
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from pptx import Presentation  # noqa: E402
from pptx.chart.data import CategoryChartData  # noqa: E402
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_TICK_LABEL_POSITION, XL_TICK_MARK  # noqa: E402
from pptx.enum.shapes import MSO_SHAPE  # noqa: E402
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN  # noqa: E402
from pptx.util import Inches, Pt  # noqa: E402

import build_review2_deck as base  # noqa: E402
from build_midsem_deck import TEAM, _arrow  # noqa: E402
from build_review2_deck import (  # noqa: E402
    BODY, CONTENT_W, DISPLAY, INK, MARGIN_X, MONO, NAVY, NO, PALE, PARTIAL, SLATE, TEAL, WHITE, YES,
    add_slide, badge, callout, data_table, notes, section_label, slide_number, textbox, write,
)
from build_review4_deck import IMG, _circles, _white_box, picture  # noqa: E402
from evaluation.recorded_results import E1, E2_PILOT, FIXTURE, TESTS, VERIFICATION  # noqa: E402

SCREENSHOTS = ("midsem_overview.png", "midsem_lint.png", "midsem_verification.png")

# The finding the demo and slides 6 and 10 follow: Bandit's shell-injection report in ping_host.
DEMO_SYMBOL, DEMO_RULE = "ping_host", "B602"
SHORT_PROMPT = "Fix the command injection in ping_host in app.py."   # the developer's shortened prompt

# Plain names for the nine prompting strategies (app/ai/strategies), in the words a reader needs.
WAYS = {
    "S0": "No security hint (baseline)",
    "S1": "Just say “be secure”",
    "S2": "Bug-specific advice",
    "S3": "Full secure-coding checklist",
    "S4": "“Think step by step”",
    "S5": "“Review and improve your answer”",
    "S6": "“Act as a security expert”",
    "S7": "Ours: explain + checked prompt + review",
    "S8": "Security rules file",
}
# What each prompt part the linter requires means, for a reader who has never seen a lint report.
PART_NAMES = {"A1": "the risky input", "A2": "when it may run", "A3": "how to fix it",
              "A4": "change nothing else", "A5": "what and where"}

HEAD_SIZE = 30


def headline(slide, text):
    base.headline(slide, text, size=HEAD_SIZE)


def _clip(text: str, n: int) -> str:
    text = text.replace("`", "")
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " …"


@lru_cache(maxsize=1)
def prompt_example() -> dict:
    """The real S7 prompt for the demo finding and the linter's verdict on it, shortened, and repaired."""
    from app.ai.linter import apply_fixes, expectation_for, lint
    from app.ai.prompt_builder import build_prompt
    from evaluation.e1_mutation import NONCE, ROLES, contexts

    ctx = next(c for c in contexts() if c.symbol == DEMO_SYMBOL and c.rule_id == DEMO_RULE)
    canonical = build_prompt(ctx, "S7", nonce=NONCE).messages[0]
    exp = expectation_for(ctx, canonical=canonical)
    short = lint(SHORT_PROMPT, exp)
    return {
        "parts": dict(zip(ROLES, canonical.split("\n\n"), strict=True)),
        "full": lint(canonical, exp),
        "short": short,
        "repaired": lint(apply_fixes(SHORT_PROMPT, short, exp), exp),
    }


def verdict_counts() -> dict[str, int]:
    counts = {"VERIFIED_RESOLVED": 0, "FIX_REJECTED": 0, "UNVERIFIED": 0}
    for verdict, _, _ in VERIFICATION.values():
        counts[verdict] += 1
    return counts


# ==========================================================================
# small layout helpers (house palette and fonts only)
# ==========================================================================

def _panel(slide, x, y, w, h, *, fill=WHITE):
    shp = _white_box(slide, x, y, w, h)
    shp.fill.fore_color.rgb = fill
    return shp


def _down_arrow(slide, x, y, w=0.30, h=0.26):
    shp = slide.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = TEAL
    shp.line.fill.background()
    shp.shadow.inherit = False


def _titled_box(slide, x, y, w, h, title, body, *, fill=WHITE, title_color=NAVY, body_color=SLATE,
                title_size=14, body_size=12.5, align=PP_ALIGN.LEFT, pad=0.18):
    _panel(slide, x, y, w, h, fill=fill)
    tf = textbox(slide, x + pad, y + 0.12, w - 2 * pad, 0.36)
    write(tf, title, font=DISPLAY, size=title_size, bold=True, color=title_color, align=align)
    tf = textbox(slide, x + pad, y + 0.50, w - 2 * pad, h - 0.58)
    write(tf, body, size=body_size, color=body_color, align=align, line_spacing=1.08)


def _stat(slide, x, y, w, big, title, body, *, big_w=1.45, big_size=24, body_size=12.5):
    """A big teal figure on the left, a bold title and one short line beside it."""
    tf = textbox(slide, x, y - 0.04, big_w, 0.55)
    write(tf, big, font=DISPLAY, size=big_size, bold=True, color=TEAL)
    tf = textbox(slide, x + big_w + 0.12, y, w - big_w - 0.12, 0.34)
    write(tf, title, font=DISPLAY, size=14, bold=True, color=NAVY)
    tf = textbox(slide, x + big_w + 0.12, y + 0.36, w - big_w - 0.12, 0.60)
    write(tf, body, size=body_size, color=SLATE, line_spacing=1.08)


def _step(slide, x, y, w, num, title, body):
    badge(slide, x, y, 0.46, num, shape=MSO_SHAPE.ROUNDED_RECTANGLE, label_size=13)
    tf = textbox(slide, x + 0.62, y - 0.02, w - 0.62, 0.32)
    write(tf, title, font=DISPLAY, size=15, bold=True, color=NAVY)
    tf = textbox(slide, x + 0.62, y + 0.30, w - 0.62, 0.36)
    write(tf, body, size=13, color=SLATE)


def _highlight_column(table, col):
    """Our column reads as the answer: teal header, white cells on the mist background."""
    for r, row in enumerate(table.rows):
        cell = row.cells[col]
        cell.fill.solid()
        cell.fill.fore_color.rgb = TEAL if r == 0 else WHITE


# ==========================================================================
# SLIDES
# ==========================================================================

def slide_01_title(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 2.05, 8.40, 0.40)
    write(tf, "SECURE SOFTWARE ENGINEERING · MID-SEMESTER REVIEW", font=DISPLAY, size=13, bold=True, color=TEAL)
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
TEAM-3 · mid-semester review · Friday 30 October 2026 · 15 minutes (about 4½ of them are the demo video).
Open with one sentence: "Developers now ask AI assistants to fix security bugs. Our tool helps them ask
well - and then proves, without trusting the AI, whether the fix really worked."
""")


def slide_02_problem(prs):
    s = add_slide(prs)
    section_label(s, "1 · Problem statement")
    headline(s, "AI writes the security fix. Nobody checks it.")
    for col, (num, title, body, source) in enumerate((
        ("40.95%", "of AI-written Python code had a security flaw",
         "Java 8.82% and C 0.78% in the same study, so we focus on Python.", "Cicalese et al. (Paper 2)"),
        ("1 / 10", "secure answers from GPT-4o with a plain request",
         "With security instructions, the best model got 10 / 10. How you ask matters.",
         "Backslash Security, 2025"),
        ("14–54%", "of safe, working code lost by earlier “secure” methods",
         "A fix can remove the bug by breaking the code. That is not a fix.", "SecCoderX, 2026"),
    )):
        x = base.CARD_X[col]
        _white_box(s, x, 1.85, base.CARD_W, 2.85)
        tf = textbox(s, x + 0.30, 2.00, base.CARD_W - 0.60, 0.62)
        write(tf, num, font=DISPLAY, size=34, bold=True, color=TEAL)
        tf = textbox(s, x + 0.30, 2.68, base.CARD_W - 0.60, 0.62)
        write(tf, title, font=DISPLAY, size=15, bold=True, color=NAVY, line_spacing=1.0)
        tf = textbox(s, x + 0.30, 3.36, base.CARD_W - 0.60, 0.92)
        write(tf, body, size=13, color=SLATE, line_spacing=1.08)
        tf = textbox(s, x + 0.30, 4.30, base.CARD_W - 0.60, 0.28)
        write(tf, source, size=10.5, color=SLATE)
    tf = textbox(s, MARGIN_X, 4.98, CONTENT_W, 0.38)
    write(tf, "Three questions our project answers", font=DISPLAY, size=17, bold=True, color=NAVY)
    for i, q in enumerate(("Which way of asking the AI gives a safe fix?",
                           "Did the fix really work? Decided by the security scanners, not by the AI.",
                           "Does the same bug come back in a later commit?")):
        badge(s, 0.70, 5.48 + i * 0.47, 0.34, str(i + 1), label_size=12)
        tf = textbox(s, 1.20, 5.49 + i * 0.47, 11.00, 0.36)
        write(tf, q, size=15, color=NAVY)
    slide_number(s, 2)
    notes(s, """
Developers already paste scanner warnings into Copilot or ChatGPT and accept the answer. Three facts: AI-written
Python is often insecure; the wording of the request changes the result a lot; and some "secure" fixes simply
break the code. Nobody checks the fix independently - that is our project.
Likely question: "Where do these numbers come from?" - the three sources under each card (Paper 2 was assigned).
""")


def slide_03_sota_tools(prs):
    s = add_slide(prs)
    section_label(s, "2 · State of the art — existing tools")
    headline(s, "Existing tools each do part of the job")
    table = data_table(
        s,
        ["What it does", "Copilot\nAutofix", "Snyk / Semgrep\nAI assistants", "DefectDojo", "Backslash\nrules file",
         "Plain\nChatGPT", "Our\ntool"],
        [
            ["Finds bugs with real security scanners", YES, YES, YES, PARTIAL, NO, YES],
            ["Re-checks the fix with the scanners", PARTIAL, PARTIAL, NO, NO, NO, YES],
            ["Checks the fix did not break the code", NO, NO, NO, NO, NO, YES],
            ["Follows each bug across commits", NO, NO, YES, NO, NO, YES],
            ["Tests and checks the prompt itself", NO, NO, NO, NO, NO, YES],
        ],
        [4.05, 1.30, 1.75, 1.30, 1.30, 1.15, 1.25],
        y=1.85, row_h=0.62, header_pt=12.5, body_pt=15,
    )
    _highlight_column(table, 6)
    tf = textbox(s, MARGIN_X, 5.68, CONTENT_W, 0.32)
    write(tf, f"{YES}  yes        {PARTIAL}  partly        {NO}  no", size=13, color=SLATE)
    callout(s, "GitHub Copilot Autofix already does scan → fix → re-scan (since August 2024). We do not claim that "
               "loop. We add the extra checks, and we test the prompt.", emphasis=True, y=6.12, h=0.68, size=14)
    slide_number(s, 3)
    notes(s, """
Read the last column, then the rows where only we have a tick. Copilot Autofix is the closest: it finds, fixes and
re-scans, but hides its prompt and does not check that the code still works. DefectDojo tracks findings across
scans but has no AI. Backslash sells a rules file for prompts; nobody re-checks its fixes.
Likely question: "Isn't this just Copilot Autofix?" - the bottom line answers it.
""")


def slide_04_sota_research(prs):
    s = add_slide(prs)
    section_label(s, "2 · State of the art — research")
    headline(s, "What research found, and what we built from it")
    data_table(s, ["Source", "What they found", "What we built from it"], [
        ["Paper 1 · Yan et al.", "Explaining a scanner warning before asking for a fix gives better fixes "
         "(over 98% of explanations correct)", "Every prompt first explains the bug"],
        ["Paper 2 · Cicalese et al.", "Python is most often vulnerable; prompts that leave out key details "
         "give unsafe code; they propose a prompt checker", "We focus on Python and built that checker"],
        ["Paper 3 · Tony et al.", "Compared 7 ways of asking for secure code; “review and improve your answer” "
         "did best on GPT-4", "We test the same 7 ways on real fixes"],
        ["Backslash Security", "A file of security rules added to every prompt; claims 100%, never checked "
         "independently", "We test it under the same checks"],
        ["SecCoderX, 2026", "Count a fix only if the code is both secure and still works",
         "Our main score: fixes that pass all checks"],
    ], [2.75, 5.85, 3.50], y=1.85, row_h=0.66, header_pt=13, body_pt=13)
    callout(s, "The gap: research tests prompts on new code; tools fix real projects without testing the prompt. "
               "We test prompts on real fixes, and check every fix ourselves.", y=6.05, h=0.68, size=14)
    slide_number(s, 4)
    notes(s, """
Read the right-hand column: each source changed one part of our tool. Papers 1-3 are the three assigned papers.
Paper 3's best method on GPT-4 ("review and improve") becomes one of the nine ways we test; Backslash's rules file
is another; SecCoderX gives us the score we report.
Likely question: "What exactly is new compared with Paper 3?" - they tested prompts on freshly generated code; we
test them on fixes to an existing project, checked by re-scanning.
""")


def slide_05_how_it_works(prs):
    s = add_slide(prs)
    section_label(s, "3 · Architecture — how it works")
    headline(s, "How it works: the scanners decide, never the AI")
    steps = (("1 · Connect", "a GitHub link or a ZIP file"),
             ("2 · Scan", "4 free scanners: code, secrets, libraries"),
             ("3 · Label", "bug type (CWE, OWASP) and an ID that survives edits"),
             ("4 · Write prompt", "explain the bug, then ask for a precise fix"),
             ("5 · Check prompt", "no safety instruction is missing"),
             ("6 · Verify fix", "scan again, then run 3 checks"))
    w, gap, y = 1.78, 0.285, 1.85
    for i, (title, body) in enumerate(steps):
        x = MARGIN_X + i * (w + gap)
        _titled_box(s, x, y, w, 1.45, title, body, title_size=13.5, body_size=12, align=PP_ALIGN.CENTER, pad=0.10)
        if i < len(steps) - 1:
            _arrow(s, x + w + 0.005, y + 0.58, w=gap - 0.01)
    for x in (3.38, 9.63):
        _down_arrow(s, x, 3.40)
        _down_arrow(s, x, 5.06)
    _titled_box(s, 0.60, 3.74, 5.85, 1.24, "Developer mode — the product",
                "The developer pastes our prompt into their own AI assistant (Copilot or any other) and commits "
                "the fix; we re-check it. We run no AI model and cost them no tokens.", body_size=13)
    _titled_box(s, 6.85, 3.74, 5.85, 1.24, "Lab mode — for our experiments",
                "A small AI model on our own machine writes fixes into a throwaway copy, so we can compare "
                "9 ways of asking on the same bugs.", body_size=13)
    _titled_box(s, 0.60, 5.40, 12.10, 1.02, "After the fix: the same scanners run again, then 3 checks",
                "VERIFIED (all checks pass)   ·   REJECTED (with the reason)   ·   UNVERIFIED (evidence "
                "missing, so we never guess)", fill=NAVY, title_color=WHITE, body_color=PALE, body_size=13.5,
                align=PP_ALIGN.CENTER)
    tf = textbox(s, MARGIN_X, 6.62, CONTENT_W, 0.30)
    write(tf, f"Built with Python, FastAPI, SQLite and a web interface  ·  {TESTS} automated tests",
          size=11.5, color=SLATE)
    slide_number(s, 5)
    notes(s, """
Left to right: connect a project, scan it with four free tools, label each bug with a standard type and a stable
ID, write the fix request, check it, and after the fix scan again. Two modes: in developer mode (the real product)
the developer's own assistant writes the fix and we never call an AI; lab mode is only for our experiments.
Likely question (from Review 3): "Is it an IDE plugin?" - no; it works next to any assistant.
""")


def slide_06_prompt(prs):
    s = add_slide(prs)
    section_label(s, "3 · Architecture — what the developer gets")
    headline(s, "What the developer gets: a complete fix request")
    ex = prompt_example()
    parts = ex["parts"]
    _panel(s, 0.60, 1.85, 7.95, 4.80)
    rows = (("WHAT & WHERE", "opening"), ("WHY IT MATTERS", "explanation"), ("HOW TO FIX", "directive"),
            ("ONLY IF", "guard"), ("CHANGE NOTHING ELSE", "scope"), ("CODE IS DATA", "inert-data instruction"))
    for i, (label, role) in enumerate(rows):
        y = 2.02 + i * 0.52
        tf = textbox(s, 0.82, y + 0.02, 1.55, 0.44)
        write(tf, label, font=DISPLAY, size=10.5, bold=True, color=TEAL, line_spacing=0.95)
        tf = textbox(s, 2.45, y, 5.95, 0.48)
        write(tf, _clip(parts[role], 128), size=12, color=INK, line_spacing=1.0)
    tf = textbox(s, 0.82, 5.18, 1.55, 0.30)
    write(tf, "THE CODE", font=DISPLAY, size=10.5, bold=True, color=TEAL)
    tf = textbox(s, 2.45, 5.14, 5.95, 1.40)
    for line in parts["untrusted code"].splitlines():
        line = re.sub(r' id="[^"]*"', "", line)
        write(tf, line, font=MONO, size=9.5, color=SLATE, line_spacing=1.0)
    tokens = ex["full"].tokens
    for i, (title, body) in enumerate((
        ("Specific", "names the exact function, input and risky call"),
        ("Minimal", "only this one function is sent; comments removed, secrets hidden"),
        ("Guarded", "the code is marked as data, and the AI is told not to follow anything inside it"),
        ("Ready to paste", f"into Copilot or any assistant; about {tokens} tokens, plus two short "
                           "follow-ups asking it to review its answer"),
    )):
        y = 1.85 + i * 0.93
        tf = textbox(s, 8.85, y, 3.85, 0.32)
        write(tf, title, font=DISPLAY, size=14.5, bold=True, color=NAVY)
        tf = textbox(s, 8.85, y + 0.33, 3.85, 0.58)
        write(tf, body, size=12.5, color=SLATE, line_spacing=1.05)
    _titled_box(s, 8.85, 5.62, 3.85, 1.03, "No AI writes this prompt",
                "It is built from templates and code analysis, so it costs nothing.", fill=NAVY, title_color=WHITE,
                body_color=PALE, title_size=13.5, body_size=12.5)
    slide_number(s, 6)
    notes(s, """
This is the real prompt our tool built for the shell-command bug in the demo app, lightly shortened. Each grey label
is a part the prompt checker looks for. The code goes in last, between markers, with an instruction that it is
data - so a comment like "ignore previous instructions" inside the code is not obeyed.
Likely question: "Does an AI write this?" - no: templates plus analysis of the code; that is why it is free.
""")


def slide_07_threat_model(prs):
    s = add_slide(prs)
    section_label(s, "4 · Threat model")
    headline(s, "Our tool reads untrusted code, so it guards itself")
    data_table(s, ["Where an attack can come in", "What could go wrong", "How we stop it"], [
        ["A repository link", "It makes our server call internal machines (SSRF)",
         "Only public https addresses; no IP addresses; no redirects"],
        ["A ZIP upload", "Files land outside the folder; a zip bomb fills the disk",
         "Every file path checked; links refused; size and count limits"],
        ["Running the scanners", "Command injection; a scanner that never stops",
         "Never through a shell; fixed arguments; time limits"],
        ["Code sent to the AI", "Hidden instructions in comments take over the AI (prompt injection)",
         "Comments removed; code marked as data; secrets hidden; one function only"],
        ["The AI's answer", "A confident but wrong fix",
         "Never run or committed by us; the scanners and checks decide"],
        ["Testing a fix (lab only)", "Running untrusted code",
         "Throwaway copy, separate Python, only after the other checks, time limit"],
        ["Our web interface", "Script injection, forged requests, DNS tricks",
         "Only this computer can connect; sign-in and anti-forgery tokens; strict browser policy"],
    ], [2.75, 4.20, 5.15], y=1.85, row_h=0.54, header_pt=13, body_pt=12.5)
    callout(s, "Every row has its own attack tests. We also scan our own tool with its own scanners.",
            emphasis=True, y=6.40, h=0.52, size=14)
    slide_number(s, 7)
    notes(s, """
Our tool is a target: it downloads strangers' code and passes parts of it to an AI. Each row is one way in, what an
attacker could do, and our control. The two most specific to this project are rows 4 and 5: code comments are
attacker-controlled text, and nothing the AI writes is trusted.
Likely question: "How do you know these controls work?" - each row has automated attack tests (SSRF, archive,
injection, web payload suites).
""")


def slide_08_usps(prs):
    s = add_slide(prs)
    section_label(s, "5 · What is new (USPs)")
    headline(s, "Four things our tool does that others don't")
    cards = (("We test which prompt works", "9 ways of asking the AI, on the same bugs, judged by the same checks."),
             ("We check the developer's prompt", "If a safety instruction is cut out, the checker flags it "
                                                "and puts it back."),
             ("We don't take the AI's word", "3 checks: bug gone, nothing new, code still works. An emptied "
                                             "function fools scanners, not us."),
             ("We remember every bug", "Each bug keeps its ID across commits: fixed, still open, or back again."))
    w, gap = 2.80, 0.30
    for i, (title, body) in enumerate(cards):
        x = MARGIN_X + i * (w + gap)
        _white_box(s, x, 1.85, w, 2.95)
        badge(s, x + 0.25, 2.07, 0.62, str(i + 1), label_size=16)
        tf = textbox(s, x + 0.25, 2.85, w - 0.50, 0.72)
        write(tf, title, font=DISPLAY, size=16, bold=True, color=NAVY, line_spacing=1.0)
        tf = textbox(s, x + 0.25, 3.66, w - 0.50, 1.08)
        write(tf, body, size=13, color=SLATE, line_spacing=1.08)
    _titled_box(s, 0.60, 5.02, 5.90, 0.96, "Works with any AI assistant",
                "No plugin needed; in developer mode we run no AI model at all.", body_size=13)
    _titled_box(s, 6.80, 5.02, 5.90, 0.96, "Free and runs locally",
                "Open-source scanners; every number we show is re-checked by a test.", body_size=13)
    callout(s, "What we do not claim: finding more bugs than CodeQL, writing better fixes than large AI models, or "
               "inventing the scan → fix → re-scan loop.", emphasis=True, y=6.18, h=0.66, size=13.5)
    slide_number(s, 8)
    notes(s, """
The four numbered cards are our USPs; the next two slides prove cards 3 and 2. The bottom line is deliberate: we
say up front what we do not claim, so the contribution is the measuring and the checking.
Likely question: "Which of these is the main contribution?" - testing which prompt produces a verified fix,
using independent checks (cards 1 and 3 together).
""")


def slide_09_fake_fix(prs):
    s = add_slide(prs)
    section_label(s, "5 · What is new — proof 1")
    headline(s, "A fake fix fooled the scanners, not our checks")
    tf = textbox(s, MARGIN_X, 1.85, CONTENT_W, 0.36)
    write(tf, "The bug: ping_host puts what the user typed into a shell command (command injection).",
          size=15, color=NAVY)
    w, gap = 2.72, 0.40
    flows = (
        (("Fake fix", "the function body is emptied"),
         ("Checks 1 + 2 (scanners)", f"bug gone {YES}   nothing new {YES}"),
         ("Check 3: still works?", f"{NO}  the function now does nothing"),
         ("REJECTED", NAVY)),
        (("Real fix", "the command runs as a list of arguments, with no shell"),
         ("Checks 1 + 2 (scanners)", f"bug gone {YES}   nothing new {YES}"),
         ("Check 3: still works?", f"{YES}  same function, real body"),
         ("VERIFIED", TEAL)),
    )
    for r, (fix, scan, check3, (verdict, colour)) in enumerate(flows):
        y = 2.40 + r * 1.52
        for i, (title, body) in enumerate((fix, scan, check3)):
            x = MARGIN_X + i * (w + gap)
            _titled_box(s, x, y, w, 1.20, title, body, body_size=13)
            _arrow(s, x + w + 0.05, y + 0.47, w=gap - 0.10)
        x = MARGIN_X + 3 * (w + gap)
        _panel(s, x, y, w, 1.20, fill=colour)
        tf = textbox(s, x, y, w, 1.20, anchor=MSO_ANCHOR.MIDDLE)
        write(tf, verdict, font=DISPLAY, size=22, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    counts = verdict_counts()
    tf = textbox(s, MARGIN_X, 5.50, CONTENT_W, 0.34)
    write(tf, f"We scripted {len(VERIFICATION)} test commits, each with a known right answer — every verdict "
              "came out as expected:", size=14, bold=True, color=NAVY)
    for col, (big, text) in enumerate((
        (f"{counts['VERIFIED_RESOLVED']} verified", "real fixes passed all checks"),
        (f"{counts['FIX_REJECTED']} rejected", "one by each of the 3 checks"),
        (f"{counts['UNVERIFIED']} unverified", "a scanner was down, so no verdict"),
    )):
        x = base.CARD_X[col]
        _white_box(s, x, 5.95, base.CARD_W, 0.78)
        tf = textbox(s, x + 0.25, 5.95, base.CARD_W - 0.50, 0.78, anchor=MSO_ANCHOR.MIDDLE)
        write(tf, big, font=DISPLAY, size=16, bold=True, color=TEAL, para=None)
        write(tf, text, size=12.5, color=SLATE)
    slide_number(s, 9)
    notes(s, """
The most important slide. If the function is simply emptied, the bug disappears from every scanner - a
scanner-only check would call it fixed. Our third check sees the function no longer does anything and rejects it.
The next commit, a real fix, passes all three. The seven scripted commits test each check, plus a scanner outage.
Likely question: "What exactly is check 3?" - same parameters and decorators, a real body (not pass/return/raise),
no undefined names; in lab mode the app's own behaviour tests also run.
""")


def slide_10_checker(prs):
    s = add_slide(prs)
    section_label(s, "5 · What is new — proof 2")
    headline(s, "Shorten the prompt, and the checker notices")
    ex = prompt_example()
    full, short, repaired = ex["full"], ex["short"], ex["repaired"]
    missing = " · ".join(PART_NAMES[rule] for rule, ok in short.constituents.items() if not ok)

    def verdict(report):
        return f"{'PASS' if report.passed else 'FAIL'} · {report.constituent_score:.0%}"

    rows = ((f"Our prompt ({full.tokens} tokens)", "all 5 safety parts present", verdict(full), TEAL),
            ("Developer shortens it", f"“{SHORT_PROMPT}”\nmissing: {missing}", verdict(short), NAVY),
            ("One click: suggested fixes", f"the missing sentences are put back ({repaired.tokens} tokens)",
             verdict(repaired), TEAL))
    for i, (title, body, result, colour) in enumerate(rows):
        y = 1.85 + i * 1.38
        _panel(s, 0.60, y, 6.40, 1.18)
        tf = textbox(s, 0.80, y + 0.10, 4.40, 0.32)
        write(tf, title, font=DISPLAY, size=14, bold=True, color=NAVY)
        tf = textbox(s, 0.80, y + 0.44, 4.40, 0.70)
        for line in body.split("\n"):
            write(tf, line, size=12.5, color=SLATE, line_spacing=1.0)
        _panel(s, 5.30, y + 0.24, 1.50, 0.70, fill=colour)
        tf = textbox(s, 5.30, y + 0.24, 1.50, 0.70, anchor=MSO_ANCHOR.MIDDLE)
        write(tf, result, font=DISPLAY, size=13.5, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        if i < 2:
            _down_arrow(s, 3.40, y + 1.20, h=0.16)
    c, u = E1["constituent"], E1["unchecked"]
    tf = textbox(s, 7.45, 1.85, 5.25, 0.36)
    write(tf, "We tested the checker (no AI involved)", font=DISPLAY, size=16, bold=True, color=NAVY)
    tf = textbox(s, 7.45, 2.22, 5.25, 0.34)
    write(tf, f"{E1['findings']} real prompts × 12 kinds of cuts", size=13, color=SLATE)
    _stat(s, 7.45, 2.80, 5.25, f"{c['flagged']} / {c['mutants']}", "cuts caught",
          "every cut that removed a safety part was flagged", big_w=1.85)
    _stat(s, 7.45, 3.85, 5.25, f"0 / {u['mutants']}", "false alarms",
          "cutting a harmless part raised nothing", big_w=1.85)
    _stat(s, 7.45, 4.90, 5.25, f"{c['failed']} / {c['failed']}", "repaired",
          "every prompt that failed was fixed by the suggestions", big_w=1.85)
    gap = E1["by_operator"]["undelimit the code"][1]
    callout(s, f"Honest gap: code pasted without its markers is caught only {gap} of {E1['findings']} times "
               "(very short snippets slip through).", y=6.20, h=0.60, size=13)
    slide_number(s, 10)
    notes(s, f"""
Developers shorten prompts. On the left, the demo's one-line prompt keeps "what and where" but loses the four other
safety parts, so the checker fails it at 20% and offers the missing sentences back. On the right, the experiment
(E1): {E1['findings']} real prompts, 12 kinds of edit each, no AI involved, re-run by a test on every build.
Likely question: "Isn't this just keyword matching?" - it checks that the prompt names this bug's own input and
call, and uses fix vocabulary for this bug type; code inside the markers never counts.
""")


def slide_11_demo(prs):
    s = add_slide(prs)
    section_label(s, "6 · Demo of the existing work")
    headline(s, "Demo: one developer's Friday release")
    _titled_box(s, 0.60, 1.85, 5.30, 1.42, "The story",
                "Rahul must ship helpdesk-portal tomorrow. The team rule: nothing ships without a clean "
                "security scan.", body_size=13.5)
    tf = textbox(s, 0.60, 3.36, 5.30, 0.30)
    write(tf, f"helpdesk-portal is our test app with {FIXTURE['seeded']} planted bugs, under a realistic name.",
          size=11.5, color=SLATE)
    # Top of the overview page only (severity tiles, bug states, verdicts): the full page is too tall here.
    picture(s, "midsem_overview.png", 0.60, 3.78, 5.30, crop=(0.04, 0.0, 0.08, 0.35))
    for i, (title, body) in enumerate((
        ("Scan", f"4 scanners find {FIXTURE['findings']} issues; a false alarm is marked, not deleted"),
        ("Build the prompt", "for the shell-command bug; the checker says PASS"),
        ("Shorten it", "the checker says FAIL; one click puts the missing parts back"),
        ("Fake fix", "the scanners go quiet, but our checks say REJECTED"),
        ("Real fix", "the prompt goes to an AI assistant; proper fix: VERIFIED"),
        ("History", "every scan and every verdict is kept"),
    )):
        _step(s, 6.35, 1.90 + i * 0.70, 6.35, str(i + 1), title, body)
    callout(s, "Recorded video, about 4½ minutes, run on our own test app. Every number in it can be reproduced.",
            emphasis=True, y=6.32, h=0.56, size=13.5)
    slide_number(s, 11)
    notes(s, f"""
Play the video now (core cut, about 4½ minutes). Rahul and helpdesk-portal are a story; the app is our seeded test
application with one planted bug per weakness type, and the video caption says so.
What to point out: the false alarm is kept as SUPPRESSED, not deleted; the fake fix is rejected even though every
scanner is quiet; the prompt is pasted into a real AI assistant, and the committed fix is a prepared file (captioned
on screen) so every take gives the same verdict.
If the video fails: the two "demo backup" slides at the end walk the same steps.
""")


def slide_12_results(prs):
    s = add_slide(prs)
    section_label(s, "6 · Results so far")
    headline(s, "The way you ask the AI changes the result")
    by = E2_PILOT["by_strategy"]
    order = sorted(by, key=lambda sid: (-by[sid][0], sid))
    tf = textbox(s, MARGIN_X, 1.85, 7.20, 0.34)
    write(tf, "Fixes that passed all 3 checks, out of 10 bugs — for each way of asking", font=DISPLAY, size=14,
          bold=True, color=NAVY)
    data = CategoryChartData()
    data.categories = [WAYS[sid] for sid in order]
    data.add_series("Fixes that passed all checks", [by[sid][0] for sid in order])
    chart = s.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, Inches(0.60), Inches(2.22), Inches(7.20),
                               Inches(4.00), data).chart
    chart.has_legend = False
    chart.has_title = False
    chart.font.name = BODY
    chart.font.size = Pt(12.5)
    chart.font.color.rgb = INK
    plot = chart.plots[0]
    plot.gap_width = 55
    plot.vary_by_categories = False
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.font.size = Pt(13)
    labels.font.bold = True
    labels.font.color.rgb = NAVY
    labels.number_format = "0"
    labels.number_format_is_linked = False
    labels.position = XL_LABEL_POSITION.OUTSIDE_END
    for i, sid in enumerate(order):
        fill = plot.series[0].points[i].format.fill
        fill.solid()
        fill.fore_color.rgb = TEAL if sid == "S7" else NAVY
    cat = chart.category_axis
    cat.reverse_order = True
    cat.major_tick_mark = XL_TICK_MARK.NONE
    cat.format.line.fill.background()
    cat.has_major_gridlines = False
    val = chart.value_axis
    val.minimum_scale, val.maximum_scale = 0, 10
    val.has_major_gridlines = False
    val.major_tick_mark = XL_TICK_MARK.NONE
    val.tick_label_position = XL_TICK_LABEL_POSITION.NONE
    val.format.line.fill.background()
    s2, s7, s5 = by["S2"], by["S7"], by["S5"]
    for i, (big, title, body) in enumerate((
        (f"{FIXTURE['detected']} / {FIXTURE['seeded']}", "planted bugs found",
         f"{FIXTURE['findings']} issues reported; {FIXTURE['true_positive_findings']} are real"),
        (f"{s2[0]} / {s2[1]}", "bug-specific advice did best",
         f"ours: {s7[0]} / {s7[1]}, using {s7[3] / s2[3]:.1f}× the tokens"),
        (f"{s5[0]} / {s5[1]}", "“review and improve” did worst",
         "best in Paper 3, but here its rewrites broke the code"),
        (f"{E2_PILOT['failed_at']['3b']}", "fixes fooled every scanner",
         "they broke the app; only our behaviour tests caught them"),
    )):
        _stat(s, 8.15, 1.92 + i * 1.03, 4.55, big, title, body, big_w=1.15, big_size=22)
    callout(s, f"A pilot: {E2_PILOT['trials']} fixes by one small local AI model, one try per bug and way. It "
               "shows the ways differ; it does not rank them yet.", y=6.30, h=0.58, size=13)
    slide_number(s, 12)
    notes(s, f"""
Left: 10 planted bugs x 9 ways of asking = {E2_PILOT['trials']} fixes by a local 7B model; each was re-scanned and
checked. Teal is ours. Honest reading: ours did not win - bug-specific advice was best and cheapest; ours spends
extra tokens on "review" rounds, which on a small model sometimes break the code.
Likely question: "So what is your contribution if yours lost?" - the test bench itself; next we test our prompt
without the review rounds, and repeat every run (see next slide). Full numbers are in the appendix.
""")


def slide_13_next(prs):
    s = add_slide(prs)
    section_label(s, "7 · Next two weeks")
    headline(s, "Next two weeks: from a working system to evidence")
    plan = (("31 Oct – 3 Nov", "Finish the experiments",
             "More runs and more bugs; weak vs checked prompts; prompt-injection attack tests; a Copilot check "
             "if time allows"),
            ("4 – 7 Nov", "Security-review our own tool", "Including the web interface; update libraries with "
                                                         "known issues"),
            ("8 – 11 Nov", "Final testing and documents", "Architecture, threat model and results write-ups"),
            ("~13 Nov", "Final review", "Rehearsal on 12 Nov, then the final presentation"),
            ("18 Nov", "Submission", "14–17 Nov kept for feedback and buffer"))
    w, gap = 2.24, 0.225
    for i, (when, title, body) in enumerate(plan):
        x = MARGIN_X + i * (w + gap)
        _white_box(s, x, 1.95, w, 3.20)
        tf = textbox(s, x + 0.20, 2.12, w - 0.40, 0.32)
        write(tf, when, font=DISPLAY, size=14, bold=True, color=TEAL)
        tf = textbox(s, x + 0.20, 2.52, w - 0.40, 0.70)
        write(tf, title, font=DISPLAY, size=15.5, bold=True, color=NAVY, line_spacing=1.0)
        tf = textbox(s, x + 0.20, 3.28, w - 0.40, 1.80)
        write(tf, body, size=13, color=SLATE, line_spacing=1.08)
        if i < len(plan) - 1:
            _arrow(s, x + w + 0.02, 3.42, w=gap - 0.04)
    callout(s, "If we fall behind, the optional items go first (the Copilot check, the extra bugs). Testing and "
               "security work are never cut.", emphasis=True, y=5.50, h=0.72, size=14)
    slide_number(s, 13)
    notes(s, """
Week 1 completes the experiments: repeat runs with a second planted bug per type, our prompt without the review
rounds, weak versus checked prompts, and a set of prompt-injection attacks. Week 2 is a security review of our own
tool. The final review is around 13 November; submission is 18 November.
Likely question: "Can you finish by 18 Nov?" - yes: the system works today, and the cut rule protects the date.
""")


def slide_14_thanks(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 3.05, 8.60, 1.10)
    write(tf, "Thank You", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.20, 8.20, 0.60)
    write(tf, "Questions welcome — TEAM-3", size=16, color=PALE)
    notes(s, "The appendix has a glossary, the full pilot numbers, prepared answers and demo backup screenshots.")


def slide_15_glossary(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — glossary")
    headline(s, "Words we use")
    terms = (
        ("CWE", "a standard ID for a type of bug, e.g. CWE-89 is SQL injection"),
        ("OWASP Top 10", "the ten main web-application risk categories, e.g. A03 Injection"),
        ("CVE", "the ID of a known vulnerability in a specific library version"),
        ("Scanner", "reads code and reports likely bugs: Semgrep, Bandit (code), Gitleaks (secrets), pip-audit "
                    "(libraries)"),
        ("Prompt", "the request a developer types into an AI assistant"),
        ("Prompt checker", "our linter: checks a prompt still has its safety parts"),
        ("Fix-it", "a missing sentence the checker can put back automatically"),
        ("Bug ID", "identifies a bug by rule, file and code (not line number), so it survives edits"),
        ("Bug states", "NEW · STILL_OPEN · RESOLVED · REGRESSION (came back) · SUPPRESSED (false alarm, kept)"),
        ("The 3 checks", "bug gone · nothing new of the same or higher severity · code still works"),
        ("Safe-and-working rate", "share of fixes passing all checks; SecCoderX's Effective Safety Rate"),
        ("Developer / lab mode", "the developer's own AI writes the fix / a local model writes fixes for our "
                                 "experiments"),
        ("SSRF", "tricking a server into requesting internal addresses"),
        ("Prompt injection", "text hidden in input that tries to give the AI new instructions"),
    )
    for i, (term, meaning) in enumerate(terms):
        col, row = divmod(i, 7)
        x, y = 0.60 + col * 6.20, 1.85 + row * 0.68
        tf = textbox(s, x, y, 1.95, 0.60)
        write(tf, term, font=DISPLAY, size=13, bold=True, color=NAVY, line_spacing=1.0)
        tf = textbox(s, x + 2.00, y, 3.90, 0.62)
        write(tf, meaning, size=12, color=SLATE, line_spacing=1.05)
    slide_number(s, 15)
    notes(s, "Appendix. Use it if a term comes up in questions.")


def slide_16_full_results(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — pilot results in full")
    headline(s, "All nine ways of asking, with their token cost")
    by = E2_PILOT["by_strategy"]
    rows = [[sid, WAYS[sid], f"{v} / {a}", f"{esr:.1f}", f"{tok:,}"] for sid, (v, a, esr, tok) in by.items()]
    data_table(s, ["Id", "Way of asking", "Passed all checks", "Rate", "Tokens (10 fixes)"], rows,
               [0.75, 5.20, 2.20, 1.30, 2.65], y=1.80, row_h=0.42, header_pt=12, body_pt=12.5,
               bold_rows=(list(by).index("S2"), list(by).index("S7")))
    failed = E2_PILOT["failed_at"]
    callout(s, f"Where the rejected fixes stopped: check 1 ×{failed['1']}, check 3 static ×{failed['3a']}, check 3 "
               f"behaviour tests ×{failed['3b']}. All {E2_PILOT['dependency_bumps_rejected']} library upgrades "
               "stopped one version short (PyYAML 5.3.1; 5.4 is needed) — our prompt will name the right version.",
            y=6.12, h=0.78, size=12.5)
    slide_number(s, 16)
    notes(s, f"Appendix. Model {E2_PILOT['model']} (digest {E2_PILOT['digest']}), temperature 0, seed 42.")


def slide_17_answers(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — prepared answers")
    headline(s, "Questions we expect")
    for i, (q, a) in enumerate((
        ("“Your own way of asking did not win — so what is new?”",
         "The test bench: 9 ways of asking, the same bugs, the same checks. Finding that bug-specific advice beats "
         "ours is a real result, one the papers could not measure on real fixes."),
        ("“Why not let the AI say whether its fix worked?”",
         "An AI that writes a wrong fix confidently will judge it confidently too. The scanners re-run and our checks "
         "decide; slide 9 shows a fix every scanner accepted that our checks rejected."),
        ("“Who pays for the AI tokens?”",
         "In developer mode we run no AI model: the explanation and the prompt come from templates, and the checker "
         "warns when a prompt gets too long. Lab mode uses a free local model."),
        ("“Why use a small 7B model?”",
         "Lab mode compares ways of asking on the same model; a model that fixed everything would hide the "
         "differences. Developer mode never depends on it."),
    )):
        base._qa_row(s, i, q, a)
    slide_number(s, 17)
    notes(s, "Appendix. Present only if asked.")


def slide_18_backup(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — demo backup (1 of 2)")
    headline(s, "If the video does not play")
    picture(s, "midsem_overview.png", 0.60, 1.80, 5.90,
            caption="Overview: severity, bug states, latest verdicts, OWASP spread, scan trend.")
    picture(s, "midsem_lint.png", 6.80, 1.80, 5.90,
            caption="The checker on a shortened prompt: FAIL, with the sentences that repair it.")
    slide_number(s, 18)
    notes(s, "Walk the demo steps on these screenshots, then the next slide.")


def slide_19_backup(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — demo backup (2 of 2)")
    headline(s, "The fake fix, as the verification page shows it")
    picture(s, "midsem_verification.png", MARGIN_X, 1.80, CONTENT_W,
            caption="Checks 1 and 2 pass (the scanners went quiet); check 3 fails: the function body is a stub. "
                    "Check 3b (behaviour tests) runs only in lab mode.")
    short = {"VERIFIED_RESOLVED": "verified", "FIX_REJECTED": "rejected", "UNVERIFIED": "unverified"}
    commits = [label.split("-")[0] for label in VERIFICATION]
    data_table(s, ["Test commit", *commits],
               [["verdict", *(short[v] for v, _, _ in VERIFICATION.values())],
                ["decided by", *("all checks" if g is None else f"check {g}" for _, g, _ in VERIFICATION.values())]],
               [1.95, *([(CONTENT_W - 1.95) / len(commits)] * len(commits))], y=5.25, row_h=0.42, header_pt=12,
               body_pt=12)
    slide_number(s, 19)
    notes(s, "v2 is the fake fix; v4 edits the bug without fixing it; v5 fixes it but adds a new risky route; v7 runs "
             "while the secrets scanner is down, so it cannot be verified.")


BUILDERS = [
    slide_01_title, slide_02_problem, slide_03_sota_tools, slide_04_sota_research, slide_05_how_it_works,
    slide_06_prompt, slide_07_threat_model, slide_08_usps, slide_09_fake_fix, slide_10_checker, slide_11_demo,
    slide_12_results, slide_13_next, slide_14_thanks, slide_15_glossary, slide_16_full_results, slide_17_answers,
    slide_18_backup, slide_19_backup,
]


def build(out_path: Path) -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(base.SLIDE_W)
    prs.slide_height = Inches(base.SLIDE_H)
    for builder in BUILDERS:
        builder(prs)
    props = prs.core_properties
    props.author = props.last_modified_by = "TEAM-3"
    props.title = "Building a Prompt Assistant for Secure Coding — mid-semester review"
    props.subject = props.keywords = props.comments = ""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    return prs


def main() -> int:
    default_out = ROOT.parent / "Secure_Prompt_Assistant_MidSem_Review_v2.pptx"
    parser = argparse.ArgumentParser(description="Build the plain-language mid-semester review deck")
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
