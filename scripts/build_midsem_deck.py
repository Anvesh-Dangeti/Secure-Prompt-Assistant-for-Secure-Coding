#!/usr/bin/env python3
"""
Build the mid-semester review deck (Friday 30 October 2026).

The panel asked for seven sections in fifteen minutes -- problem statement,
state of the art, architecture, threat model, USPs, a demonstration of the
existing work, and the next two weeks -- presented as a team. Each slide names
its presenter. The design system is imported from build_review2_deck.py and
the picture/panel helpers from build_review4_deck.py, so the series stays
visually identical. Every result number is imported from
evaluation/recorded_results.py, the constants the tests assert against real
runs. Content is mirrored in docs/midsem_slides.md.

Usage:
    python scripts/build_midsem_deck.py
    python scripts/build_midsem_deck.py --out path/to/deck.pptx
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from pptx import Presentation  # noqa: E402
from pptx.enum.shapes import MSO_SHAPE  # noqa: E402
from pptx.enum.text import PP_ALIGN  # noqa: E402
from pptx.util import Inches  # noqa: E402

import build_review2_deck as base  # noqa: E402
from build_review2_deck import (  # noqa: E402
    CONTENT_W, DISPLAY, MARGIN_X, MONO, NAVY, NO, PALE, PARTIAL, SLATE, TEAL, WHITE, YES,
    add_slide, callout, card, data_table, headline, notes, section_label, slide_number, textbox, write,
)
from build_review4_deck import IMG, _circles, _mini_box, _note_row, _white_box, picture  # noqa: E402
from app.ai.strategies import STRATEGIES  # noqa: E402
from evaluation.recorded_results import E1, E2_PILOT, FIXTURE, TESTS, VERIFICATION  # noqa: E402

STRATEGY_NAMES = {sid: s.name for sid, s in STRATEGIES.items()}
SCREENSHOTS = ("midsem_overview.png", "midsem_prompt.png", "midsem_lint.png", "midsem_verification.png")

ANVESH, DHANANJAY, MUDAY = "Anvesh Dangeti", "Dhananjay Kumar", "Muday Saiprakash Nayak"
TEAM = (("Anvesh Dangeti", "EM26MTECH14009", "lead · architecture · verification"),
        ("Dhananjay Kumar", "CS26MTECH13007", "research · threat model · security testing"),
        ("Muday Saiprakash Nayak", "EM26MTECH11001", "fixtures · evaluation"))


def presenter(slide, name: str) -> None:
    """Top-right: who presents this section -- the panel asked to see the whole team."""
    tf = textbox(slide, 8.60, base.LABEL_Y, 4.13, base.LABEL_H)
    write(tf, f"Presenter · {name}", size=11, bold=True, color=SLATE, align=PP_ALIGN.RIGHT)


def _box(slide, x, y, w, h, title, body, *, fill=WHITE, title_color=NAVY, body_color=SLATE, size=11):
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    shp.line.fill.background()
    shp.shadow.inherit = False
    shp.adjustments[0] = 0.08
    tf = textbox(slide, x + 0.12, y + 0.08, w - 0.24, 0.32)
    write(tf, title, font=DISPLAY, size=12.5, bold=True, color=title_color, align=PP_ALIGN.CENTER)
    tf = textbox(slide, x + 0.12, y + 0.40, w - 0.24, h - 0.45)
    write(tf, body, size=size, color=body_color, align=PP_ALIGN.CENTER, line_spacing=1.05)


def _arrow(slide, x, y, w=0.30, h=0.26):
    shp = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = TEAL
    shp.line.fill.background()
    shp.shadow.inherit = False


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
    tf = textbox(s, 0.70, 4.45, 8.20, 0.90)
    write(tf, "Scan · explain · prompt your own assistant · verify the fix — without trusting the model",
          size=16, color=PALE, line_spacing=1.2)
    for i, (name, roll, role) in enumerate(TEAM):
        x = 0.70 + i * 2.95
        tf = textbox(s, x, 6.10, 2.80, 0.36)
        write(tf, name, size=12, bold=True, color=WHITE)
        tf = textbox(s, x, 6.44, 2.80, 0.30)
        write(tf, roll, size=11, color=PALE)
        tf = textbox(s, x, 6.72, 2.80, 0.30)
        write(tf, role, size=11, color=PALE)
    notes(s, """
TEAM-3 · mid-semester review · Friday 30 October 2026 · fifteen minutes.

Speaking order (each slide names its presenter):
  Anvesh       problem, architecture, USPs, demo           ~8 min
  Dhananjay    state of the art, threat model              ~3 min
  Muday        results so far, the team, next two weeks    ~3 min

Anvesh opens: "Three of us, seven sections, one running system. Dhananjay will
take the literature and the threat model, Muday our results and the plan."
""")


def slide_02_problem(prs):
    s = add_slide(prs)
    section_label(s, "1 · Problem statement")
    presenter(s, ANVESH)
    headline(s, "AI assistants write the fix. Nobody checks it.")
    for col, (num, title, body) in enumerate((
        ("40.95%", "of LLM Python vulnerable",
         "Cicalese et al. (Paper 2): vs Java 8.82%, C 0.78%. 40% of Copilot completions in security-relevant "
         "scenarios were vulnerable (Pearce et al.)."),
        ("1 / 10", "GPT-4o on naive prompts",
         "Backslash Security, 10 CWE cases: 40–90% of AI code vulnerable by default; security-prompted, the best "
         "model reached 10/10. The prompt is the lever."),
        ("14–54%", "safety lost by “secure” methods",
         "SecCoderX: prior secure-generation methods lower the Effective Safety Rate — code that is secure "
         "and still works. A fix that deletes the function is not a fix."),
    )):
        _white_box(s, base.CARD_X[col], 1.95, base.CARD_W, 2.55)
        tf = textbox(s, base.CARD_X[col] + 0.30, 2.10, base.CARD_W - 0.60, 0.65)
        write(tf, num, font=DISPLAY, size=30, bold=True, color=TEAL)
        tf = textbox(s, base.CARD_X[col] + 0.30, 2.78, base.CARD_W - 0.60, 0.40)
        write(tf, title, font=DISPLAY, size=14, bold=True, color=NAVY)
        tf = textbox(s, base.CARD_X[col] + 0.30, 3.20, base.CARD_W - 0.60, 1.25)
        write(tf, body, size=11, color=SLATE, line_spacing=1.1)
    tf = textbox(s, MARGIN_X, 4.75, CONTENT_W, 0.35)
    write(tf, "Three questions no current tool answers together", font=DISPLAY, size=15, bold=True, color=NAVY)
    for i, q in enumerate(("Which way of prompting the developer's assistant actually produces a secure fix?",
                           "Did the fix work — decided by the scanners, not by the model that wrote it?",
                           "Is the same weakness back three commits later?")):
        base.badge(s, 0.70, 5.22 + i * 0.42, 0.32, str(i + 1), label_size=11)
        tf = textbox(s, 1.15, 5.22 + i * 0.42, 11.00, 0.36)
        write(tf, q, size=13, color=NAVY)
    slide_number(s, 2)
    notes(s, """
Say: "Developers already ask Copilot or Cursor to fix what the scanner found. Two
things go wrong. The prompt they write decides how secure the answer is - and
shortening a prompt removes exactly the security constraints. And the fix is
usually accepted because the assistant says it is fixed."

Our project answers three questions with one system: the prompt (measured
strategies plus a linter), the verdict (independent rescan plus gates), and
identity across commits (fingerprints and a lifecycle).

Hand over to Dhananjay: "What exists already?"
""")


def slide_03_sota_tools(prs):
    s = add_slide(prs)
    section_label(s, "2 · State of the art — tools")
    presenter(s, DHANANJAY)
    headline(s, "Each tool has a piece. None joins them.")
    data_table(
        s,
        ["Capability", "Copilot\nAutofix", "Snyk\nCode", "Semgrep\nAssistant", "Defect\nDojo", "Backslash\nRules",
         "Raw\nChatGPT", "Ours"],
        [
            ["Scanner-grounded findings", "CodeQL", YES, YES, "500+", "gen-time", NO, "4 tools"],
            ["Independent re-scan verification", "limited", PARTIAL, PARTIAL, NO, NO, NO, YES],
            ["Fix introduced nothing new", PARTIAL, NO, NO, NO, NO, NO, YES],
            ["Fix preserved functionality", NO, NO, NO, NO, NO, NO, YES],
            ["Cross-commit lifecycle", NO, NO, NO, YES, NO, NO, YES],
            ["Prompt strategy measured", NO, NO, NO, NO, NO, NO, YES],
            ["Developer's own prompt linted", NO, NO, NO, NO, NO, NO, YES],
            ["Open / reproducible / local model", NO, NO, "partial", YES, NO, NO, YES],
        ],
        [3.30, 1.30, 1.15, 1.35, 1.25, 1.30, 1.20, 1.25],
        row_h=0.48, header_pt=10, body_pt=10.5, bold_rows=(2, 3, 5, 6),
    )
    callout(s, "Copilot Autofix (GA August 2024) already closes the scan–fix–rescan loop — we say so, and we do "
               "not claim the loop. Our claim is the measurement and the gates around it.", emphasis=True,
            y=6.40, h=0.62)
    slide_number(s, 3)
    notes(s, """
Dhananjay. Point at the four bold rows: these are what nobody does.

Copilot Autofix: proprietary prompt, CodeQL only, no functional check. DefectDojo:
excellent finding lifecycle, no AI at all. Backslash: their product is a prompt -
a CWE rules file claimed to score 100% - but the ruleset is unpublished and
nothing re-scans or runs the code. We implemented their technique as strategy S8
and measure it under the same gates.
""")


def slide_04_sota_research(prs):
    s = add_slide(prs)
    section_label(s, "2 · State of the art — research")
    presenter(s, DHANANJAY)
    headline(s, "Five results we build on")
    data_table(s, ["Work", "Finding", "What we took"], [
        ["Yan et al. — Paper 1 (arXiv 2506.23034)", "Explained feedback beats raw scanner output; >98% of "
         "explanations correct", "two-stage AI layer: explain, then prompt"],
        ["Cicalese et al. — Paper 2 (arXiv 2607.15937)", "Python 40.95% vulnerable; the constituents that bind an "
         "input to a constraint matter; proposes a prompt linter", "Python scope · the Prompt Security Linter"],
        ["Tony et al. — Paper 3 (ACM TOSEM 34(8))", "Seven prompting techniques; RCI −77.55% weakness density on "
         "GPT-4; persona worse than baseline", "strategies S0–S6 as a measured registry"],
        ["Backslash Security (Apr 2025)", "A CWE rules file in every prompt; claims 100%, unpublished, unverified",
         "strategy S8, measured under our gates"],
        ["SecCoderX (arXiv 2602.07422)", "Effective Safety Rate = secure and still working; prior methods lose "
         "14–54%", "ESR as our headline metric; gate 3"],
    ], [3.35, 5.15, 3.60], row_h=0.70, body_pt=11)
    callout(s, "Gap: the papers measure prompts on generated code; the tools fix repositories without measuring "
               "prompts. We measure prompts on repository fixes, verified independently.", y=6.30, h=0.62)
    slide_number(s, 4)
    notes(s, """
Dhananjay. One line per row - the last column is the point: each work changed a
specific component of the system.

The three assigned papers map to the three parts of the AI layer: the explainer
(Paper 1), the linter (Paper 2), the strategy registry (Paper 3). SecCoderX gives
the metric. Hand back to Anvesh for the architecture.
""")


def slide_05_architecture(prs):
    s = add_slide(prs)
    section_label(s, "3 · Architecture")
    presenter(s, ANVESH)
    headline(s, "Scanners produce evidence. The model only drafts.")
    top = (("Connect", "git URL (SSRF-checked)\nor ZIP (zip-slip-checked)"),
           ("Scan", "Semgrep · Bandit\nGitleaks · pip-audit"),
           ("Normalise + map", "SARIF model\nCWE · OWASP · CVE"),
           ("Track", "fingerprint, not line\nNEW … REGRESSION"),
           ("Explain + prompt", "template explainer\nS0–S8 strategies"),
           ("Lint", "A1–A7 · B1–B5 · C1\nfix-its"))
    w, gap, y = 1.78, 0.285, 1.95
    for i, (title, body) in enumerate(top):
        x = MARGIN_X + i * (w + gap)
        _box(s, x, y, w, 1.15, title, body, size=10.5)
        if i < len(top) - 1:
            _arrow(s, x + w + 0.005, y + 0.45, w=gap - 0.01)
    _box(s, 0.60, 3.45, 5.85, 1.05, "Developer mode — the product",
         "the developer pastes the linted prompt into their own assistant (Copilot, Cursor, Codex), commits; "
         "we rescan. No model of ours, no tokens from us, no repository code executed.", size=11)
    _box(s, 6.85, 3.45, 5.85, 1.05, "Lab mode — the instrument",
         "a local model (qwen2.5-coder 7B, Ollama, loopback) writes the fix into a scratch copy, for the "
         "strategy experiments only. Never your checkout, never over the API.", size=11)
    _box(s, 0.60, 4.80, 12.10, 0.95, "Rescan, same pinned scanners  →  gates 1 · 2 · 3a (both modes) · 3b (lab)",
         "VERIFIED_RESOLVED  ·  FIX_REJECTED with the reason  ·  UNVERIFIED when evidence is missing  →  lifecycle, "
         "history, web interface", fill=NAVY, title_color=WHITE, body_color=PALE, size=11.5)
    for x in (3.40, 9.65):                                   # lint -> both modes -> rescan
        for y in (3.14, 4.53):
            shp = s.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(x), Inches(y), Inches(0.30), Inches(0.26))
            shp.fill.solid()
            shp.fill.fore_color.rgb = TEAL
            shp.line.fill.background()
            shp.shadow.inherit = False
    callout(s, "The model never decides whether a vulnerability is fixed. It explains and drafts; the scanners and "
               "the gates decide.", y=5.95, h=0.58)
    tf = textbox(s, MARGIN_X, 6.62, CONTENT_W, 0.32)
    write(tf, "Python 3.12 · FastAPI · SQLite + SQLAlchemy · Jinja2 + htmx · CLI, API and web interface over the "
              f"same services · {TESTS} automated tests", font=MONO, size=10.5, color=SLATE)
    slide_number(s, 5)
    notes(s, """
Anvesh. Left to right along the top: connect, scan with four tools, normalise to
one SARIF-based model and map to CWE/OWASP (CVE only from pip-audit), track each
finding by a fingerprint rather than a line number, explain and build the prompt
with a chosen strategy, lint it.

Then two modes. Developer mode is the product and answers the Review 3 question
"is it a plugin?": no - it sits beside whatever assistant the developer uses.
Lab mode is only for measuring the strategies.

Bottom: whichever mode, the same scanners re-run and the gates decide.
""")


def slide_06_threat_model(prs):
    s = add_slide(prs)
    section_label(s, "4 · Threat model")
    presenter(s, DHANANJAY)
    headline(s, "A tool that reads hostile code is a target")
    data_table(s, ["Boundary", "Threat (STRIDE)", "Control", "Tested by"], [
        ["Repository URL", "SSRF to internal hosts (I, E)", "https + host allowlist; IP literals refused; resolved "
         "addresses must be public; no redirects", "SSRF suite"],
        ["ZIP upload", "zip-slip, symlinks, bombs (T, D)", "every member path confined; symlinks, devices, NTFS "
         "streams refused; size, count, ratio caps", "archive suite"],
        ["Scanner subprocess", "command injection, hangs (E, D)", "argument lists, never a shell; allowlisted env; "
         "timeouts; process-tree kill", "subprocess tests"],
        ["Code → prompt", "prompt injection via comments (T)", "comments stripped; nonce-delimited, inert-data "
         "instruction; secrets redacted; only the function", "injection tests"],
        ["Model → us", "a confident wrong fix (S, T)", "schema-checked; never executed, never committed; the "
         "gates decide", "lab output tests"],
        ["Running a fix", "untrusted code execution (E)", "lab only, scratch copy, separate interpreter, after "
         "gates 1–3a, timeout", "gate 3b tests"],
        ["Web interface", "XSS, CSRF, DNS rebinding (T, S)", "loopback + Host check; session + CSRF; CSP without "
         "inline script; escaped text only", "payload tests"],
    ], [1.95, 2.70, 5.75, 1.70], row_h=0.56, body_pt=10.5)
    callout(s, "Also: ORM-only queries · secrets redacted from logs and fingerprints · a scanner that did not run "
               "can never resolve a finding · our own app/ self-scanned by its own tools.", y=6.52, h=0.50, size=11.5)
    slide_number(s, 6)
    notes(s, """
Dhananjay. STRIDE letters in brackets: Spoofing, Tampering, Repudiation,
Information disclosure, Denial of service, Elevation of privilege.

The two that matter most for this project: code to prompt (a comment saying
"ignore previous instructions" is attacker input) and model to us (nothing the
model writes is trusted - the scanners and gates decide).

The web interface was built this week; its controls are tested by planting
payloads in rule ids, messages, file names and labels and checking they appear
only as escaped text on every page. Phase 9 is a full review of our own app.
""")


def slide_07_usps(prs):
    s = add_slide(prs)
    section_label(s, "5 · What is new")
    presenter(s, ANVESH)
    headline(s, "Four things this system does that others do not")
    card(s, 0, 1.90, "1", "Prompts, measured", [
        "Nine strategies — Paper 3's seven, ours, Backslash's rules file — on the same findings and gates.",
        "Scored by Effective Safety Rate and verified fixes per 1k tokens."], h=2.95)
    card(s, 1, 1.90, "2", "A linter for prompts", [
        "Paper 2 proposed it; we built it — for the developer's own edited prompt, with fix-its.",
        "Mutation-tested (E1, slide 9)."], h=2.95)
    card(s, 2, 1.90, "3", "Gates, not trust", [
        "Weakness gone · nothing new · function intact · behaviour kept (lab).",
        "A deleted function silences every scanner; the gates still reject it."], h=2.95)
    _mini_box(s, 0, 5.00, "4  Identity across commits",
              "fingerprints survive edits, reformatting and comments — RESOLVED and REGRESSION are real", h=0.98)
    _mini_box(s, 1, 5.00, "Assistant-agnostic",
              "no plugin: works beside Copilot, Cursor, Codex; developer mode calls no model", h=0.98)
    _mini_box(s, 2, 5.00, "Open and local",
              "open-source scanners, a local model for experiments, every number asserted by a test", h=0.98)
    callout(s, "What we do not claim: better detection than CodeQL, better fixes than GPT-4-class models, or the "
               "loop itself. The contribution is the measurement and the verification.", emphasis=True,
            y=6.20, h=0.65)
    slide_number(s, 7)
    notes(s, """
Anvesh. The four numbered items are the USPs; the three small boxes are how a
developer experiences them.

If asked "isn't this Copilot Autofix?": Autofix hides its prompt, uses one
scanner, never checks the function still works, and does not track a finding
across commits. We measure the prompt and verify the result independently.
""")


def slide_08_gates_proof(prs):
    s = add_slide(prs)
    section_label(s, "5 · USP evidence — gates, not trust")
    presenter(s, ANVESH)
    headline(s, "The scanners went quiet. The fix was rejected.")
    picture(s, "midsem_verification.png", MARGIN_X, 1.85, CONTENT_W,
            caption="Web interface → Verify, finding #5 (Bandit B602 in ping_host): the v2 commit emptied the "
                    "function.")
    short = {"VERIFIED_RESOLVED": "verified", "FIX_REJECTED": "rejected", "UNVERIFIED": "unverified"}
    commits = [label.split("-")[0] for label in VERIFICATION]
    data_table(s, ["Eight scripted commits", *commits],
               [["verdict", *(short[v] for v, _, _ in VERIFICATION.values())],
                ["decided by", *("all gates" if g is None else f"gate {g}" for _, g, _ in VERIFICATION.values())]],
               [1.95, *([(CONTENT_W - 1.95) / len(commits)] * len(commits))], y=5.05, row_h=0.36, header_pt=10.5,
               body_pt=10.5)
    callout(s, "A scanner-only check accepts v2 — deleting vulnerable code deletes the finding too. Gate 3a sees "
               "the stub; the next commit, a real fix, verifies.", emphasis=True, y=6.30, h=0.60)
    slide_number(s, 8)
    notes(s, """
Anvesh. The headline result in one screen. v2: every CWE-78 finding is gone from
ping_host (gate 1 PASS) because the body was replaced by `pass` - gate 3a FAILs
and the verdict is FIX_REJECTED with the reason recorded.

The list on the right is scripts/demo_verify.py: churn (v4) is caught by gate 1, a
new os.system route added in the same commit (v5) by gate 2, and v7 is UNVERIFIED
because Gitleaks was down - never "verified" on missing evidence.
""")


def slide_09_linter_proof(prs):
    s = add_slide(prs)
    section_label(s, "5 · USP evidence — the linter, mutation-tested (E1)")
    presenter(s, ANVESH)
    headline(s, "Cut the prompt; the linter notices")
    ops = E1["by_operator"]
    n = E1["findings"]
    shown = ("delete opening", "delete directive", "delete guard", "delete scope", "delete inert-data instruction",
             "genericise directive + guard", "truncate to the opening")
    data_table(s, ["Edit to the S7 prompt", "Fails lint", "Flagged"],
               [[name, f"{ops[name][0]} / {n}", f"{ops[name][1]} / {n}"] for name in shown],
               [4.20, 1.30, 1.30], row_h=0.44, body_pt=11)
    c, u = E1["constituent"], E1["unchecked"]
    _note_row(s, 0, "✓", f"{c['flagged']} / {c['mutants']} flagged",
              f"every edit that removes a constituent is reported; {c['failed']} fail outright, and their fix-its "
              "repair all of them", x=7.55, w=5.15, pitch=1.25)
    _note_row(s, 1, "0", f"0 / {u['mutants']} false alarms",
              "deleting the explanation, classification, code or output contract — which no rule protects — "
              "raises nothing", x=7.55, w=5.15, pitch=1.25)
    _note_row(s, 2, "!", "Found by E1, fixed",
              "S7's guard restates the mitigation, so a deleted directive still passed; A7 now flags a generated "
              "sentence that was edited out", x=7.55, w=5.15, pitch=1.25)
    callout(s, f"{n} real findings × 12 edits, no model, re-run by a test on every build.  Gap kept honest: code "
               "pasted without delimiters is flagged 16/24 (one-line snippets slip through).", y=6.30, h=0.62,
            size=12)
    slide_number(s, 9)
    notes(s, f"""
Anvesh. E1 asks: when a developer edits our prompt, does the linter notice what
they removed? For each of the {n} real findings we built the S7 prompt and made
twelve kinds of edit - delete each paragraph, replace the directive and guard
with "make it secure", truncate to the first sentence, strip the delimiters.

"Flagged" includes warnings: a deleted directive whose meaning survives in the
guard sentence is a warning, not an error - the prompt still says how to fix it.
Before E1 the linter flagged that case only 9/24 times; it is a real defect that
mutation testing found, and the fix is in the code.
""")


def slide_10_demo(prs):
    s = add_slide(prs)
    section_label(s, "6 · Demo of the existing work")
    presenter(s, ANVESH)
    headline(s, "Live: one finding, from scan to verified fix")
    picture(s, "midsem_prompt.png", MARGIN_X, 1.95, 7.20,
            caption="Prompt & lint: an S7 prompt (here for the path traversal), ready to copy into any assistant.")
    for i, (num, title, body) in enumerate((
        ("1", "Scan", "upload the vulnerable Flask fixture; 24 findings, 10/10 seeded weaknesses"),
        ("2", "Prompt + lint", "build S7 for the shell injection; shorten it → FAIL; fix-its → PASS"),
        ("3", "Fix + verify", "apply the assistant's change; rescan; gates 1 · 2 · 3a → VERIFIED_RESOLVED"),
        ("4", "Rejected fix", "the stubbed function from slide 8, rejected at gate 3a"),
    )):
        _note_row(s, i, num, title, body, x=8.15, w=4.55, pitch=1.05)
    callout(s, "http://127.0.0.1:8080 — the web interface built this week, over the same services as the CLI. "
               "Backup: screenshots and a recorded run.", y=6.30, h=0.62, size=12)
    slide_number(s, 10)
    notes(s, """
DEMO - about five minutes. Follow docs/midsem_presenter_script.md, part B.

Before the review: web interface running on a fresh database with the fixture
copy scanned once; the browser signed in on the Overview page; a terminal open
on the checkout copy for the hand fix.

If anything fails, switch to the backup slides (appendix) - do not debug live.
""")


def slide_11_results(prs):
    s = add_slide(prs)
    section_label(s, "6 · Existing work — results so far")
    presenter(s, MUDAY)
    headline(s, "Results so far: the strategy matters")
    by = E2_PILOT["by_strategy"]
    rows = [[sid, STRATEGY_NAMES[sid], f"{v} / {a}", f"{esr:.1f}", f"{tok:,}"] for sid, (v, a, esr, tok) in by.items()]
    best = max(by, key=lambda k: by[k][2])
    data_table(s, ["", "Strategy", "Verified", "ESR", "Tokens"], rows, [0.55, 2.10, 1.05, 0.70, 0.95], row_h=0.405,
               header_pt=11, body_pt=10.5, bold_rows=(list(by).index(best), list(by).index("S7")))
    failed = E2_PILOT["failed_at"]
    s2, s7, s5 = by["S2"], by["S7"], by["S5"]
    _note_row(s, 0, "10", "of 10 seeded weaknesses detected",
              f"{FIXTURE['findings']} findings from four scanners; precision {FIXTURE['true_positive_findings']}/"
              f"{FIXTURE['in_scope']}; Semgrep and Bandit agree on {FIXTURE['semgrep_bandit_agree'][0]}/"
              f"{FIXTURE['semgrep_bandit_agree'][1]}", x=6.15, w=6.55, pitch=1.15)
    _note_row(s, 1, "E2", f"{E2_PILOT['verified']} of {E2_PILOT['trials']} live fixes verified — strategy matters",
              f"CWE-specific guidance (S2) {s2[0]}/10; ours (S7) {s7[0]}/10 at {s7[3] / s2[3]:.1f}× the tokens; "
              f"Paper 3's RCI (S5) only {s5[0]}/10 — its rewrites broke behaviour", x=6.15, w=6.55, pitch=1.15)
    _note_row(s, 2, "3b", f"{failed['3b']} scanner-clean fixes broke behaviour",
              f"only the behaviour tests caught them; gate 1 rejected all {E2_PILOT['dependency_bumps_rejected']} "
              "PyYAML bumps that stopped at a version with a remaining CVE", x=6.15, w=6.55, pitch=1.15)
    callout(s, "A pilot: one trial per (weakness, strategy), one 7B model, temperature 0. It shows the strategies "
               "differ; it does not rank them. Full E2, an S7-without-RCI ablation and E3 come next.",
            y=6.30, h=0.62, size=12)
    slide_number(s, 11)
    notes(s, f"""
Muday. Left: the E2 pilot. Ten seeded weaknesses x nine strategies = {E2_PILOT['trials']} lab
trials with qwen2.5-coder 7B (digest {E2_PILOT['digest']}), every fix rescanned with all four tools
and judged by all four gates. ESR = verified / applicable (Effective Safety Rate,
as in SecCoderX: secure and still working).

Honest reading: our S7 did not win. CWE-specific guidance in one turn (S2) did best
and cheapest. S7 includes RCI's three turns, and on a 7B model the critique turns
cost about five times the tokens and sometimes break behaviour - S5, pure RCI,
shows that most clearly. The next run separates the two: S7 without RCI.

Rejections: gate 1 x{failed['1']}, gate 3a x{failed['3a']}, gate 3b x{failed['3b']}. Every model pinned PyYAML
5.3.1 - the version the advisory named - but a second advisory needs 5.4, so gate 1
rejected all nine. Our prompt should name the highest fixed version; that is fixed
before the full run.

The pilot also found two measurement problems before the real run, and we fixed
them in the open: imports written as a bare module name, and the behaviour tests
running without the API_TOKEN a deployment would set.
""")


def slide_12_team(prs):
    s = add_slide(prs)
    section_label(s, "The team")
    presenter(s, MUDAY)
    headline(s, "Who built what")
    data_table(s, ["Member", "Owned", "Phases led"], [
        ["Anvesh Dangeti", "architecture; scanners, normalisation, repository handling; the AI layer; "
                           "verification gates; the web interface", "1–7, 7b, 10"],
        ["Dhananjay Kumar", "literature review and landscape; threat model; security testing — SSRF, archive, "
                            "injection and web payload suites", "9"],
        ["Muday Saiprakash Nayak", "the vulnerable fixture and its ground truth; behaviour tests for gate 3b; the "
                                   "evaluation harness, E1 and E2", "8"],
    ], [2.70, 7.60, 1.80], row_h=0.62, body_pt=11.5)
    _mini_box(s, 0, 4.85, "Reviews so far", "R1 ideation · R2 scope accepted · R3 Phases 1–4 · today: the whole "
                                            "system", h=1.05)
    _mini_box(s, 1, 4.85, "Engineering", f"per-phase commits on GitHub · {TESTS} automated tests · every result "
                                        "asserted", h=1.05)
    _mini_box(s, 2, 4.85, "Decisions", "every choice traced to a paper or a measurement; two reversed on "
                                      "evidence", h=1.05)
    slide_number(s, 12)
    notes(s, """
Muday. Name the ownership; keep it short. The repository's phase log records who
led each phase and every design decision with its source.
""")


def slide_13_next(prs):
    s = add_slide(prs)
    section_label(s, "7 · Next two weeks")
    presenter(s, MUDAY)
    headline(s, "From a working system to measured evidence")
    data_table(s, ["Dates", "Work", "Deliverable"], [
        ["31 Oct – 3 Nov", "8  Evaluation", "E2 in full (repeat runs; a second seeded instance per CWE) · E3 weak "
                                            "vs linted prompts · prompt-injection corpus · E4 Copilot spot-check "
                                            "(should)"],
        ["4 – 7 Nov", "9  Hardening", "security review of our own application, the web interface included; "
                                      "retire Streamlit; dependency upgrades"],
        ["8 – 11 Nov", "10  Final", "integration and regression testing; architecture, threat-model and "
                                    "evaluation documents"],
        ["12 – 13 Nov", "Final review", "rehearsal, then the final presentation"],
        ["18 Nov", "Submission", "14–17 November kept for review feedback and buffer"],
    ], [1.85, 2.15, 8.10], row_h=0.60, body_pt=11.5)
    callout(s, "Cut rule, unchanged since Review 3: a phase more than two days late drops the next Should item "
               "(E4, the second instance) — never tests or hardening.", emphasis=True, y=5.85, h=0.62)
    callout(s, "Question for the panel: is one local open model across all nine strategies an acceptable scope for "
               "E2, with a hosted model as stretch?", y=6.55, h=0.50, size=12)
    slide_number(s, 13)
    notes(s, """
Muday. End on the question - hand the floor back deliberately.

Dependency note for Phase 9: our own audit found new advisories in two
development-only packages (Pillow via the deck builder and Streamlit, certifi);
neither is reachable from untrusted input, and both are upgraded when Streamlit is
retired.
""")


def slide_14_thanks(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 3.05, 8.60, 1.10)
    write(tf, "Thank You", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.20, 8.20, 0.60)
    write(tf, "Questions welcome — TEAM-3", size=16, color=PALE)
    notes(s, "Appendix slides hold the demo backup and prepared answers. Jump there only if needed.")


def slide_15_backup(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — demo backup")
    headline(s, "If the live demo fails", size=28)
    picture(s, "midsem_overview.png", 0.60, 1.85, 5.90,
            caption="Overview: severity, lifecycle, latest verdicts, OWASP spread, scan trend.")
    picture(s, "midsem_lint.png", 6.80, 1.85, 5.90,
            caption="Lint of a shortened prompt: FAIL, with the sentences that repair it.")
    slide_number(s, 15)
    notes(s, "Walk the same four steps on these screenshots and slide 8.")


def slide_16_answers(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions")
    headline(s, "Prepared answers", size=28)
    base._qa_row(s, 0, "“Your own strategy did not win the pilot — so what is the contribution?”",
                 "The testbed is: nine strategies on the same findings under the same gates. A pilot where a "
                 "CWE-specific prompt beats ours is a result, and exactly the kind the papers could not measure "
                 "on repository fixes.")
    base._qa_row(s, 1, "“Why not let the model decide whether its fix worked?”",
                 "A model that writes a wrong fix confidently judges it confidently too. The scanners re-run and the "
                 "gates decide; slide 8 is a fix every scanner accepted that the gates rejected.")
    base._qa_row(s, 2, "“Who pays for the tokens?”",
                 "In developer mode we call no model: the explanation is a template, the prompt is built locally, "
                 "and the linter's C1 rule warns above a budget. Lab mode runs a local model.")
    base._qa_row(s, 3, "“A 7B model is weak — why use it?”",
                 "Lab mode compares strategies on the same model; a model that fixed everything would hide the "
                 "differences. Developer mode never depends on it.")
    slide_number(s, 16)
    notes(s, "Appendix. Present only if asked.")


BUILDERS = [
    slide_01_title, slide_02_problem, slide_03_sota_tools, slide_04_sota_research, slide_05_architecture,
    slide_06_threat_model, slide_07_usps, slide_08_gates_proof, slide_09_linter_proof, slide_10_demo,
    slide_11_results, slide_12_team, slide_13_next, slide_14_thanks, slide_15_backup, slide_16_answers,
]


def build(out_path: Path) -> Presentation:
    prs = Presentation()
    prs.slide_width = Inches(base.SLIDE_W)
    prs.slide_height = Inches(base.SLIDE_H)
    for builder in BUILDERS:
        builder(prs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    return prs


def main() -> int:
    default_out = ROOT.parent / "Secure_Prompt_Assistant_MidSem_Review.pptx"
    parser = argparse.ArgumentParser(description="Build the mid-semester review deck")
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
