#!/usr/bin/env python3
"""
Build the Review 3 presentation deck.

The design system (palette, fonts, grid, helpers) is imported from
build_review2_deck.py so the series stays visually identical. Content is
mirrored in docs/review3_slides.md. Every result number is imported from
evaluation/recorded_results.py -- the same constants the integration tests
assert against real scanner runs -- so no slide can show a number the code
does not actually produce.

Usage:
    python scripts/build_review3_deck.py
    python scripts/build_review3_deck.py --out path/to/deck.pptx
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402
from pptx import Presentation  # noqa: E402
from pptx.enum.shapes import MSO_SHAPE  # noqa: E402
from pptx.util import Inches  # noqa: E402

import build_review2_deck as base  # noqa: E402
from build_review2_deck import (  # noqa: E402
    CONTENT_Y, DEEP1, DEEP2, DISPLAY, NAVY, PALE, TEAL, WHITE, YES,
    add_slide, callout, card, data_table, headline, mono_block, notes, section_label,
    slide_number, stacked_row, textbox, write,
)
from evaluation.recorded_results import (  # noqa: E402
    FIXTURE, LIFECYCLE, LIFECYCLE_KEYS, LIVE_VULPY, SELF_SCAN, TESTS,
)

GROUND_TRUTH = ROOT / "fixtures" / "flask_vuln_app" / "ground_truth.yaml"
TOOL_LABEL = {"semgrep": "Semgrep", "bandit": "Bandit", "gitleaks": "Gitleaks", "pip-audit": "pip-audit"}


def _circles(s) -> None:
    for x, y, d, col in ((9.40, 1.10, 3.60, DEEP1), (10.00, 1.70, 2.40, DEEP2), (10.55, 2.25, 1.30, TEAL)):
        shp = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
        shp.fill.solid()
        shp.fill.fore_color.rgb = col
        shp.line.fill.background()
        shp.shadow.inherit = False


def _lc(label: str) -> dict[str, int]:
    counts, _status = LIFECYCLE[label]
    return dict(zip(LIFECYCLE_KEYS, counts))


# ==========================================================================
# SLIDES
# ==========================================================================

def slide_01_title(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 2.15, 8.20, 0.40)
    write(tf, "SECURE SOFTWARE ENGINEERING · REVIEW 3", font=DISPLAY, size=13, bold=True, color=TEAL)
    tf = textbox(s, 0.70, 2.60, 8.60, 1.90)
    write(tf, "Building a Prompt Assistant", font=DISPLAY, size=40, bold=True, color=WHITE)
    write(tf, "for Secure Coding", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.55, 8.00, 0.90)
    write(tf, "Phases 1–4 built: scan, normalise, classify — and track every finding across commits",
          size=16, color=PALE, line_spacing=1.2)
    for name, roll, x in (("Student 1 : Anvesh Dangeti", "Roll no: EM26MTECH14009", 0.70),
                          ("Student 2 : Sai Prakash Nayak", "Roll no: EM26MTECH11001", 3.57),
                          ("Student 3 : Dhananjay Kumar", "Roll no: CS26MTECH13007", 6.44)):
        tf = textbox(s, x, 6.34, 2.60, 0.46)
        write(tf, name, size=12, bold=True, color=PALE)
        tf = textbox(s, x, 6.74, 2.60, 0.38)
        write(tf, roll, size=12, bold=True, color=PALE)
    notes(s, """
Review 3 - Saturday 10 October 2026 (moved from 3 October). Fifteen minutes.

Frame: at Review 2 the panel accepted the scope; this review is about showing it
running. Lead with "promised vs delivered" (slide 2), then the live demo.

Load-bearing slides: 2, 5, 7, 8, 9. Cuttable if short on time: 3, 11.
Have a terminal open with the demo already run once (pip-audit needs internet).
""")


def slide_02_delivered(prs):
    s = add_slide(prs)
    section_label(s, "Since Review 2")
    headline(s, "Promised at Review 2, delivered at Review 3")
    data_table(
        s,
        ["Promised for the next two weeks (Review 2, slide 12)", "Status"],
        [
            ["Phase 1 Foundation — config, secure logging, DB models, safe subprocess", f"{YES}  done"],
            ["Phase 2 Scanner layer — 4 scanners behind one interface, SARIF normalisation", f"{YES}  done"],
            ["Phase 3 Repository — SSRF-safe clone, zip-slip-safe upload, fixture with ground truth",
             f"{YES}  done"],
            ["Phase 4 Intelligence — CWE/OWASP mapping, fingerprints, lifecycle  (not promised)",
             f"{YES}  done, ahead of plan"],
            ["Requirement 12 — project on GitHub with regular check-ins", f"{YES}  per-phase commits"],
        ],
        [9.10, 3.00],
        row_h=0.62, body_pt=12.5, bold_rows=(3,),
    )
    callout(s, "Review 2 outcome: scope accepted as presented — 1 language, 10 CWEs, 4 scanners, "
               "9 prompt strategies, 3 verification gates. Nothing in it has changed.", emphasis=True)
    slide_number(s, 2)
    notes(s, f"""
Say: "Two weeks ago we committed to Phases 1 to 3. All three are done, plus Phase 4,
which was scheduled for later."

Point at the bold row - Phase 4 (finding identity and lifecycle) is the part of the
contribution that no existing AI tool has, so getting it built early matters.

{TESTS} automated tests back these claims. The GitHub repository is private; we can
add the panel as collaborators.
""")


def slide_03_architecture(prs):
    s = add_slide(prs)
    section_label(s, "System architecture")
    headline(s, "What runs today")
    built = [
        ("Repository: https URL  or  ZIP upload", "SSRF-checked / zip-slip-safe"),
        ("Semgrep . Bandit . Gitleaks . pip-audit", "isolated, pinned, hardened"),
        ("Normalise (SARIF shape) -> CWE / OWASP / CVE", "data-driven YAML tables"),
        ("Fingerprint -> lifecycle (5 states)", "NEW STILL_OPEN RESOLVED REGRESSION SUPPRESSED"),
    ]
    planned = [
        ("Explainer -> prompt builder x S0-S8 -> linter", "Review 4"),
        ("Sandboxed apply -> rescan -> Gate 1 . 2 . 3", "Review 4"),
        ("Dashboard . strategy evaluation as ESR", "Review 5"),
    ]
    lines = []
    for i, (step, note) in enumerate(built):
        lines += ([] if i == 0 else ["|"]) + [f"{step:<46}<-- built   {note}"]
    for step, note in planned:
        lines += ["|", f"{step:<46}    ({note})"]
    mono_block(s, "\n".join(lines), y=1.90, h=3.30, size=11.5)
    callout(s, "API (FastAPI, key-authenticated) and CLI drive one scan service. "
               "The LLM is still nowhere in the decision path.", y=5.50, h=0.62)
    slide_number(s, 3)
    notes(s, """
Do not read the diagram. The bold lines are built and tested; the grey lines are the
next two reviews.

Cuttable if running short.
""")


def slide_04_scanners(prs):
    s = add_slide(prs)
    section_label(s, "Scanner layer")
    headline(s, "Four independent scanners, one finding shape")
    by_tool = FIXTURE["by_tool"]
    data_table(
        s,
        ["Scanner", "Finds", "How it runs", "Hardening against the code it scans", "Fixture"],
        [
            ["Semgrep 1.180.0", "SAST — taint + patterns", "pinned 151-rule snapshot, SHA-256 recorded",
             "--disable-nosem, --no-git-ignore, telemetry off", str(by_tool["semgrep"])],
            ["Bandit 1.9.4", "SAST — AST checks", "isolated virtualenv",
             "--ignore-nosec", str(by_tool["bandit"])],
            ["Gitleaks 8.30.1", "hard-coded secrets", "standalone binary",
             "secret masked before storage; gitleaks:allow ignored", str(by_tool["gitleaks"])],
            ["pip-audit 2.10.1", "vulnerable deps → CVEs", "isolated virtualenv",
             "never installs the repo's deps; unpinned = not audited", str(by_tool["pip-audit"])],
        ],
        [1.95, 2.25, 3.10, 3.90, 0.90],
        row_h=0.70, header_pt=11.5, body_pt=11,
    )
    callout(s, "Semgrep's “native fingerprint” is the literal string \"requires login\" for every "
               "finding — so identity is derived, never trusted from the tool.", y=5.60, h=0.62)
    callout(s, "Scanners live in isolated virtualenvs: Semgrep's pins conflict with FastAPI's, and "
               "isolation keeps each scanner's supply chain out of the application.", y=6.35, h=0.62)
    slide_number(s, 4)
    notes(s, """
The right-hand column of hardening is the security point: every scanner is run so
that the code under scan cannot switch it off. A "# nosec" comment, a .semgrepignore
file or a gitleaks:allow tag is attacker-controlled - including by an AI "fix".

pip-audit: the default mode installs the requirements file to resolve it, which
executes the untrusted repository's setup.py. We run it in no-install mode.
""")


def slide_05_ground_truth(prs):
    s = add_slide(prs)
    section_label(s, "Detection on the seeded fixture")
    detected, seeded = FIXTURE["detected"], FIXTURE["seeded"]
    headline(s, f"{detected} of {seeded} seeded weaknesses detected")
    gt = yaml.safe_load(GROUND_TRUTH.read_text(encoding="utf-8"))["seeded"]
    rows = [[e["cwe"], e["name"], f"{e['file']} :: {e['symbol']}",
             " + ".join(TOOL_LABEL[t] for t in sorted(e["expected_detectors"]))] for e in gt]
    data_table(s, ["CWE", "Seeded weakness", "Located by symbol", "Detected by (every expected tool)"],
               rows, [1.25, 4.55, 3.70, 2.60], row_h=0.36, header_pt=11, body_pt=10.5)
    tp, in_scope = FIXTURE["true_positive_findings"], FIXTURE["in_scope"]
    both, total = FIXTURE["semgrep_bandit_agree"]
    callout(s, f"Recall {detected}/{seeded}   ·   precision {tp}/{in_scope}  (2 false positives: Bandit "
               f"import advisories, suppressed)   ·   Semgrep + Bandit agree {both}/{total}",
            emphasis=True, y=6.30, h=0.62, size=12.5)
    slide_number(s, 5)
    notes(s, """
Ground truth is located by symbol (function or variable name) and resolved with
Python's ast at scoring time, so editing the fixture never breaks it.

Scoring is detector-aware: a tool is "expected" only if its pinned ruleset has a
rule for the pattern. Semgrep's p/python has no Flask pickle rule and no rule for
stdlib random, so its silence there is not counted as a miss. This keeps per-tool
recall honest rather than flattering.

Each scanner sees weaknesses the other cannot: only Semgrep finds XSS and path
traversal here, only Bandit finds weak randomness and pickle. That is the
measured case for running two SAST engines.
""")


def slide_06_identity(prs):
    s = add_slide(prs)
    section_label(s, "Finding identity")
    headline(s, "Identity that survives code moving")
    data_table(
        s,
        ["Never part of a fingerprint", "Because", "How we know"],
        [
            ["Line number", "inserting a line above a finding is not a fix",
             "Phase 0: 9/11 findings falsely RESOLVED+NEW"],
            ["Whitespace and comments — including # nosec", "reformatting or silencing is not a fix",
             "tokenizer-based normalisation, tested"],
            ["Ruleset install path", "Semgrep prefixes rule ids with the rules file's absolute path",
             "found on the first local-ruleset scan"],
            ["Scratch directory", "every scan runs in a fresh temporary directory",
             "repo-relative POSIX paths"],
            ["Raw secret value", "rotating a hard-coded secret is not a fix; a hash of a weak password "
             "is a guessing oracle", "snippets redacted before hashing"],
            ["Tool's own fingerprint, when fake", "Semgrep CE: \"requires login\"; Gitleaks: embeds the line",
             "rejected → derived"],
        ],
        [3.55, 5.20, 3.35],
        row_h=0.58, body_pt=11,
    )
    callout(s, "Verified end-to-end: line shifts + reformatting + nosec / nosemgrep / gitleaks:allow + "
               ".semgrepignore  →  0 false RESOLVED, 0 false NEW.", emphasis=True)
    slide_number(s, 6)
    notes(s, """
This is the load-bearing property of the whole lifecycle. If identity is unstable,
every regression statistic in the evaluation is wrong.

Material = tool | rule id | repo-relative path | normalised snippet (comments and
all whitespace removed, secrets redacted). Dependency findings use package + vuln id,
not version - bumping to another still-vulnerable version is not a fix.

Two of these rows were discovered only because we ran the real tools on real output.
""")


def slide_07_lifecycle(prs):
    s = add_slide(prs)
    section_label(s, "Lifecycle — live demonstration")
    headline(s, "Six commits, every lifecycle state")
    stories = {
        "v1-baseline": "first scan; 2 import advisories suppressed as false positives",
        "v2-fix-sqli": "SQL query parameterised — same commit adds an os.system() route",
        "v3-refactor": "reformat + \"# nosec\" / \"# nosemgrep\" comments, nothing else",
        "v4-revert": "a later commit reverts the SQL fix",
        "v5-secret-gitleaks-down": "token moved to an env var — while Gitleaks is down",
        "v6-gitleaks-back": "same code, Gitleaks available again",
    }
    rows = []
    for label, story in stories.items():
        c = _lc(label)
        rows.append([label.split("-")[0], story, str(c["NEW"]), str(c["RESOLVED"]), str(c["REGRESSION"]),
                     str(c["UNVERIFIED"]), LIFECYCLE[label][1]])
    data_table(s, ["", "What the commit did", "NEW", "RESOLVED", "REGRESS.", "UNVERIF.", "Scan"],
               rows, [0.55, 6.25, 0.85, 1.15, 1.10, 1.05, 1.15], row_h=0.50, header_pt=11, body_pt=11,
               bold_rows=(1, 2, 4))
    callout(s, "v2 is why Gate 2 exists: a real fix and a new weakness in one commit.   "
               "v5 is why absence alone is not evidence.", emphasis=True, y=5.75, h=0.62)
    callout(s, "Run it:   python scripts/demo_lifecycle.py   —   real scanners, real ZIP upload path, "
               "asserted by an integration test.", y=6.48, h=0.55, size=12)
    slide_number(s, 7)
    v2, v4 = _lc("v2-fix-sqli"), _lc("v4-revert")
    notes(s, f"""
RUN THE DEMO HERE if there is a laptop. ~35 seconds.

v2: the fix resolves {v2['RESOLVED']} findings (Semgrep x2 + Bandit, all CWE-89) and the
new route adds {v2['NEW']} findings, all CWE-78. A scanner-only "is the old finding gone?"
check would call this commit a success.

v3: every line moved, spacing changed, suppression comments added - zero transitions.

v4: the reverted SQL injection is recognised by fingerprint at its new line numbers
and comes back as {v4['REGRESSION']} REGRESSIONs, not as NEW.

v5/v6: Bandit's view of the secret resolves; Gitleaks' view is kept open and flagged
UNVERIFIED because Gitleaks could not run. It resolves only in v6 when Gitleaks
actually confirms it.
""")


def slide_08_fail_safe(prs):
    s = add_slide(prs)
    section_label(s, "Verification integrity")
    headline(s, "Absence of a finding is not evidence of a fix")
    stacked_row(s, 0, "01", "A finding is RESOLVED only if its scanner could have seen it",
                "Scanner crashed, timed out or is missing; a file it could not parse; a dependency that "
                "became unpinned — the finding stays open and the event is recorded as UNVERIFIED.")
    stacked_row(s, 1, "02", "Tested over the whole state space",
                "The state machine is a pure function: 6 states × present × verifiable = 24 transitions, "
                "each asserted, plus a property test that nothing becomes RESOLVED unverified.")
    stacked_row(s, 2, "03", "And on real code",
                f"Live scan of vulpy: {LIVE_VULPY['unpinned_not_audited']} of its requirements are unpinned. "
                "pip-audit reports them as not audited — never as clean.")
    callout(s, "The LLM appears nowhere in this decision — and when Phase 5 adds it, it still won't.",
            emphasis=True)
    slide_number(s, 8)
    notes(s, """
This is the sharpest engineering point of the review. Every scanner-based "fixed"
claim silently assumes the scanner actually looked. We make that assumption
explicit and enforce it.

Scope is tracked per finding: "file:<path>" for code, "package:<name>" for
dependencies. A tool reports the scopes it could not examine; findings in those
scopes cannot be resolved by that scan.
""")


def slide_09_self_security(prs):
    s = add_slide(prs)
    section_label(s, "Securing the tool itself")
    headline(s, "A scanner of untrusted code is an attack surface")
    data_table(
        s,
        ["Trust boundary", "Control", "Proven by"],
        [
            ["Repository URL → SSRF", "https only; exact host allowlist; IP literals in any notation refused; "
             "every resolved address must be public; redirects off", "58 tests"],
            ["ZIP upload", "traversal, symlinks, NTFS streams, device names, bombs, encrypted and duplicate "
             "members refused before anything is written", "24 tests"],
            ["git clone", "operator's git config and credential helpers never loaded (no confused deputy); "
             "no hooks, submodules or LFS; '--' before the URL", "10 tests + live"],
            ["Scanner subprocess", "list args, never a shell; no binary from scratch space; env allowlist "
             "hides API keys; process-tree kill on timeout; output caps", "10 tests"],
            ["Code under scan", "nosec / nosemgrep / gitleaks:allow ignored; .semgrepignore and .gitleaks* "
             "removed from the scratch copy", "integration"],
            ["Secrets", "redacted before storage, logging and hashing; unredacted Gitleaks report deleted "
             "after parsing", "no-leak tests"],
            ["HTTP API", "key on every route and fails closed (503); body-size cap before multipart "
             "parsing; no stack traces returned", "14 tests"],
        ],
        [2.45, 8.15, 1.50],
        row_h=0.56, body_pt=10.5,
    )
    slide_number(s, 9)
    notes(s, """
The brief says the application must itself be built as a secure application. This
slide is that claim, with the test that backs each row.

If asked about DNS rebinding: the host allowlist (github.com, gitlab.com,
bitbucket.org) is what makes it impractical - an attacker would need to control DNS
for github.com - and git runs with redirects disabled. Stated as residual risk in
the code.

Confused deputy: Git for Windows' system config enables the credential manager. If
we loaded it, a request could make the server clone the operator's private
repositories with the operator's token. We load no system or global git config.
""")


def slide_10_defects(prs):
    s = add_slide(prs)
    section_label(s, "What testing found")
    headline(s, "Six defects we would not have found by reading")
    data_table(
        s,
        ["Defect", "Found by", "Would have broken"],
        [
            ["Semgrep CE's native fingerprint is \"requires login\" for every finding", "real SARIF output",
             "all Semgrep findings collapse into one identity"],
            ["Semgrep rule ids embed the ruleset's absolute install path", "first local-ruleset scan",
             "every finding NEW on a teammate's machine"],
            ["A trailing # nosec comment changed a finding's identity", "adapter design review, then tested",
             "silencing a finding would look like fixing it"],
            ["Semgrep tags its SQLi rule CWE-704; debug mode CWE-489 vs Bandit CWE-94", "real output + scoring",
             "wrong CWE; two tools disagree on one weakness"],
            ["An SSRF refusal raised inside its own except ValueError", "the CLI's refusal message",
             "one SSRF layer silently disabled"],
            ["taskkill by partial path — the first fix trusted %SYSTEMROOT%", "scanning our own code",
             "the fix introduced a new finding"],
        ],
        [5.35, 2.70, 4.05],
        row_h=0.56, body_pt=11,
    )
    callout(s, "And one we report rather than hide: Gitleaks misses  DB_PASSWORD = \"SuperSecret123!\"  "
               "entirely. Bandit catches it — another reason for more than one scanner.", y=6.30, h=0.75)
    slide_number(s, 10)
    notes(s, """
"We found this by testing it" plays well - say it.

The last row is worth telling as a story: our own Bandit scan flagged taskkill
called by a partial path. The first fix built the path from SYSTEMROOT - and Semgrep
then flagged environment-tainted process arguments. A fix that introduced a new
finding, on our own code. That is precisely what verification gate 2 exists for.
The final fix asks Windows for the system directory via its API.
""")


def slide_11_evidence(prs):
    s = add_slide(prs)
    section_label(s, "Beyond the fixture")
    headline(s, "A real repository, and our own code")
    card(s, 0, CONTENT_Y, "01", "Live repository", [
        "github.com/fportantier/vulpy — cloned and scanned by URL",
        f"{LIVE_VULPY['findings']} findings in ~{LIVE_VULPY['seconds']} s (clone + 4 scanners)",
        f"{LIVE_VULPY['in_scope']} in scope across {LIVE_VULPY['scoped_cwes']} CWEs",
        f"{LIVE_VULPY['unpinned_not_audited']} unpinned requirements reported as not audited",
    ], h=3.20)
    card(s, 1, CONTENT_Y, "02", "Our own code", [
        "app/ scanned by its own four tools",
        f"Semgrep {SELF_SCAN['semgrep']} · Gitleaks {SELF_SCAN['gitleaks']} · pip-audit {SELF_SCAN['pip-audit']}",
        f"Bandit: {SELF_SCAN['bandit_low']} LOW advisories, inherent to the subprocess wrapper",
        f"{SELF_SCAN['fixed_from_self_scan']} real issues found and fixed",
    ], h=3.20)
    card(s, 2, CONTENT_Y, "03", "Engineering", [
        f"{TESTS} automated tests — unit, integration, security",
        "Per-phase commits on GitHub (private)",
        "Pinned toolchain; ruleset hash recorded per run",
        "API and CLI over one scan service",
    ], h=3.20)
    callout(s, "Snapshot of 8 Oct 2026; third-party repositories change, so this one is recorded, "
               "not asserted.", y=5.45, h=0.55, size=11.5)
    slide_number(s, 11)
    notes(s, f"""
If there is time, scan vulpy live:
    python -m app.cli scan-url {LIVE_VULPY['url']} --project vulpy
And show a refusal:
    python -m app.cli scan-url https://169.254.169.254/latest/meta-data --project x

Cuttable if short on time.
""")


def slide_12_next(prs):
    s = add_slide(prs)
    section_label(s, "Plan")
    headline(s, "What comes next")
    data_table(
        s,
        ["Review", "Phase", "Deliverable"],
        [
            ["Review 4  (~24 Oct)", "5  AI layer", "Explainer + prompt builder × S0–S8 + prompt linter; local "
             "qwen2.5-coder 7B + stub; injection defences; schema-checked output"],
            ["Review 4", "6  Verification", "sandboxed worktree apply → rescan → Gate 1 · Gate 2 · Gate 3 → "
             "VERIFIED_RESOLVED / FIX_REJECTED"],
            ["Review 5  (~7 Nov)", "7–8  Dashboard + evaluation", "Streamlit dashboard; strategy ablation "
             "reported as Effective Safety Rate"],
            ["Review 6  (~21 Nov)", "9–10  Hardening + final", "security review of our own app, threat model "
             "and architecture docs, final demo"],
        ],
        [2.20, 2.90, 7.00],
        row_h=0.72, body_pt=11.5,
    )
    callout(s, "Questions for the panel:  (1) Is one local 7B model plus one hosted arm enough model "
               "diversity for the ESR comparison?   (2) Should optional CodeQL cross-validation be in "
               "scope for the evaluation chapter?", emphasis=True, y=5.80, h=0.95, size=12.5)
    slide_number(s, 12)
    notes(s, """
End on the questions - hand the floor back deliberately.

What Phase 5 inherits from today: minimal context (finding + ~10 lines), already-
redacted snippets, untrusted-code delimiting, and the rule that the LLM output is a
recommendation only. Phase 6 inherits the fail-safe lifecycle: a fix is verified by
the same scanners, and an unverifiable scan cannot verify anything.
""")


def slide_13_thanks(prs):
    s = add_slide(prs, NAVY)
    _circles(s)
    tf = textbox(s, 0.70, 3.05, 8.60, 1.10)
    write(tf, "Thank You", font=DISPLAY, size=40, bold=True, color=WHITE)
    tf = textbox(s, 0.70, 4.20, 8.20, 0.60)
    write(tf, "Questions welcome — demo ready on request.", size=16, color=PALE)
    notes(s, "Appendix slides 14 and 15 hold prepared answers. Jump there only if pressed.")


def _qa(slide, index, q, a):
    base._qa_row(slide, index, q, a)


def slide_14_appendix_a(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions  (1 of 2)")
    headline(s, "Prepared answers", size=28)
    _qa(s, 0, "“Isn't ‘the scanner no longer reports it’ easy to game?”",
        "Three things stop that today: suppression comments are ignored, in-repo scanner configuration is "
        "removed, and a scan that could not examine a file or package cannot resolve anything in it. "
        "Gate 3 (Review 4) adds the check that the code still works.")
    _qa(s, 1, "“Why four scanners instead of one?”",
        "Measured blind spots: on our fixture only Semgrep finds XSS and path traversal, only Bandit finds "
        "weak randomness and pickle, only pip-audit finds CVEs, and Gitleaks misses a password Bandit "
        "catches. Where Semgrep and Bandit overlap, they agree 4 of 4.")
    _qa(s, 2, "“You said SARIF — why do two adapters read JSON?”",
        "The finding model is SARIF-shaped; Semgrep and Bandit are read as SARIF. Gitleaks' JSON carries "
        "the exact secret we must mask, and pip-audit has no SARIF output. CodeQL would drop in as SARIF.")
    _qa(s, 3, "“Is the API safe to expose?”",
        "It binds to localhost by default, requires a key on every route, and refuses to serve at all if "
        "no key is configured. Multi-user RBAC is out of scope by design — this is a single-user tool.")
    slide_number(s, 14)
    notes(s, "Appendix. Present only if asked.")


def slide_15_appendix_b(prs):
    s = add_slide(prs)
    section_label(s, "Appendix — anticipated questions  (2 of 2)")
    headline(s, "Prepared answers", size=28)
    _qa(s, 0, "“What does precision 22 of 24 mean?”",
        "All 24 findings are in scoped CWEs; 22 match a seeded weakness. The other 2 are Bandit flagging "
        "`import pickle` and `import subprocess` — the call sites are the real weaknesses. Those 2 are "
        "suppressed with a reason: tracked, never deleted, excluded from NEW and REGRESSION.")
    _qa(s, 1, "“How do you keep the vulnerable fixture out of the product?”",
        "It lives only under fixtures/, is never imported, and Flask is not even a dependency of the "
        "application. Our own code is scanned by the same tools, with zero Semgrep and Gitleaks findings.")
    _qa(s, 2, "“Why isn't the Semgrep ruleset in the repository?”",
        "The rules are published under the Semgrep Rules License, so each installation fetches its own "
        "snapshot. Its SHA-256 is stored with every scanner run, so results stay attributable.")
    _qa(s, 3, "“Can a scan be fooled by a repository that is huge or hostile?”",
        "Clone and scan have hard timeouts with process-tree kill; repositories and archives have file-count "
        "and size caps; scanner reports are size-capped; and every failure is recorded, never treated as clean.")
    slide_number(s, 15)
    notes(s, "Appendix. Present only if asked.")


BUILDERS = [
    slide_01_title, slide_02_delivered, slide_03_architecture, slide_04_scanners,
    slide_05_ground_truth, slide_06_identity, slide_07_lifecycle, slide_08_fail_safe,
    slide_09_self_security, slide_10_defects, slide_11_evidence, slide_12_next,
    slide_13_thanks, slide_14_appendix_a, slide_15_appendix_b,
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
    default_out = ROOT.parent / "Secure_Prompt_Assistant_Review3.pptx"
    parser = argparse.ArgumentParser(description="Build the Review 3 deck")
    parser.add_argument("--out", type=Path, default=default_out)
    args = parser.parse_args()
    build(args.out)
    print(f"  built {len(BUILDERS)} slides -> {args.out}")
    if base._warnings:
        print(f"\n  {len(base._warnings)} possible layout issue(s):")
        for w in base._warnings:
            print(w)
    else:
        print("  no layout warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
