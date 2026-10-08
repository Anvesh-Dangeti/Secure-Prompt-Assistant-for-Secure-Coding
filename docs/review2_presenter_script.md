# Review 2 — Presenter Script

**Date:** 19 September 2026 · **Duration:** ~15 minutes · **Team:** TEAM-3
**Deck:** `../../Secure_Prompt_Assistant_Review2.pptx` (16 slides)

Everything here is extracted from the deck's own speaker notes, so this and the notes pane cannot
drift apart. Rehearse from this page; present from the deck.

---

## Before you walk in

**Timing.** 12 presented slides, roughly **70 seconds each**. Slides 13–16 are the closing slide and
three appendix slides — you do not present those.

**The four that carry the argument: 3, 4, 7, 9.** If you are running short, cut **10 and 11**. Never
cut those four.

**The frame for the whole talk:** the panel gave us four action items, and answering the first one
changed the project. Do not bury that — lead with it on slide 3.

**Demo is live and takes ~2 seconds.** Verified working today in both Git Bash and PowerShell:

```
cd Secure-Prompt-Assistant-for-Secure-Coding
python scripts/demo_scan.py fixtures/vuln_demo
```

Expected: 11 findings · 10 in scope · 5 OWASP categories · 8/8 ground-truth recall · exit 0.
That matches the numbers printed on slide 12, so you can run it without contradicting the slide.

---

## Slide-by-slide

### 1 — Building a Prompt Assistant for Secure Coding

Title slide. Keep it to names and move.

---

### 2 — Four questions, four answers

> **Say:** *"We'll take these in order, but the honest place to start is action item 1 — because what
> we found there changed the project."*

Keep this slide short. It is a roadmap, not a result.

---

### 3 — The loop we proposed at Review 1 already ships ⚑

**MOST IMPORTANT SLIDE — do not rush it.**

> **Say:** *"We'd rather tell you this than have you find it. Our Review 1 pitch was 'closed-loop
> verification.' That's a shipped GitHub product. So the real question became: what do these tools
> genuinely NOT do?"*

**If asked "isn't this just Copilot Autofix?"**
No, and we opened with that. Autofix hides its prompt, validates only against the default query
suite, uses one scanner, and doesn't check the fix preserved functionality. We measure eight
prompting strategies against real findings, verify against three gates, and track identity across
commits. We're not claiming better fixes than GPT-4 — we're claiming a measurement nobody has made.

---

### 4 — Three empty columns ⚑

**MOST IMPORTANT SLIDE. Point at the four bold rows.**

> **Say:** *"Every tool hides its prompt. Nobody checks the fix still works. And the one tool that
> does finding lifecycle properly has no AI at all."*

The four bold rows are the contribution. Everything else on this slide is context.

**If asked why not CodeQL, since all three papers use it:**
It's the strongest citation anchor, so we've wired it as an optional adapter for the evaluation
chapter. It needs a database build per scan — too slow for the interactive loop. Semgrep and Bandit
give two independent engines with sub-second scans and an agreement metric.

---

### 5 — Three papers, three findings we build on

One sentence per paper, then move. The detail lives in `docs/literature_review.md`.

The arrow at the end of each row is the point — each paper changed a specific component, not just
the bibliography.

---

### 6 — One language: Python

> **Say:** *"One language: Python. It is where LLM-generated code is measurably least secure —
> 40.95% vulnerable versus 8.82% for Java and 0.78% for C — it is the only language where all four
> of our scanners work, and it is the language of every benchmark we want to compare against."*

**If pressed on why not add a second language:** the professor asked for depth over breadth, and
Java is the worst possible second choice given the 86.81% analysis failure rate.

---

### 7 — 8 core CWEs + 2 supporting → 7 of 10 OWASP categories ⚑

**MOST IMPORTANT SLIDE for the scope question.**

> **Say:** *"The top four rows are the four CWEs Paper 3 measured as most prevalent in LLM-generated
> Python. CWE-78 is in scope BECAUSE no prompting technique fixes it — that's an open problem, which
> makes it a better research target than a solved one."*

**If told ten still sounds like a lot:**
Eight are core, two come free from dependency and config scanning. Each gets exactly one seeded
instance in our fixture with recorded ground truth, so we can compute real precision and recall.
Ten CWEs × nine strategies is ninety runs per model arm — tractable locally. We'd rather defend ten
with evidence than claim thirty without.

---

### 8 — What we now claim

Read the claim sentence **out loud, slowly**. It is the thesis statement of the project.

Then walk the right-hand column of the table — that is what changed.

**If asked what's genuinely novel in one sentence:**
Nobody has measured which prompting technique produces scanner-verified fixes on real repository
findings, and nobody checks whether the fix broke the program — even though the literature documents
LLMs renaming functions `secure_*` without changing them.

---

### 9 — A fix that deletes the vulnerable code passes any scanner-only check ⚑

**MOST IMPORTANT SLIDE for novelty. This is the sharpest thing we have.**

> **Say:** *"Everyone checks whether the scanner stopped complaining. Nobody checks whether the code
> still works. Paper 3 documents LLMs renaming a function `secure_` and leaving the body unchanged —
> under a scanner-only criterion that's a perfect score."*

Gate 3 is cheap to build and no existing tool has it. Lean on that.

**If asked whether "scanner says it's gone" is a weak definition of secure:**
Yes, and we say so in the threat-model section. Our claim is precisely: the scanner no longer detects
this weakness, the fix introduced nothing new, and the code still runs — strictly stronger than
what's published, and we don't overclaim beyond it.

---

### 10 — Where the changes land *(cuttable)*

**Do not read the diagram.** Point at the three arrows on the right — those are the three new
components, one per paper.

Then say the design rule out loud: the LLM explains and drafts, it never decides fix status. That was
right at Review 1, and the triple gate now enforces it harder.

---

### 11 — Five gaps, and how we measure against them *(cuttable)*

The sanity check at the bottom is worth saying explicitly — it shows we thought about whether our own
measurement instrument is trustworthy, which is the kind of thing a panel rewards.

If you must cut this slide, try to still say the sanity-check line.

---

### 12 — Where we are

**End on the questions card — hand the floor back to the panel deliberately.**

If there is time and a laptop, run the demo live (~2 seconds):

```
python scripts/demo_scan.py fixtures/vuln_demo
```

**Two defects worth mentioning if asked what we learned building it:**

1. Bandit embeds line numbers in its code snippet, which leaked into fingerprints — a 12-line
   insertion that touched nothing turned **9 of 11 findings into false RESOLVED plus false NEW**.
   Fixed; now 11/11 stable.
2. Bandit reports hard-coded credentials as **CWE-259**, the child of **CWE-798**. Without
   canonicalisation, two tools finding one weakness count as two. Paper 3 makes the same point.

*"We found this by testing it"* plays well.

---

### 13 — Thank You

Appendix slides 14 and 15 hold prepared answers. Jump there only if pressed.

---

## Appendix slides 14–15 — the seven prepared answers

Do not present these. Jump to them only if the panel asks directly.

| # | Question | Core of the answer |
|---|---|---|
| 1 | *Isn't this just Copilot Autofix?* | Autofix hides its prompt, validates only the default query suite, one scanner, no functional check. We measure 9 strategies, 3 gates, cross-commit identity. |
| 2 | *Why not CodeQL, since all three papers use it?* | Wired as an optional evaluation adapter. Needs a DB build per scan — too slow for the live loop. Semgrep + Bandit give two engines and an agreement metric. |
| 3 | *Ten CWEs still sounds like a lot.* | Eight core, two free from dependency/config scanning. One seeded instance each with ground truth → real precision and recall. 90 runs per model arm (9 strategies). |
| 4 | *What if the local 7B model produces bad fixes?* | Then that **is** the result — it is gap G5, which nobody has measured. A hosted arm runs alongside, so we report open vs proprietary on scanner-verified repair. |
| 5 | *How do you handle false positives?* | A `SUPPRESSED` lifecycle state — human-marked, tracked, never deleted, excluded from new and regression counts. Plus the Semgrep/Bandit agreement metric measures disagreement rather than hiding it. |
| 6 | *Isn't "scanner says it's gone" a weak definition of secure?* | Yes, and we say so in the threat model. Our claim is exactly: weakness no longer detected, nothing new introduced, code still runs. Stronger than what's published; we don't overclaim. |
| 7 | *What did you actually learn building the demo?* | The two fingerprint/CWE-hierarchy defects above. Good answer to any "what have you built" probe. |
| 8 | *Is this not what Backslash / Cursor rules already do?* | They ship a CWE rules file and report 100% — on seeded *generation* scenarios, with no published ruleset, no independent re-scan, no functional check and no cross-commit tracking. We added their technique to the registry as **S8** and will measure it on real scanner findings under all three gates. If it holds up, that is a result; if it does not, that is a bigger one. |
| 9 | *Why not train the model, like SafeCodeX?* | Different axis. SafeCodeX (NUS, arXiv:2602.07422) changes the model with online RL — needs weights and GPUs. We change the prompt: inference-time, black-box, works on a repository we do not own. We adopt their **Effective Safety Rate** metric, and their finding that prior methods *degrade* ESR by **14–54%** is the hardest evidence going for why gate 3 exists. |

---

## Numbers you must not get wrong

Every one of these was re-verified against the original PDFs today.

| Number | Means | Source |
|---|---|---|
| **40.95%** | of LLM-generated Python snippets were vulnerable (Java 8.82%, C 0.78%) | Paper 2, Table II |
| **86.81%** | of Java snippets failed static analysis | Paper 2, §IV-A |
| **77.55%** | weakness-density reduction from RCI on GPT-4 | Paper 3, §7.1 |
| **κ = 0.87** | Bandit's agreement with manual review | Paper 3, §6.3 |
| **>98%** | of LLM explanations of scanner output were correct and actionable | Paper 1, §5.3 |
| **54 → 3** | Flask debug-mode instances, baseline → RCI, GPT-4 | Paper 3, §7.2 |
| **21 → 5** | hard-coded credential instances, baseline → RCI, GPT-4 | Paper 3, §7.2 |
| **40%** | of Copilot completions in security-relevant scenarios were vulnerable | Pearce et al., CACM 2025 |
| **Aug 2024** | Copilot Autofix went GA — why we repositioned | GitHub |
| **3× / 7× / 12×** | Autofix speed-up: overall / XSS / SQL injection | GitHub |

**Our own numbers:** 11 findings · 10 in scope · 5 OWASP categories · 8/8 ground-truth recall ·
4/4 scanner tests passing.

---

## The three questions we are putting to the panel

1. Is the repositioned contribution — measured prompting strategies, triple-gate verification,
   cross-commit lifecycle — sufficiently novel, given Copilot Autofix exists?
2. Is 10 CWEs the right size, or should we narrow to the 4 that Paper 3 measured as most prevalent?
3. Should CodeQL be added as a third SAST engine for the evaluation chapter, accepting the runtime
   cost?
