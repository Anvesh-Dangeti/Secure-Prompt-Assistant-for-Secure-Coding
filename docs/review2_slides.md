# Review 2 — Slide Content

**Date:** 19 September 2026 · **Duration:** ~15 minutes · **Team:** TEAM-3

Paste each block into the existing `Secure_Prompt_Assistant_Ideation.pptx` template — same house
style: ALL-CAPS section label, bold headline, short body blocks, slide number bottom-right.

**Suggested timing:** 12 slides, ~60–75 seconds each. Slides 3, 4 and 7 are the ones that matter —
if you run short, cut slides 9 and 10, not those.

---

## Slide 1 — Title

> **SECURE SOFTWARE ENGINEERING · REVIEW 2**
>
> # Building a Prompt Assistant for Secure Coding
>
> **Revised scope, literature review and competitive landscape**
>
> Anvesh Dangeti — EM26MTECH14009
> Sai Prakash Nayak — EM26MTECH11001
> Dhananjay Kumar — CS26MTECH13007

---

## Slide 2 — What we were asked to do

> **REVIEW 1 ACTION ITEMS**
> ## Four questions, four answers
>
> | # | Action item | Where it is answered |
> |---|---|---|
> | 1 | Research existing prompt assistants | `related_tools.md` — 6 tool categories surveyed |
> | 2 | Finalize language scope | **Python only** — with measured justification |
> | 3 | Finalize vulnerability scope | **10 CWEs, 7 OWASP categories** |
> | 4 | Conduct literature review | 3 assigned papers + 14 supporting works → **5 research gaps** |
> | 5 | Update project scope | **13 changes** to the architecture and plan |
>
> *Every decision in this deck traces to a paper finding or an existing tool's limitation.*

**Say:** "We'll take these in order, but the honest place to start is action item 1 — because what we
found there changed the project."

---

## Slide 3 — The uncomfortable finding ⚠️ *most important slide*

> **EXISTING SOLUTIONS**
> ## The loop we proposed at Review 1 already ships
>
> **GitHub Copilot Autofix** — generally available since **August 2024**
>
> CodeQL raises an alert → an LLM drafts a fix → **CodeQL re-runs to validate it**
> GitHub's own slogan: ***"found means fixed."***
>
> - Covers **90%+** of alert types in JavaScript, TypeScript, Java and Python
> - Fixes land **3× faster** overall — **7×** for XSS, **12×** for SQL injection
>
> ### So we are no longer claiming that loop as our contribution.

**Say:** "We'd rather tell you this than have you find it. Our Review 1 pitch was 'closed-loop
verification.' That's a shipped GitHub product. So the real question became: what do these tools
genuinely *not* do?"

---

## Slide 4 — What the existing tools don't do ⚠️ *most important slide*

> **COMPETITIVE LANDSCAPE**
> ## Three empty columns
>
> | Capability | Copilot Autofix | Snyk Code | Semgrep Assistant | DefectDojo | Backslash Rules | Raw ChatGPT | **Ours** |
> |---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
> | Scanner-grounded findings | ✅ CodeQL only | ✅ | ✅ | ✅ 500+ | ❌ gen-time | ❌ | ✅ 4 tools |
> | Independent re-scan verification | ✅ limited | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ✅ |
> | **Fix introduced nothing new** | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
> | **Fix preserved functionality** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
> | **Cross-commit lifecycle** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
> | **Prompt strategy measured** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
> | Open / reproducible / local LLM | ❌ | ❌ | partial | ✅ | ❌ | ❌ | ✅ |
>
> **DefectDojo has lifecycle without AI. Copilot Autofix has AI without lifecycle. Nobody has joined them.**

**Say:** "Every tool hides its prompt. Nobody checks the fix still works. And the one tool that does
finding lifecycle properly has no AI at all."

---

## Slide 5 — Literature review: the three papers

> **ACADEMIC LITERATURE**
> ## Three papers, three findings we build on
>
> **Paper 1 — Yan et al., *Guiding AI to Fix Its Own Flaws* (arXiv 2506.23034)**
> Raw scanner output is weak feedback. **"Explained feedback"** — scanner output enriched by an LLM
> into contextualised, actionable guidance — substantially improves repair. **>98%** of those
> explanations were manually validated as correct.
> → *We split our AI layer into two stages.*
>
> **Paper 2 — Cicalese et al., *The Language of Security* (arXiv 2607.15937)**
> 12,960 prompt permutations, 40,230 code solutions. **Python was vulnerable in 40.95% of snippets
> vs Java 8.82% and C 0.78%.** Prompt constituents that bind entities to constraints are the
> security-critical ones.
> → *We chose Python, and we built the prompt linter they called for.*
>
> **Paper 3 — Tony et al., ACM TOSEM 34(8):225**
> Seven prompting techniques on 150 tasks. **RCI cut weakness density 77.55% on GPT-4.**
> **Persona prompting was worse than no security instruction at all.**
> → *We implement all seven, plus two of our own, as a measurable registry.*

---

## Slide 6 — Scope decision: language

> **ACTION ITEM 2 — LANGUAGE SCOPE**
> ## One language: Python
>
> | Evidence | Source |
> |---|---|
> | **40.95%** of LLM-generated Python was vulnerable — vs Java **8.82%**, C **0.78%** | Paper 2, Table II |
> | Java snippets **failed static analysis 86.81%** of the time | Paper 2, §IV-A |
> | Bandit is **Python-only**; Semgrep's Python ruleset is its most mature; pip-audit is Python | tooling |
> | Every benchmark we need (LLMSecEval, SecurityEval, SecCodePLT) is Python | Papers 1–3 |
>
> **Python is where LLM-generated code is measurably least secure, and the only language where all
> four of our scanners work.**
>
> *Stretch, not promised: one JavaScript run as a validity check — exactly how Paper 3 generalised to C.*

---

## Slide 7 — Scope decision: vulnerabilities ⚠️ *most important slide*

> **ACTION ITEM 3 — VULNERABILITY SCOPE**
> ## 8 core CWEs + 2 supporting → 7 of 10 OWASP categories
>
> **Selection rule:** MITRE Top 25 ∩ OWASP Top 10 ∩ *measured prevalence in LLM-generated Python* ∩ scanner-detectable
>
> | CWE | Name | OWASP | Why |
> |---|---|---|---|
> | **78** | OS Command Injection | A03 | **Most frequent in LLM code — and resisted every prompting technique** |
> | **798/259** | Hard-coded Credentials | A07 | Top-4 prevalent; RCI cut it 21→5; found by **two** tools |
> | **94/215** | Flask debug / misconfig | A05 | **54 → 3 under RCI** — largest measured prompting effect |
> | **330** | Insecure Randomness | A02 | Top-4 prevalent in LLM code |
> | 89 | SQL Injection | A03 | Top 25, canonical |
> | 79 | Cross-Site Scripting | A03 | Top 25 |
> | 22 | Path Traversal | A01 | Top 25 |
> | 502 | Unsafe Deserialization | A08 | Top 25 |
> | 1395 + CVEs | Vulnerable Dependency | A06 | **The only honest source of CVEs** |
> | 327/328 | Weak Crypto | A02 | Crisp, verifiable fix |
>
> **Not covered, deliberately:** A04 Insecure Design — static analysis structurally cannot detect it.

**Say:** "The top four rows are the four CWEs Paper 3 measured as most prevalent in LLM-generated
Python. CWE-78 is in scope *because* no prompting technique fixes it — that's an open problem, which
makes it a better research target than a solved one."

---

## Slide 8 — The repositioned contribution

> **REVISED DIRECTION**
> ## What we now claim
>
> ### An open, reproducible testbed that measures **which prompting strategy** produces scanner-verified secure fixes — under **triple-gate verification**, with **cross-commit regression tracking**.
>
> | | Review 1 | Review 2 |
> |---|---|---|
> | Contribution | closed-loop verification | **measured prompting strategy + stricter verification** |
> | Languages | unspecified | **Python** |
> | Vulnerabilities | all of OWASP Top 10 | **10 CWEs / 7 categories** |
> | Scanners | 3 | **4** (Bandit restored) |
> | Prompts | one, implicit | **9, compared** |
> | Verification | 1 gate | **3 gates** |
> | Fix application | manual only | **+ sandboxed auto-apply** |
> | Evaluation | own fixture | **+ LLMSecEval, SecurityEval, OWASP PyGoat** |

---

## Slide 9 — The sharpest point: gate 3 ⚠️ *keep this one*

> **VERIFICATION**
> ## A fix that *deletes* the vulnerable code passes any scanner-only check
>
> Documented — and now measured: prior methods degrade Effective Safety Rate by 14–54%
> (SecCoderX, 2026):
>
> - **Paper 3 §7.4(vi):** LLM output contains *"calls to undeclared methods that did not exist within
>   the code's scope"* — annotated *"securely verify the user session."*
> - **Paper 3 §7.4(vii):** functions renamed `secure_ping()`, `secure_upload_file()` — *"the actual
>   implementation within these methods remains unaltered."*
> - **GitHub:** Copilot Autofix's single-file suggestions **can break the build.**
>
> ### Our three gates
>
> | Gate | Check |
> |---|---|
> | 1 | Target finding's fingerprint is **absent** from the rescan |
> | 2 | **No new findings** at equal-or-higher severity |
> | 3 | **Function preserved** — AST parses, module imports, test suite passes |
>
> **All three must pass. Any failure → `FIX_REJECTED`, with the reason recorded.**
>
> *Paper 3 observes this failure mode. Its own methodology cannot penalise it — the code never had to run.*

---

## Slide 10 — Revised architecture

> **SYSTEM ARCHITECTURE**
> ## Where the changes land
>
> ```
> Repository (GitHub / ZIP)
>        ↓
> Semgrep · Bandit · Gitleaks · pip-audit        ← Bandit restored
>        ↓
> Normalise (SARIF) → Map CWE/OWASP → Fingerprint + lifecycle
>        ↓
> Stage A: EXPLAINER      contextualised explanation        ← Paper 1
>        ↓
> Stage B: PROMPT BUILDER × strategy S0–S8                  ← Paper 3 + S8
>        ↓
> PROMPT SECURITY LINTER  constituents present?             ← Paper 2
>        ↓
>   ┌────┴────┐
> manual   sandboxed worktree apply
>   │         ↓
>   │    rescan → GATE 1 · GATE 2 · GATE 3
>   │         ↓
>   └──→ VERIFIED_RESOLVED | FIX_REJECTED → dashboard
> ```
>
> **Design rule, unchanged from Review 1:** the LLM explains and drafts. It never decides fix status.

---

## Slide 11 — Research gaps and evaluation plan

> **RESEARCH GAPS & EVALUATION**
> ## Five gaps, and how we measure against them
>
> | Gap | Our answer |
> |---|---|
> | **G1** Prompting techniques never tested on real scanner findings in real repos | Strategy registry applied to live findings |
> | **G2** Verification is single-shot; cannot detect a fake fix | Triple gate |
> | **G3** Paper 2's prompt linter doesn't exist | We build it |
> | **G4** No study tracks finding identity across commits | Fingerprint + lifecycle |
> | **G5** No reproducible open-model repair pipeline | Local model, temp 0.0, pinned weights |
>
> **Evaluation targets:** LLMSecEval (150 prompts) · SecurityEval (130 samples) · **OWASP PyGoat** ·
> our own fixture with ground truth
>
> **Metrics:** **Effective Safety Rate** — correct AND secure *(SecCoderX's metric)* · weakness count
> / rate / density *(Paper 3's units)* · remediation rate per strategy · regression and
> functional-break rates · inter-scanner agreement (Cohen's κ)
>
> **Built-in sanity check:** if our harness reproduces *RCI best, persona worst*, the harness itself
> is validated before we trust our own strategy's result.

---

## Slide 12 — Status and next steps

> **STATUS**
> ## Where we are
>
> **Done since Review 1**
> - 3 papers analysed in depth · 14 supporting works · 5 research gaps identified
> - 7 existing tools surveyed; contribution repositioned
> - Scope locked: 1 language · 10 CWEs · 4 scanners · 9 strategies · 3 gates
> - Project skeleton + **working demo: Semgrep + Bandit scanning a seeded fixture, normalised output with CWE/OWASP mapping**
>
> **Next two weeks (Phases 1–3)**
> - Foundation: config, secure logging, DB models, safe subprocess
> - Scanner layer: 4 scanners behind one interface, SARIF normalisation
> - Repository handling: SSRF-safe clone, zip-slip-safe extraction; vulnerable fixture with ground truth
>
> **Questions for the panel**
> 1. Is the repositioned contribution sufficiently novel, given Copilot Autofix exists?
> 2. Is 10 CWEs right — or narrow further to the 4 most prevalent?
> 3. Add CodeQL as a third SAST engine for evaluation, accepting the runtime cost?

---

## Anticipated questions — prepared answers

**"Isn't this just Copilot Autofix?"**
> No, and we opened with that. Autofix hides its prompt, validates only against the default query
> suite, uses one scanner, and doesn't check the fix preserved functionality. We measure nine
> prompting strategies against real findings, verify against three gates, and track identity across
> commits. We're not claiming better fixes than GPT-4 — we're claiming a measurement nobody has made.

**"Why not use CodeQL, since all three papers do?"**
> It's the strongest citation anchor, so we've wired it as an optional adapter for the evaluation
> chapter. It needs a database build per scan, which is too slow for the interactive loop. Semgrep
> and Bandit give us two independent engines with sub-second scans and an agreement metric.

**"Ten CWEs still sounds like a lot."**
> Eight are core, two come free from dependency and config scanning. Each gets exactly one seeded
> instance in our fixture with recorded ground truth, so we can compute real precision and recall.
> Ten CWEs × nine strategies is ninety runs per model arm — tractable locally. We'd rather defend
> ten with evidence than claim thirty without.

**"What if the local 7B model produces bad fixes?"**
> Then that *is* the result — and it's gap G5, which nobody has measured. We also run a hosted
> free-tier arm, so we report open versus proprietary on scanner-verified repair. A negative result
> on the local arm is still a publishable finding.

**"How do you handle false positives?"**
> A `SUPPRESSED` lifecycle state — human-marked, tracked, never deleted, and excluded from new and
> regression counts. Plus the inter-tool agreement metric between Semgrep and Bandit measures the
> disagreement rather than hiding it.

**"Isn't 'scanner says it's gone' a weak definition of secure?"**
> Yes, and we say so in the threat-model section. Our claim is precisely *the scanner no longer
> detects this weakness, the fix introduced nothing new, and the code still runs* — which is strictly
> stronger than what's published, and we don't overclaim beyond it.

**"What's genuinely novel here — in one sentence?"**
> Nobody has measured which prompting technique produces scanner-verified fixes on real repository
> findings, and nobody checks whether the fix broke the program — even though the literature documents
> LLMs renaming functions `secure_*` without changing them.

**"Isn't this what Backslash or Cursor rules already do?"**
> They ship a CWE rules file and report 100% — on seeded code-generation scenarios, with no published
> ruleset, no independent re-scan, no functional check and no cross-commit tracking. We added their
> technique to the registry as **S8** and measure it on real scanner findings under all three gates.
> If it holds up that is a result; if it does not, a bigger one.

**"Why not train the model, like SafeCodeX?"**
> Different axis. SafeCodeX (NUS, arXiv:2602.07422) changes the model with online reinforcement
> learning — it needs weights and GPUs. We change the prompt: inference-time, black-box, works on a
> repository we do not own. We adopt their **Effective Safety Rate** metric, and their finding that
> prior methods degrade ESR by **14–54%** is why gate 3 exists.
