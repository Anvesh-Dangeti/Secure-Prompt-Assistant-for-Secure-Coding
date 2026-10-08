# Revised Project Direction — What Changed After Review 1, and Why

**Project:** Building a Prompt Assistant for Secure Coding · TEAM-3
**Prepared for:** Review 2 (19 September 2026)
**Responds to:** Review 1 Action Item 5 — *"Update project scope: revise the architecture/plan based
on the above findings."*

This document is a **diff against the Review 1 ideation deck**. Every change is traceable to either a
specific paper finding or a specific capability of an existing tool. Nothing here changed because we
felt like it.

---

## Summary: 13 changes

| # | Change | Driver |
|---|---|---|
| C1 | **Repositioned the core contribution** | Copilot Autofix already ships the loop we claimed |
| C2 | Language scope fixed at **Python only** | Action item 2; Paper 2 Table II |
| C3 | Vulnerability scope cut to **8 core + 2 supporting CWEs** | Action item 3; Paper 3 §7.2 |
| C4 | **Bandit restored** as a first-class scanner | Paper 3 §6.3 (κ = 0.87); Paper 2 threats-to-validity |
| C5 | Normalisation moved to a **SARIF-based model** | Industry standard; multi-tool extensibility |
| C6 | AI layer split into **two stages (explained feedback)** | Paper 1 §5.3 |
| C7 | **NEW: Prompt Strategy Registry (S0–S8)** | Paper 3 Table 2 |
| C8 | **NEW: Prompt Security Linter** | Paper 2 §V-B (their own stated next step) |
| C9 | Verification upgraded to a **triple gate** | Paper 3 §7.4(vi–vii); Shukla et al. |
| C10 | **Sandboxed auto-apply** of candidate fixes | Required to collect evaluation data at scale |
| C11 | Evaluation adds **LLMSecEval, SecurityEval, OWASP PyGoat** | Papers 1–3; external validity |
| C12 | **Dual-arm models**: local open + hosted free-tier | Paper 2 reproducibility; Paper 3 §8 leakage risk |
| C13 | Explicit **drop list** | Panel guidance: depth over breadth |

---

## C1 — Repositioning the contribution (the critical change)

**Review 1 claim:**
> *"The gap this project targets: a closed loop that connects detection → AI-assisted remediation →
> independent verification."* (Slide 2)
> *"Design rule: the LLM never decides whether a vulnerability is fixed."* (Slide 5)

**The problem.** GitHub **Copilot Autofix** has shipped exactly this since August 2024: a CodeQL alert
goes to an LLM, which drafts a fix, and **CodeQL re-runs to validate it**. GitHub's slogan is *"found
means fixed."* Snyk DeepCode AI Fix and Semgrep Assistant occupy adjacent ground.

Presenting the Review 1 framing unchanged would be presenting a reimplementation of a shipped product.

**Revised claim:**

> **An open, reproducible testbed that measures *which prompting strategy* actually produces
> scanner-verified secure fixes — under *differential* verification (target resolved **and** nothing
> new introduced **and** function preserved) with cross-commit regression tracking.**

Four sub-claims, each in a column that is empty for every incumbent:

1. **Prompt strategy is a measured variable.** Paper 3 shows technique choice moves weakness density
   by 77.55%, and that persona prompting is worse than no security instruction at all. No shipping
   tool exposes, selects or measures its prompt.
2. **Triple-gate verification.** Everybody checks "did the scanner stop complaining." Nobody checks
   "does the code still work" — see C9.
3. **Cross-commit finding identity and regression states.** DefectDojo has lifecycle without AI;
   Copilot Autofix has AI without lifecycle. Nobody has joined them.
4. **Runs on a local open model.** Papers 1 and 3 used proprietary GPT models; Paper 2 used open
   models but only for generation, never repair.

**What stays from Review 1.** The responsibility separation (scanner produces evidence, LLM explains
and drafts, scanner verifies), the security-first engineering posture, and the fingerprint-based
lifecycle model were all correct and are retained unchanged.

---

## C2 — Language scope: Python only

*Full justification in `scope_decisions.md` §1.* Headline: Python-generated code was vulnerable in
**40.95%** of snippets versus Java 8.82% and C 0.78% (Paper 2, Table II), Java failed analysis
**86.81%** of the time, and Bandit is Python-only.

---

## C3 — Vulnerability scope: 8 core + 2 supporting CWEs

*Full justification in `scope_decisions.md` §2.* Review 1 implied the whole OWASP Top 10. Now: ten
CWEs covering seven OWASP categories, chosen as the intersection of MITRE Top 25, OWASP Top 10,
Paper 3's measured prevalence in LLM-generated Python, and what our scanners can reliably detect.

Notably **CWE-78 (OS command injection) is in scope precisely because Paper 3 found no prompting
technique fixes it** — an unsolved problem is a better research target than a solved one.

---

## C4 — Bandit restored (reverses a Review 1 decision)

**Review 1 decision:** *"no Bandit (heavy overlap with Semgrep's Python ruleset)."*

**Why that was wrong:**

- Paper 3 used **Bandit as its primary detector**, with reliability established against manual review
  at **weighted Cohen's κ = 0.87** over 315 inspected snippets.
- Paper 2's threats-to-validity section explicitly recommends *"consensus across independent static
  analyzers"* to strengthen validation.
- The "overlap" we were avoiding is actually the **measurement**: two independent engines produce an
  **inter-tool agreement metric**, which is a result in the evaluation chapter rather than wasted work.

**Final scanner set:** Semgrep + Bandit (dual SAST) · Gitleaks (secrets) · pip-audit (SCA → CVEs).
CodeQL deferred to an optional Phase 8 cross-validation adapter — strongest citation anchor, but too
slow (database build per scan) for the live loop.

---

## C5 — SARIF-based normalisation

**Was:** a bespoke per-tool normaliser.
**Now:** SARIF (OASIS standard) as the internal shape. Semgrep (`--sarif`), Bandit (`-f sarif`) and
CodeQL all emit it natively; Gitleaks and pip-audit get thin adapters. This is what industrial
vulnerability-management tooling does, and it makes adding a fifth scanner a config change rather than
a rewrite.

---

## C6 — AI layer split into two stages ("explained feedback")

**Was:** finding → remediation prompt. One step.

**Paper 1's central result:** repair with **explained feedback** substantially outperformed repair
with **direct feedback** (raw scanner output). Over **98%** of LLM-generated explanations of scanner
output were manually validated as correct and actionable. Paper 1 also found **contextualised** hints
beat generic CWE definitions.

**Now:**

```
Scanner finding + minimal code context
        |
        v
Stage A: Explainer   ->  contextualised explanation of why THIS code is vulnerable
        |                 + actionable fix guidance
        v
Stage B: PromptBuilder -> the remediation prompt (via selected strategy + linter)
```

The Explainer must tie the CWE to *this specific code*. Pasting MITRE boilerplate is explicitly
forbidden — Paper 1 measured that as the weaker option.

---

## C7 — NEW: Prompt Strategy Registry

Review 1 had one implicit prompt. Paper 3 shows that choice is worth up to **77.55%** of weakness
density. We implement all seven of Paper 3's Table 2 templates, our own combination, and the
rules-file technique industry actually ships:

| ID | Strategy | Paper 3 expectation |
|---|---|---|
| S0 | Baseline — no security cue | negative control |
| S1 | Naive-secure — adds the word "secure" | −28% to −43% density |
| S2 | CWE-specific — MITRE mitigation text | strong on GPT-3 |
| S3 | Comprehensive — references OWASP secure-coding practices | strong on GPT-3.5/4, and cheap |
| S4 | Zero-shot CoT | underwhelming for security |
| S5 | **RCI** — recursive criticism & improvement | **best: −77.55% on GPT-4** |
| S6 | Persona — "act as a security expert" | **worst — below baseline on GPT-3.5** |
| S7 | **Ours** — explained feedback + RCI + linted template | the thing we are claiming |
| S8 | **Rules-file injection** — a persistent, machine-readable CWE ruleset prepended to every prompt | industry practice (Backslash); claimed 100%, never independently verified |

**Why this matters methodologically:** S5 and S6 have *known expected outcomes*. If our harness
reproduces "RCI best, persona worst," that validates the harness itself before we trust S7's result.

**Why S8 is not folded into S3.** The difference is kind, not degree. S3 is per-finding guidance
composed inside one prompt; S8 is a standing ruleset applied to every request regardless of which
finding triggered it — the deployment model behind Cursor-style rules files and Backslash's product.
That distinction is the whole point of measuring it: a fixed ruleset cannot adapt to the finding, and
whether that costs anything is an open question. Backslash reports 100% for it against seeded
generation scenarios, with no published ruleset, no independent re-scan and no functional check. We
measure the same technique on real scanner findings under all three gates. If it holds up, that is a
result worth reporting; if it does not, that is a bigger one.

---

## C8 — NEW: Prompt Security Linter

Paper 2 §V-B lists this as *"a concrete next step enabled by our findings"* — and nobody has built it.

A deterministic validator runs on every generated prompt **before it is sent**:

| Check | Paper 2 evidence |
|---|---|
| **Entity binding** — *which* input/parameter is at risk | WHNP removal gave the highest risk ratios (up to 1.88) |
| **Condition / guard** — *under what conditions* the operation may proceed | WHADVP / SBAR removal consistently raised vulnerability rates |
| **Handling directive** — *how* it must be validated, encoded or parameterised | VP removal |
| **Scope constraint** — "change nothing unrelated" | project requirement |
| **Opening-sentence anchor** — task semantics in sentence 0 | opening-sentence removals raised vulnerability rates in all models (RR up to 2.31) |
| **No stranded final constraint** | late-position removals showed a monotonic risk gradient in Python |
| **No-shorten guard** — reject silent truncation | minimal-granularity removals *alone* raised vulnerability rates |

**Implementation:** slot-filled templates plus a checklist validator — **not** a real constituency
parser. Cheap to build, genuinely novel, directly citable.

---

## C9 — Verification upgraded to a triple gate

**Was (Review 1):** one gate — is the finding's fingerprint absent from the rescan.

**Now:** `VERIFIED_RESOLVED` requires **all three**:

| Gate | Check | Why |
|---|---|---|
| **1. Target resolved** | Finding's fingerprint absent from post-fix scan | The original Review 1 criterion |
| **2. Nothing new introduced** | Differential scan shows zero new findings at equal-or-higher severity | Shukla et al.: iterative AI refinement can *amplify* critical flaws without human oversight |
| **3. Function preserved** | Patched file parses (`ast.parse`), module imports, fixture test suite still passes | **See below — our sharpest point** |

### Why gate 3 is the headline

> **A fix that simply deletes the vulnerable code passes any scanner-only check.**

The cost of not gating on this is now measured, not merely observed. SecCoderX (Wu et al.,
arXiv:2602.07422) reports that prior secure-generation methods **degrade Effective Safety Rate by
14–54%** — ESR counting only code that is *both* functionally correct **and** secure. Between one in
seven and one in two of the security "improvements" those methods produce break working code. A
pipeline that reports security without measuring functionality is reporting half a result, and the
missing half is large.

The specific failure modes are documented, not hypothetical:

- Paper 3 §7.4(vi): LLM output contains *"calls to undeclared methods that did not exist within the
  code's scope"* — often for security-sensitive tasks, annotated with comments like *"securely verify
  the user session."*
- Paper 3 §7.4(vii): functions renamed `secure_ping()`, `secure_upload_file()` — *"despite the
  suggestive prefixes, the actual implementation within these methods remains unaltered."*
- GitHub acknowledges Copilot Autofix's single-file suggestions **can break the build** when a real
  fix needs multi-file changes.

So the failure mode is documented from the research side, the vendor side and now the measurement
side — and **nothing gates on it.** Paper 3 *observes* the behaviour but its own weakness-density methodology cannot penalise it,
because the code was never required to run.

Any gate failing produces `FIX_REJECTED` with the reason recorded. Never silently pass.

---

## C10 — Sandboxed auto-apply of candidate fixes

**Was (Review 1):** *"Developer applies fix via Copilot"* — a human in the loop for every fix.

**Why that had to change:** a human cannot hand-apply fixes across 10 CWEs × 9 strategies × 2 model
arms × multiple benchmarks. Without automation there is no evaluation chapter, only anecdotes.

**Now:** `git worktree add` a scratch branch → apply the candidate patch → rescan → run the three
gates → record the verdict → `git worktree remove`.

**Safety properties (non-negotiable):**

- Never writes to the user's working checkout. Never commits. Never pushes.
- Patch applied only inside the scratch directory; every path validated to stay under it.
- File count, file size and patch size capped.
- Subprocess timeouts, list-form arguments, non-root, no `shell=True`.
- Guaranteed cleanup on every exit path including failure.
- **The AI's patch is never executed as trusted code** — only parsed, scanned, and run inside the
  fixture's own test harness.

Manual / Copilot hand-off mode is retained for the live demo, because demonstrating the developer
workflow is still part of the brief.

---

## C11 — Evaluation on established benchmarks

**Was:** one homemade Flask vulnerable app. No external validity.

**Now, four evaluation targets:**

| Target | Role | Provenance |
|---|---|---|
| **LLMSecEval** | 150 NL prompts over 18 of the MITRE Top-25 | Used by **both** Paper 2 and Paper 3 — makes our numbers directly comparable to published ones |
| **SecurityEval** | 130 Python samples, 75 CWE types | Paper 1's primary benchmark |
| **OWASP PyGoat** | A real, OWASP-listed intentionally-vulnerable Django app covering the OWASP Top 10 | Our "realistic repository" case |
| **Our `flask_vuln_app` fixture** | Exactly one seeded instance of each scoped CWE, ground truth in `ground_truth.yaml` | The only source of true **precision and recall** — benchmarks alone cannot give this |

**Metrics adopt Paper 3's units** so they are comparable: weakness **count**, **rate** (per file) and
**density** (per 100 LOC). Plus ours: scanner-confirmed remediation rate *per strategy*, gate-2
regression rate, gate-3 functional-break rate, inter-scanner agreement (Cohen's κ), and fingerprint
stability across commits.

**Headline metric: Effective Safety Rate**, defined as in SecCoderX (arXiv:2602.07422) — the
proportion of outcomes that are *both* functionally correct **and** secure. This is exactly what our
three gates jointly decide, so adopting the published name costs nothing and makes our per-strategy
numbers comparable against a published baseline rather than only against ourselves. Gate 3's
mechanism is unchanged (`ast.parse` + module import + fixture test suite); ESR is how the result is
reported, not a new check.

**Reproducibility protocol** (mirrors Paper 3 §5.1): temperature **0.0**, fixed `top_p`, and every
result row records model ID, version, parameters, scanner versions and ruleset commit.

---

## C12 — Dual-arm model strategy

**Hardware:** RTX 5050 (8 GB VRAM), 24 GB RAM, i7-14650HX.

| Arm | Model | Role |
|---|---|---|
| **Local (default, for volume)** | Ollama + `qwen2.5-coder:7b-instruct` Q4_K_M (~4.7 GB) | Fits 8 GB VRAM comfortably; strong code model; deterministic at temperature 0. Fallback: `deepseek-coder:6.7b-instruct` Q4. **Not 14B** — Q4 is ~9 GB and would spill to system RAM |
| **Hosted (quality comparison)** | Free-tier hosted model (Gemini free tier / Groq Llama-3.3-70B) | The "strong model" arm, mirroring Papers 1 and 3 |
| **Stub** | Deterministic fake provider | Lets the whole pipeline be tested in CI with no model at all |

**This is not a budget compromise — it is the experiment.** Papers 1 and 3 used proprietary GPT
models, which Paper 3 itself flags as an external-validity threat and data-contamination risk. Paper 2
used open models *specifically for reproducibility*, but only for generation. **Open-versus-proprietary
on scanner-verified repair** is gap G5, and having both arms gives it to us for free.

---

## C13 — Explicit drop list

The panel asked for depth over breadth. These are dropped, and we say so out loud:

| Dropped | Reason |
|---|---|
| Multi-language support | C2 |
| Full OWASP Top 10 coverage | C3 — A04 Insecure Design is structurally undetectable by static analysis |
| GitHub webhooks | Public endpoint + signature verification; attack surface for no research value |
| RBAC / multi-tenant authentication | Single-user local research tool. Stated honestly in the threat model rather than built as theatre |
| Large custom CVE database | CVEs come from pip-audit only |
| Container-per-scan sandboxing | Phase 9 stretch; subprocess isolation, timeouts and non-root suffice for the MVP |
| Incremental scanning as a feature | Secondary metric only — full rescan stays authoritative, because incremental scanning can miss findings whose relevant code lies outside the diff |

---

## Revised architecture

```
Connect repository (GitHub URL or ZIP)
        |
        v
Full scan  ──  Semgrep · Bandit · Gitleaks · pip-audit
        |
        v
Normalise to SARIF-based Finding model            [C5]
        |
        v
Map to CWE / OWASP  (CVE only from pip-audit)     [C3]
        |
        v
Fingerprint + lifecycle state                     [G4]
        |
        v
Stage A: Explainer  → contextualised explanation  [C6, Paper 1]
        |
        v
Stage B: PromptBuilder × Strategy S0–S8           [C7, Paper 3]
        |
        v
Prompt Security Linter  (reject if constituents missing)   [C8, Paper 2]
        |
        +──> Manual mode: hand the prompt to the developer / Copilot   (demo)
        |
        +──> Sandboxed mode: apply patch in a throwaway git worktree   [C10]
                    |
                    v
             Rescan (same scanners, same rules)
                    |
                    v
             ┌──────────────────────────────────┐
             │ Gate 1  target finding resolved  │
             │ Gate 2  no new findings          │   [C9]
             │ Gate 3  function preserved       │
             └──────────────────────────────────┘
                    |
                    v
        VERIFIED_RESOLVED  |  FIX_REJECTED (with reason)
                    |
                    v
        Lifecycle update + dashboard + history
```

---

## What did *not* change

Worth stating, because it shows the Review 1 work was not wasted:

- The **responsibility separation** — scanner produces evidence, LLM explains and drafts, scanner
  verifies independently. Correct, and now enforced more strictly by the triple gate.
- The **fingerprint-not-line-number** identity model. Correct, and validated by the fact that
  DefectDojo's industrial deduplication works the same way.
- The **lifecycle states** `NEW` / `STILL_OPEN` / `RESOLVED` / `REGRESSION` / `SUPPRESSED`.
- The **security-first engineering posture** — SSRF validation, zip-slip protection, safe subprocess
  invocation, secret redaction, data minimisation to the LLM, treating repository content as untrusted
  input to the prompt.
- The **technology stack** — Python, FastAPI, Streamlit, SQLite, Semgrep, Gitleaks, pip-audit.

---

## The three sentences to open Review 2 with

> First: the loop we proposed at Review 1 — scan, ask AI to fix, rescan to verify — has been shipped by
> GitHub as Copilot Autofix since August 2024, so we are no longer claiming it as our contribution.
>
> Second: what no existing tool does is treat the prompt as a measurable variable, even though the
> literature shows prompting technique changes weakness density by up to 77%; nor does any tool verify
> that a fix preserved functionality, even though the same literature documents LLMs renaming functions
> `secure_*` without changing them.
>
> Third: we have therefore narrowed to one language and ten CWEs, and repositioned the project as a
> reproducible testbed that measures which prompting strategy produces scanner-verified fixes under
> triple-gate verification, with finding identity tracked across commits.
