# Existing Prompt Assistants and AI Remediation Tools — Landscape Survey

**Project:** Building a Prompt Assistant for Secure Coding · TEAM-3
**Prepared for:** Review 2 (19 September 2026)
**Responds to:** Review 1 Action Item 1 — *"Study already existing prompt assistants and related
solutions to understand their features, approaches, limitations, and how our project can be
differentiated."*

---

## 0. The uncomfortable finding, stated first

We will open the review with this rather than bury it:

> **The workflow we presented at Review 1 — scan, ask an AI to fix it, re-scan to verify — has been a
> shipped GitHub product since August 2024.** GitHub **Copilot Autofix** takes a CodeQL alert, has an
> LLM draft a fix, and **re-runs CodeQL to validate it**. GitHub's own launch slogan for it is
> *"found means fixed."*

Presenting the same loop unchanged would be presenting a reimplementation. Section 3 is therefore the
most important part of this document: it identifies what these tools genuinely do **not** do, and
that is where the project moves.

---

## 1. Tool-by-tool survey

### 1.1 GitHub Copilot Autofix (with CodeQL code scanning) — the closest competitor

**Category:** Commercial, integrated into GitHub Advanced Security. GA since August 2024.

**What it does.** CodeQL raises an alert on a pull request or the default branch. An LLM generates a
suggested fix using the alert data plus surrounding codebase context. The suggestion is shown inline
on the PR, and Copilot **re-runs CodeQL to check the fix actually clears the alert**.

**Reported effectiveness.** Covers more than 90% of alert types in JavaScript, TypeScript, Java and
Python. GitHub reports fixes remediate over two-thirds of found vulnerabilities with little or no
editing, and that vulnerabilities with a fix suggestion are fixed roughly 3× faster overall — 7× for
XSS and 12× for SQL injection.

**Limitations (documented by GitHub itself, plus independent analysis):**

| Limitation | Consequence for us |
|---|---|
| **Validation runs only against the default code-scanning query suite.** GitHub explicitly states it cannot confirm that a fix resolves alerts from *custom queries* or the *security-extended* suite. | Their verification is narrower than it appears. Ours re-runs the exact ruleset that produced the finding. |
| **Works from the immediate alert context.** A fix needing structural changes across multiple files can produce a single-file suggestion that **breaks the build**. | Direct evidence that functional breakage is a real failure mode — and that they do not gate on it. |
| Fix quality for alerts from **third-party tools** is not guaranteed. | Multi-scanner corroboration is unoccupied ground. |
| **Single scanner (CodeQL).** No cross-tool corroboration, no agreement metric. | We run two independent SAST engines. |
| **The prompt is a hidden implementation detail.** Users cannot see it, select a strategy, or compare strategies. | The entire prompting-technique literature is invisible here. This is our main opening. |
| **No user-facing cross-commit lifecycle.** Alerts open and close; there is no fingerprint-identity model exposing `REGRESSION` when a verified fix reappears later. | G4. |
| **Closed and paid.** Requires GitHub Advanced Security; not reproducible for research; cannot be run against a local open model. | G5, and the reproducibility argument. |

---

### 1.2 Snyk Code / DeepCode AI Fix

**Category:** Commercial SAST with AI autofix.

**What it does.** A hybrid engine — symbolic AI plus generative AI plus data-flow analysis, reportedly
trained across 25M+ data-flow cases — that detects vulnerabilities and produces fix suggestions
directly in IDEs (VS Code, JetBrains, Eclipse, Cursor) and pull requests. Broad platform: SAST, SCA,
container and IaC in one product.

**Limitations:**

- **Detection logic is not inspectable.** A closed AI engine produces findings without exposing why;
  you cannot read, fork or modify a rule. For an academic project that must explain its evidence in a
  viva, this is disqualifying as a component and useful as a contrast.
- Falls short on organisation-specific patterns and novel vulnerability types, because rules are not
  user-authorable.
- **Prompting strategy again hidden.** No selection, no measurement, no comparison.
- No published closed-loop re-verification story equivalent to Copilot Autofix's.
- Commercial licensing.

---

### 1.3 Semgrep + Semgrep Assistant

**Category:** Open-source scanner (Semgrep OSS) with a paid cloud AI layer (Assistant).

**What it does.** Semgrep OSS is the scanner we are actually adopting: rules are plain YAML, every
detection is readable and forkable, 3,000+ community rules, native per-finding fingerprints, JSON and
SARIF output. **Assistant** adds AI triage — reported at roughly 96% alignment with human triage
decisions — plus autofix suggestions.

**Limitations:**

- Assistant is **primarily a triage aid** ("is this finding real and worth fixing"), not a closed-loop
  remediation-and-verification system.
- Assistant is a **paid cloud feature**, so the AI half is neither free nor reproducible, even though
  the scanner half is.
- No cross-commit lifecycle with regression states exposed to the user.
- No prompting-strategy selection or measurement.

**Why this matters to us:** Semgrep OSS is the best available *evidence layer* and we use it. The AI
layer above it is exactly where our contribution sits.

---

### 1.4 DefectDojo

**Category:** Open-source vulnerability management / ASPM.

**What it does.** The half of our system that is genuinely a solved problem, and we should say so.
It ingests results from 500+ tools via native parsers or standard formats (SARIF, CycloneDX),
normalises them, and performs **intelligent deduplication** — if three tools find the same
vulnerability it creates one finding with three references, reportedly cutting raw alert volume by up
to 90%. It manages the full finding lifecycle: discovery, assessment, reporting, remediation.

**Limitations:**

- **No AI remediation whatsoever.** No prompt generation, no fix suggestion, no LLM in the loop.
- **No verification loop.** It tracks state that humans set; it does not independently prove a fix
  worked.

**Why this matters to us:** DefectDojo proves the *lifecycle and deduplication* half is valuable and
well-understood — and it validates our fingerprinting design, since their dedup is the same idea. But
DefectDojo and Copilot Autofix are **disjoint**: one has lifecycle without AI, the other AI without
lifecycle. **Nobody has joined them.** That intersection is gap G4.

---

### 1.5 Amazon CodeGuru Security / CodeWhisperer

**Category:** Commercial, AWS-bound.

Scan plus suggested remediation inside the AWS toolchain. Limitations for our purposes: vendor
lock-in, closed detection logic, hidden prompts, and no cross-commit regression lifecycle. Included
for completeness of the landscape.

---

### 1.6 Raw Copilot / ChatGPT / Cursor used as a "prompt assistant"

**Category:** What developers actually do today — and the real baseline our project should beat.

**What it does.** The developer pastes code and asks "is this secure" or "fix this."

**Limitations — and this is the strongest motivation slide in the deck:**

- **No scanner grounding.** The model decides both *whether* there is a vulnerability and *whether it
  is fixed*. Paper 1 shows models miss vulnerabilities routinely; Paper 3 Takeaway (6) explicitly
  advises using static analysis tools *in tandem* because they catch what LLMs overlook.
- **No verification at all.** The model's claim that it fixed the issue is the only evidence.
- **Actively harmful in measured conditions.** Perry et al. (CCS 2023) found participants with an AI
  assistant produced *more* insecure code — while being *more confident* it was secure. Over-trust is
  the documented failure mode.
- **No memory across commits.** Nothing notices when a fix regresses three commits later.

---

### 1.7 Backslash Security — AI Rules and MCP server

**Category:** The second commercial competitor on the *prompting* axis — and the closer one, since
prompting is where we repositioned after Copilot Autofix.

**What it does.** Backslash publishes machine-readable, language- and CWE-specific *rules files*
(the Cursor `rules` format and equivalents) that AI editors inject into every prompt, plus an MCP
server that feeds scanner context into AI-native IDEs. The premise is identical to ours: the prompt
is the lever.

**Their research (April 2025, vendor-published, not peer-reviewed).** Seven current models from
OpenAI, Anthropic and Google, tested at three prompting tiers — naive, "make it secure", and "follow
OWASP secure coding best practices" — scored against 10 CWE use cases:

| | Naive | Security-prompted |
|---|---|---|
| GPT-4o | 1/10 | ~8 CWEs still present |
| GPT-4.1 | 1.5/10 | — |
| Claude 3.7 Sonnet | 6/10 (best of the seven) | 10/10 |

Headline claims: **40–90% of AI-generated code is vulnerable by default**; the OWASP tier moved
GPT-4o from 20% to 65%; and their own rules files reach **100% across all tested models**.

**Why this matters to us — both ways.** It independently replicates Paper 3's central finding on
2025-era models, which is useful corroboration. It also means a shipping product already sells
"better prompts produce more secure code," so we must say what we add.

**Limitations — and this is the cleanest differentiation in the survey:**

- **Generation, not remediation.** They score freshly generated code against seeded CWE scenarios.
  They never take an existing scanner finding in a real repository and fix it. That is gap G1.
- **No independent re-scan.** The 100% figure is measured by their own scoring of the output, not by
  re-running an independent scanner over a committed change.
- **No functional check whatsoever.** Nothing establishes that the "100% secure" code still runs.
  Gate 3 has no counterpart here.
- **The ruleset is not published.** The prompt remains the hidden implementation detail — which is
  exactly D1, and Backslash illustrates it more sharply than Autofix does, because the hidden prompt
  *is* the entire product.
- **No cross-commit identity.** A rules file has no memory; nothing detects a regression later.

**What we take from it.** The technique itself, as **strategy S8 — rules-file injection** — a
persistent, machine-readable CWE ruleset prepended to every prompt, distinct in kind from per-finding
prompt construction. It is what industry actually deploys, it is claimed to be perfect, and nobody
has verified it under an independent re-scan with a functional gate. Our harness can.

---

### 1.8 Academic prototypes

Not products, but the closest research systems:

- **RCI-based secure generation** (Paper 3) — best-performing prompting technique, but evaluated on
  isolated benchmark snippets, never applied to scanner findings in a repository.
- **Explained-feedback repair** (Paper 1) — feeds LLM-enriched CodeQL output back for repair. Closest
  in spirit to our AI layer; again snippet-level, single-shot, no functional check.
- **Reflexion-based secure code generation**, **RESCUE (retrieval-augmented secure code generation)** —
  adjacent approaches to improving generated-code security, same snippet-level evaluation limits.
- **SVEN** (He & Vechev) — the fine-tuning alternative, +25% secure output on CodeGen. We note it to
  justify choosing prompting: no GPU budget for tuning, and prompting is what developers actually do.
- **SafeCodeX / SecCoderX** (NUS Institute of Data Science, Google GARA-funded; Wu, Du, Liu, Yang,
  Zhuo, Zhang & Ng, arXiv:2602.07422, Feb 2026) — online reinforcement learning with a *vulnerability
  reward model*, trained over PrimeVul/CrossVul/R2Vul and graded with CodeQL. Reports **+~10%
  Effective Safety Rate**, where ESR counts only code that is *both* functionally correct **and**
  secure — and notes that prior secure-generation methods **degrade ESR by 14–54%**. A different
  axis from ours, not a competitor: SafeCodeX changes the *model* (training time, needs weights and
  GPUs), we change the *prompt* (inference time, black-box, works on a repository we do not own and a
  model we cannot retrain). We adopt its ESR metric, and its degradation figure is the hardest
  available evidence for why gate 3 must exist.

---

## 2. Capability matrix

The single most important table in the Review 2 deck. Rows where only our column is ticked are the
defensible contribution.

| Capability | Copilot Autofix | Snyk Code | Semgrep Assistant | DefectDojo | Backslash Rules | Raw Copilot / ChatGPT | **Ours** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Scanner-grounded findings | ✅ CodeQL only | ✅ | ✅ | ✅ 500+ tools | ❌ generation-time | ❌ | ✅ 4 tools |
| Multi-scanner corroboration / agreement metric | ❌ | ❌ | ❌ | ✅ dedup only | ❌ | ❌ | ✅ |
| AI remediation prompt | ✅ hidden | ✅ hidden | ✅ hidden | ❌ | ✅ hidden ruleset | ✅ ad hoc | ✅ **inspectable** |
| Independent re-scan verification | ✅ limited suite | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ✅ |
| **Gate 2 — no new findings introduced by the fix** | ⚠️ partial | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Gate 3 — functional preservation (fix didn't just delete the code)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Cross-commit lifecycle (NEW / STILL_OPEN / RESOLVED / REGRESSION)** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **Prompting strategy selectable and measured** | ❌ | ❌ | ❌ | ❌ | ❌ one fixed ruleset | ❌ | ✅ |
| **Prompt security linter** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Open source / reproducible | ❌ | ❌ | partial | ✅ | ❌ | ❌ | ✅ |
| Runs against a local open LLM | ❌ | ❌ | ❌ | n/a | ❌ | ❌ | ✅ |

---

## 3. Where we differentiate

Four claims. Each corresponds to an empty column in the matrix above, and each is traceable to a
paper finding.

### D1 — Prompt strategy is a measured variable, not a hidden implementation detail

Every commercial tool hard-codes one prompt and never reveals it. Meanwhile Paper 3 shows the choice
of prompting technique changes weakness density by **77.55%** on GPT-4, and that one popular technique
(persona) is *worse than no security instruction at all*. That is an enormous effect that no shipping
tool exposes, selects or measures.

Backslash is the sharpest illustration. Its entire product is a prompt — a CWE-specific rules file
injected into every request — and it reports a perfect 100% across all tested models. The ruleset is
not published, the result is not confirmed by an independent re-scan, and nothing checks the code
still runs. A claim of 100% that cannot be reproduced or falsified is precisely the problem D1
describes.

We implement nine strategies (Paper 3's seven, our own combination, and Backslash's rules-file
technique as S8), run them over the same findings, and report which produces the most
scanner-verified fixes under all three gates. **This is the study nobody has run on real repository
findings.**

### D2 — Triple-gate verification, including functional preservation

Everyone asks "did the scanner stop complaining." Nobody asks "does the code still work."

> **A fix that simply deletes the vulnerable function passes any scanner-only check.**

This is not hypothetical. Paper 3 §7.4(vi) documents LLM output calling **undeclared "secure" methods
that do not exist**; §7.4(vii) documents functions renamed `secure_ping()`, `secure_upload_file()`
with **bodies left unchanged**. Independently, GitHub acknowledges Copilot Autofix's single-file
suggestions **can break the build**. So the failure mode is documented from both the research side and
the vendor side — and nothing gates on it.

Our gate 3 runs the AST parse, the import, and the fixture's test suite. It is cheap to build and it
is the sharpest thing we have.

### D3 — Cross-commit finding identity and regression detection

DefectDojo has lifecycle and no AI. Copilot Autofix has AI and no user-facing lifecycle. We join them:
fingerprint-based identity that survives line shifts and refactors, with an explicit `REGRESSION`
state when a previously-verified fix reappears in a later commit.

### D4 — Reproducible, and runs on a local open model

Papers 1 and 3 used proprietary GPT models — which Paper 3 itself flags as an external-validity threat
and a data-contamination risk. Paper 2 used open models *specifically for reproducibility*, but only
for generation, never repair. Our pipeline runs on a locally-hosted open model at temperature 0.0 with
pinned weights, alongside a hosted arm — which makes **open-versus-proprietary on scanner-verified
repair** a result we get for free.

---

## 4. What we deliberately do *not* claim

Stated up front, because the panel will probe it:

- We are **not** claiming to detect vulnerabilities better than CodeQL, Semgrep or Snyk. Detection is
  delegated to established scanners; we are not building a detection engine.
- We are **not** claiming to produce better fixes than Copilot Autofix. A 7B local model will not beat
  GPT-4-class fixes on quality.
- We are **not** claiming "closed-loop verification" as novel — **that is Copilot Autofix, and we say
  so explicitly.**

What we claim is narrower and actually defensible: **a reproducible testbed that measures which
prompting strategy yields scanner-verified fixes, under stricter verification than anyone currently
applies, with finding identity tracked across commits.**

---

## 5. One-paragraph answer for the panel

> We surveyed six categories of existing solution. The closest is GitHub Copilot Autofix, which has
> shipped the scan-fix-rescan loop since August 2024 — so we are explicitly *not* claiming that loop as
> our contribution. What none of them do is treat the prompt as a measurable variable, even though the
> literature shows prompting technique changes weakness density by up to 77%; none verifies that the
> fix preserved functionality, even though the same literature documents LLMs renaming functions
> `secure_*` without changing them; and the one tool that does finding lifecycle well, DefectDojo, has
> no AI remediation at all, while every tool with AI remediation has no lifecycle. Our project sits in
> that intersection: measured prompting strategies, triple-gate verification, and cross-commit
> regression tracking — open and reproducible, on a local model.

---

## Sources

- [Found means fixed: Introducing code scanning autofix — GitHub Blog](https://github.blog/news-insights/product-news/found-means-fixed-introducing-code-scanning-autofix-powered-by-github-copilot-and-codeql/)
- [Copilot Autofix GA — GitHub Changelog](https://github.blog/changelog/2024-08-14-copilot-autofix-for-codeql-code-scanning-alerts-is-now-generally-available/)
- [About Copilot Autofix for code scanning — GitHub Docs](https://docs.github.com/en/code-security/concepts/code-scanning/copilot-autofix-for-code-scanning)
- [Copilot Autofix Code Scanning: How It Works & Its Limits](https://safeguard.sh/resources/blog/how-copilot-autofix-generates-ai-powered-vulnerability-fixes-in-code-scanning)
- [Semgrep vs Snyk Code (2026) SAST Comparison](https://appsecsanta.com/sast-tools/semgrep-vs-snyk-code)
- [Snyk Code vs Semgrep: SAST platform comparison 2026](https://safeguard.sh/resources/blog/snyk-code-vs-semgrep-2026)
- [DefectDojo — Open-Source Vulnerability Management and ASPM](https://defectdojo.com/)
- [About Deduplication — DefectDojo Documentation](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/)
- [SARIF integration — DefectDojo](https://defectdojo.com/integrations/sarif)
- [PyGoat — OWASP Foundation](https://owasp.org/www-project-pygoat/)
- [LLMSecEval: A Dataset of Natural Language Prompts for Security Evaluations](https://arxiv.org/pdf/2303.09384)
- [SeCodePLT: A Unified Platform for Evaluating the Security of Code GenAI](https://arxiv.org/pdf/2410.11096)
- [Harnessing Prompt Rules for Secure Code Generation — Backslash Security](https://www.backslash.security/blog/harnessing-prompt-rules-for-secure-code-generation)
- [Backslash Security research: popular LLMs generate insecure code unless explicitly prompted (April 2025)](https://www.globenewswire.com/news-release/2025/04/24/3067494/0/en/Backslash-Security-Reveals-in-New-Research-that-GPT-4-1-Other-Popular-LLMs-Generate-Insecure-Code-Unless-Explicitly-Prompted.html)
- [SafeCodeX: Security-Aware Code Generation with LLMs — NUS Institute of Data Science](https://ids.nus.edu.sg/safecodex.html)
- [Secure Code Generation via Online Reinforcement Learning with Vulnerability Reward Model (SecCoderX), arXiv:2602.07422](https://arxiv.org/abs/2602.07422)
