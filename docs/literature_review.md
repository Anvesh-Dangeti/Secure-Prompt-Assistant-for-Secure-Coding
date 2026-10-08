# Literature Review — AI-Assisted Secure Coding, Vulnerability Remediation and Fix Verification

**Project:** Building a Prompt Assistant for Secure Coding · TEAM-3
**Prepared for:** Review 2 (19 September 2026)
**Responds to:** Review 1 Action Item 4 — *"Explore relevant academic literature related to
AI-assisted secure coding, vulnerability remediation, prompt-based code repair, and verification of
AI-generated fixes."*

---

## 0. How to read this document

Section 1 covers the three papers assigned by the panel, in depth. Section 2 covers the supporting
literature those three papers rest on. Section 3 states the five research gaps we extract. Section 4
maps each gap to a concrete design decision, so the panel can see the literature actually changed the
build rather than decorating it.

Every claim below is attributed. Where we give a number, it comes from the cited paper's own tables.

---

## 1. The three assigned papers

### 1.1 Paper 1 — *Guiding AI to Fix Its Own Flaws: An Empirical Study on LLM-Driven Secure Code Generation*

Yan, Vaidya, Zhang & Yao — George Mason University. arXiv:2506.23034v1, June 2025.

**What they did.** A three-part evaluation of 16 LLMs (proprietary and open-weight, 7B through
GPT-4o) on two Python security benchmarks — **SecurityEval** (130 samples, 75 CWE types) and
**SecCodePLT** (21 CWE types). CodeQL is the detector throughout. Three research questions:

1. *Do LLMs generate vulnerable code?* — measured with vanilla prompts.
2. *Do self-generated vulnerability hints help prevention?* — the model predicts its own likely CWEs
   before writing code.
3. *How do LLMs use different levels of feedback for post-hoc repair?* — the key part for us.

**Findings that matter to us.**

| Finding | Evidence |
|---|---|
| **All models generate vulnerable code, routinely.** Averages: SecCodePLT 8.5% target-vulnerability rate / 13.2% all-vulnerability rate; SecurityEval 20.7% / 33.4%. | §5.1, Table 3 |
| Vulnerabilities span both common (Top-25) and uncommon CWEs — narrow mitigation is insufficient. | §5.1 Takeaway |
| Counter-intuitively, **code-optimised models (CodeLlama, StarCoder2) produced safer code than newer general models** (GPT-4o, Llama-3). Size and recency do not imply security. | §5.1 Takeaway |
| Self-generated hints help **only when they name the right vulnerability**. Irrelevant hints *increased* vulnerability rates in most models. | §5.2, Table 5 |
| **Contextualised hints beat generic CWE definitions** — tying the weakness to the specific coding scenario produced larger reductions than pasting the MITRE description. | §5.2, Table 7 |
| **The headline result for us: "explained feedback" outperforms "direct feedback" for repair.** Direct feedback = raw CodeQL output (rule, short description, line). Explained feedback = that output passed through an LLM that explains *why* it is vulnerable and *what actions* fix it. Explained feedback produced substantially larger reductions on GPT-4o, DeepSeek-Coder-V2 and GPT-3.5. | §5.3, Table 8 |
| The explanations were reliable: manual validation of 160 sampled explanations found **over 98% correct and actionable**. | §5.3 |

**Authors' own recommendation to developers** (§6) — worth quoting at the review, because it reads
almost as a specification for our AI layer:

> *"Incorporating fine-grained, explained feedback is essential for effective vulnerability repair…
> Developers should design their systems to provide rich, actionable insights that guide the LLM in
> identifying and fixing security flaws."*

**What we take.** The AI layer becomes **two stages, not one**: an *Explainer* that converts raw
scanner output into contextualised, actionable guidance, feeding a *PromptBuilder* that drafts the
remediation prompt. Also: adopt SecurityEval as a benchmark, and always prefer contextualised
explanation over pasted CWE boilerplate.

**What it leaves open.** Everything is measured on **isolated benchmark snippets the model itself
just generated**. There is no repository, no commit history, no cross-scan identity, and the only
success criterion is "CodeQL reports fewer weaknesses" — with no check that the repaired code runs.

---

### 1.2 Paper 2 — *The Language of Security: How Prompt Syntax Shapes Secure Code Generation in Open LLMs*

Cicalese, Della Porta, Lambiase, Iannone, Hinrichs, Scandariato & Palomba — University of Salerno /
Aalborg / TU Hamburg. arXiv:2607.15937v1, July 2026.

**What they did.** A parser-driven causal study. Starting from the 150 **LLMSecEval** prompts, they
built a constituency parse tree of each and generated variants removing **exactly one syntactic
constituent** — 4,320 permutations per language across C, Java and Python (12,960 prompts), run
through three locally-hosted open models (Qwen-2.5 32B, Athene-V2 72B, Phi-4 14.7B), producing 40,230
code solutions, all labelled with CodeQL. Statistics: omnibus χ² with Cramér's V, Barnard's exact
test, Benjamini–Hochberg FDR correction.

**Findings that matter to us.**

| Finding | Evidence |
|---|---|
| **Python is by far the most vulnerability-prone target: 40.95% of analysed Python snippets contained at least one CWE, versus Java 8.82% and C 0.78%.** | §IV-A-2, Table II |
| Java snippets **failed analysis 86.81% of the time** (compilation strictness); Python analysed successfully 100% of the time. | §IV-A-1 |
| **Position is the strongest single predictor.** Removing content from the *opening* sentence raised vulnerability rates across all models (RR up to 2.31). In Python there was a monotonic gradient — removals at *later* positions were progressively worse, in several cases approaching 100% vulnerability. | §IV-B-1 |
| **Constituent type matters.** WHNP and WHADVP — phrases like *"which input"*, *"how the data is validated"*, *"under what authority"* — were the most consistently security-sensitive structures across every model and language, risk ratios up to 1.88. These are the constituents that **bind entities to constraints**. | §IV-B, Table III |
| **Even minimal edits are dangerous.** Minimal-granularity removals — the smallest possible edit — were enough to raise vulnerability rates. Casual rewording or shortening can silently strip a security-relevant element. | §V-B |
| A confirmatory re-run (109 baseline + 353 permutation prompts, 3 samples each) reproduced every trend. | §VI, internal validity |

**Authors' explicit call for future work** (§V-B) — the origin of one of our components:

> *"A prompt linter that parses constituency structure and flags when security-sensitive constituents
> are missing, weakened, or buried in low-attention positions could serve as a lightweight complement
> to post-generation static analysis. Building and evaluating such tooling is a concrete next step
> enabled by our findings."*

**What we take.** Two things. (a) The **language scope decision** — Python is empirically where
LLM-generated code is least secure *and* most analysable, which justifies focusing there rather than
spreading thin. (b) A **Prompt Security Linter**: our remediation prompts must be generated from
slot-filled templates that provably retain the entity binding, the guard/condition, the handling
directive and the scope constraint, with the task anchored in the opening sentence, no constraint
left stranded in the final position, and no silent shortening.

**What it leaves open.** The study is about **generation**, not **repair**. It never feeds scanner
findings back to a model, never applies a fix, never verifies one. And the linter it proposes does
not exist.

---

### 1.3 Paper 3 — *Prompting Techniques for Secure Code Generation: A Systematic Investigation*

Tony, Díaz Ferreyra, Mutas, Dhif & Scandariato — TU Hamburg.
ACM TOSEM 34(8), Article 225, October 2025. DOI 10.1145/3722108.

**What they did.** A systematic literature review producing an inventory of prompting techniques
usable for code generation, followed by a controlled evaluation of seven of them on GPT-3, GPT-3.5
and GPT-4 over the 150 **LLMSecEval** prompts. Detection by **Bandit** (primary) with **CodeQL**
(secondary). Temperature fixed at 0.0 for reproducibility. Generalisation check on C with GPT-4.

**The seven templates (Table 2)** — we implement all of these as our strategy registry:

| Strategy | Shape |
|---|---|
| Baseline (0-shot) | "Generate Python code for the following: `<task>`" |
| Naive-secure (0-shot) | adds the single word *secure* |
| CWE-specific (0-shot) | adds MITRE-derived mitigation text for the target CWE |
| Comprehensive (0-shot) | "prevents top security weaknesses listed in CWE" — generic, short |
| Zero-shot CoT | + *"Let's think step by step"* then *"Therefore, final secure Python implementation is:"* |
| **RCI** (Recursive Criticism & Improvement) | generate → *"Review the following answer and find security problems with it"* → *"Based on the critique, improve the following answer"* |
| Persona / memetic proxy | *"Act as a software security expert…"* |

**Findings that matter to us.**

| Finding | Evidence |
|---|---|
| **RCI is the best technique, decisively.** On GPT-4 it cut average weakness density **77.55%** versus baseline, and beat every other technique head-to-head: 60.70% below naive-secure, 45% below CWE-specific, 60.71% below zero-shot CoT. Best on GPT-3.5 too. | §7.1, Tables 3–4 |
| **Persona prompting was the *worst* technique across all three models** — on GPT-3.5 it was worse than the baseline containing no security instruction at all. Role-play is not a security control. | §7.1 |
| Zero-shot CoT underperformed expectations. Reasoning triggers help arithmetic and logic; security is a *non-functional* requirement that "think step by step" does not surface. | §7.1 |
| Merely adding the word *"secure"* reduced weakness density 28–43%. Cheap, but far from sufficient. | §7.1, Table 4 |
| **The four most prevalent CWEs in LLM-generated Python: CWE-78 (OS command injection), CWE-259/798 (hard-coded credentials), CWE-94 (code injection — Flask debug mode), CWE-330 (insecure randomness).** | §7.2, Table 5 |
| **CWE-78 resisted every prompting technique.** No template meaningfully reduced it. | §7.2 |
| RCI was uniquely effective on hard-coded credentials (GPT-4: 21 → 5 instances) and Flask debug mode (GPT-4: 54 → 3). | §7.2 |
| **LLMs fake fixes.** §7.4(vi): generated code contains *"calls to undeclared methods that did not exist within the code's scope"*, often for security-sensitive tasks, with comments like *"securely verify the user session"*. §7.4(vii): method names get prefixed `secure_` — `secure_ping()`, `secure_upload_file()` — *"despite the suggestive prefixes, the actual implementation within these methods remains unaltered."* | §7.4 |
| Bandit's reliability was established against manual review: **weighted Cohen's κ = 0.87** over 315 manually inspected snippets. | §6.3 |
| **Static analysis catches what LLMs miss.** Takeaway (6): *"it is still strongly advised to use these tools in tandem with LLMs in the development pipeline."* | §7.5 |
| RCI's advantage held on C as well as Python — the technique generalises even where other rankings shift. | §7.5, Table 6 |

**What we take.** Three things. (a) The **prompt strategy registry** — implementing all seven
templates turns our evaluation from an anecdote into a controlled experiment with a *known expected
ordering* (RCI best, persona worst) that doubles as a validation of our own harness. (b) **Bandit as
a first-class scanner** — Paper 3 used it as primary detector at κ = 0.87, which reverses our
Review 1 decision to drop it. (c) Most importantly, §7.4(vi–vii) is the empirical basis for our
**functional preservation gate**: the literature *documents* LLMs producing code that looks fixed and
is not, and a scanner-only verifier scores those as successes.

**What it leaves open.** Again, isolated snippets from a benchmark. No repository, no lifecycle, no
regression tracking — and critically, *the paper observes the fake-fix behaviour but its own
methodology cannot penalise it*, because weakness density is measured on code that was never
required to run.

---

## 2. Supporting literature

The works the three assigned papers lean on, and which we cite for framing.

| Work | Relevance |
|---|---|
| **Pearce et al., "Asleep at the Keyboard?" (CACM 68(2), 2025)** | The founding result: **40% of GitHub Copilot completions in security-relevant scenarios contained vulnerabilities**, across 18 CWEs. Establishes that the problem exists. |
| **Perry et al., CCS 2023, "Do users write more insecure code with AI assistants?"** | User study: participants **with** an AI assistant produced *more* insecure solutions — and were *more confident* they were secure. The human-factors argument for why an independent verifier, not a persuasive explanation, must decide fix status. |
| **Tony et al., MSR 2023 — LLMSecEval** | The 150-prompt NL dataset covering 18 of the 2021 MITRE Top-25. Used by both Paper 2 and Paper 3; adopting it makes our numbers comparable to theirs. |
| **Siddiq & Santos — SecurityEval** | 130 Python samples over 75 CWE types. Paper 1's primary benchmark. |
| **Yang et al. — SecCodePLT** | Broader successor with manual security-relevance verification and dynamic test cases. Paper 1's second benchmark; our stretch benchmark. |
| **Kim et al. — RCI (Recursive Criticism and Improvement)** | The technique Paper 3 found best. Originally proposed for computer-control tasks, not security. |
| **Wei et al. — Chain-of-Thought** | The reasoning-trigger family; Paper 3's evidence that it underperforms for security is a useful negative result. |
| **He & Vechev — SVEN (controlled secure code generation)** | The fine-tuning alternative to prompting: +25% secure output on CodeGen. Cited to explain why we chose prompting — no GPU budget for tuning, and prompting is what developers actually do. |
| **Shukla, Joshi & Syed, ISTAS 2025 — "Security degradation in iterative AI code generation: a systematic analysis of the paradox"** | Iterative AI refinement can *amplify* critical flaws without human oversight. Direct justification for our "no new findings introduced" gate. |
| **Schreiber & Tippe, ICICS 2025** | Large-scale analysis of public GitHub repositories finding thousands of CWE-mapped vulnerabilities in AI-generated code. The scale argument. |
| **Cotroneo et al., ISSRE 2025** | Human-written vs AI-generated code compared at scale on defects, vulnerabilities and complexity. |
| **Asare et al.** | The useful counterweight: Copilot is *not* uniformly worse than humans at introducing vulnerabilities. Cited to stay honest rather than overclaim. |
| **Backslash Security (April 2025) — prompt rules for secure code generation** | *Vendor research, not peer-reviewed — cited for corroboration and as competitive landscape, never as evidence.* Seven current OpenAI/Anthropic/Google models at three prompting tiers, scored over 10 CWE use cases: **40–90% of generated code vulnerable by default**; GPT-4o 1/10 and GPT-4.1 1.5/10 on naive prompts against 6/10 for the best model; the OWASP tier moved GPT-4o 20% → 65%. Independent replication of Paper 3's core claim on 2025-era models. Their CWE-specific rules files are the source of our strategy **S8**. |
| **Wu, Du, Liu, Yang, Zhuo, Zhang & Ng — SecCoderX / SafeCodeX (arXiv:2602.07422, 2026)** | NUS IDS, Google GARA-funded. Online RL with a *vulnerability reward model* over PrimeVul/CrossVul/R2Vul, CodeQL-graded. Source of our headline metric **Effective Safety Rate** — code that is *both* functionally correct **and** secure. Reports +~10% ESR while **prior secure-generation methods degrade ESR by 14–54%**. The RL alternative we are *not* taking, for the same reason as SVEN: no GPU budget, and our target models are black-box. |
| **SARIF (OASIS standard)** | The interchange format that lets Semgrep, Bandit and CodeQL results share one normalised shape. |

---

## 3. Research gaps

Synthesising across the above, five gaps are open. Each is small enough for a student project and
each is defensible in a viva.

### G1 — Prompting techniques have never been evaluated on scanner-grounded findings in real repositories

Papers 1 and 3 both evaluate on **isolated benchmark snippets that the model itself just generated**,
scored by counting weaknesses. Nobody has taken a *real finding from a real scanner on a real
repository*, applied RCI or explained-feedback prompting to it, and measured whether the **same
scanner independently confirms the finding is gone**. The prompting literature and the vulnerability
management literature have not met.

### G2 — Verification in the literature is single-shot and cannot detect a fake fix

Every paper's success criterion is "weakness count went down." None checks whether the remediation
**introduced new weaknesses** (Shukla et al. show iterative refinement can amplify flaws), and none
checks whether the remediated code **still works**. This is not theoretical: Paper 3 §7.4(vi–vii)
*documents* LLMs calling undeclared "secure" methods and renaming functions `secure_*` without
changing their bodies. Under a scanner-only criterion, **deleting the vulnerable code is a perfect
score.** The literature observes this failure mode but has no mechanism that penalises it.

It is also now *measured*, not merely anecdotal. SecCoderX (arXiv:2602.07422) reports that prior
secure-generation methods **degrade Effective Safety Rate by 14–54%** — ESR counting only code that
is both functionally correct and secure. Between one in seven and one in two of the "improvements"
those methods produce break working code. Any pipeline that reports security without measuring
functionality is reporting half a result, and the missing half is large.

### G3 — The prompt linter Paper 2 calls for does not exist

Paper 2 §V-B proposes syntax-aware prompt analysis tooling as *"a concrete next step enabled by our
findings."* No implementation exists. Their own results specify exactly what it must check: entity
bindings (WHNP), conditions and guards (WHADVP/SBAR), handling directives (VP), opening-sentence
anchoring, and resistance to shortening.

### G4 — No study tracks finding identity across commits

All of this work is single-snapshot. Without stable finding identity across commits you cannot
distinguish a genuine fix from a shifted line, a renamed file or a refactor — and you cannot detect
**regression**, where a previously-verified fix quietly reappears in a later commit. Industrial
vulnerability-management tooling (DefectDojo) solves deduplication and lifecycle but has no AI
remediation; the AI remediation tools have no lifecycle. Neither side has crossed over.

### G5 — No reproducible open-model repair-and-verification pipeline exists

Papers 1 and 3 rely on proprietary GPT models, which Paper 3 itself flags as an external-validity
threat and a data-leakage risk (§8–§9). Paper 2 uses open models *for reproducibility* — but only for
**generation**, never for **repair**. An end-to-end pipeline that repairs and verifies using a
locally-hosted open model, with fixed weights and temperature, has not been reported.

---

## 4. Gap to design decision

The table that shows the literature review changed the project rather than accompanying it.

| Gap | Design decision | Where it lives |
|---|---|---|
| **G1** | Prompt Strategy Registry (S0–S8) applied to real scanner findings from cloned repositories, with scanner-confirmed resolution as the outcome variable | `app/ai/strategies/`, `evaluation/` |
| **G1** | **S8 — rules-file injection**: the technique Backslash ships and claims 100% for, evaluated here under an independent re-scan and a functional gate for the first time | `app/ai/strategies/` |
| **G1** | Two-stage AI layer: *Explainer* (raw finding → contextualised, actionable explanation) feeding *PromptBuilder* — Paper 1's explained-feedback result | `app/ai/explainer.py`, `app/ai/prompt_builder.py` |
| **G2** | **Triple-gate verification.** Gate 1 target resolved · Gate 2 no new findings at equal-or-higher severity · **Gate 3 function preserved** (AST parse + import + test suite) | `app/verification/gates/` |
| **G3** | **Prompt Security Linter** — deterministic pre-send validator for entity binding, guard/condition, handling directive, scope constraint, opening-sentence anchoring, no-shorten guard | `app/ai/linter.py` |
| **G4** | Fingerprint-based finding identity + lifecycle state machine (`NEW` / `STILL_OPEN` / `RESOLVED` / `REGRESSION` / `SUPPRESSED`) across commits | `app/intelligence/` |
| **G5** | Provider-agnostic AI layer with a **local open-model arm** (Ollama, temperature 0.0, pinned weights) alongside a hosted arm, plus a reproducibility manifest per result row | `app/ai/providers/`, `evaluation/manifest.py` |

Two further decisions follow from the reading rather than from a gap:

- **Bandit is restored as a first-class scanner** (Paper 3 used it as primary detector, κ = 0.87;
  Paper 2's threats-to-validity asks for *"consensus across independent static analyzers"*). Two
  independent SAST tools give us an inter-tool agreement metric — a result, not redundancy.
- **The vulnerability scope is drawn from Paper 3 §7.2's empirical prevalence data**, not from
  guesswork — which is why CWE-78, CWE-798/259, CWE-94 and CWE-330 are all in our scoped set. See
  `scope_decisions.md`.

---

## 5. Threats to validity we inherit, and will state

Intellectual honesty at the review is worth more than a clean story.

1. **Static analysis is imperfect.** Both false positives and false negatives are possible; Paper 2
   says so explicitly. Our `SUPPRESSED` lifecycle state exists precisely so false positives are
   tracked rather than silently deleted, and our dual-SAST agreement metric measures the
   disagreement rather than hiding it.
2. **Scanner-confirmed is not the same as secure.** Our verification proves *the scanner no longer
   detects this weakness* — a weaker claim than *the code is secure*. We will say this plainly.
3. **Data leakage / contamination.** LLMSecEval's repository predates some model training cutoffs.
   Paper 3 measured this with the Dolos plagiarism toolkit (similarity 0.075, well under the 0.5
   plagiarism threshold) and found the effect minimal; we reuse that argument and note the residual
   risk.
4. **Non-determinism.** Mitigated by temperature 0.0, fixed `top_p`, pinned model versions and pinned
   scanner rulesets — and, where budget allows, repeated runs as Paper 2 did.
5. **Single-language scope.** Python only. Findings may not transfer to compiled languages; Paper 3's
   C generalisation showed some rankings shift even though RCI stayed on top. We treat the optional
   JavaScript run as a validity check, not a feature.

---

## 6. One-paragraph answer for the panel

> The literature establishes three things. First, LLMs generate vulnerable code at high rates — about
> 40% of Copilot completions in security-relevant contexts (Pearce et al.), and 40.95% of
> LLM-generated Python snippets in the most recent controlled study (Paper 2). Second, *how* you
> prompt matters enormously and measurably: RCI prompting cut weakness density 77.55% on GPT-4, while
> persona prompting performed worse than no security instruction at all (Paper 3), and enriching raw
> scanner output into explained feedback substantially improved repair (Paper 1). Third — and this is
> our opening — every one of these studies verifies a fix by counting weaknesses in an isolated
> snippet, so an LLM that *deletes* the vulnerable code, or renames a function `secure_*` without
> changing it, scores a perfect result. Paper 3 documents that exact behaviour in §7.4 but its
> methodology cannot penalise it. We therefore build a system that applies these prompting techniques
> to real scanner findings in real repositories, and verifies each fix against three independent
> gates — the weakness is gone, nothing new appeared, and the code still runs — while tracking each
> finding's identity across commits so a regression cannot hide.

---

*Compiled from: Yan et al. (arXiv:2506.23034), Cicalese et al. (arXiv:2607.15937), Tony et al.
(ACM TOSEM 34(8):225), plus the supporting works listed in Section 2.*
