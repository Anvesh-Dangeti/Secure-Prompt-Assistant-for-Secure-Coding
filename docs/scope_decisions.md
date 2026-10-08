# Scope Decisions — Language and Vulnerability Coverage

**Project:** Building a Prompt Assistant for Secure Coding · TEAM-3
**Prepared for:** Review 2 (19 September 2026)
**Responds to:** Review 1 Action Items 2 and 3 — *"Clearly decide how many programming languages the
application will support"* and *"Clearly decide how many and which vulnerability types the application
will focus on. The professor advised prioritizing better results in a smaller, manageable scope rather
than attempting to cover every language or vulnerability category."*

---

## Decision 1 — Language scope: **Python only**

One language. Not "Python first," not "Python plus stretch goals in the MVP." **Python.**

### Evidence

| Evidence | Source |
|---|---|
| **Python-generated code was vulnerable in 40.95% of analysed snippets — versus Java 8.82% and C 0.78%.** Python is where LLM-generated code is empirically least secure, so it carries the most signal per experiment. | Paper 2, §IV-A-2, Table II |
| **Java snippets failed static analysis 86.81% of the time** because of compilation and typing strictness. Python analysed successfully 100% of the time. Choosing Java would mean discarding most of our experimental data. | Paper 2, §IV-A-1 |
| Paper 3 used Python as its primary language and treated C only as a *generalisation check* on 67 of 150 tasks — the same posture we adopt. | Paper 3, §5.1, §5.4 |
| The benchmarks we need are Python: **SecurityEval** (130 samples, 75 CWE types) and **SecCodePLT**. | Paper 1, Table 1 |
| **LLMSecEval** tasks are predominantly web-application scenarios, which map naturally onto Python web frameworks. | Paper 3, §5.4 |

### Tooling evidence

| Tool | Python support |
|---|---|
| **Bandit** | Python-only by design — we could not use it at all without this decision |
| **Semgrep** | Python ruleset is among its most mature; native per-finding fingerprints |
| **pip-audit** | Python-only; maps dependencies directly to real CVEs |
| **Gitleaks** | Language-agnostic (works regardless) |

### Rejected alternatives

| Option | Why rejected |
|---|---|
| Python + JavaScript | Doubles scanner configuration, ruleset tuning, fixture construction and evaluation runs, for no additional research finding. The professor explicitly asked for depth over breadth. |
| Python + Java | Paper 2's 86.81% analysis failure rate on Java makes it the worst possible second choice for an experiment-driven project. |
| Language-agnostic | Cannot build a ground-truth fixture, cannot use Bandit, cannot use the Python benchmarks, cannot compare to published numbers. |

### Stretch, explicitly outside the MVP

If — and only if — the core system is complete and evaluated, we run **one JavaScript generalisation
experiment**, mirroring exactly how Paper 3 generalised its Python findings to C. It is framed as a
**validity check**, not a feature, and it is not promised.

### One-line answer for the panel

> *One language: Python. It is where LLM-generated code is measurably least secure (40.95% vulnerable
> versus 8.82% for Java and 0.78% for C), it is the only language where all four of our scanners work,
> and it is the language of every benchmark we want to compare against.*

---

## Decision 2 — Vulnerability scope: **8 core CWEs + 2 supporting**

### Selection rule

We did not pick these by intuition. Each scoped CWE sits in the intersection of four criteria:

1. **MITRE Top 25** — it is a weakness that matters in practice.
2. **OWASP Top 10 (2021)** — it maps to a category the project brief requires.
3. **Empirically frequent in LLM-generated Python** — Paper 3 §7.2 measured which CWEs actually appear
   in LLM output, so this is data, not guesswork.
4. **Reliably detectable by Semgrep or Bandit** — if we cannot detect it, we cannot verify a fix for it,
   and it does not belong in the scope.

### The eight core CWEs

| # | CWE | Name | OWASP 2021 | Detector | Justification |
|---|---|---|---|---|---|
| 1 | **CWE-89** | SQL Injection | A03 Injection | Semgrep, Bandit | MITRE Top 25; LLMSecEval database-operation tasks; the canonical demonstrable case |
| 2 | **CWE-78** | OS Command Injection | A03 Injection | Semgrep, Bandit | Paper 3 §7.2: **the most frequent weakness in LLM-generated Python, and it resisted every prompting technique.** The single highest-value research target we have — an open problem, not a solved one |
| 3 | **CWE-79** | Cross-Site Scripting | A03 Injection | Semgrep | MITRE Top 25; LLMSecEval input-validation tasks (CWE-20/79/434) |
| 4 | **CWE-798** (with **CWE-259**) | Hard-coded Credentials / Password | A07 Identification & Authentication Failures | Bandit **and** Gitleaks | Paper 3 §7.2: among the four most prevalent; RCI cut it 21→5 on GPT-4. Detected by **two independent tools**, making it our cross-scanner corroboration case |
| 5 | **CWE-22** | Path Traversal | A01 Broken Access Control | Semgrep, Bandit | MITRE Top 25; the worked repair example in Paper 1 §3; LLMSecEval file-handling tasks |
| 6 | **CWE-327 / CWE-328** | Weak or Broken Cryptography | A02 Cryptographic Failures | Bandit | High-confidence Bandit detection; clean, unambiguous fix (MD5/SHA-1 → SHA-256, DES → AES) — a good demo case with a crisp verification signal |
| 7 | **CWE-330** | Insufficiently Random Values | A02 Cryptographic Failures | Bandit | Paper 3 §7.2: one of the four most prevalent CWEs in LLM-generated Python. Fix is `random` → `secrets`, which Paper 3 observed models making under RCI |
| 8 | **CWE-502** | Deserialization of Untrusted Data | A08 Software & Data Integrity Failures | Bandit, Semgrep | MITRE Top 25; Bandit detects `pickle.loads` and `yaml.load`; LLMSecEval serialization tasks |

### The two supporting categories

These come from the non-SAST scanners and round out the OWASP coverage.

| # | CWE | Name | OWASP 2021 | Detector | Justification |
|---|---|---|---|---|---|
| 9 | **CWE-1395** + component **CVEs** | Vulnerable / Outdated Dependency | A06 Vulnerable & Outdated Components | pip-audit | **The only place in this project where CVE mapping is honest.** A source-code weakness has a CWE; only a known vulnerable component version has a CVE. Forcing CVEs onto SAST findings would be wrong, and we will say so |
| 10 | **CWE-94 / CWE-215** | Code Injection / Debug Info Exposure (Flask debug mode) | A05 Security Misconfiguration | Bandit, Semgrep | Paper 3 §7.2: baseline prompts produced 54 instances on GPT-4; **RCI reduced it to 3.** The largest single prompting effect in the literature — an excellent live demo case |

### Coverage summary

**10 CWEs covering 7 of the 10 OWASP Top 10 (2021) categories:** A01, A02, A03, A05, A06, A07, A08.

Not covered, and deliberately so: A04 Insecure Design (not detectable by static analysis — it is an
architectural property), A09 Security Logging & Monitoring Failures (absence of logging is hard to
detect reliably and harder to verify a fix for), A10 SSRF (detectable but adds fixture and rule work
for no new research finding; SSRF *defence* remains in our own application's threat model, where it
belongs).

Saying "we excluded A04 because static analysis structurally cannot detect insecure design" is a
stronger answer than pretending to cover it.

### Why this is the right size

- **Every scoped CWE gets a seeded instance** in our fixture app with ground truth recorded in
  `fixtures/ground_truth.yaml` (file, line, CWE, true/false positive). That gives us real **precision
  and recall**, which a broad scope would make impossible to establish.
- **Every scoped CWE gets run through all 9 prompting strategies.** At 10 CWEs × 9 strategies that is
  90 remediation runs per model arm — tractable on a local model. Doubling the scope doubles the
  experiment matrix for no additional finding.
- **Four of the ten are the CWEs Paper 3 measured as most prevalent in LLM-generated Python**
  (CWE-78, CWE-259/798, CWE-94, CWE-330), so our results are directly comparable to published numbers.
- **Independently corroborated by industry.** Backslash Security's April 2025 study scored seven
  current models against 10 CWE use cases and published three worked rule categories — hardcoded
  secrets, path traversal and input sanitisation. Those map onto **CWE-798**, **CWE-22** and
  **CWE-89/79/78**, all already inside our ten. A commercial vendor selecting rules independently and
  landing inside our scope is a useful answer to "why these ten."
- **CWE-78 is in scope precisely because it is unsolved.** Paper 3 found no prompting technique
  reduced it. If our pipeline moves it at all, that is a genuine finding; if it does not, that
  replicates a published result. Both outcomes are publishable — which is exactly what you want from
  a research target.

### Rejected alternatives

| Option | Why rejected |
|---|---|
| All of OWASP Top 10 | The Review 1 position. Too broad to establish ground truth or run a full strategy ablation; the panel explicitly asked us to narrow it. |
| Top 3 CWEs only (injection family) | Too narrow to say anything about OWASP coverage, and loses the cross-scanner corroboration case (CWE-798) and the largest measured prompting effect (CWE-94). |
| Whatever Semgrep's default ruleset emits | Not a scope decision at all — it is an abdication. Unbounded, unreproducible, no ground truth possible. |

### One-line answer for the panel

> *Ten CWEs — eight core plus two from dependency and configuration scanning — covering seven of the
> ten OWASP categories. They were chosen as the intersection of the MITRE Top 25, OWASP Top 10, the
> CWEs that Paper 3 measured as most prevalent in LLM-generated Python, and what our scanners can
> reliably detect. Four of them are the four most prevalent CWEs in that study, and one of them —
> OS command injection — is in scope specifically because no known prompting technique fixes it.*

---

## Decision 3 — Scanner scope (follows from Decision 1)

| Scanner | Role | Why |
|---|---|---|
| **Semgrep** | SAST (primary) | Open, readable YAML rules; native per-finding fingerprints; SARIF output; mature Python ruleset |
| **Bandit** | SAST (second, independent) | **Reverses the Review 1 decision to drop it.** Paper 3 used Bandit as its primary detector, validated against manual review at Cohen's κ = 0.87. Paper 2's threats-to-validity explicitly asks for *"consensus across independent static analyzers."* Two engines give us an **inter-tool agreement metric** — a result, not redundancy |
| **Gitleaks** | Secrets | Purpose-built; gives CWE-798 a second independent detector |
| **pip-audit** | SCA | Python-native; maps dependencies to real CVEs — the only honest source of CVEs in this project |
| **CodeQL** | *Optional, Phase 8 evaluation only* | All three papers use it, so it is the strongest citation anchor for cross-validation. But it requires a database build per scan, which is too slow for the live loop. Wired as an optional adapter, never in the interactive path |

---

## Decision 4 — Explicitly out of scope

Stated openly at the review, because a defended exclusion is stronger than a vague inclusion.

| Dropped | Reason |
|---|---|
| Multi-language support | Decision 1 |
| Full OWASP Top 10 coverage | Decision 2; A04 is structurally undetectable by SAST |
| GitHub webhooks | Needs a public endpoint and signature verification; adds attack surface for no research value |
| RBAC / multi-tenant authentication | This is a single-user local research tool. We state that honestly in the threat model rather than building theatre |
| Large custom CVE database | CVEs come from pip-audit only |
| Container-per-scan sandboxing | Phase 9 stretch; subprocess isolation with timeouts and non-root execution is sufficient for the MVP |
| Incremental scanning as a feature | Remains a **secondary metric only** — full rescan stays authoritative, because incremental scanning can miss findings whose relevant code lies outside the diff |

---

## Summary card (for the slide)

| Dimension | Decision | Count |
|---|---|---|
| Languages | Python | **1** |
| Core CWEs | CWE-89, 78, 79, 798/259, 22, 327/328, 330, 502 | **8** |
| Supporting CWEs | CWE-1395 (+CVEs), CWE-94/215 | **2** |
| OWASP categories covered | A01, A02, A03, A05, A06, A07, A08 | **7 of 10** |
| Scanners in the live loop | Semgrep, Bandit, Gitleaks, pip-audit | **4** |
| Prompting strategies compared | S0–S8 | **9** |
| Verification gates | resolved · no-new-findings · function-preserved | **3** |
