# Secure Prompt Assistant for Secure Coding

> An open, reproducible testbed that measures **which prompting strategy** actually produces
> scanner-verified secure fixes — under **differential verification** (target resolved **and** nothing
> new introduced **and** function preserved) with **cross-commit regression tracking**.

Secure Software Engineering · IIT Hyderabad · Jul–Nov 2026 · **TEAM-3**
Anvesh Dangeti (EM26MTECH14009) · Dhananjay Kumar (CS26MTECH13007) · Muday Saiprakash Nayak (EM26MTECH11001)

---

## What this is

Scan a Python repository with open-source security tools, generate an AI remediation prompt for each
finding using a *selectable, measured* prompting strategy, then independently re-scan to verify the
fix — against three gates, with each finding's identity tracked across commits.

**What we do not claim.** Closed-loop verification is not novel: GitHub Copilot Autofix has shipped
it since August 2024. What no existing tool does is treat the prompt as a measurable variable,
verify that a fix preserved functionality, or track finding identity across commits. That gap is the
project. See [`docs/related_tools.md`](docs/related_tools.md).

---

## Scope (locked at Review 2)

| Dimension | Decision |
|---|---|
| Language | **Python only** — LLM-generated Python was vulnerable in 40.95% of snippets vs Java 8.82%, C 0.78% |
| Vulnerabilities | **8 core + 2 supporting CWEs**, covering 7 of the 10 OWASP Top 10 (2021) categories |
| Scanners | Semgrep · **Bandit** · Gitleaks · pip-audit |
| Prompt strategies | 8 (S0–S7), including RCI and a persona negative control |
| Verification | 3 gates — resolved · no new findings · **function preserved** |
| Models | Local `qwen2.5-coder:7b` (Ollama) + hosted free-tier arm + deterministic stub |

Full justification with evidence: [`docs/scope_decisions.md`](docs/scope_decisions.md).

---

## Try the demo

```bash
pip install bandit
python scripts/demo_scan.py fixtures/vuln_demo
```

Scans a fixture seeded with nine known weaknesses, normalises the output from each scanner into one
tool-agnostic shape, maps CWE → OWASP, computes stable fingerprints, and scores detection against
recorded ground truth.

```
TOOL    CWE           OWASP     SEVERITY  LOCATION              FINGERPRINT       MESSAGE
bandit  CWE-798<-259  A07:2021  LOW       vulnerable_app.py:34  54aeca7439a7e615  Possible hardcoded password...
bandit  CWE-89        A03:2021  MEDIUM    vulnerable_app.py:45  eb442acfd9d909c6  Possible SQL injection vector...
bandit  CWE-78        A03:2021  HIGH      vulnerable_app.py:58  7a3c24647e3201e7  subprocess call with shell=True...
...
  ground truth (recall)  : 8/8 detected  (100%)
      NOT-RUN  GT-005  CWE-22  (needs: semgrep)
```

`CWE-798<-259` shows CWE-hierarchy normalisation: Bandit reports the child CWE-259, which we
canonicalise to its parent CWE-798 so two tools finding the same weakness are not counted as two
weaknesses.

Add `--json` for the normalised findings.

### Tests

```bash
python tests/unit/test_fingerprint_stability.py
```

Proves a finding's identity survives line shifts and reformatting. This matters more than it sounds:
an unstable fingerprint reports a weakness as RESOLVED and then NEW on a commit that never touched
it, which would invalidate every regression statistic in the evaluation.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/literature_review.md`](docs/literature_review.md) | Three assigned papers, 12 supporting works, five research gaps |
| [`docs/related_tools.md`](docs/related_tools.md) | Competitive landscape and capability matrix |
| [`docs/scope_decisions.md`](docs/scope_decisions.md) | Language and CWE scope, with evidence |
| [`docs/revised_direction.md`](docs/revised_direction.md) | The 13 changes made after Review 1 |
| [`docs/review2_slides.md`](docs/review2_slides.md) | Review 2 presentation content |

---

## Status

| Phase | | |
|---|---|---|
| 0 | Review 2 pack — literature, landscape, scope, demo | ✅ done |
| 1 | Foundation — config, logging, DB, safe subprocess | ⬜ next |
| 2–10 | Scanners → repository → intelligence → AI → verification → dashboard → evaluation → hardening → final | ⬜ |

---

## Safety note

`fixtures/` contains **deliberately vulnerable code**. It is isolated, never imported by the
application, and exists only to give the scanners something to find. Do not run it, deploy it, or
copy from it.
