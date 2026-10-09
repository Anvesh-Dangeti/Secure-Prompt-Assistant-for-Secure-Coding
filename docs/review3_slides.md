# Review 3 — slide content

Saturday 10 October 2026 · 15 minutes · deck: `../Secure_Prompt_Assistant_Review3.pptx`
(built by `scripts/build_review3_deck.py`; every result number comes from
`evaluation/recorded_results.py`, which the integration tests assert against real scanner runs).

---

## 1 · Title
Building a Prompt Assistant for Secure Coding — *Phases 1–4 built: scan, normalise, classify, and
track every finding across commits.*

## 2 · Promised at Review 2, delivered at Review 3
| Promised for the next two weeks (Review 2, slide 12) | Status |
|---|---|
| Phase 1 Foundation — config, secure logging, DB models, safe subprocess | ✓ done |
| Phase 2 Scanner layer — 4 scanners behind one interface, SARIF normalisation | ✓ done |
| Phase 3 Repository — SSRF-safe clone, zip-slip-safe upload, fixture with ground truth | ✓ done |
| **Phase 4 Intelligence — CWE/OWASP mapping, fingerprints, lifecycle (not promised)** | ✓ done, ahead of plan |
| Requirement 12 — project on GitHub with regular check-ins | ✓ per-phase commits |

Review 2 outcome: scope accepted as presented. Nothing in it has changed.

## 3 · What runs today
Repository (https URL or ZIP) → 4 scanners → normalise (SARIF shape) → CWE/OWASP/CVE → fingerprint →
lifecycle — **built**. Explainer → prompt builder × S0–S8 → linter, and sandboxed apply → three gates —
Review 4. Dashboard and ESR evaluation — Review 5.

## 4 · Four independent scanners, one finding shape
| Scanner | Finds | Runs as | Hardening | Fixture |
|---|---|---|---|---|
| Semgrep 1.180.0 | SAST | pinned 151-rule snapshot, SHA-256 recorded | `--disable-nosem`, `--no-git-ignore`, telemetry off | 12 |
| Bandit 1.9.4 | SAST | isolated venv | `--ignore-nosec` | 9 |
| Gitleaks 8.30.1 | secrets | binary | secret masked before storage; `gitleaks:allow` ignored | 1 |
| pip-audit 2.10.1 | deps → CVEs | isolated venv | never installs the repo's deps; unpinned = not audited | 2 |

Semgrep CE's "native fingerprint" is `"requires login"` for every finding → identity is derived.

## 5 · 10 of 10 seeded weaknesses detected
One seeded instance per scoped CWE, located by symbol (`ast`), detector-aware scoring.
Recall 10/10 · precision 22/24 (the 2 FPs are Bandit import advisories, suppressed) · Semgrep +
Bandit agree 4/4 where both have a rule.

## 6 · Identity that survives code moving
Never part of a fingerprint: line number · whitespace and comments (incl. `# nosec`) · ruleset install
path · scratch directory · raw secret value · fake native fingerprints. Verified end-to-end: shifts +
reformatting + suppression comments + `.semgrepignore` → 0 false RESOLVED, 0 false NEW.

## 7 · Six commits, every lifecycle state
| | Commit | NEW | RESOLVED | REGRESSION | UNVERIFIED | Scan |
|---|---|---|---|---|---|---|
| v1 | baseline; 2 FPs suppressed | 24 | 0 | 0 | 0 | COMPLETED |
| v2 | SQLi parameterised + new `os.system()` route | 4 | 3 | 0 | 0 | COMPLETED |
| v3 | reformat + `# nosec` / `# nosemgrep` | 0 | 0 | 0 | 0 | COMPLETED |
| v4 | SQL fix reverted | 0 | 0 | 3 | 0 | COMPLETED |
| v5 | token → env var while Gitleaks is down | 0 | 1 | 0 | 1 | PARTIAL |
| v6 | same code, Gitleaks back | 0 | 1 | 0 | 0 | COMPLETED |

v2 is why Gate 2 exists. v5 is why absence alone is not evidence. `python scripts/demo_lifecycle.py`.

## 8 · Absence of a finding is not evidence of a fix
A finding is RESOLVED only if its scanner could have seen it (crash, timeout, missing tool, unparseable
file, unpinned dependency → UNVERIFIED). 24 transitions tested exhaustively plus a property test. On
vulpy, 9 unpinned requirements are reported as not audited. The LLM is nowhere in this decision.

## 9 · A scanner of untrusted code is an attack surface
SSRF (58 tests) · ZIP upload (24) · git clone without operator config or credential helpers (10 + live) ·
subprocess safety (10) · code-under-scan cannot silence scanners · secrets redacted before storage,
logging and hashing · API key on every route, fail-closed, body cap before multipart parsing (14).

## 10 · Six defects we would not have found by reading
"requires login" fingerprints · install-path rule ids · `# nosec` changing identity · Semgrep CWE
mis-tags · an SSRF refusal swallowed by its own `except ValueError` · `taskkill` partial path whose first
fix introduced a new Semgrep finding. Plus a reported gap: Gitleaks misses `DB_PASSWORD = "SuperSecret123!"`.

## 11 · A real repository, and our own code
vulpy by URL: 68 findings in ~11 s, 27 in scope over 6 CWEs, 9 unpinned requirements not audited
(snapshot, 8 Oct 2026). Own code: Semgrep 0 · Gitleaks 0 · pip-audit 0 · Bandit 3 LOW (inherent);
3 real issues fixed. 278 tests.

## 12 · What comes next
Review 4: Phase 5 AI layer + Phase 6 triple-gate verification. Review 5: dashboard + ESR evaluation.
Review 6: hardening + final. Questions: model diversity for ESR; CodeQL cross-validation in scope?

## 13–15 · Thank you · two appendix pages of prepared answers
