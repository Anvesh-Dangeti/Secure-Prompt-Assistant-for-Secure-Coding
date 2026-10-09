# Secure Prompt Assistant for Secure Coding

> An open, reproducible testbed that measures **which prompting strategy** actually produces
> scanner-verified secure fixes — under **differential verification** (target resolved **and** nothing
> new introduced **and** function preserved) with **cross-commit regression tracking**.

Secure Software Engineering · IIT Hyderabad · Jul–Nov 2026 · **TEAM-3**
Anvesh Dangeti (EM26MTECH14009) · Dhananjay Kumar (CS26MTECH13007) · Muday Saiprakash Nayak (EM26MTECH11001)

---

## What this is

Scan a Python repository with four independent open-source security tools, normalise and classify every
finding (CWE / OWASP / CVE), and track each finding's identity across commits as
`NEW → STILL_OPEN → RESOLVED → REGRESSION`, with human-marked `SUPPRESSED` false positives. Later phases
generate an AI remediation prompt per finding using a *selectable, measured* prompting strategy, then
independently re-scan to verify the fix against three gates.

**The LLM never decides whether a vulnerability is fixed.** Only an independent re-scan does — and a scan
that could not examine a finding's file or package can never mark it resolved.

**What we do not claim.** Closed-loop verification is not novel: GitHub Copilot Autofix has shipped it
since August 2024. See [`docs/related_tools.md`](docs/related_tools.md).

---

## Status

| Phase | | |
|---|---|---|
| 0 | Review 2 pack — literature, landscape, scope | ✅ |
| 1 | Foundation — config, redacting logs, safe subprocess, DB, API auth | ✅ |
| 2 | Scanners — Semgrep · Bandit · Gitleaks · pip-audit, normalisation, mapping, fingerprints | ✅ |
| 3 | Repository — SSRF-safe clone, zip-slip-safe upload, persisted scans, API | ✅ |
| 4 | Lifecycle — state machine, tracking, suppression, history | ✅ |
| 5–6 | AI prompt assistant · triple-gate verification | ⬜ Review 4 |
| 7–8 | Dashboard · evaluation (ESR) | ⬜ Review 5 |
| 9–10 | Hardening · final | ⬜ Review 6 |

On the seeded fixture: **10/10 weaknesses detected**, precision 22/24, 278 automated tests.

---

## Setup (Windows or Linux, Python 3.12)

```bash
python -m venv .venv && .venv/Scripts/activate          # Linux: source .venv/bin/activate
pip install -r requirements.txt
python scripts/install_scanners.py                       # Semgrep, Bandit, pip-audit in isolated venvs
winget install --id Gitleaks.Gitleaks --version 8.30.1 --exact   # or a release binary
python scripts/fetch_semgrep_rules.py                    # pinned ruleset snapshot (rules/vendor/)
cp .env.example .env                                     # set SPA_API_KEY (and SPA_GITLEAKS_BIN if needed)
python -m app.cli scanners                               # all four should be available
```

Scanners live in their own virtualenvs under `.tools/`: they are external programs, Semgrep's pins
conflict with FastAPI's, and isolation keeps their dependencies out of the application.

## Use

```bash
python -m app.cli scan-dir fixtures/flask_vuln_app --ground-truth     # scan + score, no persistence
python -m app.cli scan-zip fixtures/flask_vuln_app --project demo     # persisted, lifecycle tracked
python -m app.cli scan-url https://github.com/<owner>/<repo> --project name
python -m app.cli findings --project demo [--state new|still_open|resolved|regression|suppressed]
python -m app.cli suppress <id> --reason "why this is a false positive"
python -m app.cli history --project demo

python scripts/demo_lifecycle.py          # six scripted commits exercising every lifecycle state

python -m uvicorn app.main:app --host 127.0.0.1   # API; docs at /docs, key via X-API-Key
```

## Tests

```bash
python -m pytest                    # everything (scanner tests skip if a scanner is missing)
python -m pytest -m "not network"   # offline
```

---

## Security controls (the tool scans untrusted code, so it is itself an attack surface)

| Boundary | Control |
|---|---|
| Repository URL | https only; exact host allowlist; IP literals in any notation refused; resolved addresses must be public; no redirects |
| git clone | operator's git config and credential helpers never loaded; no hooks/submodules/LFS; shallow; `--` before the URL; size caps |
| ZIP upload | traversal, symlinks, NTFS streams, device names, bombs, encrypted and duplicate members refused before any write |
| Subprocesses | list args only, never a shell; executables never from scratch space; allowlisted environment; process-tree kill on timeout; output caps; no elevation |
| Code under scan | `nosec` / `nosemgrep` / `gitleaks:allow` ignored; in-repo scanner config removed from the scratch copy; pip-audit never installs dependencies |
| Secrets | redacted before storage, logging and fingerprinting |
| Verification | a finding is never resolved by a scan that could not see it (scanner failure, unparseable file, unpinned dependency → `UNVERIFIED`) |
| API | key on every route, fails closed when unset; body-size cap before multipart parsing; no stack traces returned |

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/literature_review.md`](docs/literature_review.md) | Three assigned papers, supporting works, five research gaps |
| [`docs/related_tools.md`](docs/related_tools.md) | Competitive landscape and capability matrix |
| [`docs/scope_decisions.md`](docs/scope_decisions.md) | Language and CWE scope, with evidence |
| [`docs/revised_direction.md`](docs/revised_direction.md) | The changes made after Review 1 |
| [`docs/review3_slides.md`](docs/review3_slides.md) | Review 3 content; deck built by `scripts/build_review3_deck.py` |

---

## Safety note

`fixtures/` contains **deliberately vulnerable code**. It is isolated, never imported by the
application, and exists only to give the scanners something to find. Do not run it, deploy it, or
copy from it. The credentials in it are fabricated.
