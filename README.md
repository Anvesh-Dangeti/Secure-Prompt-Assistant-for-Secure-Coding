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
`NEW → STILL_OPEN → RESOLVED → REGRESSION`, with human-marked `SUPPRESSED` false positives. For each finding
it builds a remediation prompt with a *selectable, measured* prompting strategy (S0–S8), checks that prompt
with a **Prompt Security Linter**, and then re-scans independently to verify the fix against three gates:
the weakness is gone (every scanner agrees), nothing new was introduced, and the function still works.

It runs in two modes:

| | Developer mode | Lab mode |
|---|---|---|
| Who writes the fix | **your own coding assistant** (Copilot, Cursor, Codex, …) | a local open model (Ollama), for experiments |
| Model needed by this tool | none — explanations and prompts come from templates | `qwen2.5-coder:7b-instruct` on this machine |
| What it is for | getting a better prompt to your assistant, then verifying its fix | measuring which strategy yields verified fixes |

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
| 5 | AI prompt assistant — context + entities, explainer, strategies S0–S8, Prompt Security Linter, providers | ✅ |
| 6 | Triple-gate verification — developer-mode `verify` (gates 1, 2, 3a), lab-mode scratch-copy apply (+ 3b) | ✅ |
| 7 | Dashboard — findings, prompt + copy, lint, rescan & verify, history (Streamlit, loopback only) | ✅ |
| 8 | Evaluation — linter mutation sensitivity, S0–S8 ESR, weak vs linted prompts | ⬜ Review 5 |
| 9–10 | Hardening · final | ⬜ by 18 Nov |

On the seeded fixture: **10/10 weaknesses detected**, precision 22/24; an eight-commit verification scenario
covers every verdict; 637 automated tests.

---

## Setup (Windows or Linux, Python 3.12)

```bash
python -m venv .venv && .venv/Scripts/activate          # Linux: source .venv/bin/activate
pip install -r requirements.txt
python scripts/install_scanners.py                       # Semgrep, Bandit, pip-audit in isolated venvs
winget install --id Gitleaks.Gitleaks --version 8.30.1 --exact   # or a release binary
python scripts/fetch_semgrep_rules.py                    # pinned ruleset snapshot (rules/vendor/)
python scripts/install_fixture_env.py                    # lab mode only: interpreter for gate 3b's tests
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

# developer mode -- no model needed
python -m app.cli strategies                                        # S0-S8
python -m app.cli explain <id> --source <your checkout>
python -m app.cli prompt <id> --source <your checkout> [--strategy S7] [--out prompt.txt]
python -m app.cli lint-prompt my_prompt.txt [--finding <id> --source <checkout>] [--fix]
#   ... paste the prompt into your assistant, let it edit, commit ...
python -m app.cli verify <id> --source <your checkout>      # rescan, then gates 1, 2, 3a (--rescan for git projects)
python -m app.cli verifications <id>                        # remediation history

python scripts/demo_verify.py             # eight scripted commits exercising every verification verdict

# lab mode -- local model writes the fix into a scratch copy; gates 1, 2, 3a, then 3b (fixture tests)
python -m app.cli providers
python -m app.cli propose <id> --source <checkout> --strategy S5               # proposal only, nothing applied
python -m app.cli lab-verify <id> --source fixtures/flask_vuln_app --strategy S7
python -m app.cli lab-verify <id> --source fixtures/flask_vuln_app --replay evaluation/replays/sqli_good.json

python -m uvicorn app.main:app --host 127.0.0.1   # API; docs at /docs, key via X-API-Key
python -m streamlit run dashboard/streamlit_app.py # dashboard at http://127.0.0.1:8501 (run from the project root)
```

## Dashboard

A local page over the same services as the CLI, for developer mode:

| Page | What it shows / does |
|---|---|
| Overview | open findings by severity, lifecycle and verdict counts, open findings by OWASP category, findings per scan, what the last scan's scanners could see; scan a checkout |
| Findings | filterable tracked findings; evidence, lifecycle events, verdicts; suppress a false positive (reason required) |
| Prompt & lint | the remediation prompt for a finding with a copy button, its lint report, and a linter for your edited prompt with fix-its |
| Verification | rescan your checkout and run gates 1, 2, 3a; per-gate history of every verification (lab runs read-only) |
| Scan history | every scan with its source (commit or archive hash), transitions and scanner status |

It binds to `127.0.0.1` only (`.streamlit/config.toml`) and refuses to render otherwise, sits behind
`SPA_API_KEY`, never runs a model or the scanned code, and shows scanned content only as literal text.

## Verification

| Gate | Passes when | Mode |
|---|---|---|
| 1 target resolved | every scanner's finding of the weakness (same CWE, same function) is verifiably gone; the same rule re-reported on the edited code counts as still present | both |
| 2 no new findings | nothing introduced at the weakness's severity or above (lower: warning); a failed scanner makes it `UNVERIFIED` | both |
| 3a function preserved | same name, parameters and decorators; not a stub; no newly undefined names (static, from scan-time symbol snapshots) | both |
| 3b fixture tests | `fixtures/<name>_tests/` pass on the patched copy (run only after 1, 2 and 3a pass) | lab |

Verdict: `VERIFIED_RESOLVED` only if every gate passes; `FIX_REJECTED` with the first failing gate;
`UNVERIFIED` when evidence is missing. Developer mode never executes repository code.

## Tests

```bash
python -m pytest                    # everything (scanner tests skip if a scanner is missing)
python -m pytest -m "not network"   # offline
python -m pytest -m "not scanners"  # fast: no real scanner runs
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
| Context to a model | only the flagged function or ±10 lines; comments and docstrings removed; redacted; path confined to the checkout |
| Prompt injection | repository code wrapped in random-nonce delimiters with an inert-data instruction; instruction-like text flagged |
| Model server | loopback only; proxies and redirects ignored; bounded response; temperature 0, fixed seed |
| Model output | schema-validated (`code`, single-statement `imports`, `summary`); anything else is a rejected fix, never repaired |
| Applying a fix (lab) | whole-window text splice into a scratch copy, confined to the flagged file; never committed, never applied to your checkout |
| Running a fix (lab, gate 3b) | only after gates 1, 2, 3a pass; separate interpreter; `python -P`, pinned pytest config; allowlisted environment; timeout; CLI only, never over the API |
| API | key on every route, fails closed when unset; body-size cap before multipart parsing; no stack traces returned |
| Dashboard | loopback only (refuses to render otherwise); `SPA_API_KEY` gate, constant-time, lockout; scanned content never rendered as Markdown/HTML; XSRF on, telemetry off, no tracebacks in the browser; checkout paths absolute, outside scratch, optionally confined (`SPA_DASHBOARD_SOURCE_ROOT`) |

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/literature_review.md`](docs/literature_review.md) | Three assigned papers, supporting works, five research gaps |
| [`docs/related_tools.md`](docs/related_tools.md) | Competitive landscape and capability matrix |
| [`docs/scope_decisions.md`](docs/scope_decisions.md) | Language and CWE scope, with evidence |
| [`docs/revised_direction.md`](docs/revised_direction.md) | The changes made after Review 1 |
| [`docs/review3_slides.md`](docs/review3_slides.md) | Review 3 content; deck built by `scripts/build_review3_deck.py` |
| [`docs/review4_slides.md`](docs/review4_slides.md) | Review 4 content; deck built by `scripts/build_review4_deck.py`; demo steps in `docs/review4_presenter_script.md` |

---

## Safety note

`fixtures/` contains **deliberately vulnerable code**. It is isolated, never imported by the
application, and exists only to give the scanners something to find. Its behaviour tests
(`fixtures/flask_vuln_app_tests/`) import it only in lab mode, in a scratch copy, through Flask's test
client, with every process call faked. Do not run it as a server, deploy it, or copy from it. The
credentials in it are fabricated.
