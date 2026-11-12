# Secure Prompt Assistant for Secure Coding

> An open, reproducible testbed that measures **which way of prompting** a coding assistant actually produces
> scanner-verified secure fixes — under **differential verification** (the weakness is gone **and** nothing new
> was introduced **and** the code still works) with **cross-commit regression tracking**.

Secure Software Engineering · IIT Hyderabad · July–November 2026 · **TEAM-3**
Anvesh Dangeti (EM26MTECH14009) · Dhananjay Kumar (CS26MTECH13007) · Muday Saiprakash Nayak (EM26MTECH11001)
· [Individual contributions](CONTRIBUTIONS.md)

The prompt linter is also published on its own:
**[github.com/Anvesh-Dangeti/secure-prompt-lint](https://github.com/Anvesh-Dangeti/secure-prompt-lint)**.

---

## What this is

The tool works in five steps:

1. **Scan.** It scans a Python repository with four independent open-source security tools (Semgrep, Bandit,
   Gitleaks, pip-audit).
2. **Classify and track.** Every finding is mapped to CWE, OWASP and, for dependencies, CVE. Its identity is tracked
   across commits as `NEW → STILL_OPEN → RESOLVED → REGRESSION`, with human-marked `SUPPRESSED` false positives.
3. **Prompt.** For each finding it builds a remediation prompt with a *selectable, measured* strategy.
4. **Lint.** A **prompt security linter** checks that the prompt — or the developer's edited version of it —
   still says what is at risk, how it must be handled, when the operation may proceed, and what not to touch.
5. **Verify.** It re-scans independently to verify the fix.

| | Developer mode (the product) | Lab mode (the experiment) |
|---|---|---|
| Who writes the fix | **your own coding assistant** (Copilot, Cursor, Codex, …) | a local open model (Ollama), in a scratch copy |
| Model run by this tool | none — explanations and prompts come from templates; **0 tokens spent by the tool** | `qwen2.5-coder:7b-instruct` on this machine |
| What you get | a linted prompt (one message, ~140–375 tokens), then a verdict on your commit | which strategy yields verified fixes, per token |

**The model never decides whether a vulnerability is fixed.** Only an independent re-scan and the structural and
behaviour checks do. A scan that could not examine a finding can never mark it resolved.

**What we do not claim.** Closed-loop verification is not novel: GitHub Copilot Autofix has shipped it since
August 2024 ([`docs/related_tools.md`](docs/related_tools.md)). We do not claim better detection than the scanners
we use, or better fixes than large hosted models.

---

## Results at a glance

All numbers are in `evaluation/recorded_results.py` and asserted by tests. The details are in
[`docs/evaluation.md`](docs/evaluation.md).

| | |
|---|---|
| Seeded weaknesses detected (10 CWEs, four scanners) | **10 / 10**, 22 of 24 findings true positives |
| Verification scenario (8 commits) | every verdict exercised: a stubbed "fix" rejected, a fix that added a new weakness rejected, a scanner outage → `UNVERIFIED` |
| Linter: mutants that remove a security constituent | **168 / 168 flagged**, 0 / 96 false alarms; every failed mutant repaired by the fix-its |
| Strategy pilot (90 lab fixes, local 7B model) | 59 verified; CWE-specific guidance led; recursive review cost ~5× the tokens and broke behaviour more often |
| **Token ladder** (the minimal prompt, live) | **9/10 verified at ~380 tokens per attempt**, against 8/10 at ~2,220 for the full three-message prompt |
| Fixes to functions that other code calls | 13 verified, **0 broke the caller**; 7 behaviour breaks the scanners missed, caught by the tests |
| Tool's own security | self-scan: 3 LOW advisories in the subprocess wrapper only; pip-audit of all 35 packages: **0 vulnerabilities**; **817 tests** |

## The panel's questions (mid-semester review)

| Question | Answer | Where |
|---|---|---|
| How low can token usage go? | The review turns are where tokens go. The minimal prompt (S7m) keeps every linted constituent, costs ~380 tokens per fix attempt, and verified as many fixes as any strategy — the most efficient measured. The floor is the code itself (median 54 tokens). | [`docs/evaluation.md` §6](docs/evaluation.md) |
| Does fixing one function break the functions around it, or larger workflows? | Four layers protect them: the prompt's scope constraint; a whole-repository rescan (check 2); a structural check that keeps parameters, decorators and parsing intact (check 3a); and behaviour tests on a patched copy (check 3b, lab mode). We also state the limits. | [`docs/related_functions.md`](docs/related_functions.md) |
| What can others use to continue the research? | **secure-prompt-lint**: the linter as a dependency-free library and command line, with its rules, fix-its, an extension API and the 288-mutant benchmark, plus a list of open problems. | [`libs/secure-prompt-lint`](libs/secure-prompt-lint) · [public repo](https://github.com/Anvesh-Dangeti/secure-prompt-lint) |

---

## Setup (Windows or Linux, Python 3.12)

```bash
python -m venv .venv && .venv/Scripts/activate          # Linux: source .venv/bin/activate
pip install -r requirements.txt                          # from the repository root (installs libs/secure-prompt-lint too)
python scripts/install_scanners.py                       # Semgrep, Bandit, pip-audit in isolated venvs
winget install --id Gitleaks.Gitleaks --version 8.30.1 --exact   # or a release binary
python scripts/fetch_semgrep_rules.py                    # pinned ruleset snapshot (rules/vendor/)
python scripts/install_fixture_env.py                    # lab mode only: interpreter for check 3b's tests
cp .env.example .env                                     # set SPA_API_KEY (and SPA_GITLEAKS_BIN if needed)
python -m app.cli scanners                               # all four should be available
```

Scanners live in their own virtualenvs under `.tools/`. They are external programs, Semgrep's pins conflict with
FastAPI's, and isolation keeps their dependencies out of the application.

## Use

```bash
python -m dashboard.web                       # web interface at http://127.0.0.1:8080 (sign in with SPA_API_KEY)

python -m app.cli scan-dir fixtures/flask_vuln_app --ground-truth     # scan + score, no persistence
python -m app.cli scan-zip fixtures/flask_vuln_app --project demo     # persisted, lifecycle tracked
python -m app.cli scan-url https://github.com/<owner>/<repo> --project name
python -m app.cli findings --project demo [--state new|still_open|resolved|regression|suppressed]
python -m app.cli suppress <id> --reason "why this is a false positive"

# developer mode -- no model needed
python -m app.cli strategies                                        # S0-S8, S7a, S7m
python -m app.cli prompt <id> --source <your checkout> [--strategy S7m] [--out prompt.txt]
python -m app.cli lint-prompt my_prompt.txt [--finding <id> --source <checkout>] [--fix]
#   ... paste the prompt into your assistant, review its change, commit ...
python -m app.cli verify <id> --source <your checkout>      # rescan, then checks 1, 2, 3a
python -m app.cli verifications <id>                        # remediation history

# the linter on its own (no tool around it)
secure-prompt-lint prompt.txt --cwe CWE-78 --entity host --location app.py [--fix -o fixed.txt] [--json]

# lab mode -- a local model writes the fix into a scratch copy; checks 1, 2, 3a, then 3b (behaviour tests)
python -m app.cli lab-verify <id> --source fixtures/flask_vuln_app --strategy S7m
python -m app.cli lab-verify <id> --source fixtures/flask_vuln_app --replay evaluation/replays/sqli_good.json

python scripts/demo_lifecycle.py ; python scripts/demo_verify.py     # the scripted scenarios
python -m uvicorn app.main:app --host 127.0.0.1                      # REST API, key via X-API-Key
```

### Strategies

| ID | Strategy | Source |
|---|---|---|
| S0–S6 | baseline, naive-secure, CWE-specific, comprehensive, zero-shot chain of thought, recursive criticism (RCI), persona | Tony et al. (Paper 3), adapted to repair |
| **S7** | ours: explained feedback + every linted constituent + an explained review turn | Papers 1, 2, 3 |
| **S7a** | ours, one message (no review turns) | token ladder |
| **S7m** | ours, minimal: only what the linter requires | token ladder |
| S8 | a standing rules file | industry practice (Backslash Security) |

Ours (S7, S7a, S7m) fail closed: if the prompt does not pass the linter, none is produced.

## Web interface

Local pages over the same services as the CLI, for developer mode (`dashboard/web/`):

| Page | What it shows / does |
|---|---|
| Overview | open findings by severity, lifecycle and verdict counts, findings by OWASP category, findings per scan, what the last scan's scanners could see; scan a checkout |
| Findings | filterable tracked findings; one page per finding with evidence, lifecycle events and verdicts; suppress a false positive (reason required) |
| Prompt & lint | the remediation prompt for a finding with a copy button, its lint report and token count, and a linter for your edited prompt, with fix-its |
| Verify | rescan your checkout and run checks 1, 2 and 3a; per-check remediation history |
| Scan history | every scan with its source (commit or archive hash), transitions and scanner status |

## Verification

| Check | Passes when | Mode |
|---|---|---|
| 1 target resolved | every scanner's finding of the weakness (same CWE, same function) is gone; the same rule re-reported on the edited code counts as still present | both |
| 2 nothing new | nothing introduced anywhere in the repository at the weakness's severity or above (lower: a warning); a scanner that did not run makes it `UNVERIFIED` | both |
| 3a structure intact | same name, parameters and decorators; not a stub; no newly undefined names; the file still parses | both |
| 3b behaviour | the project's behaviour tests pass on the patched copy (run only after 1, 2 and 3a pass) | lab |

Verdict: `VERIFIED_RESOLVED` only if every check passes; `FIX_REJECTED` with the first failing check;
`UNVERIFIED` when evidence is missing. Developer mode never executes repository code.

## Tests

```bash
python -m pytest                    # everything, including the library's own tests (scanner tests skip if a scanner is missing)
python -m pytest -m "not scanners"  # fast: no real scanner runs
python -m pytest -m "not network"   # offline
```

---

## Security controls

The tool scans untrusted code, so it is itself an attack surface. The full model is in
[`docs/threat_model.md`](docs/threat_model.md).

| Boundary | Control |
|---|---|
| Repository URL | https only; exact host allowlist; IP literals in any notation refused; resolved addresses must be public; no redirects |
| git clone | operator's git config and credential helpers never loaded; no hooks/submodules/LFS; shallow; `--` before the URL; size caps |
| ZIP upload | traversal, symlinks, NTFS streams, device names, bombs, encrypted and duplicate members refused before any write |
| Subprocesses | list args only, never a shell; executables never from scratch space; allowlisted environment; process-tree kill on timeout; output caps; no elevation |
| Code under scan | `nosec` / `nosemgrep` / `gitleaks:allow` ignored; in-repo scanner config removed from the scratch copy; pip-audit never installs dependencies |
| Secrets | redacted before storage, logging, fingerprinting and any prompt |
| Verification | a finding is never resolved by a scan that could not see it (scanner failure, unparseable file, unpinned dependency → `UNVERIFIED`) |
| Context to a model | only the flagged function or ±10 lines; comments and docstrings removed; redacted; path confined to the checkout |
| Prompt injection | repository code wrapped in random-nonce delimiters with an inert-data instruction; instruction-like text flagged |
| Model server and output (lab) | loopback only, no proxies or redirects, bounded response; output schema-validated, never auto-applied outside a scratch copy |
| Running a fix (lab, check 3b) | only after checks 1, 2, 3a pass; separate interpreter; `python -P`; allowlisted environment; timeout; CLI only, never over the API |
| API | key on every route, fails closed when unset; body-size cap; no stack traces returned |
| Web interface | loopback peer and `Host` only; key sign-in, constant-time, process-wide lockout; signed HttpOnly SameSite=Strict session; CSRF + Origin check on every POST; CSP `default-src 'none'`, no inline script or style; autoescaped templates; vendored htmx pinned by hash, eval off; no lab mode |
| Dependencies | pinned; audited with pip-audit (0 known vulnerabilities in the frozen environment); security floors for transitive packages |

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Components, data flow, the two modes, checks and verdicts, data model, the library boundary |
| [`docs/threat_model.md`](docs/threat_model.md) | Assets, adversaries, trust boundaries, threats and controls with their tests, residual risks |
| [`docs/evaluation.md`](docs/evaluation.md) | Detection, lifecycle, verification, E1 (linter), E2 (strategies), E5 (token ladder), threats to validity |
| [`docs/related_functions.md`](docs/related_functions.md) | Whether a fix breaks the code around it: the four layers, the evidence, the limits |
| [`libs/secure-prompt-lint`](libs/secure-prompt-lint) | The published linter: README, rules, extension API, benchmark, `RESEARCH.md` |
| [`docs/literature_review.md`](docs/literature_review.md) | The three assigned papers, supporting works, five research gaps |
| [`docs/related_tools.md`](docs/related_tools.md) | Competitive landscape and capability matrix |
| [`docs/scope_decisions.md`](docs/scope_decisions.md), [`docs/revised_direction.md`](docs/revised_direction.md) | Language and CWE scope with evidence; the changes made after Review 1 |
| [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md) | Individual contributions and phase ownership |

Review material from earlier reviews (slide text, presenter scripts, deck generators) is kept in `docs/` and
`scripts/` as history.

---

## Safety note

`fixtures/` contains **deliberately vulnerable code**. It is isolated, never imported by the application, and
exists only to give the scanners something to find. Its behaviour tests (`fixtures/flask_vuln_app_tests/`) import
it only in lab mode, in a scratch copy, through Flask's test client, with every process call faked. Do not run it
as a server, deploy it, or copy from it. The credentials in it are fabricated.
