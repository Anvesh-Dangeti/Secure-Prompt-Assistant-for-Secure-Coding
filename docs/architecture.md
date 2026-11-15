# Architecture

The Secure Prompt Assistant scans a Python repository with four open-source
security tools. For each finding it builds a remediation prompt and checks it
with a linter. When the developer's coding assistant has applied a fix, it
re-scans independently and decides — never a model — whether the fix worked.

This document covers the components, the data that flows between them, the two
modes of use, and the design decisions that shape them. The security design is
in [`threat_model.md`](threat_model.md); the measurements are in
[`evaluation.md`](evaluation.md).

## 1. The core rule: responsibilities are separated

```
Scanner            -> produces evidence                       (Semgrep, Bandit, Gitleaks, pip-audit)
Normaliser         -> one tool-agnostic finding shape         (SARIF-based)
Mapping layer      -> CWE / OWASP / CVE                       (YAML tables, CVE only from pip-audit)
Intelligence       -> identity across commits                 (fingerprint + lifecycle state machine)
Context analyser   -> the minimal, redacted source context    (the flagged function, or ±10 lines)
Explainer          -> why the finding matters                 (template by default; a model only in lab mode)
Prompt builder     -> the remediation prompt                  (strategy S0-S8, S7a, S7m)
Linter             -> proves the prompt kept its constituents (secure-prompt-lint)
Developer / lab    -> applies the change                      (their own assistant / a local model in a scratch copy)
Scanners + checks  -> independent verification                (checks 1, 2, 3a, 3b)
```

**The model never decides whether a vulnerability is fixed.** It can explain
and it can write code (lab mode). Only the same scanners re-run independently,
plus the structural and behaviour checks, can produce `VERIFIED_RESOLVED`. A
scan that could not examine a finding can never mark it resolved.

## 2. Components

```
                         ┌────────────────────────── dashboard/web (FastAPI + Jinja2 + htmx, 127.0.0.1) ─┐
  developer ── browser ─►│ overview · findings · prompt & lint · verify · scan history                   │
            ── CLI ─────►│ app/cli.py · app/cli_ai.py · app/cli_verify.py                                │
            ── API ─────►│ app/main.py + app/api/  (admin key or per-project token, fail closed)         │
                         └───────────────────────────────┬───────────────────────────────────────────────┘
                                                         │ same services
   ┌──────────────── app/scan_service.py ────────────────┴───────────── app/verification/service.py ──┐
   │ repository/ (SSRF-safe clone, zip-slip-safe extract)      compare · gates/ 1 2 3a (3b lab) · verdict│
   │ pipeline.scan_tree: neutralise in-repo scanner config,    symbols (AST facts) · snapshots          │
   │   run scanners/ in a scratch copy, normalise, map, fingerprint                                     │
   │ intelligence/: lifecycle state machine + tracking                                                  │
   └──────────────────────────────────────────┬──────────────────────────────────────────────────────────┘
                                              │
   app/ai/: context · guidance · explainer · strategies/ · prompt_builder · providers/ (template, Ollama)
            linter/, strategies/, sentences ──► libs/secure-prompt-lint  (rules, engine, fix-its, delimiting,
                                                 injection, secrets; the prompt templates S0–S8, S7a, S7m)
   app/sandbox/ (lab mode only): apply a model's fix to a scratch copy; run the behaviour tests (check 3b)
   app/db/: SQLite via SQLAlchemy ORM (no raw SQL)
```

| Package | Responsibility |
|---|---|
| `app/core/` | typed configuration (`SPA_` environment), JSON logging with secret redaction, `run_tool` (the only way a subprocess is started), scratch directories, path confinement |
| `app/repository/` | `url_validator` (https only, host allowlist, public addresses only), `git_clone` (hardened shallow clone), `zip_extract` (zip-slip, symlink and bomb defences) |
| `app/scanners/` | one adapter per tool behind a common `Scanner` interface; status `OK / SKIPPED / ERROR / TIMEOUT` per run |
| `app/normalization/`, `app/mapping/` | SARIF, Gitleaks and pip-audit parsers into `NormalizedFinding`; CWE canonicalisation (e.g. CWE-259 → CWE-798), CWE → OWASP, per-rule overrides |
| `app/intelligence/` | `fingerprint` (identity that survives line shifts), `lifecycle` (a pure state machine), `tracking` (suppression with a reason, never deletion) |
| `app/ai/` | context extraction and entities, per-CWE guidance, explainer, the strategies, the prompt builder, providers, schema-validated model output |
| `app/verification/` | symbol facts captured at scan time, scan comparison, the four checks, the verdict, remediation history |
| `app/sandbox/` | lab mode: splice a model's proposal into a scratch copy, rescan, run the behaviour tests |
| `dashboard/` | read models (`data.py`) and validated actions (`actions.py`) shared by the web pages |
| `libs/secure-prompt-lint/` | the prompt linter and the prompt templates as a stand-alone, dependency-free library; the application imports both (one copy of the code) |
| `libs/spa-connect/` | `spa`, the command a developer runs in a project folder to use a shared server (§10); standard library only, never imports the application |
| `app/access_tokens.py`, `app/api/prompts.py` | per-project access tokens (stored as hashes); a prompt built from the one file a connector sends |
| `evaluation/` | ground truth, scripted scenarios, experiments E1, E2, E5, the related-functions evidence, and `recorded_results.py` (every number we report, asserted by tests) |

## 3. What happens in a scan

1. **Connect.** The developer gives a local checkout path, a ZIP archive or an
   https Git URL; on a shared server, `spa scan` uploads the folder as a ZIP (§10). URLs pass the SSRF checks, are cloned shallowly with the
   operator's git configuration disabled, and the clone is deleted afterwards.
2. **Copy and neutralise.** The tree is copied into a scratch directory, and
   in-repository scanner configuration (`.semgrepignore`, `.bandit`,
   `.gitleaks.toml`) is removed. A repository must not be able to switch its
   own scanners off. `.git` is excluded.
3. **Scan.** Semgrep (a pinned local rules snapshot), Bandit (SARIF), Gitleaks
   and pip-audit (`--no-deps --disable-pip`, so nothing is installed) run as
   subprocesses: argument lists only, a timeout, an allowlisted environment.
4. **Normalise and map.** Every result becomes a `NormalizedFinding` with a
   canonical CWE, an OWASP category and, for dependencies, CVEs and fixed versions.
5. **Fingerprint.** Identity is `hash(portable rule id | normalised path |
   whitespace-stripped, comment-stripped, redacted snippet)`. The line number
   is never part of it, so inserting code above a finding does not make it "new".
6. **Snapshot.** For each flagged symbol, structural facts are stored: its
   signature, decorators, whether the body is a stub, and names it uses that
   nothing defines. Verification later compares facts, because the scanned
   source itself is never kept.
7. **Lifecycle.** The scan is compared with the project's history. A
   finding becomes `NEW`, `STILL_OPEN`, `RESOLVED`, `REGRESSION` or stays
   `SUPPRESSED`. A finding in a file or package the scan could not examine is
   `UNVERIFIED`, never `RESOLVED`.

## 4. Developer mode: the product

```
finding ──► context (function / ±10 lines, comments removed, secrets redacted)
        ──► explanation (template)      ──► prompt (strategy, default S7)      ──► linter (PASS / FAIL + fix-its)
        ──► developer pastes it into their own assistant (Copilot, ...), reviews the change, commits
        ──► verify: rescan the checkout ──► check 1 · check 2 · check 3a ──► VERIFIED_RESOLVED / FIX_REJECTED / UNVERIFIED
```

- **No model runs in this mode.** The explanation and the prompt come from
  templates and AST facts, so the tool costs no tokens. The developer's own
  assistant does the fixing.
- **The linter also checks prompts the developer edits.** A shortened prompt
  that lost its guard or directive fails, and fix-its insert the missing
  sentences before the code.
- **Developer mode never executes repository code**, so check 3b (behaviour
  tests) is shown as not run. That check belongs to the developer's own CI.

**Token cost (E5).** The full S7 prompt with its two review turns costs about
2,220 tokens per fix attempt. One message (S7a) costs about 499, and the
minimal prompt (S7m) about 380, with no loss of verified fixes in our runs.
See [`evaluation.md`](evaluation.md).

## 5. Lab mode: the experiment

```
finding ──► prompt (strategy) ──► local model (Ollama, qwen2.5-coder 7B, temperature 0, loopback only)
        ──► JSON proposal, schema-validated ──► spliced into a scratch copy (only the context window, plus imports)
        ──► rescan the copy ──► checks 1, 2, 3a ──► only then check 3b: the project's behaviour tests on the copy
```

Lab mode exists to measure *which way of asking* produces verified fixes. The
same model is used across strategies, so the comparison is relative. It is
never exposed over HTTP. The trial never touches the developer's checkout or
the lifecycle.

## 6. The checks and the verdict

| Check | Passes when | Mode |
|---|---|---|
| 1 target resolved | every scanner's finding of the weakness (same CWE in the same symbol) is gone; the same rule re-reported on the edited code counts as still present | both |
| 2 nothing new | no new finding anywhere in the repository at or above the weakness's severity; a scanner that did not run makes it `UNVERIFIED` | both |
| 3a structure intact | same name, parameters and decorators; not reduced to a stub; no newly undefined names; the file still parses | both |
| 3b behaviour | the project's behaviour tests pass on the patched copy (run only after 1, 2 and 3a pass) | lab |

`VERIFIED_RESOLVED` requires every check to pass. `FIX_REJECTED` carries the
first failing check and its reason. `UNVERIFIED` means evidence was missing.
Nothing passes silently. How these checks protect the *code around* a fix
is in [`related_functions.md`](related_functions.md).

## 7. Data model (SQLite, SQLAlchemy ORM)

| Table | Holds |
|---|---|
| `projects` | a named source (local path, archive or URL) |
| `scans`, `scanner_runs` | each scan with its source identity (commit or archive hash) and every scanner's status and version |
| `findings` | normalised evidence per scan (redacted snippet, CWE, OWASP, CVEs, fixed versions, fingerprint) |
| `tracked_findings`, `lifecycle_events` | identity across scans and every state transition, with suppression reasons |
| `blind_spots`, `symbol_snapshots` | what a scan could not see; structural facts per flagged symbol |
| `verifications` | each verdict with per-check results, mode, strategy, model, parameters and token counts |
| `access_tokens` | a developer's token for one project: SHA-256 hash, display prefix, expiry, last use, revocation |

## 8. The lint library boundary

`libs/secure-prompt-lint` contains everything about judging a prompt: the
constituent rules A1–A7, the hygiene rules B1–B5 and C1, the fix-its, the
nonce delimiting, the injection heuristic, the secret patterns, the token
estimate and the mutation benchmark. Since version 1.1 it also holds the
prompt templates (`secure_prompt_lint.templates`): the sentences, the eleven
strategies and the 24 fixture findings they were measured on. It has no
third-party dependencies and never imports the application (a test enforces
this).

The application adds what only it knows: the context extracted from a real
finding (entities from `ast`, the window, the dependency group), an expectation
bound to it, the optional model explanation, and the guidance table, exported to
the library by `scripts/export_lint_data.py`. The strategies read only
attributes, so the application passes its own `FindingContext` and
`CweGuidance` straight in. Parity tests check that the library, using only its
bundled data, builds byte-identical prompts and lint reports for all 24 findings
and all eleven strategies, renders identical sentences, and reproduces the E1
benchmark and the static token ladder. The library is also published on its own:
<https://github.com/Anvesh-Dangeti/secure-prompt-lint>.

## 9. Technology

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Bandit is Python-only; the scope is Python web code |
| Scanners | Semgrep 1.180.0, Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1 | SAST ×2 (cross-agreement), secrets, dependencies; each in its own virtualenv |
| API / web | FastAPI, Jinja2 (autoescape forced), htmx 2.0.4 vendored and pinned by hash | server-rendered, no build pipeline, strict CSP |
| Storage | SQLite + SQLAlchemy | zero operations; parameterised queries only |
| Local model (lab) | Ollama 0.40, `qwen2.5-coder:7b-instruct` | runs on an 8 GB GPU; loopback only |
| Configuration | pydantic-settings, `.env` | typed; secrets never in code |

## 10. Shared server: the `spa` connector

On one machine the tool reads the developer's checkout directly. On a server a
team shares, it cannot. There, a developer runs `spa` in the project folder.

```
spa connect  ─► GET  /api/v1/whoami                    token checked, kept in the user's config dir
spa scan     ─► POST /api/v1/projects/{id}/scans/zip    folder packed (no caches, .env, links), scanned, deleted
spa findings ─► GET  /api/v1/projects/{id}/findings
spa prompt   ─► POST /api/v1/tracked/{id}/prompt        one file: the finding's own; nothing kept
spa verify   ─► scan again, then POST /api/v1/tracked/{id}/verify?scan_id=...
```

- **Nothing about verification moves to the client.** The server runs the
  same scanners and checks on what it receives, so a laptop can never report
  a verdict of its own.
- **Each developer has a token for one project.** Another project's data
  answers 404. `SPA_API_KEY` remains the administrator's key, and the web
  interface stays loopback-only.

Setup, data handling, controls and limits are in [`deployment.md`](deployment.md).
