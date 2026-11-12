# Threat model

A tool that scans untrusted code is itself an attack surface. It clones what
it is pointed at, unpacks what it is given, runs external programs over that
content, and sends parts of it to a language model. This document lists what
we protect, from whom, at which boundary, and how. Each control has a pointer
to the tests that exercise it. The rule throughout is **security over
features**: a smaller secure tool beats a larger insecure one.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The developer's machine | the tool runs locally; a scanned repository must not run code or reach the network through it |
| Secrets in the scanned code and in our configuration | the API key, and any credential a repository contains, must not leak into logs, the database, prompts or a model provider |
| The verdict | the product's claim is "this fix is verified". A forged `VERIFIED_RESOLVED` would be worse than no tool at all |
| The prompt | it reaches a third-party assistant; it must not carry secrets or instructions hidden in the code |
| The findings history | identity and lifecycle across commits; a regression must not be lost or disguised as "new" |

## 2. Adversaries

- **A malicious repository** (the main one). It controls file names, file
  contents, comments, archive structure, Git metadata, dependency manifests
  and scanner configuration files.
- **A network attacker** who controls a URL the developer pastes, or a DNS
  answer for it.
- **A malicious web page** in the developer's browser, attempting CSRF or DNS
  rebinding against the local interface.
- **The language model**, in lab mode: its output is untrusted, because it may
  follow injected instructions or produce wrong or fake fixes.
- **A careless or rushed developer** who shortens a prompt, pastes a secret,
  or commits a "fix" that only silences the scanner.

## 3. Trust boundaries

```
   developer ─(1)─► web UI / CLI / API ─(2)─► repository URL / ZIP ─(3)─► scratch copy
                                                                           │
                                       (4) scanner subprocesses ◄──────────┤
                                       (5) source context ─► prompt ─(6)─► assistant / local model
                                       (7) model output ─► scratch copy ─► behaviour tests (lab)
   database (8) · logs (9) · scratch directories (10)
```

## 4. Threats and controls

| # | Boundary | Threat (STRIDE) | Control | Tests |
|---|---|---|---|---|
| 1 | Developer ↔ web UI / API | Spoofing, elevation: another local user or a web page drives the tool | Binds to `127.0.0.1` only. Refuses non-loopback peers and foreign `Host` headers (DNS rebinding). `SPA_API_KEY` sign-in with constant-time comparison and a process-wide lockout. Fails closed when no key is set. Signed HttpOnly, SameSite=Strict session. CSRF token plus an Origin / Sec-Fetch-Site check on every POST | `tests/security/test_web_safety.py`, `tests/unit/test_api_auth.py` |
| 1 | Web UI rendering | Tampering: scanned content (file names, messages, code) injects HTML or script | Autoescaping forced and nothing marked safe (AST-checked). CSP `default-src 'none'` with no inline script or style. Vendored htmx pinned by hash, with eval off. Payloads seeded into every page, with a positive control | `test_web_safety.py` |
| 2 | Repository URL | SSRF: `file://`, internal hosts, IP literals, redirects | https only, host allowlist, IP literals in any notation refused, resolved addresses must be public, no redirects | `test_ssrf_url_validation.py` |
| 2 | git clone | Elevation: hooks, submodules, LFS, a hostile git config | The operator's git configuration and credential helpers are never loaded. No hooks, submodules or LFS; shallow clone; `--` before the URL; size caps | `test_git_clone_hardening.py` |
| 3 | ZIP upload | Tampering: zip-slip, symlinks, NTFS streams, device names, bombs | Every member is validated before any write. Traversal, symlinks, streams, device names, encrypted and duplicate members refused. Count, size and depth caps | `test_zip_extraction.py` |
| 4 | Scanner subprocesses | Elevation, DoS: command injection, hanging tools | `run_tool` only: list arguments, never a shell. Executables never taken from scratch space. Allowlisted environment, timeout with a process-tree kill, output caps, no elevation | `tests/unit/test_subprocess_runner.py` |
| 4 | Scanner configuration | Repudiation of findings: the repository switches its own scanners off | `nosec`, `nosemgrep` and `gitleaks:allow` are ignored; in-repo `.semgrepignore`, `.bandit` and `.gitleaks.toml` are deleted from the scratch copy; pip-audit never installs dependencies | `tests/integration/test_scan_fixture.py`, `tests/unit/test_scanner_failures.py` |
| 5 | Context → prompt | Information disclosure: whole files or secrets sent to a provider | Only the flagged function or ±10 lines are sent. Comments and docstrings removed. Secrets redacted. The path is confined to the checkout. Linter rules B1 (secret) and B4 (data minimisation) | `tests/unit/test_ai_context.py`, `test_prompt_injection.py` |
| 6 | Prompt → model | Tampering: prompt injection through code comments or strings | Code wrapped in random-nonce delimiters it cannot forge; an inert-data instruction before it; instruction-like text flagged (B5); comments stripped | `test_prompt_injection.py`, `tests/unit/test_ai_delimiting.py` |
| 6 | Developer-edited prompt | Tampering by omission: the guard or directive is edited out | Linter rules A1–A7 and fix-its. Our own strategies fail closed: no prompt is produced if lint fails | `tests/unit/test_ai_linter.py`, `libs/secure-prompt-lint/tests` |
| 7 | Model output (lab) | Tampering: malformed or malicious output | JSON schema with extra fields forbidden. Each import must be a single `ast`-checked statement. Only the context window is replaced, in a scratch copy, never in the developer's checkout or a commit | `tests/unit/test_ai_lab_output.py`, `tests/unit/test_sandbox_apply.py` |
| 7 | Behaviour tests (lab) | Elevation: running model-written code | Runs only after checks 1, 2 and 3a pass. Separate interpreter with `python -P`, a pinned pytest configuration, an allowlisted environment and a timeout. CLI only, never over HTTP | `tests/unit/test_gate3b_runner.py` |
| — | The verdict | Spoofing a fix: stubbed body, deleted route, silenced scanner, a failed scanner read as "clean" | Check 3a (structure), check 2 (whole-repo differential), the churn rule in check 1, `UNVERIFIED` whenever a scanner did not run or a file could not be read; the model never judges | `test_verification_safety.py`, `tests/unit/test_gates.py` |
| 8 | Database | Tampering: SQL injection | SQLAlchemy ORM with bound parameters; the only SQL text in the codebase is the constant `PRAGMA foreign_keys=ON`. Suppression requires a reason and never deletes | `tests/integration/test_tracking.py` |
| 9 | Logs | Information disclosure: secrets in logs | JSON logs passed through a redaction filter; the API never returns stack traces | `tests/unit/test_redaction.py` |
| 10 | Scratch directories | Information disclosure: leftover copies of code | Guaranteed cleanup on every exit path, failures included | `tests/unit/test_paths_scratch.py` |
| — | Model server (lab) | SSRF, data leakage through a proxy | Loopback-only base URL, `trust_env=False` (no proxies), no redirects, bounded response | `tests/unit/test_ai_providers.py` |
| — | Lint library CLI | DoS, parser abuse through a huge or binary input | Input capped at 256 KB by default, read as UTF-8 text only and never executed; exit code 2 for bad input | `libs/secure-prompt-lint/tests/test_lib_cli.py` |

## 5. Assessing the tool itself (Phase 9)

- **Self-scan.** Our own four scanners over `app/`, `dashboard/` and `libs/`:
  only the 3 LOW Bandit advisories in the subprocess wrapper (importing
  `subprocess` and calling it without a shell), which is the one place
  subprocesses are allowed. Earlier self-scan findings were fixed rather than
  suppressed, because our tool ignores suppression comments by design.
- **Dependencies.** The Streamlit dashboard was retired once the web interface
  reached parity. That removed Streamlit and its transitive dependencies (35
  packages remain) and lifted Streamlit's cap on Pillow. Pillow 13.0.0 and
  certifi 2026.10.19 are pinned as security floors.
  **pip-audit of all 35 frozen packages reports no known vulnerabilities**; on
  22 October there were 9 advisories, none reachable.
- **Defects found by our own tests** that changed the design are recorded in
  the project history. Examples: Semgrep embedding the install path in rule
  ids, a `# nosec` comment changing a fingerprint, our own sign-in refused under
  `Referrer-Policy: no-referrer`, and a stub "fix" that would have passed a
  scanner-only check.

## 6. Residual risks (stated, not hidden)

- **Prompt injection cannot be made impossible** by any prompt-level control.
  That is why the model's output is never trusted: it is schema-validated, and
  the scanners and checks decide.
- **Check 3b does not isolate the network** for model-written code in lab mode.
  Container isolation per trial is the next step; lab mode runs only on our own
  seeded fixture.
- **Developer mode cannot see behaviour** (it never runs repository code), so a
  fix that keeps the structure but changes what a function returns is caught
  only by the developer's own tests. See [`related_functions.md`](related_functions.md).
- **Scanners have blind spots.** A weakness no scanner detects can neither be
  found nor verified. Two independent SAST engines reduce this risk but do not
  remove it.
- **Single machine, single user.** There is no multi-user authorisation model.
  The tool is designed to run locally for one developer.
