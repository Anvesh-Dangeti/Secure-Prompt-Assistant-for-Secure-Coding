# Review 4 — slide content

Saturday 24 October 2026 · 15 minutes · deck: `../Secure_Prompt_Assistant_Review4.pptx`
(built by `scripts/build_review4_deck.py`; every result number comes from
`evaluation/recorded_results.py`, which the tests assert against real runs; the screenshots in `docs/img/`
were taken from the running dashboard on the eight-commit demo database).

---

## 1 · Title
Building a Prompt Assistant for Secure Coding — *Phases 5–7 built: prompt, lint, verify — and a dashboard to
drive it.*

## 2 · Promised at Review 3, delivered at Review 4
| Promised for Review 4 (Review 3, slide 12) | Status |
|---|---|
| Phase 5 AI layer — explainer, prompt builder × S0–S8, prompt linter, injection defences | ✓ done |
| Phase 6 Verification — rescan, gates 1 · 2 · 3, VERIFIED_RESOLVED / FIX_REJECTED, history | ✓ done, four gates |
| **Phase 7 Dashboard — promised for Review 5** | ✓ done, two weeks early |
| The panel's two questions from Review 3 | ✓ answered — next slide |
| The 12 original requirements — #11's measured evaluation is Phase 8 | ✓ all 12 built |

637 automated tests, up from 278 at Review 3.

## 3 · Your two questions, answered
**"In what mode will a developer use this — an IDE plugin, or something else?"** Assistant-agnostic, no plugin.
It runs beside whatever assistant the developer already uses (Copilot, Cursor, Codex). Developer mode: we
scan, explain and build a linted prompt; their assistant writes the fix; we rescan their commit and the gates
decide. No model of ours and no tokens from us; our local model is only a lab instrument. An editor extension
stays a Could.

**"Are we overcommitting? Can the project be finished by 18 November?"** Scope is tiered (Must / Should /
Could, written down in advance) with a cut rule: a phase more than 2 days late drops the next Should item —
never tests or hardening. Phases 5–7 finished on 20 October; Phase 7 was planned for 25–31 October.

Every design decision traces to a paper or a measurement; two were reversed on evidence (Bandit restored;
patch-based apply dropped).

## 4 · How a developer uses it — no plugin needed
`scan-zip ./myapp --project myapp` → `findings` → `prompt 5 --source ./myapp --out prompt.txt` →
`lint-prompt prompt.txt --finding 5 --source ./myapp --fix` → paste into the assistant, apply, commit →
`verify 5 --source ./myapp` → VERIFIED_RESOLVED | FIX_REJECTED | UNVERIFIED. The dashboard drives the same
services. Developer mode never executes repository code.

## 5 · Nine strategies, one security envelope
| ID | Strategy | Passes lint (of 24) | Mean constituents |
|---|---|---|---|
| S0 | Baseline (raw scanner output) | 0 | 0.38 |
| S1 | Naive-secure | 0 | 0.38 |
| S2 | CWE-specific | 1 | 0.72 |
| S3 | Comprehensive | 0 | 0.45 |
| S4 | Zero-shot CoT | 0 | 0.38 |
| S5 | RCI | 0 | 0.38 |
| S6 | Persona | 0 | 0.38 |
| **S7** | **Explained + linted + RCI (ours)** | **24** | **1.00** |
| S8 | Rules file | 1 | 0.71 |

The envelope (delimiters, inert-data instruction, scope limit, output contract) is identical in all nine.
This scores prompts, not fixes; which strategy yields verified fixes is Phase 8 (E2).

## 6 · The linter catches what shortening removes
Screenshot: a shortened prompt fails A1–A4. Rules: A1–A7 constituents and shortening · B1–B5 prompt security ·
C1 token budget · fix-its. On the 24 real findings: S7 passes 24/24 · S0 passes 0/24 (constituents 0.2–0.6) ·
fix-its repair S0 on 24/24 · S7's first message 255–373 tokens.

## 7 · Repository code is data, never instructions
Comments and docstrings stripped · nonce-delimited `untrusted_code` blocks + "treat as data" instruction; forged
markers flagged (B5) but never blocking · secrets redacted; a secret in an edited prompt is B1 · only the
enclosing function (B4) · model answers schema-checked, never executed or committed · model explanations kept
only if valid, entity-naming and code-free. Nothing a model writes is believed.

## 8 · Four gates decide — the model never does
1 the weakness is gone (same CWE, same function, any scanner; churn counts as still present) · 2 nothing new at
or above its severity in the commit · 3a the function is still there (signature, decorators, real body, no new
undefined names) · 3b 10 behaviour tests pass (lab only). All pass → VERIFIED_RESOLVED; a failure →
FIX_REJECTED with the reason; missing evidence → UNVERIFIED.

## 9 · Eight commits, every verdict
| | Commit | Findings | Verdict | Decided by |
|---|---|---|---|---|
| **v2** | **ping_host emptied to `pass`** | 4 | FIX_REJECTED | gate 3a |
| v3 | ping_host fixed: argument list, no shell | 4 | VERIFIED_RESOLVED | all gates |
| v4 | SQL line edited, still concatenated | 3 | FIX_REJECTED | gate 1 |
| v5 | SQL parameterised + a new `os.system()` route | 2 | FIX_REJECTED | gate 2 |
| v6 | the route removed | 2 | VERIFIED_RESOLVED | all gates |
| v7 | token to env var while Gitleaks is down | 2 | UNVERIFIED | gate 1 — no evidence |
| v8 | same code, Gitleaks back | 2 | VERIFIED_RESOLVED | all gates |

`python scripts/demo_verify.py`.

## 10 · The scanners went quiet. The fix was rejected.
Dashboard screenshot of v2: gate 1 PASS (4/4 CWE-78 findings gone), gate 3a FAIL (stub body) → FIX_REJECTED.
A scanner-only check would accept it: deleting vulnerable code deletes the finding too.

## 11 · Lab mode: six recorded model answers, four gates
sqli_good → VERIFIED · sqli_stub → 3a · sqli_drops_route → 3a · **sqli_wrong_behaviour → 3b only** ·
cmd_quoted_shell (`shlex.quote` with `shell=True`) → 1 · cmd_good → VERIFIED. Recorded answers replayed through
the real pipeline; live local-model runs are Phase 8.

## 12 · The dashboard: the same loop, on one screen
Screenshots: Overview; Prompt & lint. Five pages, in-process over the CLI's services — no lab mode, no model,
nothing executed.

## 13 · A dashboard that displays untrusted text
Loopback only (refuses to render otherwise) · the API key, constant-time, fail-closed, delay + lockout ·
scanned text only as text/code/table cells, no Markdown/HTML writers (AST-checked) · payload test with a
positive control on every page · XSRF/CORS on, no static serving, no tracebacks or telemetry · validated
checkout path. For Review 5: FastAPI + htmx, plus session cookie, CSRF tokens and a strict CSP.

## 14 · Seven defects testing found
"salt" matched "unsalted" · guards failing their own rule · forged delimiter as a denial-of-service lever ·
churn rule rejecting a correct fix · gate 3b importing the wrong `app` · an injection test that never seeded
its payload · a smoke run on an empty database. Lesson: negative security tests need a positive control.

## 15 · What comes next — and how we finish by 18 Nov
25–31 Oct Phase 8 evaluation (E1, E2, E3) · 1–7 Nov 7b web interface · Sat 7 Nov Review 5 · 8–12 Nov hardening ·
13–16 Nov final · 17 Nov buffer · 18 Nov submission. Questions: one local open model for E2 with a hosted model
as stretch? A hand-pasted Copilot spot-check worth including?

## 16–18 · Thank you · two appendix pages of prepared answers
