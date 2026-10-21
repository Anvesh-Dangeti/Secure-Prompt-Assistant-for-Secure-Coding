# Mid-semester review — slide content

Friday 30 October 2026 · 15 minutes · deck: `../Secure_Prompt_Assistant_MidSem_Review.pptx` (built by
`scripts/build_midsem_deck.py`; every result number comes from `evaluation/recorded_results.py`, which the tests
assert against real runs; the screenshots in `docs/img/midsem_*.png` were taken from the web interface on the
eight-commit demo database). The panel's seven sections are numbered on the slides; each slide names its
presenter.

---

## 1 · Title
Building a Prompt Assistant for Secure Coding — *scan · explain · prompt your own assistant · verify the fix —
without trusting the model.* TEAM-3: Anvesh Dangeti (lead · architecture · verification), Dhananjay Kumar
(research · threat model · security testing), Muday Saiprakash Nayak (fixtures · evaluation).

## 2 · Problem statement — AI assistants write the fix. Nobody checks it. *(Anvesh)*
40.95% of LLM-generated Python vulnerable (Paper 2; 40% of Copilot completions, Pearce et al.) · GPT-4o 1/10 on
naive prompts, the best model 10/10 security-prompted (Backslash) — the prompt is the lever · 14–54% Effective
Safety Rate lost by prior "secure" methods (SecCoderX). Three questions no tool answers together: which prompt
produces a secure fix; did the fix work, decided by the scanners and not the model; is the weakness back later.

## 3 · State of the art — tools *(Dhananjay)*
Capability matrix: Copilot Autofix, Snyk Code, Semgrep Assistant, DefectDojo, Backslash Rules, raw ChatGPT, ours —
scanner-grounded findings, independent rescan, nothing new introduced, functionality preserved, cross-commit
lifecycle, prompt strategy measured, developer's own prompt linted, open/local. Copilot Autofix already closes
the loop; we claim the measurement and the gates around it.

## 4 · State of the art — research *(Dhananjay)*
Paper 1 explained feedback → two-stage AI layer · Paper 2 constituents + proposed linter → Python scope and the
Prompt Security Linter · Paper 3 seven techniques, RCI −77.55% on GPT-4 → strategies S0–S6 · Backslash rules file
→ S8 · SecCoderX ESR → headline metric and gate 3. Gap: papers measure prompts on generated code; tools fix
repositories without measuring prompts.

## 5 · Architecture — Scanners produce evidence. The model only drafts. *(Anvesh)*
Connect (SSRF / zip-slip checked) → scan (4 tools) → normalise + map (SARIF; CWE/OWASP/CVE) → track (fingerprint)
→ explain + prompt (template, S0–S8) → lint. Developer mode (the product: the developer's assistant, no model of
ours) · lab mode (the instrument: local 7B in a scratch copy). Rescan → gates 1 · 2 · 3a · 3b → verdict →
lifecycle, history, web interface.

## 6 · Threat model — A tool that reads hostile code is a target *(Dhananjay)*
Seven trust boundaries with STRIDE letters, controls and tests: repository URL (SSRF), ZIP (zip-slip, bombs),
scanner subprocess (injection, hangs), code → prompt (prompt injection), model → us (a confident wrong fix),
running a fix (lab only, isolated), web interface (XSS, CSRF, DNS rebinding).

## 7 · What is new *(Anvesh)*
1 prompts, measured (S0–S8, ESR, verified fixes per 1k tokens) · 2 a linter for the developer's own prompt,
mutation-tested · 3 gates, not trust · 4 identity across commits; assistant-agnostic, open and local. What we do
not claim: better detection than CodeQL, better fixes than GPT-4-class models, or the loop itself.

## 8 · The scanners went quiet. The fix was rejected. *(Anvesh)*
Web interface screenshot of the v2 commit (ping_host emptied): gate 1 PASS, gate 3a FAIL → FIX_REJECTED. Strip:
the eight scripted commits and the gate that decided each.

## 9 · Cut the prompt; the linter notices (E1) *(Anvesh)*
Twelve edits × 24 real findings: constituent-removing edits flagged 168/168 (149 fail outright, all repaired by
fix-its); 0/96 false alarms; found by E1 and fixed — S7's guard restates the mitigation, so a deleted directive
still passed; A7 now flags it. Gap kept: undelimited code flagged 16/24.

## 10 · Live demo *(Anvesh)*
Scan the fixture copy → finding #5 (B602) → S7 prompt PASS → shortened prompt FAIL → fix-its PASS → a stubbed fix
FIX_REJECTED at gate 3a → a real fix VERIFIED_RESOLVED. Steps in `docs/midsem_presenter_script.md`.

## 11 · Results so far — the strategy matters *(Muday)*
Detection 10/10 (24 findings, precision 22/24). E2 pilot, 90 live fixes by qwen2.5-coder 7B, all gates: ESR
S0 0.5 · S1 0.6 · S2 0.9 · S3 0.7 · S4 0.6 · S5 0.5 · S6 0.6 · S7 0.7 · S8 0.8; S7 at 5.5× S2's tokens; RCI's
rewrites broke behaviour; 7 scanner-clean fixes caught only by the behaviour tests; all 9 PyYAML bumps rejected at
gate 1. A pilot, not a ranking.

## 12 · Who built what *(Muday)*
Ownership per member; reviews so far; per-phase commits and asserted results; decisions traced to sources.

## 13 · Next two weeks *(Muday)*
31 Oct–3 Nov evaluation (E2 full, E3, injection corpus, E4 should) · 4–7 Nov hardening (web interface included,
Streamlit retired, dependency upgrades) · 8–11 Nov final documents and testing · 12–13 Nov final review ·
18 Nov submission. Cut rule unchanged. Question for the panel: one local open model across all nine strategies,
hosted model as stretch?

## 14–16 · Thank you · demo backup screenshots · prepared answers
