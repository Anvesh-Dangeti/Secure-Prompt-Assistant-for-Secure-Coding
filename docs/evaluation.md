# Evaluation

Every number below is in `evaluation/recorded_results.py`, and every one is
asserted by a test. Some tests re-run the real scanners, the linter or the
scripted scenarios. Others recompute the numbers from committed result files
(the model runs, which need a GPU). A number in this document therefore cannot
drift from what the code does. Snapshots that depend on the network are labelled
as such.

**Toolchain:** Semgrep 1.180.0 (pinned `p/python` snapshot, 151 rules), Bandit
1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1. **Lab model:** `qwen2.5-coder:7b-instruct`
(digest `dae161e27b0e`) on Ollama, temperature 0, top-p 1, seed 42, 4,096-token
context, on one 8 GB laptop GPU.

## 1. Detection on the seeded fixture

`fixtures/flask_vuln_app` seeds each of the 10 scoped CWEs exactly once, inside
a named function. Ground truth is located by symbol, not by line.

| | |
|---|---|
| findings (all four scanners) | 24 — Semgrep 12, Bandit 9, Gitleaks 1, pip-audit 2 |
| seeded weaknesses detected | **10 / 10** |
| true-positive findings | 22 / 24 (the 2 others are Bandit's import advisories B403/B404, which we suppress as false positives) |
| Semgrep and Bandit both detect, where both have a rule | 4 / 4 |

Ground-truth scoring is *detector-aware*: a weakness whose only expected
detector did not run is reported as `NOT-RUN`, not `MISSED`.

## 2. Identity across commits (six-commit lifecycle scenario)

`scripts/demo_lifecycle.py` asserts exactly this table:

| Commit | NEW | STILL_OPEN | RESOLVED | REGRESSION | SUPPRESSED | UNVERIFIED | Scan |
|---|---|---|---|---|---|---|---|
| v1 baseline | 24 | 0 | 0 | 0 | 0 | 0 | complete |
| v2 fix SQL injection | 4 | 19 | 3 | 0 | 2 | 0 | complete |
| v3 refactor (code moves, nothing fixed) | 0 | 23 | 0 | 0 | 2 | 0 | complete |
| v4 revert the SQL fix | 0 | 23 | 0 | **3** | 2 | 0 | complete |
| v5 fix the secret, Gitleaks down | 0 | 24 | 1 | 0 | 2 | **1** | partial |
| v6 Gitleaks back | 0 | 24 | 1 | 0 | 2 | 0 | complete |

v3 shows that moving code is not a fix: the fingerprint ignores line numbers.
v4 shows that a revert is a *regression*, not a new finding. v5 shows the
fail-safe: the secret's finding is `UNVERIFIED`, never `RESOLVED`, while the
scanner that could see it is down.

## 3. Verification verdicts (eight-commit developer-mode scenario)

`scripts/demo_verify.py` asserts:

| Commit | Verdict | Stopped at | Why |
|---|---|---|---|
| v2 stub the ping function | FIX_REJECTED | check 3a | scanners quiet, but the body became a stub |
| v3 real fix (argument list, no shell) | VERIFIED_RESOLVED | — | |
| v4 rewrite the SQL with a new fingerprint | FIX_REJECTED | check 1 | the same weakness re-reported on the edited code |
| v5 SQL fixed + a new `os.system` route | FIX_REJECTED | check 2 | new HIGH findings elsewhere |
| v6 route removed | VERIFIED_RESOLVED | — | a rejected fix can be re-verified by a follow-up commit |
| v7 secret removed, Gitleaks down | UNVERIFIED | check 1 | the evidence is missing |
| v8 Gitleaks back | VERIFIED_RESOLVED | — | |

**Lab replays** (recorded model answers through all four checks):

| Replay | Verdict |
|---|---|
| `sqli_good`, `cmd_good` | VERIFIED_RESOLVED |
| `sqli_stub`, `sqli_drops_route` | FIX_REJECTED at check 3a |
| `cmd_quoted_shell` (`shlex.quote` but still `shell=True`) | FIX_REJECTED at check 1 |
| `sqli_wrong_behaviour` | FIX_REJECTED at **check 3b only**: the scanners and the structure check were satisfied |

## 4. E1 — does the linter notice a prompt losing what makes it secure?

No model is involved. Each of the 24 real findings' S7 prompts is mutated
12 ways, giving 288 mutants, and each mutant is linted against its finding.

| | Result |
|---|---|
| unmutated prompts clean | 24 / 24 |
| mutants that remove a security constituent — failed (error) | **149 / 168** |
| … flagged (error or warning) | **168 / 168** |
| mutants that remove only an unchecked paragraph — false alarms | **0 / 96** |
| failed mutants repaired by the fix-its | 149 / 149 |

| Mutation | Failed | Flagged |
|---|---|---|
| delete opening / scope / inert-data instruction | 24 / 24 each | 24 / 24 each |
| delete guard | 20 / 24 | 24 / 24 |
| delete directive | 9 / 24 | 24 / 24 |
| genericise directive + guard ("Make sure the code is secure.") | 24 / 24 | 24 / 24 |
| truncate to the opening sentence | 24 / 24 | 24 / 24 |
| undelimit the code | 0 / 24 | 16 / 24 |
| delete explanation / classification / code / output contract | 0 / 24 each | 0 / 24 each |

The two honest gaps: one- or two-line snippets pasted without a fence are not
recognised as code (undelimit flagged 16/24), and no rule checks the
explanation. "Delete directive" fails only 9/24, because S7's guard restates the
mitigation; the A7 rule therefore flags the deleted sentence as a warning in all 24.
The benchmark is published with the library (`python -m secure_prompt_lint.bench`).

## 5. E2 pilot — which way of asking produces verified fixes?

90 lab trials: 10 seeded weaknesses × 9 strategies, n = 1 per cell. The
model's fix is applied to a scratch copy and judged by all four checks.
**ESR** (effective safety rate, as defined in SecCoderX, arXiv:2602.07422) is
the share of fixes that are both secure and still work.

| Strategy | Verified | ESR | Tokens (10 trials) | Verified per 1k tokens |
|---|---|---|---|---|
| S0 baseline (scanner message only) | 5 | 0.5 | 3,745 | 1.34 |
| S1 naive-secure | 6 | 0.6 | 3,825 | 1.57 |
| **S2 CWE-specific** | **9** | **0.9** | 4,252 | 2.12 |
| S3 comprehensive (OWASP checklist) | 7 | 0.7 | 5,016 | 1.40 |
| S4 zero-shot chain of thought | 6 | 0.6 | 3,912 | 1.53 |
| S5 recursive criticism (RCI) | 5 | 0.5 | 17,507 | 0.29 |
| S6 persona | 6 | 0.6 | 3,947 | 1.52 |
| S7 ours (explained + linted + RCI) | 7 | 0.7 | 23,356 | 0.30 |
| S8 rules file | 8 | 0.8 | 6,614 | 1.21 |

59 of 90 fixes were verified. The 31 rejected fixes stopped at check 1 (22),
check 3b (7) and check 3a (2).

**Honest reading.** CWE-specific guidance (S2) led. Ours tied S3, at about 5×
S2's tokens. Paper 3's best technique on GPT-4 (RCI, S5) was among the worst on
a 7B model, because its "improve" turns broke behaviour. All 9 dependency
upgrades were rejected, which led to finding 23: the prompt named the fix for
one advisory (PyYAML 5.3.1), not for all of them (5.4). It is fixed. With
n = 1 per cell, we make no significance claim.

## 6. E5 — how low can the tokens go? (the panel's first question)

Two new rungs of our strategy, both of which must still pass the linter:
**S7a** is S7's first message alone, without the review turns; **S7m** is the
minimal prompt, with only what the linter requires and a compact envelope.

**Static, no model (24 real findings), estimated tokens a developer pastes:**

| Strategy | Passes lint | Median tokens (min–max) |
|---|---|---|
| S7 (three messages) | 24 / 24 | 439 (358–475) |
| S7a (one message) | 24 / 24 | 334 (279–373) |
| **S7m (minimal)** | **24 / 24** | **199 (142–234)** |
| S2 (reference) | 1 / 24 | 308 (207–423) |

Where S7's first message spends its tokens (medians): explanation 56, the code
itself 54, inert-data instruction 47, directive 38, scope 37, output contract
35, opening 28, guard 26, classification 17. **The floor is the code**, a
median of 54 tokens, which no variant can remove.

**Live, same model, same checks, after the finding-23 fix (40 trials):**

| Strategy | Verified | Tokens per fix attempt (whole conversation) | Verified per 1k tokens |
|---|---|---|---|
| S7 | 8 / 10 | 2,220 | 0.36 |
| S7a | 9 / 10 | 499 | 1.80 |
| **S7m** | **9 / 10** | **380** | **2.37** |
| S2 | 9 / 10 | 425 | 2.12 |

**The answer.** The review turns are where the tokens go: RCI re-sends the
whole conversation twice, so S7 costs about 5.8× S7m. On this model those
turns did not buy any verified fixes. The minimal prompt keeps every linted
constituent, costs about 380 tokens per attempt, verified 9/10, and is the most
token-efficient strategy measured. Every rung of ours now also verifies the
dependency upgrade (finding 23).

One S7 cell first ended in a model-server timeout, an infrastructure failure,
not a model answer. It was re-run alone, and the first attempt is kept as
`evaluation/results/e5_tokens_attempt1.json`.

**In practice.** A developer pastes **one** message, of about 140–235 tokens
(S7m) or 280–375 (S7a), into their own assistant. The tool itself spends no tokens: there is no model
in developer mode.

## 7. Does a fix break the code around it? (the panel's second question)

Evidence from the E2 pilot's 90 trials, recomputed by `evaluation/related_functions.py`:

| | |
|---|---|
| fixes to helpers that other code calls (`hash_password`, `make_reset_token`, both called by `register`) | 18 trials, **13 verified, 0 broke the caller** |
| scanner-clean, structurally intact fixes that still broke behaviour (caught by check 3b) | 7 |
| one-function edits that broke the whole module (every test errored, or the file stopped parsing) | 4, all rejected |

The four layers that protect callers, and what we do not claim, are in
[`related_functions.md`](related_functions.md).

## 8. The tool's own security and quality

| | |
|---|---|
| automated tests | **817 pass, 2 skipped** (symlink tests need privileges on Windows); 31 of them are the lint library's own |
| self-scan of `app/`, `dashboard/`, `libs/` with our four scanners | 3 LOW advisories, all in the one subprocess wrapper; 0 elsewhere |
| pip-audit of the frozen application environment (35 packages) | **0 known vulnerabilities** |
| live public repository (snapshot, 8 Oct, not asserted) | `fportantier/vulpy`: 68 findings in about 11 s, 27 in scope over 6 CWEs |

## 9. Threats to validity

- **One small fixture.** Ten seeded weaknesses, one instance each, in one Flask
  application. The results describe that fixture, not Python code in general.
- **One model, n = 1 per cell.** Temperature 0 with a fixed seed makes reruns
  repeatable, so repeated runs would not add independent samples. Differences
  of one fix between strategies are within noise.
- **Token counts.** Lab runs use the model server's exact counts. Developer-mode
  figures are estimates at about four characters per token.
- **The linter's rules are pattern checks**, not a parser. E1 measures whether
  they notice a removal, not whether a passing prompt yields a better fix. That
  correlation is open work (`libs/secure-prompt-lint/RESEARCH.md`).
- **Scanners define "resolved".** A weakness none of the four tools detects is
  invisible to both detection and verification.

## 10. Reproducing

```bash
python -m pytest                                          # everything above that is asserted
python -m app.cli scan-dir fixtures/flask_vuln_app --ground-truth
python scripts/demo_lifecycle.py ; python scripts/demo_verify.py
python -m evaluation.e1_mutation                          # E1, no model, ~2 s
python -m evaluation.e5_tokens                            # E5 static, no model
python -m evaluation.related_functions                    # section 7, from the committed pilot rows
# E2 / E5 live (needs Ollama + the model), always on a throwaway database:
python -m evaluation.e2_strategies --strategies S2,S7,S7a,S7m --out evaluation/results/e5_tokens.json
```
