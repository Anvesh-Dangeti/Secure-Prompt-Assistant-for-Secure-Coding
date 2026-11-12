# Continuing the research

This linter came out of a question: *does a remediation prompt keep what makes
it secure after a developer edits it, and does that matter for the fix?* Below
are the open problems we know of, each with what we measured and a concrete
place to start.

## 1. Do the rules predict verified fixes? (rule → outcome)

**What we know.** The mutation benchmark shows that the rules *notice* when a
constituent is removed: 168/168 such mutants flagged, and 0/96 false alarms. It
does not show that a prompt which passes yields a better fix.

In our lab runs (one 7B model, 10 seeded weaknesses), the minimal prompt —
only what the linter requires — verified 9/10 fixes. The full prompt with two
review turns verified 8/10 at about six times the tokens. That is suggestive,
not conclusive.

**Start here.**
- Take prompts that fail one rule at a time (the benchmark mutants are ready-made).
- Send each to several models, and verify every fix independently: re-scan, then
  behaviour tests.
- Estimate each rule's effect on the verified-fix rate. A rule with no measurable
  effect is a candidate for removal; an unexplained failure is a candidate for a
  new rule.

## 2. A real constituency parser

**What we know.** A1–A5 are pattern checks over the instruction text. Paper 2
defined its constituents syntactically: WHNP, WHADVP/SBAR, VP. Patterns can be
fooled by a sentence that mentions a term without directing it ("do not use a
parameterised query").

**Start here.**
- Parse the instructions with an off-the-shelf constituency parser.
- Re-implement A1–A3 over the parse tree.
- Compare both on the benchmark, plus a set of adversarial paraphrases.

## 3. Negation and contradiction

**What we know.** The vocabulary match is anchored at a word start, so "salt"
is not satisfied by "unsalted". There is no negation handling, though: "never use
an allowlist" would satisfy A3.

**Start here.** Add negation-scope detection to A3 and A2, and measure the
false-pass rate on hand-written negated prompts.

## 4. More weaknesses, more languages

**What we know.** The bundled vocabulary covers ten CWEs for Python web code.

**Start here.**
- Write a vocabulary JSON for another language's idioms (Java `PreparedStatement`,
  JS `textContent`), or for new CWEs such as CWE-601 open redirect or CWE-918 SSRF.
- Pass it with `--vocabulary`.
- The benchmark accepts your own cases with `--cases`.

## 5. Model-specific token budgets

**What we know.** Rule C1 uses one fixed budget and a four-characters-per-token
estimate. In our runs, review turns (RCI) cost about 5–6× the tokens of a single
message and did not verify more fixes on a 7B model.

**Start here.**
- Measure the cost and the verified-fix rate per model family.
- Learn a budget per model.
- Replace the estimate with the model's own tokenizer, where one is available.

## 6. The two known gaps of the benchmark

- **Undelimited short snippets.** The undelimit operator is flagged only 16/24
  times: a one- or two-line snippet pasted without a fence does not look like
  code. A better code detector would close this gap.
- **The explanation has no rule.** Paper 1 (explained feedback) suggests the
  explanation matters. Our minimal prompt drops it and still verified 9/10, so it
  is an open question whether an explanation rule earns its place.

## 7. Attacks on the linter itself

The linter is a defence, so it has adversaries. Code under repair is attacker
text: it can try to look like instructions (B5 is a heuristic), forge markers
(the nonce stops it closing its block), or pad itself to blow the token budget.

**Start here.** Write an adversarial corpus of comments and strings in the
code, and measure B5's recall. Report which forms a model actually follows.

## Citing

If you use this linter or its benchmark, please cite the Secure Prompt
Assistant project (TEAM-3, IIT Hyderabad, 2026) and the paper behind the
constituent rules:

- Cicalese, Della Porta, Lambiase, Iannone, Hinrichs, Scandariato & Palomba, *The Language of Security: How
  Prompt Syntax Shapes Secure Code Generation in Open LLMs*, arXiv:2607.15937, sections IV-B and V-B.
