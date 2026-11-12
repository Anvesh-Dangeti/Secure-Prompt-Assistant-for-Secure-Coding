# secure-prompt-lint

A deterministic linter for **security-remediation prompts**: the text a developer
hands to a coding assistant (Copilot, ChatGPT, a local model …) to fix a
vulnerability. It checks that the prompt still says *what* is at risk, *how* it
must be handled, *when* the operation may proceed and *what not to touch*. It
also checks the prompt's own safety: no secrets, untrusted code delimited and
marked as data, minimal context, and a token budget. A failing prompt can be
repaired by deterministic fix-its.

No model is involved anywhere. The same prompt always gets the same report, so
lint results can serve as evidence in experiments.

- **Zero runtime dependencies.** Python ≥ 3.10, standard library only.
- **Library + command line.** Exit codes make it usable as a CI or pre-commit gate.
- **Extensible.** Add your own rules, or a vocabulary for new CWEs, without editing the engine.
- **Benchmark included.** A 288-mutant benchmark reproduces the published numbers.

It was built as part of the *Secure Prompt Assistant for Secure Coding* project
(TEAM-3, Secure Software Engineering, IIT Hyderabad, 2026). That tool scans a
repository, generates a remediation prompt per finding, and re-scans
independently to verify the fix.

## Why a prompt needs linting

Cicalese et al. (*The Language of Security: How Prompt Syntax Shapes Secure Code Generation in Open
LLMs*, arXiv:2607.15937) removed one syntactic constituent at a time from
secure-coding prompts and measured the generated code. Prompts that lost the
entity at risk, the condition under which an operation may proceed, the
handling directive, or the opening sentence produced more vulnerable code.
Section V-B proposes a linter for exactly this and notes that none exists.

Developers rarely paste a generated prompt unchanged: they shorten it, rewrite
it, and paste code and configuration into it. Each edit can silently drop a
security constituent, or send a secret or a whole file to a third-party model.

## Install

```bash
pip install git+https://github.com/Anvesh-Dangeti/secure-prompt-lint
# or, from a checkout:
pip install .
```

Run the tests with `pip install pytest && pytest`.

## Quick start: command line

```text
$ cat prompt.txt
Fix the command injection in ping_host in app.py.

```python
def ping_host():
    host = request.args.get("host")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output
```

$ secure-prompt-lint prompt.txt --cwe CWE-78 --entity host --entity subprocess.check_output \
      --location app.py --location ping_host
FAIL  constituents 20%  ~52 tokens  (bound)
  [ERROR  ] A1 the instructions never name the value or call at risk (`host`, `subprocess.check_output`)
  [ERROR  ] A2 no condition says when the operation may proceed (e.g. 'only after the value is validated')
  [ERROR  ] A3 no handling directive says how to fix it (expected e.g. 'shell=false', 'argument list', ...)
  [ERROR  ] A4 nothing forbids unrelated changes; an assistant may rewrite more than the flagged code
  [WARNING] B2 code is pasted without untrusted-data delimiters; comments in it can act as instructions ...
  [WARNING] B3 no instruction tells the model to treat the pasted code as data and ignore instructions ...

$ secure-prompt-lint prompt.txt --cwe CWE-78 ... --fix -o fixed.txt  # PASS after fix-its
$ secure-prompt-lint fixed.txt  --cwe CWE-78 ...
PASS  constituents 100%  ~256 tokens  (bound)
```

Without `--cwe` the prompt is linted **unbound**: any known weakness, entity and
directive counts, and fix-its repair only the structural rules (delimiters and
the inert-data instruction).

Exit status: `0` pass (warnings allowed) · `1` an error was reported · `2` usage or input problem.
Other options: `--fix -o FILE` (write the fixed prompt to a file), `--json`, `--preamble FILE` (a system/rules text sent first), `--budget N`,
`--max-block-lines N`, `--vocabulary FILE`, `--rules`. Input is capped (`--max-bytes`, 256 KB by default)
and is only ever read as text.

## Quick start: Python

```python
from secure_prompt_lint import lint, expectation, apply_fixes

exp = expectation("CWE-78", entities=["host", "subprocess.check_output"], locations=["app.py", "ping_host"])
report = lint(prompt_text, exp)
report.passed, report.constituent_score, report.tokens
for issue in report.issues:
    print(issue.rule, issue.severity, issue.message, issue.fix)

fixed = apply_fixes(prompt_text, report, exp)      # deterministic insertions, never a model rewrite
```

`expectation()` takes plain values. The first entity is read as the untrusted
value and the second as the call it reaches; a location with a file extension
is the file, and any other location is the function. To control the fix-it
sentences exactly, pass `slots={...}` or `fixits={rule: sentence}`.

## The rules

| Rule | Checks | Severity | Source |
|---|---|---|---|
| A1 | entity binding: the instructions name the value or call at risk | error | Paper 2 §IV-B (WHNP) |
| A2 | condition / guard: when the operation may proceed | error | Paper 2 §IV-B (WHADVP/SBAR) |
| A3 | handling directive: how the value must be handled (per-CWE vocabulary) | error | Paper 2 §IV-B (VP) |
| A4 | scope constraint: forbids unrelated changes | error | remediation practice |
| A5 | opening anchor: task, weakness and location in sentence one | error | Paper 2 §IV-B (opening position) |
| A6 | no stranded constraint: guard and directive not only at the end | warning | Paper 2 (late positions) |
| A7 | no silent shortening against the generated prompt | warning | Paper 2 §V-B |
| B1 | no secret-like value in the prompt | error | threat model: tool ↔ LLM |
| B2 | untrusted code delimited with a nonce, markers intact | error / warning | prompt-injection defence |
| B3 | an inert-data instruction before untrusted code | error / warning | prompt-injection defence |
| B4 | untrusted code within the data-minimisation budget | error | data minimisation |
| B5 | no instruction-like text inside untrusted code | warning | prompt-injection heuristic |
| C1 | within the token budget | warning | cost |

Only the **instructions** are searched for constituents. A name that appears
inside the delimited code, or inside a Markdown code fence, does not bind the
instruction to it, because that text is data.

## Extending

**A new rule:**

```python
from secure_prompt_lint import register_rule, LintIssue, WARNING

@register_rule("X1", "names the web framework the fix must use")
def framework_named(ctx):                      # ctx: RuleContext (text, instructions, blocks, preamble, expectation)
    if "flask" not in ctx.instructions.lower():
        return [LintIssue("X1", WARNING, "the instructions never name the web framework")]
    return []
```

**New CWEs:** give `--vocabulary my_table.json` (or call `use_vocabulary(load_vocabulary(path))`)
with the same shape as `src/secure_prompt_lint/data/cwe_vocabulary.json`: per CWE, a `name`,
`aliases`, directive `vocabulary` stems and optional `templates` for the fix-it sentences.

## The benchmark

```bash
python -m secure_prompt_lint.bench
```

It contains 24 real remediation prompts: one per finding that four scanners
report on a seeded Flask application. Each prompt is mutated in 12 ways a
developer edits a prompt (delete each of its nine paragraphs, genericise the
directive, truncate, undelimit the code), giving 288 mutants. Result:

| | |
|---|---|
| unmutated prompts clean | 24 / 24 |
| mutants that remove a security constituent — failed | 149 / 168 |
| … flagged (error or warning) | 168 / 168 |
| mutants that remove only an unchecked paragraph — false alarms | 0 / 96 |
| failed mutants repaired by the fix-its | 149 / 149 |

Use `--cases FILE` to run the same operators on your own prompts.

## What it showed in practice

In the Secure Prompt Assistant's lab runs, a 7B local model (qwen2.5-coder,
temperature 0) wrote 10 seeded fixes per prompting strategy. Each fix was
verified by re-running four scanners plus structural and behaviour checks. Two
prompts compared:

- **the full prompt**: explanation, every constituent, and two review turns;
- **the minimal prompt**: only what this linter requires.

The minimal one verified **9/10** fixes at about **380 tokens** per attempt.
The full one verified **8/10** at about **2,220**. These are single-model runs
with n = 10, so they show an effect worth studying, not a general ranking.

## Limitations

- Constituent rules are **pattern checks, not a constituency parser**. They are
  necessary conditions: a prompt can mention "parameterised query" and still be a
  poor prompt.
- English prompts only. The bundled vocabulary covers ten CWEs.
- A one- or two-line code snippet pasted without a fence may not be recognised as
  code (B2), so in the benchmark "undelimit" is flagged 16/24 times.
- No rule checks the *explanation* part of a prompt.
- Token counts are estimates (about four characters per token).
- B5 is a heuristic. Delimiting does not make prompt injection impossible.
  Treat a model's output as untrusted and verify fixes independently.

See [RESEARCH.md](RESEARCH.md) for open problems and how to start on them.

## Licence

MIT — see [LICENSE](LICENSE).
