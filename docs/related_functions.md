# Does fixing one function break the code that calls it?

*The panel's question at the mid-semester review: "how well does the application
handle the functions related to the vulnerable function being fixed — will a fix
break them, or affect complex workflows?"*

**Short answer.** A fix is judged by *what the scanners see* and *what the program
still does*, not only by the fixed function. Four layers protect the code around
the fix. The first three run in both modes. The fourth, actually running the
code, runs only in lab mode, by design. In our 90 recorded lab trials, no
verified fix broke a function that calls the fixed one. Every fix that broke
behaviour or the whole module was rejected. A change to the *meaning* of a return
value is the case we cannot see without running the code. We state that limit
openly.

All numbers below are recomputed from the committed E2 pilot rows by
`python -m evaluation.related_functions` and asserted by
`tests/unit/test_recorded_related.py` (`recorded_results.RELATED`).

## The four layers

| # | Layer | Where | What it protects for callers and workflows |
|---|---|---|---|
| 1 | **The prompt's scope constraint** | every prompt (rule A4) | "change only the code between the markers, do not rename `ping_host`, keep its behaviour for valid input". The model is told the function's name and contract are fixed, so call sites keep working. The linter fails a prompt that loses this sentence. |
| 2 | **Check 2 — nothing new** | both modes | The *whole repository* is rescanned, not only the edited function. A fix that moves the weakness into a caller, or adds a new one anywhere, is rejected at or above the weakness's severity. |
| 3 | **Check 3a — the function is still intact** | both modes, static | The same parameters, so every existing call site stays valid. No decorator removed, so a route's caller (the framework) still reaches it. The body is not a stub, and it uses no names nothing defines. The file still parses: a module that no longer parses breaks *every* function in it. |
| 4 | **Check 3b — behaviour tests** | lab mode only | The project's behaviour tests run on the patched copy, including tests that drive the callers. In our fixture, `register` calls the two crypto helpers, and its test posts a password and checks the JSON reply. A helper fix that returned `bytes` instead of `str` would break `register`'s JSON response and fail here, even though the helper itself looks fine. |

Developer mode stops at layer 3 on purpose: it never executes repository code,
because the repository is untrusted input (threat model, *App ↔ cloned source*).
In developer mode, running the tests is the developer's own CI. The tool's
verdict says that check 3b was not run, and never claims it passed.

## What the recorded trials show

**Fixes to helpers that other code calls.** In the fixture, two of the ten seeded
weaknesses sit in helpers called by another function: `hash_password` (CWE-327)
and `make_reset_token` (CWE-330), both called by the `/register` route.

| | trials | verified | rejected |
|---|---|---|---|
| fixes to `hash_password` and `make_reset_token` (9 strategies each) | 18 | **13** | 5, all at check 1 (the weakness was still there) |

All 13 verified fixes passed the behaviour test that drives `register`. **None of
them broke the caller.** None of the 5 rejected fixes was rejected for breaking
it either: those fixes simply did not remove the weakness.

**Fixes that broke behaviour the scanners could not see.** 7 of the 90 fixes were
scanner-clean and structurally intact, yet failed the behaviour tests (check 3b).
Five were XSS fixes to `greet` after which `/greet?name=Ann` no longer answered
200 with "Hello" and "Ann"; one was a SQL fix and one a hard-coded-secret fix.
Without layer 4, these seven would have been reported as resolved.

**Fixes whose damage spread beyond the fixed function.** In 4 trials, a change to
one function broke the whole module:

| strategy and target | what happened | caught by |
|---|---|---|
| S5 on `get_user` | 8 of the 10 tests errored at setup: the shared fixture could no longer import the app | check 3b |
| S5 on `API_TOKEN` | the configuration change broke the app's import: 8 errors, 1 failure | check 3b |
| S7 on `greet` | `app.py` no longer parsed | check 3a |
| S5 on `download_file` | `app.py` no longer parsed | check 3a |

These are the "complex workflow" failures that matter most: every route in the
file stops working, not just the fixed one. All four were rejected, and the two
parse failures were caught statically, so developer mode would catch them too.

## What we do not claim

- **Return-value meaning is not checked statically.** If a fix keeps the
  signature but changes what the return value means — a password hash that is now
  salted, so the old comparison in a login function no longer matches — checks 1
  to 3a pass. Only a behaviour test that exercises the caller catches it. Our
  fixture has no login path, so this case is reasoned about here, not measured.
- **Fixes that need more than one function changed are out of scope.** A correct
  salted password hash usually needs a new `verify_password` and a change in the
  caller. Our fix unit is one function (the context window), and the scope
  constraint forbids touching the caller. The tool reports such a fix as rejected
  or unverified; it does not silently break the caller. The developer makes the
  wider change and the tool verifies it.
- **The fixture is small.** Two helpers with one caller are evidence, not a
  general result.

## Future work

1. **A "callers intact" check (3c)**: build an AST call map of the repository
   (as `evaluation/related_functions.py` does for the fixture) and check that
   every call site still matches the new signature. Then compare the static
   return shape — literal kind, tuple length, dictionary keys — before and after.
2. **Callers in the prompt**: one line, with no code, naming who calls the
   function and what they use from it ("`register` uses the return value as a
   string"). That costs a few tokens and tells the model the contract.
3. **A workflow fixture**: a second test application with multi-step workflows
   (register then log in; a shared database helper used by three routes), and a
   measured rate of caller breaks with and without the callers line.
