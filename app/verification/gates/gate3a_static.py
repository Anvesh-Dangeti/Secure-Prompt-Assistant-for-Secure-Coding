"""Gate 3a -- the fixed code is structurally intact (static; both modes; never executes anything).

Compares the target symbol's snapshot before the change with the one after:

    file            still exists and still parses
    function        still defined under the same qualified name; same parameters;
                    every decorator kept (a dropped ``@app.route`` silently removes
                    the endpoint); body not reduced to a stub; no newly undefined name
    module name     still bound (``API_TOKEN`` moved to an env lookup is fine)
    __main__ block  still present and not a stub
    dependency      still listed (removing the package breaks every import of it)

These are the fake fixes Paper 3 section 7.4 documents, and the ones that make
SecCoderX's "effective safety rate" lower than the raw security rate. A
non-Python file has no structure to check: NOT_APPLICABLE, stated as such.
"""

from __future__ import annotations

from app.verification.gates import GateResult, GateStatus
from app.verification.symbols import (ASSIGNMENT, DEPENDENCY, FILE, FILE_MISSING, FUNCTION, MAIN_BLOCK, MISSING,
                                      UNPARSEABLE, SymbolFacts)

TITLE = "function preserved (static)"


def _function_problems(before: SymbolFacts, after: SymbolFacts) -> list[str]:
    problems = []
    if after.signature != before.signature:
        problems.append(f"parameters changed: {before.signature} -> {after.signature}")
    dropped = [d for d in before.decorators if d not in after.decorators]
    if dropped:
        problems.append("decorator(s) removed: " + ", ".join(f"@{d}" for d in dropped))
    if after.body_trivial and not before.body_trivial:
        problems.append("body reduced to a stub (pass / constant return / raise)")
    if not after.star_import:
        new_names = sorted(set(after.undefined_names) - set(before.undefined_names))
        if new_names:
            problems.append("uses name(s) nothing defines: " + ", ".join(new_names))
    return problems


def gate3a_static(before: SymbolFacts | None, after: SymbolFacts | None) -> GateResult:
    if before is None:
        return GateResult("3a", TITLE, GateStatus.UNVERIFIED,
                          "no snapshot of the target before the change (scanned before verification "
                          "support existed): rescan, then fix and verify")
    if after is None:
        return GateResult("3a", TITLE, GateStatus.UNVERIFIED, f"the rescan recorded nothing for {before.label}")
    if before.kind == FILE and not before.file_path.endswith(".py"):
        return GateResult("3a", TITLE, GateStatus.NOT_APPLICABLE, f"{before.file_path} is not Python source")
    if after.state == FILE_MISSING:
        return GateResult("3a", TITLE, GateStatus.FAIL, f"{after.file_path} was deleted")
    if after.state == UNPARSEABLE:
        return GateResult("3a", TITLE, GateStatus.FAIL, f"{after.file_path} no longer parses (or cannot be read)")
    if after.state == MISSING:
        what = {FUNCTION: "is no longer defined", ASSIGNMENT: "is no longer assigned",
                MAIN_BLOCK: "was removed", DEPENDENCY: "is no longer listed"}.get(before.kind, "is gone")
        return GateResult("3a", TITLE, GateStatus.FAIL, f"{before.label} {what}")
    problems: list[str] = []
    if before.kind == FUNCTION:
        problems = _function_problems(before, after)
    elif before.kind == MAIN_BLOCK and after.body_trivial and not before.body_trivial:
        problems = ["the __main__ block was reduced to a stub"]
    if problems:
        return GateResult("3a", TITLE, GateStatus.FAIL, f"{before.label}: {problems[0]}",
                          tuple(problems) if len(problems) > 1 else ())
    checked = {FUNCTION: "same parameters and decorators, real body, no undefined names",
               ASSIGNMENT: "still assigned", MAIN_BLOCK: "still present", DEPENDENCY: "still listed",
               FILE: "file parses"}.get(before.kind, "present")
    return GateResult("3a", TITLE, GateStatus.PASS, f"{before.label}: {checked}")
