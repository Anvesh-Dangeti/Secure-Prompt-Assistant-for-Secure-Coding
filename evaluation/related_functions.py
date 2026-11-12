"""Does fixing one function break the code that calls it? The evidence already in the E2 pilot.

    python -m evaluation.related_functions

No model and no new trial: this reads ``evaluation/results/e2_pilot.json`` and
the fixture's source. It answers three questions from what was recorded:

1. **Fixed helpers with callers.** Which seeded weaknesses sit in a function
   that other code in the repository calls (found with a small AST call map,
   not a type-aware call graph)? For those trials, did a verified fix ever break
   the caller? A ``VERIFIED_RESOLVED`` lab verdict needs the behaviour tests
   (gate 3b) to pass, and the fixture's tests exercise the callers.
2. **Behaviour breaks the scanners could not see.** How many fixes were
   scanner-clean and structurally intact, yet failed the behaviour tests?
3. **Breaks that spread beyond the fixed function.** How many single-function
   edits broke the whole module -- a file that no longer parses (gate 3a), or a
   test run where every test errors because the module will not import?

The answer is limited by design and stated as such: developer mode never runs
repository code, so behaviour is checked only in lab mode, and a change in a
return value's type or meaning is not caught statically.
"""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "flask_vuln_app"
PILOT = ROOT / "evaluation" / "results" / "e2_pilot.json"
VERIFIED = "VERIFIED_RESOLVED"
_ERRORS = re.compile(r"(\d+) errors?\b")


def call_map(root: Path = FIXTURE) -> dict[str, list[str]]:
    """function name -> the in-repository functions that call it (by name, across modules)."""
    defined: set[str] = set()
    calls: dict[str, set[str]] = {}
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Call):
                        name = (inner.func.id if isinstance(inner.func, ast.Name)
                                else inner.func.attr if isinstance(inner.func, ast.Attribute) else None)
                        if name and name != node.name:
                            calls.setdefault(name, set()).add(node.name)
    return {name: sorted(callers) for name, callers in sorted(calls.items()) if name in defined}


def run(pilot: Path = PILOT, root: Path = FIXTURE) -> dict:
    trials = json.loads(pilot.read_text(encoding="utf-8"))["trials"]
    callers = call_map(root)
    with_callers = [t for t in trials if t["symbol"] in callers]
    verdicts = Counter(t["verdict"] for t in with_callers)
    rejected_gates = Counter(t["gate"] for t in with_callers if t["verdict"] != VERIFIED)
    at_3b = [t for t in trials if t["gate"] == "3b"]
    module_wide_3b = [t for t in at_3b if (m := _ERRORS.search(t["reason"] or "")) and int(m.group(1)) >= 2]
    unparseable = [t for t in trials if t["gate"] == "3a" and "no longer parses" in (t["reason"] or "")]
    return {
        "callers": {sym: callers[sym] for sym in sorted({t["symbol"] for t in with_callers})},
        "trials_on_helpers_with_callers": len(with_callers),
        "verified_on_helpers_with_callers": verdicts[VERIFIED],
        "rejected_on_helpers_with_callers_by_gate": dict(sorted(rejected_gates.items())),
        "caller_broken_by_a_verified_fix": 0 if verdicts[VERIFIED] else None,   # 3b passed for every one
        "scanner_clean_but_behaviour_broken": len(at_3b),
        "behaviour_broken_by_cwe": dict(sorted(Counter(t["cwe"] for t in at_3b).items())),
        "module_wide_breaks": {"tests_error": len(module_wide_3b), "file_no_longer_parses": len(unparseable)},
        "module_wide_examples": sorted(f"{t['strategy']} on {t['symbol']}" for t in (*module_wide_3b, *unparseable)),
    }


def main() -> None:
    r = run()
    print("Related functions -- evidence from the E2 pilot (90 lab trials, no new run)")
    for sym, who in r["callers"].items():
        print(f"  `{sym}` is called by {', '.join(f'`{c}`' for c in who)}")
    print(f"  trials on those helpers: {r['trials_on_helpers_with_callers']}, verified "
          f"{r['verified_on_helpers_with_callers']} (every one passed the callers' behaviour tests); "
          f"rejected by gate {r['rejected_on_helpers_with_callers_by_gate']}")
    print(f"  scanner-clean fixes that broke behaviour (caught by gate 3b): {r['scanner_clean_but_behaviour_broken']} "
          f"{r['behaviour_broken_by_cwe']}")
    m = r["module_wide_breaks"]
    print(f"  one-function edits that broke the whole module: {m['tests_error'] + m['file_no_longer_parses']} "
          f"({', '.join(r['module_wide_examples'])})")


if __name__ == "__main__":
    main()
