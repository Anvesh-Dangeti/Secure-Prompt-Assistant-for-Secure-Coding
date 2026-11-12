"""Export the linter's data from this application into the stand-alone library.

    python scripts/export_lint_data.py          # rewrite both bundled files
    python scripts/export_lint_data.py --check  # exit 1 if either is out of date

Two files ship inside ``libs/secure-prompt-lint/src/secure_prompt_lint/data/``:

* ``cwe_vocabulary.json`` -- what the constituent rules look for, per CWE:
  name, aliases, handling-directive vocabulary, and the child-to-parent CWE
  aliases. ``app/mapping/data/cwe_guidance.yaml`` stays the one place this
  wording is edited (it also holds the prompt sentences), but the library has
  no dependency on this application, so the part it needs is exported.
* ``e1_benchmark.json`` -- the 24 mutation-benchmark cases: the S7 prompt for
  each real fixture finding (secrets already redacted) and the expectation it
  is linted against. ``python -m secure_prompt_lint.bench`` reproduces E1 from it.

A test runs the ``--check`` comparison, so the bundled copies cannot drift.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_prompt_lint.bench import case_to_dict  # noqa: E402

from app.ai.guidance import SLOT_DEFAULTS, all_guidance  # noqa: E402
from app.mapping.mapper import tables  # noqa: E402
from evaluation.e1_mutation import cases  # noqa: E402

DATA = ROOT / "libs" / "secure-prompt-lint" / "src" / "secure_prompt_lint" / "data"
# The sentences a fix-it inserts for A1 (binding), A3 (directive) and A2 (guard).
TEMPLATE_FIELDS = ("explain", "directive", "guard")


def vocabulary() -> dict:
    return {
        "source": "Secure Prompt Assistant guidance table (cwe_guidance.yaml), exported by "
                  "scripts/export_lint_data.py",
        "weaknesses": {g.cwe: {"name": g.name, "aliases": list(g.aliases), "vocabulary": list(g.vocabulary),
                               "templates": {f: " ".join(g.texts[f].split()) for f in TEMPLATE_FIELDS}}
                       for g in all_guidance()},
        "cwe_aliases": dict(sorted(tables().aliases.items())),
        "slot_defaults": dict(SLOT_DEFAULTS),
    }


def benchmark() -> dict:
    return {
        "source": "the 24 in-scope findings four scanners report on the Secure Prompt Assistant's seeded Flask "
                  "fixture; each prompt is that project's strategy S7 first message, with a fixed delimiter nonce",
        "paragraphs": ["opening", "explanation", "directive", "guard", "classification", "scope",
                       "inert-data instruction", "untrusted code", "output contract"],
        "cases": [case_to_dict(c) for c in cases()],
    }


def _render(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


FILES = {"cwe_vocabulary.json": vocabulary, "e1_benchmark.json": benchmark}


def stale() -> list[str]:
    """Bundled files whose content differs from a fresh export."""
    out = []
    for name, build in FILES.items():
        path = DATA / name
        if not path.exists() or path.read_text(encoding="utf-8") != _render(build()):
            out.append(name)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="only report whether the bundled files are current")
    args = parser.parse_args(argv)
    if args.check:
        out_of_date = stale()
        print("up to date" if not out_of_date else "out of date: " + ", ".join(out_of_date))
        return 1 if out_of_date else 0
    for name, build in FILES.items():
        (DATA / name).write_text(_render(build()), encoding="utf-8", newline="\n")
        print(f"wrote {(DATA / name).relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
