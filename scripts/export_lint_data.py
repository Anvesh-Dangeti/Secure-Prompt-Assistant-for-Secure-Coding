"""Export the linter's data from this application into the stand-alone library.

    python scripts/export_lint_data.py          # rewrite the bundled files
    python scripts/export_lint_data.py --check  # exit 1 if any is out of date

Three files ship inside ``libs/secure-prompt-lint/src/secure_prompt_lint/data/``:

* ``cwe_vocabulary.json`` -- per CWE: name, aliases, handling-directive
  vocabulary and the sentence templates the prompts and fix-its are worded
  from, plus the generic wording, the slot defaults and the child-to-parent
  CWE aliases. ``app/mapping/data/cwe_guidance.yaml`` stays the one place this
  wording is edited, but the library has no dependency on this application,
  so it is exported.
* ``e1_benchmark.json`` -- the 24 mutation-benchmark cases: the S7 prompt for
  each real fixture finding (secrets already redacted) and the expectation it
  is linted against. ``python -m secure_prompt_lint.bench`` reproduces E1 from it.
* ``findings.json`` -- the same 24 findings as prompt-template input (the
  context each prompt is built from), so ``python -m secure_prompt_lint.templates
  --ladder`` reproduces the static token ladder (E5) and anyone can regenerate
  every strategy's prompt for them.

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
from secure_prompt_lint.templates import Finding  # noqa: E402
from secure_prompt_lint.vocabulary import TEMPLATE_FIELDS  # noqa: E402

from app.ai.guidance import SLOT_DEFAULTS, all_guidance, guidance_for  # noqa: E402
from app.mapping.mapper import tables  # noqa: E402
from evaluation.e1_mutation import cases, contexts  # noqa: E402

DATA = ROOT / "libs" / "secure-prompt-lint" / "src" / "secure_prompt_lint" / "data"


def _flat(text: str) -> str:
    return " ".join(text.split())


def vocabulary() -> dict:
    generic = guidance_for(None)
    return {
        "source": "Secure Prompt Assistant guidance table (cwe_guidance.yaml), exported by "
                  "scripts/export_lint_data.py",
        "weaknesses": {g.cwe: {"name": g.name, "aliases": list(g.aliases), "vocabulary": list(g.vocabulary),
                               "templates": {f: _flat(g.texts[f]) for f in TEMPLATE_FIELDS}}
                       for g in all_guidance()},
        "generic": {"name": generic.texts["name"], **{f: _flat(generic.texts[f]) for f in TEMPLATE_FIELDS}},
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


def _finding_ids(ctxs: list) -> list[str]:
    """tool:rule:file:symbol, with a longer rule name where two rules share their last part."""
    def ident(c, parts: int) -> str:
        rule = ".".join(c.rule_id.split(".")[-parts:])
        return f"{c.tool}:{rule}:{c.file_path}:{c.symbol or c.start_line}"
    short = [ident(c, 1) for c in ctxs]
    return [ident(c, 2) if short.count(s) > 1 else s for c, s in zip(ctxs, short, strict=True)]


def findings() -> dict:
    ctxs = contexts()
    return {
        "source": "the 24 in-scope findings four scanners report on the Secure Prompt Assistant's seeded Flask "
                  "fixture, as the context each prompt is built from (code comments removed, secrets redacted)",
        "findings": [{"id": ident, "finding": Finding.from_context(c).to_dict()}
                     for ident, c in zip(_finding_ids(ctxs), ctxs, strict=True)],
    }


def _render(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


FILES = {"cwe_vocabulary.json": vocabulary, "e1_benchmark.json": benchmark, "findings.json": findings}


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
