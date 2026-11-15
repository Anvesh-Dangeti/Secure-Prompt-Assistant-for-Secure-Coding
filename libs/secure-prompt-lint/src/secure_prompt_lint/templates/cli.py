"""Command line: print the prompt for one finding, or reproduce the token ladder.

    python -m secure_prompt_lint.templates --list
    python -m secure_prompt_lint.templates --finding finding.json --strategy S7m
    python -m secure_prompt_lint.templates --bundled 5 --strategy S2 --json
    python -m secure_prompt_lint.templates --ladder

A finding file is a JSON object with the fields of ``Finding`` (at least
``cwe``, ``file_path`` and ``code``). ``--bundled N`` uses one of the 24 real
findings shipped with the library instead (``--list-bundled`` shows them).

Exit status: 0 when a prompt is printed, 1 when one of our strategies (S7,
S7a, S7m) refuses to produce a prompt that fails the linter, 2 for a usage or
input problem.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secure_prompt_lint import __version__
from secure_prompt_lint.cli import DEFAULT_MAX_BYTES, InputError, read_prompt
from secure_prompt_lint.templates.build import PromptRejected, build_prompt, bundled_findings, ladder
from secure_prompt_lint.templates.finding import Finding
from secure_prompt_lint.templates.strategies import PAPERS, RECOMMENDED, STRATEGIES
from secure_prompt_lint.vocabulary import VocabularyError, load_vocabulary, use_vocabulary

EXIT_OK, EXIT_REJECTED, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m secure_prompt_lint.templates", description=__doc__.split("\n")[0])
    what = p.add_mutually_exclusive_group()
    what.add_argument("--finding", help="JSON file describing the finding, or - for stdin")
    what.add_argument("--bundled", type=int, metavar="N", help="use bundled real finding N (1-24)")
    what.add_argument("--list", action="store_true", help="list the strategies and exit")
    what.add_argument("--list-bundled", action="store_true", help="list the bundled findings and exit")
    what.add_argument("--ladder", action="store_true", help="reproduce the static token ladder and exit")
    p.add_argument("--strategy", default=RECOMMENDED, help=f"S0-S8, S7a or S7m (default {RECOMMENDED})")
    p.add_argument("--explanation", help="text to use as S7/S7a's explanation instead of the template one")
    p.add_argument("--vocabulary", help="JSON vocabulary table to use instead of the bundled one")
    p.add_argument("--json", action="store_true", help="print the prompt and its lint report as JSON")
    p.add_argument("-o", "--output", help="write the prompt to this file (UTF-8) instead of stdout")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _list() -> None:
    for s in STRATEGIES.values():
        mark = "  (must pass the linter)" if s.enforce_lint else ""
        print(f"  {s.id:<4} {s.name:<26} {s.summary}{mark}")
        print(f"       from: {s.origin}")
    print("\n  " + "\n  ".join(f"{short}: {ref}" for short, ref in PAPERS.items()))


def _ladder() -> None:
    result = ladder()
    print(f"Token ladder (static, no model) -- {result['findings']} real findings, estimated tokens")
    print(f"  {'strategy':<9} {'passes lint':>12}   {'typed: min / median / max':>27}")
    for sid, (lo, mid, hi) in result["typed"].items():
        print(f"  {sid:<9} {result['passes_lint'][sid]:>6} / {result['findings']:<4}   {lo:>9} / {mid:>6} / {hi:<6}")
    lo, mid, hi = result["code_block"]
    print(f"\n  the delimited code alone: {lo} / {mid} / {hi} -- what no strategy can remove")
    print(f"  S7m's first message is {round(result['s7m_saving_vs_s7a'] * 100)}% shorter than S7a's")


def _finding(args: argparse.Namespace) -> Finding:
    if args.bundled is not None:
        found = bundled_findings()
        if not 1 <= args.bundled <= len(found):
            raise InputError(f"--bundled takes 1-{len(found)}")
        return found[args.bundled - 1][1]
    try:
        data = json.loads(read_prompt(args.finding, DEFAULT_MAX_BYTES))
    except json.JSONDecodeError as exc:
        raise InputError(f"the finding is not valid JSON: {exc}") from exc
    try:
        return Finding.from_dict(data)
    except (TypeError, ValueError) as exc:
        raise InputError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.vocabulary:
            use_vocabulary(load_vocabulary(args.vocabulary))
    except (VocabularyError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.list:
        _list()
        return EXIT_OK
    if args.list_bundled:
        for n, (ident, _) in enumerate(bundled_findings(), start=1):
            print(f"  {n:>2}  {ident}")
        return EXIT_OK
    if args.ladder:
        _ladder()
        return EXIT_OK
    if args.finding is None and args.bundled is None:
        parser.print_usage(sys.stderr)
        print("error: give --finding FILE, --bundled N, --list or --ladder", file=sys.stderr)
        return EXIT_USAGE
    try:
        finding = _finding(args)
        plan = build_prompt(finding, args.strategy, explanation=args.explanation)
    except PromptRejected as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REJECTED
    except (InputError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        text = json.dumps({"strategy": plan.strategy, "system": plan.system, "messages": list(plan.messages),
                           "estimated_tokens": plan.estimated_tokens, "lint": plan.lint.to_dict()}, indent=2)
    else:
        text = plan.render()
    text = text if text.endswith("\n") else text + "\n"
    if args.output:
        try:
            Path(args.output).write_text(text, encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    else:
        sys.stdout.write(text)
    verdict = "PASS" if plan.lint.passed else "FAIL"
    print(f"{plan.strategy}: lint {verdict}  constituents {round(plan.lint.constituent_score * 100)}%  "
          f"~{plan.estimated_tokens} tokens to paste", file=sys.stderr)
    return EXIT_OK
