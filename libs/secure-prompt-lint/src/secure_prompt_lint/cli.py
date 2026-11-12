"""Command line: lint a prompt file (or stdin) before it is sent to a coding assistant.

    secure-prompt-lint prompt.txt
    secure-prompt-lint prompt.txt --cwe CWE-78 --entity host --entity subprocess.check_output --location app.py
    cat prompt.txt | secure-prompt-lint - --json
    secure-prompt-lint prompt.txt --fix > fixed.txt
    secure-prompt-lint --rules

Exit status: 0 when the prompt passes (warnings allowed), 1 when any rule
reports an error, 2 for a usage or input problem -- so it can gate a CI job or
a pre-commit hook on prompt files.

The input is treated as text and nothing else: it is never executed, and it is
capped in size (``--max-bytes``) because a prompt larger than that is already a
data-minimisation failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secure_prompt_lint import __version__
from secure_prompt_lint.engine import lint
from secure_prompt_lint.expectation import DEFAULT_MAX_BLOCK_LINES, DEFAULT_TOKEN_BUDGET, expectation
from secure_prompt_lint.fixit import apply_fixes
from secure_prompt_lint.rules import describe_rules
from secure_prompt_lint.vocabulary import VocabularyError, load_vocabulary, use_vocabulary

DEFAULT_MAX_BYTES = 256 * 1024
EXIT_PASS, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


class InputError(ValueError):
    pass


def read_prompt(source: str, max_bytes: int) -> str:
    """Read the prompt from a file path or ``-`` (stdin), refusing anything over ``max_bytes``."""
    if source == "-":
        data = sys.stdin.buffer.read(max_bytes + 1)
    else:
        path = Path(source)
        if not path.is_file():
            raise InputError(f"not a file: {source}")
        if path.stat().st_size > max_bytes:
            raise InputError(f"{source} is larger than {max_bytes} bytes")
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputError(f"the prompt is larger than {max_bytes} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("the prompt is not UTF-8 text") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secure-prompt-lint", description=__doc__.split("\n")[0])
    p.add_argument("prompt", nargs="?", help="prompt file, or - for stdin")
    p.add_argument("--cwe", help="bind to a weakness, e.g. CWE-89 (otherwise the prompt is linted unbound)")
    p.add_argument("--entity", action="append", default=[], help="a value or call at risk (repeatable)")
    p.add_argument("--location", action="append", default=[], help="file or function of the finding (repeatable)")
    p.add_argument("--preamble", help="file holding a system / rules-file text sent before the prompt")
    p.add_argument("--vocabulary", help="JSON vocabulary table to use instead of the bundled one")
    p.add_argument("--budget", type=int, default=DEFAULT_TOKEN_BUDGET, help="token budget for rule C1")
    p.add_argument("--max-block-lines", type=int, default=DEFAULT_MAX_BLOCK_LINES, help="limit for rule B4")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="refuse larger input")
    p.add_argument("--fix", action="store_true", help="print the prompt with every automatic fix applied")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--rules", action="store_true", help="list the rules and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _print_report(report, bound: bool) -> None:  # noqa: ANN001
    verdict = "PASS" if report.passed else "FAIL"
    print(f"{verdict}  constituents {round(report.constituent_score * 100)}%  ~{report.tokens} tokens  "
          f"({'bound' if bound else 'unbound'})")
    for issue in report.issues:
        print(f"  [{issue.severity.upper():7}] {issue.rule} {issue.message}")
        if issue.fix:
            print(f"            fix: {issue.fix}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.rules:
        for rule, text in describe_rules().items():
            print(f"  {rule:<4} {text}")
        return EXIT_PASS
    if not args.prompt:
        parser.print_usage(sys.stderr)
        print("secure-prompt-lint: error: give a prompt file, or - for stdin", file=sys.stderr)
        return EXIT_USAGE
    if args.budget < 1 or args.max_block_lines < 1 or args.max_bytes < 1:
        print("secure-prompt-lint: error: limits must be positive", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.vocabulary:
            use_vocabulary(load_vocabulary(args.vocabulary))
        text = read_prompt(args.prompt, args.max_bytes)
        preamble = read_prompt(args.preamble, args.max_bytes) if args.preamble else ""
    except (InputError, VocabularyError, OSError, json.JSONDecodeError) as exc:
        print(f"secure-prompt-lint: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    exp = expectation(args.cwe, entities=args.entity, locations=args.location, token_budget=args.budget,
                      max_block_lines=args.max_block_lines)
    report = lint(text, exp, preamble=preamble)
    if args.fix:
        fixed = apply_fixes(text, report, exp)
        sys.stdout.write(fixed if fixed.endswith("\n") else fixed + "\n")
        after = lint(fixed, exp, preamble=preamble)
        print(f"secure-prompt-lint: {'PASS' if after.passed else 'FAIL'} after fix-its "
              f"({len(after.errors)} error(s) left)", file=sys.stderr)
        return EXIT_PASS if after.passed else EXIT_FAIL
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_report(report, exp.bound)
    return EXIT_PASS if report.passed else EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
