"""AI-layer commands for the CLI (registered by ``app.cli``).

Developer mode -- no model needed:

    python -m app.cli strategies
    python -m app.cli explain 7 --source <checkout>
    python -m app.cli prompt 7 --source <checkout> [--strategy S7] [--out prompt.txt] [--json]
    python -m app.cli lint-prompt my_prompt.txt [--finding 7 --source <checkout>] [--fix] [--report]

Lab mode -- local model, experiments only (nothing is applied):

    python -m app.cli providers
    python -m app.cli propose 7 --source <checkout> --strategy S7
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.ai.context import ContextError, FindingContext
from app.ai.conversation import run_conversation
from app.ai.explainer import explain
from app.ai.linter import RULES, apply_fixes, lint, unbound_expectation
from app.ai.prompt_builder import PromptRejected, build_prompt
from app.ai.providers import OllamaProvider, ProviderError, get_provider
from app.ai.service import FindingNotFound, bound_expectation, context_for_tracked
from app.ai.strategies import DEFAULT_STRATEGY, STRATEGIES
from app.db.session import init_db, session_scope

MAX_PROMPT_INPUT = 256 * 1024


def _context(args: argparse.Namespace) -> FindingContext | None:
    init_db()
    try:
        with session_scope() as session:
            ctx = context_for_tracked(session, args.finding, Path(args.source).resolve())
    except (FindingNotFound, ContextError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None
    if ctx.snippet_verified is False:
        print("warning: the code in --source differs from the scanned version; rescan for exact context",
              file=sys.stderr)
    return ctx


def _print_report(report, as_json: bool = False) -> None:  # noqa: ANN001
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
        return
    status = "PASS" if report.passed else "FAIL"
    mode = "bound to finding" if report.bound else "unbound"
    print(f"\n  lint: {status}  constituents {report.constituent_score:.0%}  ~{report.tokens} tokens  ({mode})")
    for rule, present in report.constituents.items():
        mark = {True: "ok", False: "MISSING", None: "n/a"}[present]
        print(f"    {rule} {mark:8} {RULES[rule]}")
    for issue in report.issues:
        print(f"  [{issue.severity.upper():7}] {issue.rule} {issue.message}")
        if issue.fix:
            print(f"            fix: {issue.fix}")
    print()


def cmd_strategies(_args: argparse.Namespace) -> int:
    for s in STRATEGIES.values():
        lint_note = "  [must pass lint]" if s.enforce_lint else ""
        print(f"  {s.id}  {s.name:26} {s.summary}  ({s.origin}){lint_note}")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    ctx = _context(args)
    if ctx is None:
        return 2
    provider = get_provider(args.provider) if args.provider else None
    e = explain(ctx, provider)
    print(f"\n  {ctx.cwe} {ctx.file_path}:{ctx.start_line}  ({e.source})\n\n  {e.text}\n")
    if e.note:
        print(f"  note: {e.note}\n")
    return 0


def cmd_prompt(args: argparse.Namespace) -> int:
    ctx = _context(args)
    if ctx is None:
        return 2
    explainer = get_provider(args.explainer) if args.explainer else None
    try:
        plan = build_prompt(ctx, args.strategy, explanation=explain(ctx, explainer))
    except PromptRejected as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps({"strategy": plan.strategy, "system": plan.system, "messages": list(plan.messages),
                          "explanation": {"text": plan.explanation.text, "source": plan.explanation.source},
                          "estimated_tokens": plan.estimated_tokens, "lint": plan.lint.to_dict()}, indent=2))
        return 0
    if args.out:
        Path(args.out).write_text(plan.render() + "\n", encoding="utf-8")
        print(f"  prompt written to {args.out}")
    else:
        print("\n" + plan.render())
    _print_report(plan.lint)
    return 0


def cmd_lint_prompt(args: argparse.Namespace) -> int:
    raw = sys.stdin.read(MAX_PROMPT_INPUT + 1) if args.file == "-" else \
        Path(args.file).read_text(encoding="utf-8", errors="replace")[:MAX_PROMPT_INPUT + 1]
    if len(raw) > MAX_PROMPT_INPUT:
        print("error: prompt too large to lint", file=sys.stderr)
        return 2
    expectation = None
    if args.finding is not None:
        if not args.source:
            print("error: --finding needs --source (the checkout the finding refers to)", file=sys.stderr)
            return 2
        ctx = _context(args)
        if ctx is None:
            return 2
        expectation = bound_expectation(ctx)
    report = lint(raw, expectation)
    if args.fix:
        fixed = apply_fixes(raw, report, expectation or unbound_expectation())
        after = lint(fixed, expectation)
        print(fixed)
        _print_report(after, args.json)
        return 0 if after.passed or args.report else 1
    _print_report(report, args.json)
    return 0 if report.passed or args.report else 1


def cmd_providers(_args: argparse.Namespace) -> int:
    print("  template  available  (no model; developer-mode default)")
    try:
        ok, reason = OllamaProvider().available()
    except ProviderError as exc:
        ok, reason = False, str(exc)
    print(f"  ollama    {'available' if ok else 'NOT READY'}  ({reason})")
    return 0


def cmd_propose(args: argparse.Namespace) -> int:
    ctx = _context(args)
    if ctx is None:
        return 2
    try:
        provider = get_provider(args.provider)
        plan = build_prompt(ctx, args.strategy)
    except (ProviderError, PromptRejected) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not provider.generates:
        print("error: lab mode needs a generating provider (--provider ollama)", file=sys.stderr)
        return 2
    result = run_conversation(plan, provider)
    print(json.dumps({
        "strategy": result.strategy, "model": result.model, "calls": result.calls,
        "prompt_tokens": result.prompt_tokens, "completion_tokens": result.completion_tokens,
        "error": result.error, "proposal": result.proposal.model_dump() if result.proposal else None,
        "note": "unverified proposal -- nothing has been applied",
    }, indent=2))
    return 0 if result.ok else 1


def register(sub: argparse._SubParsersAction) -> None:
    sub.add_parser("strategies", help="list the prompt strategies S0-S8").set_defaults(func=cmd_strategies)

    def finding_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("finding", type=int, help="tracked finding id (see `findings`)")
        p.add_argument("--source", required=True, help="your checkout of the scanned code")

    p = sub.add_parser("explain", help="explain a tracked finding in terms of the code")
    finding_args(p)
    p.add_argument("--provider", choices=["template", "ollama"])
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("prompt", help="build the remediation prompt for a tracked finding")
    finding_args(p)
    p.add_argument("--strategy", default=DEFAULT_STRATEGY, choices=list(STRATEGIES))
    p.add_argument("--explainer", choices=["template", "ollama"])
    p.add_argument("--out", help="write the prompt to this file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_prompt)

    p = sub.add_parser("lint-prompt", help="lint a prompt (a file, or - for stdin)")
    p.add_argument("file")
    p.add_argument("--finding", type=int, help="bind to a tracked finding for exact checks and fix-its")
    p.add_argument("--source", help="checkout the finding refers to (with --finding)")
    p.add_argument("--fix", action="store_true", help="print the prompt with fix-its applied")
    p.add_argument("--report", action="store_true", help="report only; exit 0 even on errors")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_lint_prompt)

    sub.add_parser("providers", help="show which LLM providers are usable").set_defaults(func=cmd_providers)

    p = sub.add_parser("propose", help="lab mode: ask the local model for a fix proposal (not applied)")
    finding_args(p)
    p.add_argument("--strategy", default=DEFAULT_STRATEGY, choices=list(STRATEGIES))
    p.add_argument("--provider", default="ollama", choices=["ollama"])
    p.set_defaults(func=cmd_propose)
