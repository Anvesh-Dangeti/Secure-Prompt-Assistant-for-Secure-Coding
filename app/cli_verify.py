"""Verification commands for the CLI (registered by ``app.cli``).

Developer mode -- your own assistant wrote the fix; nothing here executes your code:

    python -m app.cli verify 7 --source <checkout>      # rescan the checkout (ZIP project), then the gates
    python -m app.cli verify 7 --rescan                 # re-clone the repository (git project), then the gates
    python -m app.cli verify 7 --scan 12                # judge an existing scan, no new scan
    python -m app.cli verifications 7                   # remediation history of a finding

Lab mode -- our local model writes the fix into a scratch copy (experiments only):

    python -m app.cli lab-verify 7 --source fixtures/flask_vuln_app --strategy S7 [--replay replies.json]
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from app.ai.providers import ProviderError, ReplayProvider, get_provider
from app.ai.strategies import DEFAULT_STRATEGY, STRATEGIES
from app.core.scratch import scratch_dir
from app.db.models import Project, SourceType, TrackedFinding, Verification
from app.db.session import init_db, session_scope
from app.sandbox.lab import LabError, run_lab_trial
from app.scan_service import InvalidRequest, ScanSummary, scan_git, scan_zip
from app.verification.gates import GateResult, GateStatus
from app.verification.service import NotVerifiable, VerificationNotFound, history, verify

_SHORT = {GateStatus.NOT_APPLICABLE: "n/a", GateStatus.NOT_RUN: "not run"}


def print_verification(row: Verification) -> None:
    where = (f"scan #{row.before_scan_id} -> scan #{row.after_scan_id}" if row.after_scan_id
             else f"{row.strategy or '-'} via {row.model or row.provider or '-'}")
    print(f"\n  verification #{row.id}  finding #{row.tracked_finding_id}  ({row.mode.value}: {where})")
    print(f"  weakness: {len(row.target)} finding(s)")
    for label in row.target:
        print(f"    - {label}")
    print()
    for g in (GateResult.from_dict(d) for d in row.gates):
        print(f"  {g.gate:<3} {g.title:<28} {_SHORT.get(g.status, g.status.value):<11} {g.detail}")
        for item in g.items[:8]:
            print(f"  {'':<44}{item}")
        if len(g.items) > 8:
            print(f"  {'':<44}... {len(g.items) - 8} more")
    if row.proposal:
        print(f"\n  model's summary (untrusted): {row.proposal.get('summary') or '-'}")
    print(f"\n  verdict: {row.verdict.value}" + (f"  -- {row.reason}" if row.reason else ""))
    if row.prompt_tokens is not None:
        print(f"  tokens: {row.prompt_tokens} prompt + {row.completion_tokens} completion over {row.calls} call(s)")
    print()


def _rescan(project: Project, args: argparse.Namespace) -> ScanSummary | None:
    from app.cli import print_summary, zip_directory   # app.cli imports this module

    label = args.label or f"verify #{args.finding}"
    if args.source:
        if project.source_type != SourceType.ZIP:
            print("error: this project tracks a git repository; use --rescan", file=sys.stderr)
            return None
        source = Path(args.source).resolve()
        with scratch_dir("cli-") as work:
            if source.is_dir():
                archive = work / f"{source.name}.zip"
                zip_directory(source, archive)
            elif source.is_file():
                archive = work / "upload.zip"
                shutil.copyfile(source, archive)
            else:
                print(f"error: {source} not found", file=sys.stderr)
                return None
            summary = scan_zip(project.name, archive, label=label)
    else:
        if project.source_type != SourceType.GIT or not project.repo_url:
            print("error: --rescan needs a git project; give the fixed code with --source", file=sys.stderr)
            return None
        try:
            summary = scan_git(project.name, project.repo_url, label=label)
        except InvalidRequest as exc:
            print(f"error: {exc}", file=sys.stderr)
            return None
    print_summary(summary)
    return summary


def cmd_verify(args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        tracked = session.get(TrackedFinding, args.finding)
        if tracked is None:
            print(f"error: no tracked finding #{args.finding}", file=sys.stderr)
            return 2
        project = session.get(Project, tracked.project_id)
    scan_id = args.scan
    if scan_id is None:
        summary = _rescan(project, args)
        if summary is None:
            return 2
        scan_id = summary.scan_id
    try:
        with session_scope() as session:
            row = verify(session, args.finding, scan_id)
            print_verification(row)
            verdict = row.verdict.value
    except (VerificationNotFound, NotVerifiable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if verdict == "VERIFIED_RESOLVED" else 1


def cmd_verifications(args: argparse.Namespace) -> int:
    init_db()
    try:
        with session_scope() as session:
            rows = history(session, args.finding)
            if not rows:
                print(f"\n  finding #{args.finding} has no verifications yet\n")
            for row in rows if args.full else rows[-1:]:
                print_verification(row)
            if rows and not args.full:
                print("  " + ", ".join(f"#{r.id} {r.verdict.value}" for r in rows) + "\n")
    except VerificationNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_lab_verify(args: argparse.Namespace) -> int:
    init_db()
    try:
        provider = ReplayProvider.from_file(Path(args.replay)) if args.replay else get_provider(args.provider)
        with session_scope() as session:
            row = run_lab_trial(session, args.finding, Path(args.source).resolve(), args.strategy, provider,
                                run_tests=not args.no_tests)
            print_verification(row)
            verdict = row.verdict.value
    except (VerificationNotFound, LabError, ProviderError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if verdict == "VERIFIED_RESOLVED" else 1


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("verify", help="rescan the fixed code and run verification gates 1, 2, 3a")
    p.add_argument("finding", type=int, help="tracked finding id (see `findings`)")
    how = p.add_mutually_exclusive_group(required=True)
    how.add_argument("--source", help="your fixed checkout (or a ZIP of it) -- for ZIP projects")
    how.add_argument("--rescan", action="store_true", help="re-clone the repository -- for git projects")
    how.add_argument("--scan", type=int, help="judge this existing scan instead of scanning again")
    p.add_argument("--label", help="label for the new scan")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("lab-verify", help="lab mode: model fix -> scratch copy -> rescan -> gates 1, 2, 3a, 3b")
    p.add_argument("finding", type=int, help="tracked finding id (see `findings`)")
    p.add_argument("--source", required=True, help="the fixture the finding was scanned from")
    p.add_argument("--strategy", default=DEFAULT_STRATEGY, choices=list(STRATEGIES))
    model = p.add_mutually_exclusive_group()
    model.add_argument("--provider", default="ollama", choices=["ollama"])
    model.add_argument("--replay", help="a recorded answer (evaluation/replays/*.json) instead of a live model")
    p.add_argument("--no-tests", action="store_true", help="skip gate 3b (the verdict is then UNVERIFIED at best)")
    p.set_defaults(func=cmd_lab_verify)

    p = sub.add_parser("verifications", help="remediation history of a tracked finding")
    p.add_argument("finding", type=int)
    p.add_argument("--full", action="store_true", help="print every verification, not just the latest")
    p.set_defaults(func=cmd_verifications)
