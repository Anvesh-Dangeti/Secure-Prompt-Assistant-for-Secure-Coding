"""Lab mode: one experiment trial -- prompt, model, apply in scratch, rescan, gates 1, 2, 3a, 3b.

    tracked finding + --source (our fixture) + strategy + provider
        -> context from a scratch copy -> build_prompt -> run_conversation (schema-validated)
        -> apply_proposal to the copy -> rescan the copy with the same scanners
        -> compare with the pristine baseline -> gates 1, 2, 3a -> (only if all pass) 3b
        -> one Verification row: verdict, gates, strategy, model, params, tokens

The trial never touches the project's lifecycle (the copies are not project
scans) and never touches the developer's files. The pristine baseline is
scanned once and can be reused across trials, so a batch of S0-S8 runs
compares every strategy against the same evidence (Phase 8).

Verdicts: a provider failure is ERROR (there was no fix to judge); a reply that
fails the schema, or cannot be applied, is FIX_REJECTED with every gate
NOT_RUN; otherwise the gates decide, exactly as in developer mode.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.context import ContextError, extract_context
from app.ai.conversation import ConversationResult, run_conversation
from app.ai.prompt_builder import PromptRejected, build_prompt
from app.ai.providers.base import LLMProvider
from app.ai.service import FindingNotFound, finding_for_tracked
from app.core.redaction import redact
from app.core.scratch import copy_trusted_tree, scratch_dir
from app.db.models import TrackedFinding, Verdict, Verification, VerificationMode
from app.pipeline import TreeScan, scan_tree
from app.sandbox.apply import ApplyError, apply_proposal
from app.scanners import Scanner
from app.scanners.base import EXCLUDED_DIRS
from app.verification.compare import ScanView, compare, view_from_tree
from app.verification.gates import GateResult, GateStatus
from app.verification.gates.gate3b_tests import behaviour_tests_for, run_fixture_tests
from app.verification.service import VerificationNotFound, record, static_gates, suppressed_fingerprints
from app.verification.snapshots import capture
from app.verification.symbols import SymbolFacts
from app.verification.verdict import Outcome, decide

_GATES = (("1", "target resolved"), ("2", "no new findings"), ("3a", "function preserved (static)"),
          ("3b", "fixture tests"))
_PASSING = {GateStatus.PASS, GateStatus.NOT_APPLICABLE}


class LabError(ValueError):
    """The trial cannot be run faithfully -- a harness problem, not a verdict on a fix."""


@dataclass(frozen=True)
class Baseline:
    view: ScanView                   # the pristine copy, scanned and snapshotted
    tests: GateResult | None         # the behaviour tests on the pristine copy (None: not run)


def _scan_copy(root: Path, work: Path, scanners: list[Scanner] | None,
               carried: list[tuple[str, str, str]] = ()) -> tuple[TreeScan, list[SymbolFacts]]:
    out = Path(tempfile.mkdtemp(prefix="out-", dir=work))
    tree = scan_tree(root, out, scanners)
    return tree, capture(root, tree.findings, carried)


def prepare_baseline(source_root: Path, scanners: list[Scanner] | None = None, run_tests: bool = True) -> Baseline:
    """Scan (and test) an unmodified copy of ``source_root`` once, for one or many trials."""
    with scratch_dir("lab-base-") as work:
        pristine = work / "code"
        copy_trusted_tree(source_root, pristine, EXCLUDED_DIRS)
        tree, symbols = _scan_copy(pristine, work, scanners)
        tests = run_fixture_tests(pristine, behaviour_tests_for(source_root), work) if run_tests else None
    return Baseline(view_from_tree(tree, symbols), tests)


def _not_run(why: str) -> tuple[GateResult, ...]:
    return tuple(GateResult(gate, title, GateStatus.NOT_RUN, why) for gate, title in _GATES)


def _gate3b(static: list[GateResult], baseline: Baseline, run_tests: bool, patched: Path, source_root: Path,
            work: Path) -> GateResult:
    title = _GATES[3][1]
    if not all(g.status in _PASSING for g in static):
        # Model-written code is executed only once it is scanner-clean and structurally intact.
        return GateResult("3b", title, GateStatus.NOT_RUN, "not executed: an earlier gate did not pass")
    if not run_tests:
        return GateResult("3b", title, GateStatus.UNVERIFIED, "behaviour tests were switched off for this trial")
    if baseline.tests is None or baseline.tests.status != GateStatus.PASS:
        detail = baseline.tests.detail if baseline.tests else "not run"
        return GateResult("3b", title, GateStatus.UNVERIFIED, f"the tests do not pass on the unmodified code ({detail})")
    return run_fixture_tests(patched, behaviour_tests_for(source_root), work)


def run_lab_trial(session: Session, tracked_id: int, source_root: Path, strategy: str, provider: LLMProvider, *,
                  scanners: list[Scanner] | None = None, baseline: Baseline | None = None,
                  run_tests: bool = True) -> Verification:
    started = time.monotonic()
    tracked = session.get(TrackedFinding, tracked_id)
    if tracked is None:
        raise VerificationNotFound(f"no tracked finding #{tracked_id}")
    if not provider.generates:
        raise LabError("lab mode needs a provider that generates text")
    try:
        finding = finding_for_tracked(session, tracked_id)
    except FindingNotFound as exc:
        raise LabError(str(exc)) from exc
    baseline = baseline or prepare_baseline(source_root, scanners, run_tests)
    if finding.fingerprint not in baseline.view.findings:
        raise LabError("scanning --source does not reproduce this finding (different code or scanner versions)")
    suppressed = suppressed_fingerprints(session, tracked.project_id)

    conversation: ConversationResult | None = None
    target: list[str] = []
    with scratch_dir("lab-") as work:
        patched = work / "code"
        copy_trusted_tree(source_root, patched, EXCLUDED_DIRS)
        try:
            ctx = extract_context(finding, patched)
            if ctx.snippet_verified is False:
                raise LabError("--source differs from the scanned code; rescan it first")
            plan = build_prompt(ctx, strategy)
        except (ContextError, PromptRejected) as exc:
            raise LabError(str(exc)) from exc
        conversation = run_conversation(plan, provider)
        if conversation.proposal is None:
            error = conversation.error or "no proposal"
            outcome = (Outcome(Verdict.ERROR, error, _not_run("the model produced no answer"))
                       if error.startswith("provider") else
                       Outcome(Verdict.FIX_REJECTED, f"unusable model reply ({error})", _not_run("no usable proposal")))
        else:
            try:
                apply_proposal(patched, ctx, conversation.proposal)
            except ApplyError as exc:
                outcome = Outcome(Verdict.FIX_REJECTED, f"proposal could not be applied: {exc}",
                                  _not_run("nothing was applied"))
            else:
                carried = [(s.file_path, s.symbol, s.kind) for s in baseline.view.symbols.values()]
                tree, symbols = _scan_copy(patched, work, scanners, carried)
                ev = compare(finding.fingerprint, baseline.view, view_from_tree(tree, symbols), suppressed)
                target = [m.label for m in ev.group]
                static = static_gates(ev)
                outcome = decide([*static, _gate3b(static, baseline, run_tests, patched, source_root, work)])

    proposal = conversation.proposal
    return record(
        session, tracked, VerificationMode.LAB, outcome, target or [finding.rule_id],
        strategy=strategy, provider=provider.name, model=conversation.model, params=dict(conversation.params),
        prompt_tokens=conversation.prompt_tokens, completion_tokens=conversation.completion_tokens,
        calls=conversation.calls, duration_s=round(time.monotonic() - started, 2),
        proposal={"code": redact(proposal.code), "imports": proposal.imports, "summary": redact(proposal.summary)}
        if proposal else None,
    )
