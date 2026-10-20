"""Scan-to-scan comparison: the evidence every verification gate reads.

One scan is reduced to a ``ScanView`` -- its findings, which scanners ran, what
they could not examine, and its symbol snapshots. A view is built either from
the database (developer mode: two persisted scans of a project) or from two
in-memory ``TreeScan``s (lab mode: a pristine and a patched scratch copy, which
must never touch the project's lifecycle). ``compare`` then produces the same
``RescanEvidence`` from either, so both modes are judged by identical gates.

Whether a finding's absence counts is decided by ``classify_scan`` -- the
lifecycle's own rule -- so verification can never call RESOLVED what the
lifecycle would call UNVERIFIED.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import BlindSpot, Finding, LifecycleState, ScannerRun, SymbolSnapshot, ToolStatus
from app.intelligence.lifecycle import Transition, classify_scan
from app.normalization.finding import SEVERITIES
from app.pipeline import TreeScan
from app.verification.snapshots import from_row
from app.verification.symbols import DEPENDENCY, SymbolFacts

# A tool that had nothing to scan (no requirements file) cannot be hiding a new finding.
_HARMLESS_STATUSES = {ToolStatus.OK.value, ToolStatus.SKIPPED.value}


def severity_rank(severity: str) -> int:
    """CRITICAL highest; an unknown value ranks lowest."""
    return len(SEVERITIES) - SEVERITIES.index(severity) if severity in SEVERITIES else 0


@dataclass(frozen=True)
class FindingRef:
    fingerprint: str
    tool: str
    rule_id: str
    cwe: str | None
    severity: str
    file_path: str
    line: int | None
    package: str | None = None

    @property
    def scope_key(self) -> str:   # same definition as NormalizedFinding.scope_key
        return f"package:{self.package.lower()}" if self.package else f"file:{self.file_path}"

    @property
    def label(self) -> str:
        return f"{self.tool} {self.rule_id.split('.')[-1]} {self.file_path}:{self.line or '-'}"


@dataclass(frozen=True)
class ScanView:
    findings: Mapping[str, FindingRef]
    tool_status: Mapping[str, str]
    blind_spots: Mapping[str, frozenset[str]] = field(default_factory=dict)
    symbols: Mapping[tuple[str, str], SymbolFacts] = field(default_factory=dict)
    scan_id: int | None = None

    def verifiable(self, ref: FindingRef) -> bool:
        """Could this scan have seen ``ref``? (its scanner ran OK and could examine its file/package)"""
        return (self.tool_status.get(ref.tool) == ToolStatus.OK.value
                and ref.scope_key not in self.blind_spots.get(ref.tool, frozenset()))

    def symbol_for(self, ref: FindingRef) -> SymbolFacts | None:
        """The innermost snapshotted symbol containing ``ref``."""
        if ref.package:
            return self.symbols.get((ref.file_path, ref.package.lower()))
        inside = [s for (path, _), s in self.symbols.items()
                  if path == ref.file_path and s.kind != DEPENDENCY and s.contains(ref.line)]
        return min(inside, key=lambda s: (s.span_end or 0) - (s.span_start or 0)) if inside else None


def view_from_tree(tree: TreeScan, symbols: Iterable[SymbolFacts]) -> ScanView:
    findings = {f.fingerprint: FindingRef(f.fingerprint, f.tool, f.rule_id, f.cwe, f.severity, f.file_path,
                                          f.start_line, f.package) for f in tree.findings}
    return ScanView(
        findings=findings,
        tool_status={r.tool: r.status.value for r in tree.results},
        blind_spots={r.tool: frozenset(r.unverified_scopes) for r in tree.results},
        symbols={s.key: s for s in symbols},
    )


def view_from_scan(session: Session, scan_id: int) -> ScanView:
    findings = {r.fingerprint: FindingRef(r.fingerprint, r.tool, r.rule_id, r.cwe, r.severity, r.file_path,
                                          r.start_line, r.package)
                for r in session.scalars(select(Finding).where(Finding.scan_id == scan_id))}
    blind: dict[str, set[str]] = {}
    for b in session.scalars(select(BlindSpot).where(BlindSpot.scan_id == scan_id)):
        blind.setdefault(b.tool, set()).add(b.scope_key)
    return ScanView(
        findings=findings,
        tool_status={r.tool: r.status.value for r in session.scalars(
            select(ScannerRun).where(ScannerRun.scan_id == scan_id))},
        blind_spots={tool: frozenset(scopes) for tool, scopes in blind.items()},
        symbols={(r.file_path, r.symbol): from_row(r) for r in session.scalars(
            select(SymbolSnapshot).where(SymbolSnapshot.scan_id == scan_id))},
        scan_id=scan_id,
    )


@dataclass(frozen=True)
class RescanEvidence:
    target: FindingRef
    group: tuple[FindingRef, ...]            # every before-finding of the same weakness
    severity: str                            # the weakness's severity: highest in the group
    symbol_before: SymbolFacts | None
    symbol_after: SymbolFacts | None
    transitions: Mapping[str, Transition]    # before-finding fingerprint -> what the rescan did to it
    introduced: tuple[FindingRef, ...]       # present after, absent before, not suppressed
    failed_tools: tuple[str, ...]            # scanners that did not run successfully after the change
    target_blind: bool                       # the after-scan could not examine the target's file/package


def compare(target_fp: str, before: ScanView, after: ScanView,
            suppressed: frozenset[str] = frozenset()) -> RescanEvidence:
    """Everything the gates need to judge whether ``target_fp`` was fixed between two scans."""
    target = before.findings[target_fp]
    symbol = before.symbol_for(target)

    def same_weakness(f: FindingRef) -> bool:
        # The target is the weakness, not one scanner's view of it: Bandit and
        # Semgrep reporting the same SQL injection are both in the group.
        if f.fingerprint == target_fp:
            return True
        if f.fingerprint in suppressed or not target.cwe or f.cwe != target.cwe or f.file_path != target.file_path:
            return False
        return symbol is not None and before.symbol_for(f) == symbol

    group = tuple(sorted((f for f in before.findings.values() if same_weakness(f)), key=lambda f: f.label))
    transitions = {t.fingerprint: t for t in classify_scan(
        {fp: LifecycleState.STILL_OPEN for fp in before.findings},
        set(after.findings),
        {fp: after.verifiable(ref) for fp, ref in before.findings.items()},
    )}
    introduced = tuple(sorted((f for fp, f in after.findings.items()
                               if fp not in before.findings and fp not in suppressed), key=lambda f: f.label))
    tools = sorted(set(before.tool_status) | set(after.tool_status))
    return RescanEvidence(
        target=target,
        group=group,
        severity=max((f.severity for f in group), key=severity_rank),
        symbol_before=symbol,
        symbol_after=after.symbols.get(symbol.key) if symbol else None,
        transitions=transitions,
        introduced=introduced,
        failed_tools=tuple(t for t in tools if after.tool_status.get(t) not in _HARMLESS_STATUSES),
        target_blind=any(target.scope_key in scopes for scopes in after.blind_spots.values()),
    )
