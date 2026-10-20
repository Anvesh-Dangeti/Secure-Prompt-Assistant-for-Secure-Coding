"""Record, at scan time, the symbol facts that a later verification will compare.

A scan snapshots:

* the symbol around every finding it reports, so that "before the fix" exists;
* every symbol the project's previous scan snapshotted ("carried"), so that a
  function whose finding disappeared still has an "after the fix" record --
  the moment a weakness vanishes is exactly when its function must be checked.

The carried set only grows by symbols that once had a finding, so it stays
small. Snapshots are facts (``symbols.SymbolFacts``), never code: the scratch
copy is deleted when the scan ends, as before.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.context import ContextError, read_source
from app.core.paths import PathTraversalError, safe_join
from app.db.models import Scan, SymbolSnapshot
from app.normalization.finding import NormalizedFinding
from app.verification.symbols import UNPARSEABLE, SymbolFacts, facts_for, locate, parse

Carried = tuple[str, str, str]      # (file_path, symbol, kind)


class _Tree:
    """One scanned tree, each file read and parsed at most once."""

    _UNREADABLE = object()

    def __init__(self, root: Path) -> None:
        self.root = root
        self._text: dict[str, object] = {}
        self._ast: dict[str, ast.Module | None] = {}

    def text(self, rel: str) -> object:
        """File text; ``None`` if absent; ``_UNREADABLE`` if it may not be read (symlink, size, escape)."""
        if rel not in self._text:
            try:
                exists = safe_join(self.root, *Path(rel).parts).exists()
                self._text[rel] = read_source(self.root, rel) if exists else None
            except (ContextError, PathTraversalError, OSError):
                self._text[rel] = self._UNREADABLE
        return self._text[rel]

    def tree(self, rel: str) -> ast.Module | None:
        if rel not in self._ast:
            text = self.text(rel)
            self._ast[rel] = parse(text) if isinstance(text, str) and rel.endswith(".py") else None
        return self._ast[rel]

    def facts(self, rel: str, symbol: str, kind: str) -> SymbolFacts:
        text = self.text(rel)
        if text is self._UNREADABLE:
            return SymbolFacts(rel, symbol, kind, UNPARSEABLE)
        return facts_for(rel, symbol, kind, text if isinstance(text, str) else None, self.tree(rel))


def capture(root: Path, findings: Iterable[NormalizedFinding], carried: Iterable[Carried] = ()) -> list[SymbolFacts]:
    """Snapshot every symbol with a finding in ``root``, plus every carried symbol."""
    tree = _Tree(root)
    wanted: dict[tuple[str, str], str] = {}
    for f in findings:
        symbol, kind = locate(tree.tree(f.file_path), f.start_line, f.package)
        wanted.setdefault((f.file_path, symbol), kind)
    for file_path, symbol, kind in carried:
        wanted.setdefault((file_path, symbol), kind)
    return [tree.facts(path, symbol, kind) for (path, symbol), kind in sorted(wanted.items())]


def carried_symbols(session: Session, project_id: int) -> list[Carried]:
    """The symbol set of the project's most recent snapshotted scan."""
    latest = session.scalar(
        select(func.max(SymbolSnapshot.scan_id)).join(Scan, SymbolSnapshot.scan_id == Scan.id)
        .where(Scan.project_id == project_id))
    if latest is None:
        return []
    rows = session.scalars(select(SymbolSnapshot).where(SymbolSnapshot.scan_id == latest))
    return [(r.file_path, r.symbol, r.kind) for r in rows]


def to_row(scan_id: int, f: SymbolFacts) -> SymbolSnapshot:
    return SymbolSnapshot(
        scan_id=scan_id, file_path=f.file_path, symbol=f.symbol[:300], kind=f.kind, state=f.state,
        span_start=f.span_start, span_end=f.span_end, signature=f.signature, decorators=list(f.decorators),
        body_trivial=f.body_trivial, undefined_names=list(f.undefined_names), star_import=f.star_import,
    )


def from_row(r: SymbolSnapshot) -> SymbolFacts:
    return SymbolFacts(
        file_path=r.file_path, symbol=r.symbol, kind=r.kind, state=r.state, span_start=r.span_start,
        span_end=r.span_end, signature=r.signature, decorators=tuple(r.decorators or ()),
        body_trivial=r.body_trivial, undefined_names=tuple(r.undefined_names or ()), star_import=r.star_import,
    )
