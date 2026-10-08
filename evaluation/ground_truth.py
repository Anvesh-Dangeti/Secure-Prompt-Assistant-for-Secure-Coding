"""Score scanner findings against a fixture's seeded ground truth.

Locations are resolved from *symbols* with ``ast`` at scoring time, so the
ground truth never goes stale when the fixture is edited.

Scoring is **detector-aware**: a seeded weakness whose expected detectors did
not run is NOT-RUN, not MISSED. Otherwise recall would punish a missing tool
rather than a missed detection -- the kind of measurement error that quietly
invalidates an evaluation chapter.

Matching rule: a finding matches a seeded weakness when the canonical CWE and
file agree and the finding's line range overlaps the symbol's line range.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.mapping.mapper import canonical_cwe
from app.normalization.finding import NormalizedFinding


@dataclass
class Seeded:
    id: str
    cwe: str
    name: str
    file: str
    symbol: str
    expected_detectors: set[str]
    lines: tuple[int, int] | None = None


@dataclass
class SeedScore:
    seeded: Seeded
    detected_by: set[str] = field(default_factory=set)
    status: str = "MISSED"   # DETECTED | MISSED | NOT-RUN


@dataclass
class GroundTruthReport:
    seeds: list[SeedScore]
    tools_run: set[str]
    true_positive_findings: int
    in_scope_findings: int

    @property
    def scoreable(self) -> list[SeedScore]:
        return [s for s in self.seeds if s.status != "NOT-RUN"]

    @property
    def recall(self) -> float | None:
        scoreable = self.scoreable
        return sum(s.status == "DETECTED" for s in scoreable) / len(scoreable) if scoreable else None

    @property
    def precision(self) -> float | None:
        return self.true_positive_findings / self.in_scope_findings if self.in_scope_findings else None

    def tool_recall(self, tool: str) -> tuple[int, int]:
        """(detected, expected) over seeds that expect ``tool``, if it ran."""
        expected = [s for s in self.seeds if tool in s.seeded.expected_detectors]
        if tool not in self.tools_run:
            return 0, 0
        return sum(tool in s.detected_by for s in expected), len(expected)

    def corroboration(self, tool_a: str, tool_b: str) -> tuple[int, int]:
        """(detected by both, expected from both) -- the inter-tool agreement metric."""
        both = [s for s in self.seeds if {tool_a, tool_b} <= s.seeded.expected_detectors]
        return sum({tool_a, tool_b} <= s.detected_by for s in both), len(both)


def _symbol_lines(source_path: Path, symbol: str) -> tuple[int, int] | None:
    text = source_path.read_text(encoding="utf-8")
    if source_path.suffix != ".py":
        # requirements.txt etc.: the symbol is a literal line.
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip().lower() == symbol.lower():
                return number, number
        return None
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
            return node.lineno, node.end_lineno or node.lineno
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == symbol for t in node.targets):
            return node.lineno, node.end_lineno or node.lineno
        if (symbol == "__main__" and isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"):
            return node.lineno, node.end_lineno or node.lineno
    return None


def load_ground_truth(fixture_dir: Path) -> list[Seeded]:
    data = yaml.safe_load((fixture_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    seeds = []
    for entry in data.get("seeded", []):
        seed = Seeded(
            id=str(entry["id"]),
            cwe=canonical_cwe(str(entry["cwe"])) or str(entry["cwe"]),
            name=str(entry.get("name", "")),
            file=str(entry["file"]),
            symbol=str(entry["symbol"]),
            expected_detectors={str(d) for d in entry.get("expected_detectors", [])},
        )
        seed.lines = _symbol_lines(fixture_dir / seed.file, seed.symbol)
        if seed.lines is None:
            raise ValueError(f"{seed.id}: symbol {seed.symbol!r} not found in {seed.file}")
        seeds.append(seed)
    return seeds


def _matches(finding: NormalizedFinding, seed: Seeded) -> bool:
    if finding.cwe != seed.cwe or finding.file_path != seed.file or seed.lines is None:
        return False
    start = finding.start_line or 0
    end = finding.end_line or start
    return start <= seed.lines[1] and end >= seed.lines[0]


def score(seeds: list[Seeded], findings: Iterable[NormalizedFinding], tools_run: set[str]) -> GroundTruthReport:
    findings = list(findings)
    scores = [SeedScore(seed) for seed in seeds]
    true_positive_ids: set[int] = set()
    for sc in scores:
        for f in findings:
            if _matches(f, sc.seeded):
                sc.detected_by.add(f.tool)
                true_positive_ids.add(id(f))
        if sc.detected_by & sc.seeded.expected_detectors or sc.detected_by:
            sc.status = "DETECTED"
        elif not (sc.seeded.expected_detectors & tools_run):
            sc.status = "NOT-RUN"
        else:
            sc.status = "MISSED"
    in_scope = [f for f in findings if f.in_scope]
    return GroundTruthReport(
        seeds=scores,
        tools_run=tools_run,
        true_positive_findings=sum(1 for f in in_scope if id(f) in true_positive_ids),
        in_scope_findings=len(in_scope),
    )
