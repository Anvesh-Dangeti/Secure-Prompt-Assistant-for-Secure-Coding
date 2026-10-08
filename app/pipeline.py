"""Scan orchestration: one place that runs every scanner over a prepared tree.

Order of operations for a scan:

1. ``neutralise_scanner_config`` -- remove in-repo files that would let the
   code under scan reconfigure or silence its own scanners;
2. run every scanner, independently (one failing never stops the others);
3. classify (inside each scanner) and fingerprint every finding.

Persistence and lifecycle (Phases 3-4) build on ``scan_tree``'s result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger
from app.core.paths import is_within
from app.intelligence.fingerprint import assign_fingerprints
from app.normalization.finding import NormalizedFinding
from app.scanners import Scanner, ScannerResult, all_scanners

log = get_logger(__name__)

# Files through which a scanned repository could configure its own scanners:
# ignore lists that hide files, allowlists that hide secrets, config that
# disables rules. They are deleted from the *scratch copy* only.
SCANNER_CONFIG_FILES = (
    ".semgrepignore",
    ".semgrep.yml",
    ".semgrep.yaml",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".bandit",
)


@dataclass
class TreeScan:
    results: list[ScannerResult]
    neutralised: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[NormalizedFinding]:
        return [f for r in self.results for f in r.findings]

    @property
    def all_ok(self) -> bool:
        return all(r.ok for r in self.results)

    def result_for(self, tool: str) -> ScannerResult | None:
        return next((r for r in self.results if r.tool == tool), None)


def neutralise_scanner_config(root: Path) -> list[str]:
    removed: list[str] = []
    for name in SCANNER_CONFIG_FILES:
        for path in root.rglob(name):
            if path.is_file() and not path.is_symlink() and is_within(path, root):
                path.unlink()
                removed.append(path.relative_to(root).as_posix())
    if removed:
        log.warning("removed in-repo scanner configuration", extra={"files": ",".join(removed)})
    return removed


def scan_tree(root: Path, out_dir: Path, scanners: list[Scanner] | None = None) -> TreeScan:
    """Scan ``root`` (a scratch copy of the code) writing reports to ``out_dir``.

    ``out_dir`` must be outside ``root`` so no scanner ever scans another
    scanner's report.
    """
    if is_within(out_dir, root):
        raise ValueError("report directory must not be inside the scanned tree")
    neutralised = neutralise_scanner_config(root)
    results = [scanner.scan(root, out_dir) for scanner in (scanners or all_scanners())]
    assign_fingerprints([f for r in results for f in r.findings])
    return TreeScan(results=results, neutralised=neutralised)
