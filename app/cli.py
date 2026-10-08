"""Command-line interface -- the reliable demo surface.

    python -m app.cli scanners                      # which scanners are usable
    python -m app.cli scan-dir fixtures/flask_vuln_app [--ground-truth]

``scan-dir`` is a developer command for *trusted local* directories such as the
fixtures: the tree is copied into scratch (symlinks skipped) and scanned there.
Untrusted input arrives only through the ZIP and git paths (Phase 3).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.scratch import scratch_dir
from app.normalization.finding import NormalizedFinding
from app.pipeline import TreeScan, scan_tree
from app.scanners import all_scanners
from app.scanners.base import EXCLUDED_DIRS


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
             "  ".join("-" * w for w in widths)]
    lines += ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows]
    return "\n".join(lines)


def _short(text: str, n: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _cwe_label(f: NormalizedFinding) -> str:
    if f.cwe and f.cwe_reported and f.cwe != f.cwe_reported:
        return f"{f.cwe}<-{f.cwe_reported.replace('CWE-', '')}"
    return f.cwe or "-"


def print_findings(findings: list[NormalizedFinding]) -> None:
    rows = [
        [f.tool, _cwe_label(f), f.owasp or "-", f.severity, f"{f.file_path}:{f.start_line or '-'}",
         f.fingerprint[:12], _short(f.rule_id.split(".")[-1], 34)]
        for f in sorted(findings, key=lambda x: (x.file_path, x.start_line or 0, x.tool))
    ]
    print(_table(rows, ["TOOL", "CWE", "OWASP", "SEV", "LOCATION", "FINGERPRINT", "RULE"]))


def print_scanner_status(tree: TreeScan) -> None:
    rows = [[r.tool, r.status.value, r.version or "-", str(len(r.findings)), f"{r.duration_s:.1f}s",
             _short(r.error or "; ".join(r.notes) or "", 60)] for r in tree.results]
    print(_table(rows, ["SCANNER", "STATUS", "VERSION", "FINDINGS", "TIME", "NOTES"]))


def print_ground_truth(fixture: Path, tree: TreeScan) -> None:
    from evaluation.ground_truth import load_ground_truth, score

    tools_run = {r.tool for r in tree.results if r.ok}
    report = score(load_ground_truth(fixture), tree.findings, tools_run)
    rows = [[s.seeded.id, s.seeded.cwe, s.seeded.name[:34], s.status,
             ",".join(sorted(s.detected_by)) or "-", ",".join(sorted(s.seeded.expected_detectors))]
            for s in report.seeds]
    print(_table(rows, ["ID", "CWE", "WEAKNESS", "STATUS", "DETECTED BY", "EXPECTED"]))
    print()
    if report.recall is not None:
        detected = sum(s.status == "DETECTED" for s in report.scoreable)
        print(f"  recall (any tool)      : {detected}/{len(report.scoreable)} = {report.recall:.0%}")
    if report.precision is not None:
        print(f"  precision (in-scope)   : {report.true_positive_findings}/{report.in_scope_findings} "
              f"= {report.precision:.0%}  (unmatched in-scope findings count as false positives)")
    for tool in ("semgrep", "bandit", "gitleaks", "pip-audit"):
        hit, expected = report.tool_recall(tool)
        if expected:
            print(f"  recall {tool:<16}: {hit}/{expected}")
    both, total = report.corroboration("semgrep", "bandit")
    if total:
        print(f"  semgrep+bandit agree   : {both}/{total} weaknesses both are expected to find")


def _copy_trusted_tree(source: Path, dest: Path) -> None:
    ignore = shutil.ignore_patterns(*EXCLUDED_DIRS)
    shutil.copytree(source, dest, symlinks=True, ignore=ignore)
    for path in list(dest.rglob("*")):
        if path.is_symlink():
            path.unlink()  # never follow links out of the tree


def cmd_scanners(_args: argparse.Namespace) -> int:
    rows = [[s.name, "yes" if s.is_available() else "NO", s.version() or "-", str(s.locate() or "-")]
            for s in all_scanners()]
    print(_table(rows, ["SCANNER", "AVAILABLE", "VERSION", "PATH"]))
    return 0


def cmd_scan_dir(args: argparse.Namespace) -> int:
    source = Path(args.path).resolve()
    if not source.is_dir():
        print(f"error: {source} is not a directory", file=sys.stderr)
        return 2
    with scratch_dir("scan-") as work:
        root, out = work / "src", work / "out"
        out.mkdir()
        _copy_trusted_tree(source, root)
        tree = scan_tree(root, out)
    if args.json:
        print(json.dumps([asdict(f) for f in tree.findings], indent=2))
        return 0 if tree.all_ok else 1
    print()
    print_scanner_status(tree)
    print()
    print_findings(tree.findings)
    if args.ground_truth and (source / "ground_truth.yaml").is_file():
        print()
        print_ground_truth(source, tree)
    print()
    return 0 if tree.all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Secure Prompt Assistant")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scanners", help="show scanner availability").set_defaults(func=cmd_scanners)
    p = sub.add_parser("scan-dir", help="scan a trusted local directory (fixtures)")
    p.add_argument("path")
    p.add_argument("--ground-truth", action="store_true", help="score against ground_truth.yaml")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan_dir)
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging(get_settings().log_level if "--verbose" in (argv or sys.argv) else "WARNING")
    args = build_parser().parse_args([a for a in (argv or sys.argv[1:]) if a != "--verbose"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
