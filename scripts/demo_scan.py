#!/usr/bin/env python3
"""
Review 2 demo — scan a directory, normalise the findings, map them to CWE/OWASP.

This is a deliberately small standalone preview of what Phase 2 builds properly
inside `app/scanners/` and `app/normalization/`. It exists to show a working
mechanism at Review 2, not to be the final implementation.

What it demonstrates:
  1. Two independent SAST engines (Bandit + Semgrep) behind one interface.
  2. Tool-specific output normalised into a single tool-agnostic Finding shape.
  3. CWE -> OWASP Top 10 (2021) mapping.
  4. Stable fingerprints that survive line-number shifts.
  5. Inter-tool agreement -- which findings both engines corroborate.
  6. Scoring against ground truth (precision / recall) when available.

Usage:
    python scripts/demo_scan.py fixtures/vuln_demo
    python scripts/demo_scan.py fixtures/vuln_demo --json

Security note: every subprocess call below uses list-form arguments and an
explicit timeout, and never `shell=True`. That pattern is established here
deliberately -- it is the rule for every external call in this project.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# --------------------------------------------------------------------------
# CWE -> OWASP Top 10 (2021) mapping.
#
# Deliberately small and explicit. Section 11 of the brief says: build a
# maintainable mapping mechanism, do not hard-code thousands of entries. This
# covers our 10 scoped CWEs and is structured so Phase 4 can load it from a
# data file instead.
# --------------------------------------------------------------------------
CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-89": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-94": "A05:2021 Security Misconfiguration",
    "CWE-215": "A05:2021 Security Misconfiguration",
    "CWE-605": "A05:2021 Security Misconfiguration",
    "CWE-1395": "A06:2021 Vulnerable and Outdated Components",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-259": "A07:2021 Identification and Authentication Failures",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
}

# CWE hierarchy aliases: child -> canonical parent used by this project.
#
# This exists because scanners disagree on granularity. Bandit reports a
# hard-coded password as CWE-259, which is the *child* of CWE-798 (Use of
# Hard-coded Credentials). Paper 3 makes exactly this point in section 7.2.
# Without this normalisation, two tools reporting the same weakness look like
# two different weaknesses -- which would corrupt both the inter-tool agreement
# metric and the fingerprint-based lifecycle.
CWE_ALIASES: dict[str, str] = {
    "CWE-259": "CWE-798",   # hard-coded password -> hard-coded credentials
    "CWE-328": "CWE-327",   # reversible one-way hash -> broken crypto algorithm
}


def canonical_cwe(cwe: str | None) -> str | None:
    """Resolve a scanner-reported CWE to this project's canonical identifier."""
    if not cwe:
        return None
    return CWE_ALIASES.get(cwe, cwe)


# The 10 CWEs this project has scoped, in canonical form.
# See docs/scope_decisions.md.
SCOPED_CWES = {
    "CWE-89", "CWE-78", "CWE-79", "CWE-798", "CWE-22",
    "CWE-327", "CWE-330", "CWE-502", "CWE-1395", "CWE-94", "CWE-215",
}

SUBPROCESS_TIMEOUT_SECONDS = 120


@dataclass
class Finding:
    """Tool-agnostic normalised finding.

    Phase 2 replaces this with the SARIF-backed model in app/normalization/.
    The field set is kept identical so that migration is mechanical.
    """

    tool: str
    rule_id: str
    message: str
    file: str
    line: int
    severity: str
    cwe: str | None = None
    owasp: str | None = None
    snippet: str = ""
    cwe_reported: str | None = field(default=None, init=False)
    fingerprint: str = field(default="", init=False)
    in_scope: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        # Keep what the tool actually said, but reason about the canonical form.
        self.cwe_reported = self.cwe
        self.cwe = canonical_cwe(self.cwe)
        self.owasp = CWE_TO_OWASP.get(self.cwe or "", "unmapped")
        self.in_scope = (self.cwe or "") in SCOPED_CWES
        self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        """Identity that survives line shifts and reformatting.

        Material is `rule_id | normalised_path | whitespace-stripped snippet`.

        Two deliberate exclusions:

        * **Line number.** Code moves as it is edited. A fingerprint keyed on
          line number reports every insertion above a finding as a RESOLVED plus
          a NEW, on a commit that never touched the weakness.
        * **All whitespace.** Reformatting is not a fix. Collapsing runs of
          whitespace to a single space is not enough, because `f( x )` and
          `f(x)` still differ; stripping whitespace entirely makes identity
          robust to any reformatting, including a `black` run.

        Trade-off, stated honestly: stripping all whitespace means two snippets
        differing *only* by a token boundary (`not x` vs a hypothetical `notx`)
        would collide. `rule_id` and path are part of the material, so the
        residual collision risk is negligible in practice.

        Phase 4 prefers the scanner's own native fingerprint (Semgrep emits one)
        whenever it is present, and falls back to this derivation otherwise.
        """
        normalised_path = Path(self.file).as_posix().lstrip("./")
        normalised_snippet = re.sub(r"\s+", "", self.snippet)
        material = f"{self.rule_id}|{normalised_path}|{normalised_snippet}"
        return hashlib.sha256(material.encode()).hexdigest()[:16]


def _read_snippet(root: Path, rel_file: str, line: int, context: int = 0) -> str:
    """Read the finding's line, for fingerprinting.

    Phase 5 widens this to +/-10 lines for LLM context, with secret redaction
    applied before anything leaves the process. Here we only need enough to
    make the fingerprint stable.
    """
    try:
        target = (root / rel_file) if not Path(rel_file).is_absolute() else Path(rel_file)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        return "\n".join(lines[start:end])
    except (OSError, IndexError):
        return ""


# --------------------------------------------------------------------------
# Scanner adapters. Each returns list[Finding]; the caller does not care which
# tool produced them. This is the interface Phase 2 formalises as ScannerBase.
# --------------------------------------------------------------------------

def run_bandit(target: Path) -> tuple[list[Finding], str | None]:
    """Run Bandit and normalise its JSON output.

    Bandit is Python-only, which is one of the reasons the project scope is
    Python-only. Paper 3 used it as its primary detector, validated against
    manual review at Cohen's kappa = 0.87.
    """
    if shutil.which("bandit") is None:
        return [], "bandit not installed  (pip install bandit)"

    try:
        # List-form args, explicit timeout, never shell=True.
        proc = subprocess.run(
            ["bandit", "-r", str(target), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], f"bandit timed out after {SUBPROCESS_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return [], f"bandit failed to start: {exc}"

    # Bandit exits 1 when it finds issues -- that is success, not failure.
    if not proc.stdout.strip():
        return [], f"bandit produced no output (exit {proc.returncode})"

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        # Fail safe: a malformed scanner result is an error, never "no findings".
        return [], f"bandit output was not valid JSON: {exc}"

    findings: list[Finding] = []
    for result in payload.get("results", []):
        cwe_field = result.get("issue_cwe") or {}
        cwe_id = cwe_field.get("id")
        findings.append(
            Finding(
                tool="bandit",
                rule_id=result.get("test_id", "unknown"),
                message=result.get("issue_text", "").strip(),
                file=str(Path(result.get("filename", "")).name),
                line=int(result.get("line_number", 0)),
                severity=str(result.get("issue_severity", "UNKNOWN")).upper(),
                cwe=f"CWE-{cwe_id}" if cwe_id else None,
                snippet=_strip_bandit_line_numbers(result.get("code", "") or ""),
            )
        )
    return findings, None


def _strip_bandit_line_numbers(code: str) -> str:
    """Remove the line-number prefix Bandit embeds in its `code` field.

    Bandit returns snippets like "22 import os\\n23 import pickle\\n". Those
    numbers are part of the *presentation*, not the code -- but if they reach
    the fingerprint, then inserting an unrelated line anywhere above the finding
    changes its identity. The lifecycle engine would then report the weakness as
    RESOLVED and immediately re-report it as NEW, on a commit that never touched
    it.

    This was caught by the fingerprint-stability check in
    tests/unit/test_fingerprint_stability.py, which is why that test exists.
    """
    return "\n".join(
        re.sub(r"^\s*\d+\s", "", line) for line in code.splitlines()
    )


def run_semgrep(target: Path) -> tuple[list[Finding], str | None]:
    """Run Semgrep and normalise its JSON output.

    Semgrep emits a native per-finding fingerprint, which Phase 4 will prefer
    over our derived hash whenever it is present.
    """
    if shutil.which("semgrep") is None:
        return [], "semgrep not installed  (pip install semgrep -- needs WSL/Linux on Windows)"

    try:
        proc = subprocess.run(
            ["semgrep", "--config", "p/python", "--json", "--quiet", str(target)],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], f"semgrep timed out after {SUBPROCESS_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return [], f"semgrep failed to start: {exc}"

    if not proc.stdout.strip():
        return [], f"semgrep produced no output (exit {proc.returncode})"

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return [], f"semgrep output was not valid JSON: {exc}"

    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Semgrep reports CWE as a string or list, e.g.
        # "CWE-89: Improper Neutralization of Special Elements..."
        raw_cwe = metadata.get("cwe")
        if isinstance(raw_cwe, list):
            raw_cwe = raw_cwe[0] if raw_cwe else None
        cwe_id = None
        if isinstance(raw_cwe, str):
            match = re.search(r"CWE-\d+", raw_cwe)
            cwe_id = match.group(0) if match else None

        findings.append(
            Finding(
                tool="semgrep",
                rule_id=result.get("check_id", "unknown"),
                message=extra.get("message", "").strip(),
                file=str(Path(result.get("path", "")).name),
                line=int(result.get("start", {}).get("line", 0)),
                severity=str(extra.get("severity", "UNKNOWN")).upper(),
                cwe=cwe_id,
                snippet=extra.get("lines", "") or "",
            )
        )
    return findings, None


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "  ".join("-" * w for w in widths)
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), sep]
    out.extend("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)) for row in rows)
    return "\n".join(out)


def report(
    findings: list[Finding], errors: list[str], target: Path, tools_run: set[str]
) -> None:
    print()
    print("=" * 100)
    print("  SECURE PROMPT ASSISTANT  --  scan + normalisation demo")
    print(f"  target: {target}")
    print("=" * 100)

    for err in errors:
        print(f"  [!] {err}")
    if errors:
        print()

    if not findings:
        print("  No findings. (If both scanners are missing, install at least Bandit.)")
        return

    rows = [
        [
            f.tool,
            # Show the alias resolution where one happened, e.g. "CWE-798<-259",
            # so the CWE-hierarchy normalisation is visible rather than silent.
            (f.cwe or "-") if f.cwe == f.cwe_reported
            else f"{f.cwe}<-{(f.cwe_reported or '').replace('CWE-', '')}",
            (f.owasp or "unmapped").split(" ")[0],
            f.severity,
            f"{f.file}:{f.line}",
            f.fingerprint,
            (f.message[:44] + "...") if len(f.message) > 47 else f.message,
        ]
        for f in sorted(findings, key=lambda x: (x.tool, x.line))
    ]
    print(_table(rows, ["TOOL", "CWE", "OWASP", "SEVERITY", "LOCATION", "FINGERPRINT", "MESSAGE"]))

    # -- summaries -------------------------------------------------------
    print()
    print("-" * 100)

    by_tool: dict[str, int] = {}
    for f in findings:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
    print("  findings per tool      : " + ", ".join(f"{k}={v}" for k, v in sorted(by_tool.items())))

    in_scope = [f for f in findings if f.in_scope]
    print(f"  total findings         : {len(findings)}")
    print(f"  within scoped 10 CWEs  : {len(in_scope)}")
    print(f"  unmapped to OWASP      : {sum(1 for f in findings if f.owasp == 'unmapped')}")

    owasp_seen = sorted({f.owasp for f in findings if f.owasp and f.owasp != "unmapped"})
    print(f"  OWASP categories hit   : {len(owasp_seen)}")
    for category in owasp_seen:
        print(f"      - {category}")

    # -- inter-tool agreement -------------------------------------------
    # This is the metric the dual-SAST decision unlocks. With only one scanner
    # installed it correctly reports that agreement cannot be computed.
    tools_present = set(by_tool)
    print()
    if len(tools_present) < 2:
        print("  inter-tool agreement   : n/a (needs both Bandit and Semgrep)")
    else:
        by_cwe_tool: dict[str, set[str]] = {}
        for f in findings:
            if f.cwe:
                by_cwe_tool.setdefault(f"{f.cwe}@{f.file}:{f.line}", set()).add(f.tool)
        corroborated = [k for k, v in by_cwe_tool.items() if len(v) > 1]
        print(f"  corroborated by both   : {len(corroborated)} / {len(by_cwe_tool)} located weaknesses")
        for key in sorted(corroborated):
            print(f"      - {key}")

    # -- ground truth ----------------------------------------------------
    _score_against_ground_truth(findings, target, tools_run)

    print()
    print("  NOTE: this is the Phase 2 mechanism previewed. The full pipeline adds")
    print("        Gitleaks + pip-audit, SARIF normalisation, the AI layer, and")
    print("        triple-gate verification. See docs/revised_direction.md.")
    print()


def _score_against_ground_truth(
    findings: list[Finding], target: Path, tools_run: set[str]
) -> None:
    """Report detection coverage against the seeded ground truth, if present.

    Scoring is *detector-aware*. A weakness whose only expected detector was not
    installed is reported as NOT-RUN rather than MISSED -- otherwise recall would
    silently punish us for a missing tool rather than for a missing detection,
    which is the sort of measurement error that quietly invalidates an
    evaluation chapter.

    Parsed with a tiny regex reader so the demo has no third-party dependency.
    Phase 3 replaces this with a proper PyYAML loader.
    """
    gt_path = target / "ground_truth.yaml"
    if not gt_path.exists():
        return

    try:
        text = gt_path.read_text(encoding="utf-8")
    except OSError:
        return

    # (id, canonical_cwe, expected_detectors)
    seeded: list[tuple[str, str, set[str]]] = []
    current_id: str | None = None
    current_cwe: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- id:"):
            current_id = line.split(":", 1)[1].strip()
            current_cwe = None
        elif line.startswith("cwe:") and current_id:
            current_cwe = canonical_cwe(line.split(":", 1)[1].strip())
        elif line.startswith("expected_detectors:") and current_id and current_cwe:
            raw_list = line.split(":", 1)[1].strip().strip("[]")
            detectors = {d.strip() for d in raw_list.split(",") if d.strip()}
            seeded.append((current_id, current_cwe, detectors))
            current_id = current_cwe = None

    if not seeded:
        return

    found_cwes = {f.cwe for f in findings if f.cwe}

    detected, missed, not_run = [], [], []
    for gid, cwe, detectors in seeded:
        if cwe in found_cwes:
            detected.append((gid, cwe))
        elif not (detectors & tools_run):
            # None of the tools expected to find this actually ran.
            not_run.append((gid, cwe, detectors))
        else:
            missed.append((gid, cwe, detectors))

    scoreable = len(detected) + len(missed)
    print()
    if scoreable:
        pct = 100 * len(detected) // scoreable
        print(f"  ground truth (recall)  : {len(detected)}/{scoreable} detected  ({pct}%)  "
              f"-- scored over weaknesses whose detector actually ran")
    for gid, cwe, detectors in missed:
        print(f"      MISSED   {gid}  {cwe}  (expected from: {', '.join(sorted(detectors))})")
    for gid, cwe, detectors in not_run:
        print(f"      NOT-RUN  {gid}  {cwe}  (needs: {', '.join(sorted(detectors))})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("target", type=Path, help="directory to scan")
    parser.add_argument("--json", action="store_true", help="emit normalised findings as JSON")
    args = parser.parse_args()

    target = args.target.resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    errors: list[str] = []
    tools_run: set[str] = set()

    for name, scanner in (("bandit", run_bandit), ("semgrep", run_semgrep)):
        results, error = scanner(target)
        findings.extend(results)
        if error:
            errors.append(error)
        else:
            # The tool ran successfully -- zero findings is a valid result.
            tools_run.add(name)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        report(findings, errors, target, tools_run)

    # Exit 0 even when findings exist -- findings are the expected outcome here.
    # A real failure is a scanner that could not run at all.
    return 1 if (errors and not findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
