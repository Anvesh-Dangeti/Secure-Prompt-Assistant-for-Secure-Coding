"""pip-audit adapter (SCA -> CVEs).

The dangerous default of auditing a requirements file is that pip-audit
*resolves and installs* it into a temporary environment -- which executes the
untrusted repository's build scripts (setup.py) on this machine. So:

* ``--no-deps --disable-pip``: audit exactly the pinned versions listed, install
  nothing, run nothing from the repository;
* every requirements file is first rewritten into a sanitised copy that keeps
  only strict ``name==version`` lines. Option lines (``-r``, ``--index-url``,
  ``-e``, direct URLs) are dropped: an untrusted file must not be able to point
  pip-audit at another file on disk or at an attacker-controlled index;
* unpinned requirements cannot be audited without resolution, so they are
  reported as *unverified* -- never as clean -- and any earlier finding for
  that package cannot be marked RESOLVED by this scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import get_settings
from app.core.paths import repo_relative
from app.core.subprocess_runner import read_capped_file, run_tool
from app.db.models import ToolStatus
from app.normalization.pip_audit_json import parse_pip_audit
from app.scanners.base import EXCLUDED_DIRS, RunOutcome, Scanner, outcome_from_process

_PINNED = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[A-Za-z0-9,._\-\s]+\])?\s*==\s*(?P<version>[A-Za-z0-9.+!_\-]+)\s*(?:;.*)?$"
)
_NAME_ONLY = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)")
MAX_REQUIREMENTS_FILES = 10
MAX_REQUIREMENTS_BYTES = 512 * 1024


@dataclass
class SanitisedRequirements:
    lines: list[str] = field(default_factory=list)
    line_of: dict[str, int] = field(default_factory=dict)
    unpinned: set[str] = field(default_factory=set)
    ignored_directives: int = 0


def sanitise_requirements(text: str) -> SanitisedRequirements:
    out = SanitisedRequirements()
    logical: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append((start, (buffer + line).strip()))
        buffer = ""
    if buffer:
        logical.append((start, buffer.strip()))

    for number, line in logical:
        if not line:
            continue
        # Drop trailing hash options of a pinned line ("pkg==1.0 --hash=sha256:...").
        line = re.split(r"\s--", " " + line, maxsplit=1)[0].strip() if " --" in line else line
        if line.startswith("-") or "://" in line or " @ " in line or line.startswith("."):
            out.ignored_directives += 1
            continue
        match = _PINNED.match(line)
        if match:
            name = match.group("name").lower()
            out.lines.append(f"{match.group('name')}=={match.group('version')}")
            out.line_of[name] = number
            continue
        name_match = _NAME_ONLY.match(line)
        if name_match:
            out.unpinned.add(name_match.group("name").lower())
            out.line_of.setdefault(name_match.group("name").lower(), number)
    return out


def find_requirements_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("requirements*.txt")):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts) or len(rel.parts) > 4:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        found.append(path)
        if len(found) >= MAX_REQUIREMENTS_FILES:
            break
    return found


class PipAuditScanner(Scanner):
    name = "pip-audit"
    binary = "pip-audit"
    tool_dir = "pip-audit"

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        settings = get_settings()
        files = find_requirements_files(root)
        if not files:
            return RunOutcome([], notes=["no requirements*.txt files found"])

        outcome = RunOutcome([])
        for index, path in enumerate(files):
            rel = repo_relative(path, root) or path.name
            if path.stat().st_size > MAX_REQUIREMENTS_BYTES:
                outcome.notes.append(f"{rel}: larger than {MAX_REQUIREMENTS_BYTES} bytes, not audited")
                outcome.unverified_scopes.add(f"file:{rel}")
                continue
            reqs = sanitise_requirements(path.read_text(encoding="utf-8", errors="replace"))
            outcome.unverified_scopes |= {f"package:{name}" for name in reqs.unpinned}
            if reqs.unpinned:
                outcome.notes.append(f"{rel}: {len(reqs.unpinned)} unpinned requirement(s) not audited: "
                                     + ", ".join(sorted(reqs.unpinned)))
            if reqs.ignored_directives:
                outcome.notes.append(f"{rel}: {reqs.ignored_directives} option/URL line(s) ignored")
            if not reqs.lines:
                continue

            sanitised = out_dir / f"requirements-{index}.txt"
            sanitised.write_text("\n".join(reqs.lines) + "\n", encoding="utf-8")
            report = out_dir / f"pip-audit-{index}.json"
            args = [str(exe), "-r", str(sanitised), "--no-deps", "--disable-pip",
                    "-f", "json", "-o", str(report), "--progress-spinner", "off"]
            proc = run_tool(args, cwd=out_dir, timeout=settings.scanner_timeout_seconds)
            failure = outcome_from_process(proc.timed_out, proc.returncode, {0, 1}, proc.stderr, self.name)
            if failure or not report.is_file():
                # Fail safe: one unreadable file makes the whole tool run non-OK.
                outcome.status = failure.status if failure else ToolStatus.ERROR
                outcome.error = (failure.error if failure else "pip-audit produced no report") + f" ({rel})"
                continue
            findings, skipped = parse_pip_audit(read_capped_file(report), rel, reqs.line_of)
            outcome.findings.extend(findings)
            if skipped:
                outcome.unverified_scopes |= {f"package:{name}" for name in skipped}
                outcome.notes.append(f"{rel}: could not audit " + ", ".join(sorted(skipped)))
        return outcome
