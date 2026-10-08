"""Scanner interface.

Every scanner is an external program run through ``run_tool`` and parsed into
``NormalizedFinding`` objects. ``Scanner.scan`` is a template method that owns
the failure semantics, so no adapter can get them wrong:

* not installed / timed out / crashed / unreadable output  ->  a non-OK status,
  never an empty "clean" result;
* partial coverage (a file the tool could not parse, a dependency it could not
  audit) is reported as ``unverified_scopes``. The lifecycle engine will not
  mark a finding RESOLVED if its file or package is in that set.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.core.config import PROJECT_ROOT, get_settings
from app.core.logging import get_logger
from app.core.redaction import redact
from app.core.subprocess_runner import ToolNotFoundError, UnsafeInvocationError, resolve_executable, run_tool
from app.db.models import ToolStatus
from app.mapping.mapper import classify
from app.normalization.finding import MalformedOutputError, NormalizedFinding

log = get_logger(__name__)

# Third-party code vendored into a repository is not the repository's code.
EXCLUDED_DIRS = (".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox")

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")


@dataclass
class RunOutcome:
    """What an adapter's ``_run`` returns. ``status`` defaults to OK."""

    findings: list[NormalizedFinding]
    status: ToolStatus = ToolStatus.OK
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    ruleset_hash: str | None = None
    unverified_scopes: set[str] = field(default_factory=set)


@dataclass
class ScannerResult:
    tool: str
    status: ToolStatus
    findings: list[NormalizedFinding] = field(default_factory=list)
    version: str | None = None
    ruleset_hash: str | None = None
    duration_s: float = 0.0
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    unverified_scopes: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.OK


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=16)
def _cached_version(exe: str, args: tuple[str, ...]) -> str | None:
    from app.core.scratch import scratch_dir  # local import avoids a cycle at import time

    with scratch_dir("ver-") as cwd:
        try:
            result = run_tool([exe, *args], cwd=cwd, timeout=60)
        except (ToolNotFoundError, UnsafeInvocationError, OSError):
            return None
    match = _VERSION_RE.search(result.stdout + " " + result.stderr)
    return match.group(1) if match else None


class Scanner(ABC):
    name: str            # e.g. "semgrep"; also the settings attribute prefix
    binary: str          # executable name
    tool_dir: str        # .tools/<tool_dir> isolated install
    version_args: tuple[str, ...] = ("--version",)

    def locate(self) -> Path | None:
        """Configured path -> isolated .tools install -> PATH."""
        settings = get_settings()
        configured = getattr(settings, f"{self.name.replace('-', '_')}_bin", None)
        sub = "Scripts" if os.name == "nt" else "bin"
        exe = self.binary + (".exe" if os.name == "nt" else "")
        candidates = [Path(configured)] if configured else []
        candidates.append(PROJECT_ROOT / ".tools" / self.tool_dir / sub / exe)
        for candidate in candidates:
            if candidate.is_file():
                try:
                    return resolve_executable(candidate)
                except (ToolNotFoundError, UnsafeInvocationError):
                    continue
        try:
            return resolve_executable(self.binary)
        except (ToolNotFoundError, UnsafeInvocationError):
            return None

    def is_available(self) -> bool:
        return self.locate() is not None

    def version(self) -> str | None:
        exe = self.locate()
        return _cached_version(str(exe), self.version_args) if exe else None

    def scan(self, root: Path, out_dir: Path) -> ScannerResult:
        started = time.monotonic()
        exe = self.locate()
        if exe is None:
            return ScannerResult(self.name, ToolStatus.NOT_INSTALLED, error=f"{self.name} is not installed")
        try:
            outcome = self._run(exe, root, out_dir)
        except MalformedOutputError as exc:
            outcome = RunOutcome([], ToolStatus.ERROR, error=f"unreadable output: {exc}")
        except (ToolNotFoundError, FileNotFoundError) as exc:
            outcome = RunOutcome([], ToolStatus.NOT_INSTALLED, error=str(exc))
        except (UnsafeInvocationError, OSError, ValueError) as exc:
            outcome = RunOutcome([], ToolStatus.ERROR, error=f"{type(exc).__name__}: {exc}")

        for finding in outcome.findings:
            classify(finding)
        result = ScannerResult(
            tool=self.name,
            status=outcome.status,
            findings=outcome.findings,
            version=self.version(),
            ruleset_hash=outcome.ruleset_hash,
            duration_s=round(time.monotonic() - started, 3),
            error=redact(outcome.error) if outcome.error else None,
            notes=[redact(n) for n in outcome.notes],
            unverified_scopes=outcome.unverified_scopes,
        )
        log.info("scanner finished", extra={"tool": self.name, "status": result.status.value,
                                            "findings": len(result.findings), "duration_s": result.duration_s})
        return result

    @abstractmethod
    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        """Run the tool on ``root`` writing reports into ``out_dir``."""


def outcome_from_process(timed_out: bool, returncode: int | None, ok_codes: set[int], stderr: str,
                         tool: str) -> RunOutcome | None:
    """Shared exit-code handling. Returns a failure outcome, or None if the run is usable."""
    if timed_out:
        return RunOutcome([], ToolStatus.TIMEOUT, error=f"{tool} exceeded its time limit")
    if returncode not in ok_codes:
        tail = stderr.strip().splitlines()[-3:] if stderr.strip() else []
        return RunOutcome([], ToolStatus.ERROR, error=f"{tool} exited with {returncode}: {' | '.join(tail)[:500]}")
    return None
