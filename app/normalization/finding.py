"""The tool-agnostic finding shape.

Field names follow SARIF's ``result`` object (ruleId, level, location, region,
fingerprints) so that adding a SARIF-native tool such as CodeQL is a parser
configuration, not a model change. Two kinds of field:

* **Evidence** -- what the scanner said, normalised but not reinterpreted
  (``cwe_reported``, ``owasp_reported``, ``native_fingerprint``).
* **Enrichment** -- filled later by the mapping layer and fingerprinting
  (``cwe``, ``owasp``, ``in_scope``, ``fingerprint``).

Keeping both makes every interpretation auditable: the dashboard can always
show "Semgrep said CWE-704, we classify it as CWE-89, because <reason>".
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class MalformedOutputError(ValueError):
    """Scanner output could not be parsed. Always an error -- never 'no findings'."""


@dataclass
class NormalizedFinding:
    tool: str
    rule_id: str
    message: str
    file_path: str                       # repo-relative POSIX path
    start_line: int | None
    end_line: int | None
    severity: str                        # one of SEVERITIES
    snippet: str = ""                    # ALREADY REDACTED -- raw secrets never stored
    cwe_reported: str | None = None
    owasp_reported: str | None = None    # tool's own OWASP 2021 tag, e.g. "A03"
    native_fingerprint: str | None = None
    # Dependency (SCA) findings only.
    package: str | None = None
    package_version: str | None = None
    vuln_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    fix_versions: list[str] = field(default_factory=list)

    # ---- enrichment ---------------------------------------------------
    cwe: str | None = None
    owasp: str | None = None
    in_scope: bool = False
    mapping_note: str | None = None
    fingerprint: str = ""
    fingerprint_source: str = ""         # "native" | "derived"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def scope_key(self) -> str:
        """What this finding's absence would have to be verified against.

        A dependency finding is about one package; a code finding is about one
        file. If a later scan could not examine that package/file, the finding's
        absence proves nothing and it must not be marked RESOLVED.
        """
        if self.package:
            return f"package:{self.package.lower()}"
        return f"file:{self.file_path}"


def normalise_severity(value: str | None, default: str = "MEDIUM") -> str:
    level = (value or "").strip().upper()
    aliases = {
        "ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "NOTE": "LOW",
        "NONE": "INFO", "INFORMATIONAL": "INFO", "UNDEFINED": default, "": default,
    }
    level = aliases.get(level, level)
    return level if level in SEVERITIES else default
