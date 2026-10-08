"""pip-audit JSON report -> NormalizedFinding (one per package x vulnerability).

This is the only source of CVE identifiers in the project: a CVE names a
vulnerable *component version*, which is exactly what pip-audit reports. SAST
findings carry CWEs, never CVEs.

pip-audit lists the same vulnerability more than once in some reports
(observed with 2.10.1), so entries are de-duplicated by (package, vuln id).
Packages it could not audit come back with a ``skip_reason``; those are
returned separately so the lifecycle treats them as *unverified*, not clean.
"""

from __future__ import annotations

import json

from app.normalization.finding import MalformedOutputError, NormalizedFinding


def parse_pip_audit(
    text: str, requirements_path: str, line_of: dict[str, int]
) -> tuple[list[NormalizedFinding], set[str]]:
    """Return (findings, skipped_package_names).

    ``line_of`` maps a lower-cased package name to its line in the original
    requirements file, so the finding points at the line a developer must edit.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedOutputError(f"pip-audit report is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("dependencies"), list):
        raise MalformedOutputError("pip-audit report has no 'dependencies' array")

    findings: list[NormalizedFinding] = []
    skipped: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for dep in payload["dependencies"]:
        if not isinstance(dep, dict) or not isinstance(dep.get("name"), str):
            raise MalformedOutputError("pip-audit dependency without a name")
        name = dep["name"]
        if dep.get("skip_reason"):
            skipped.add(name.lower())
            continue
        version = str(dep.get("version", ""))
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            raise MalformedOutputError("pip-audit 'vulns' is not an array")
        for vuln in vulns:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                raise MalformedOutputError("pip-audit vulnerability without an id")
            key = (name.lower(), vuln["id"])
            if key in seen:
                continue
            seen.add(key)
            aliases = [a for a in (vuln.get("aliases") or []) if isinstance(a, str)]
            cves = sorted({a for a in [vuln["id"], *aliases] if a.startswith("CVE-")})
            fixes = [str(v) for v in (vuln.get("fix_versions") or [])]
            label = ", ".join(cves) if cves else vuln["id"]
            message = f"{name} {version} has a known vulnerability ({label})"
            if fixes:
                message += f"; fixed in {', '.join(fixes)}"
            line = line_of.get(name.lower())
            findings.append(
                NormalizedFinding(
                    tool="pip-audit",
                    rule_id=vuln["id"],
                    message=message,
                    file_path=requirements_path,
                    start_line=line,
                    end_line=line,
                    # pip-audit reports no CVSS score; a known exploitable CVE in a
                    # pinned dependency is treated as HIGH (documented assumption).
                    severity="HIGH",
                    snippet=f"{name}=={version}",
                    package=name,
                    package_version=version,
                    vuln_id=vuln["id"],
                    cve_ids=cves,
                    fix_versions=fixes,
                )
            )
    return findings, skipped
