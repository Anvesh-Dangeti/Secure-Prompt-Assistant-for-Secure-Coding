"""Generic SARIF 2.1.0 reader (used for Semgrep and Bandit; CodeQL later).

Scanner output is treated as *semi-trusted* input: it is produced by our own
pinned tools, but it describes attacker-controlled code. So every structural
assumption is checked, every reported path is re-validated against the scan
root, and anything malformed raises ``MalformedOutputError`` -- a scanner whose
output we cannot read must never be recorded as "found nothing".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.paths import repo_relative
from app.normalization.finding import MalformedOutputError

_CWE_RE = re.compile(r"(?i)\bcwe[-/](\d{1,5})\b")
_OWASP_2021_RE = re.compile(r"\bA(\d{2}):2021\b")


@dataclass
class SarifResult:
    rule_id: str
    message: str
    level: str | None
    file_path: str
    start_line: int | None
    end_line: int | None
    snippet: str
    rule_tags: list[str] = field(default_factory=list)
    rule_default_level: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)


@dataclass
class SarifRun:
    tool_name: str
    tool_version: str | None
    execution_successful: bool
    results: list[SarifResult]
    # Files the tool reported problems with (parse errors, timeouts per file).
    error_files: set[str] = field(default_factory=set)
    notifications: list[str] = field(default_factory=list)
    dropped_out_of_root: int = 0


def cwe_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        match = _CWE_RE.search(str(tag))
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def owasp_from_tags(tags: list[str]) -> str | None:
    for tag in tags:
        match = _OWASP_2021_RE.search(str(tag))
        if match:
            return f"A{match.group(1)}"
    return None


def _as_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedOutputError(f"SARIF {what} is not an object")
    return value


def _as_list(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MalformedOutputError(f"SARIF {what} is not an array")
    return value


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def parse_sarif(text: str, root: Path) -> SarifRun:
    """Parse a single-run SARIF document produced by scanning ``root``."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise MalformedOutputError(f"SARIF is not valid JSON: {exc}") from exc
    doc = _as_dict(doc, "document")
    runs = _as_list(doc.get("runs"), "runs")
    if len(runs) != 1:
        raise MalformedOutputError(f"expected exactly one SARIF run, got {len(runs)}")
    run = _as_dict(runs[0], "run")
    driver = _as_dict(_as_dict(run.get("tool"), "tool").get("driver"), "driver")

    rules: dict[str, dict[str, Any]] = {}
    for rule in _as_list(driver.get("rules"), "rules"):
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            rules[rule["id"]] = rule

    invocations = _as_list(run.get("invocations"), "invocations")
    execution_successful = all(
        isinstance(inv, dict) and inv.get("executionSuccessful", True) is not False for inv in invocations
    )

    error_files: set[str] = set()
    notifications: list[str] = []
    for inv in invocations:
        if not isinstance(inv, dict):
            continue
        for note in _as_list(inv.get("toolExecutionNotifications"), "notifications"):
            if not isinstance(note, dict):
                continue
            text_msg = str(_as_dict(note.get("message", {}), "message").get("text", ""))[:500]
            notifications.append(text_msg)
            for loc in _as_list(note.get("locations"), "notification locations"):
                uri = (((loc or {}).get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                rel = repo_relative(uri, root) if isinstance(uri, str) else None
                if rel:
                    error_files.add(rel)

    results: list[SarifResult] = []
    dropped = 0
    for raw in _as_list(run.get("results"), "results"):
        res = _as_dict(raw, "result")
        rule_id = res.get("ruleId")
        if not isinstance(rule_id, str) or not rule_id:
            raise MalformedOutputError("SARIF result without ruleId")
        locations = _as_list(res.get("locations"), "locations")
        if not locations:
            continue
        physical = _as_dict(_as_dict(locations[0], "location").get("physicalLocation", {}), "physicalLocation")
        uri = _as_dict(physical.get("artifactLocation", {}), "artifactLocation").get("uri")
        if not isinstance(uri, str):
            raise MalformedOutputError("SARIF result without artifact uri")
        rel = repo_relative(uri, root)
        if rel is None:
            # A path outside the scanned tree cannot belong to this repository.
            dropped += 1
            continue
        region = _as_dict(physical.get("region", {}), "region")
        snippet = _as_dict(region.get("snippet", {}), "snippet").get("text", "")
        rule = rules.get(rule_id, {})
        rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
        tags = [str(t) for t in _as_list(rule_props.get("tags"), "tags")]
        default_cfg = rule.get("defaultConfiguration") if isinstance(rule.get("defaultConfiguration"), dict) else {}
        fps = res.get("fingerprints") if isinstance(res.get("fingerprints"), dict) else {}
        props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
        message = _as_dict(res.get("message", {}), "message").get("text", "")
        start = _int_or_none(region.get("startLine"))
        results.append(
            SarifResult(
                rule_id=rule_id,
                message=str(message),
                level=res.get("level") if isinstance(res.get("level"), str) else None,
                file_path=rel,
                start_line=start,
                end_line=_int_or_none(region.get("endLine")) or start,
                snippet=str(snippet) if isinstance(snippet, str) else "",
                rule_tags=tags,
                rule_default_level=default_cfg.get("level") if isinstance(default_cfg.get("level"), str) else None,
                properties=props,
                fingerprints={str(k): str(v) for k, v in fps.items()},
            )
        )

    return SarifRun(
        tool_name=str(driver.get("name", "")),
        tool_version=str(driver.get("semanticVersion") or driver.get("version") or "") or None,
        execution_successful=execution_successful,
        results=results,
        error_files=error_files,
        notifications=notifications,
        dropped_out_of_root=dropped,
    )
