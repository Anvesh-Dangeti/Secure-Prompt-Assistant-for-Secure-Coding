"""Request and response models. Responses expose redacted data only."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    repo_url: str | None = Field(default=None, max_length=300)


class GitScanRequest(BaseModel):
    label: str | None = Field(default=None, max_length=120)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    source_type: str
    repo_url: str | None
    created_at: datetime


class ScannerRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    tool: str
    tool_version: str | None
    ruleset_hash: str | None
    status: str
    duration_s: float | None
    finding_count: int
    error: str | None
    notes: str | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    source_type: str
    source_ref: str | None
    label: str | None
    status: str
    error: str | None
    started_at: datetime
    finished_at: datetime | None
    scanner_runs: list[ScannerRunOut] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    tool: str
    rule_id: str
    fingerprint: str
    severity: str
    cwe: str | None
    cwe_reported: str | None
    owasp: str | None
    cve_ids: list[str]
    in_scope: bool
    file_path: str
    start_line: int | None
    end_line: int | None
    message: str
    snippet: str
    package: str | None
    package_version: str | None
    fix_versions: list[str]


class ScanSummaryOut(BaseModel):
    scan_id: int
    project_id: int
    project: str
    status: str
    source_ref: str | None
    error: str | None
    scanners: dict[str, str]
    findings: int
    lifecycle: dict[str, int]


class TrackedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    fingerprint: str
    status: str
    tool: str
    rule_id: str
    cwe: str | None
    severity: str
    file_path: str
    start_line: int | None
    message: str
    first_seen_scan_id: int
    last_seen_scan_id: int
    resolved_in_scan_id: int | None
    regression_count: int
    suppressed_reason: str | None


class LifecycleEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    scan_id: int | None
    from_status: str | None
    to_status: str
    unverified: bool
    note: str | None
    created_at: datetime


class TrackedDetailOut(TrackedOut):
    events: list[LifecycleEventOut] = []


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
