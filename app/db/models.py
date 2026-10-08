"""ORM models.

Two kinds of finding record, deliberately separate:

* ``Finding`` -- what one scanner reported in one scan. Immutable evidence.
* ``TrackedFinding`` -- one weakness's identity across scans of a project,
  keyed by fingerprint, carrying its lifecycle state. This is what makes
  NEW / STILL_OPEN / RESOLVED / REGRESSION computable.

``LifecycleEvent`` records every state transition, so the history of a
weakness can be audited rather than inferred. Suppressed findings are never
deleted -- they keep their row and their history.

All queries go through the ORM, which parameterises every value.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SourceType(str, enum.Enum):
    GIT = "git"
    ZIP = "zip"


class ScanStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"   # every scanner ran successfully
    PARTIAL = "PARTIAL"       # at least one scanner failed -- results are incomplete
    FAILED = "FAILED"         # the scan could not run at all


class ToolStatus(str, enum.Enum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    NOT_INSTALLED = "NOT_INSTALLED"
    SKIPPED = "SKIPPED"       # nothing for this tool to scan (e.g. no requirements file)


class LifecycleState(str, enum.Enum):
    NEW = "NEW"
    STILL_OPEN = "STILL_OPEN"
    RESOLVED = "RESOLVED"
    REGRESSION = "REGRESSION"
    SUPPRESSED = "SUPPRESSED"


def _enum(cls: type[enum.Enum]) -> Enum:
    # Stored as plain strings: readable in the DB, no backend-specific enum types.
    return Enum(cls, native_enum=False, length=20, values_callable=lambda e: [m.value for m in e])


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    source_type: Mapped[SourceType] = mapped_column(_enum(SourceType))
    repo_url: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scans: Mapped[list[Scan]] = relationship(back_populates="project", order_by="Scan.id")
    tracked: Mapped[list[TrackedFinding]] = relationship(back_populates="project")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    source_type: Mapped[SourceType] = mapped_column(_enum(SourceType))
    # Commit SHA for git sources, SHA-256 of the archive for ZIP uploads.
    source_ref: Mapped[str | None] = mapped_column(String(80))
    label: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus), default=ScanStatus.RUNNING)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    scanner_runs: Mapped[list[ScannerRun]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScannerRun(Base):
    __tablename__ = "scanner_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    tool: Mapped[str] = mapped_column(String(40))
    tool_version: Mapped[str | None] = mapped_column(String(80))
    # SHA-256 of the ruleset file, so results are reproducible and comparable.
    ruleset_hash: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[ToolStatus] = mapped_column(_enum(ToolStatus))
    duration_s: Mapped[float | None] = mapped_column(Float)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)     # already redacted
    notes: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="scanner_runs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    tool: Mapped[str] = mapped_column(String(40))
    rule_id: Mapped[str] = mapped_column(String(300))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint_source: Mapped[str] = mapped_column(String(20))   # "native" | "derived"
    severity: Mapped[str] = mapped_column(String(10))
    cwe: Mapped[str | None] = mapped_column(String(20))            # canonical
    cwe_reported: Mapped[str | None] = mapped_column(String(20))   # what the tool said
    owasp: Mapped[str | None] = mapped_column(String(80))
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    file_path: Mapped[str] = mapped_column(String(500))            # repo-relative POSIX
    start_line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    snippet: Mapped[str] = mapped_column(Text, default="")          # redacted before storage
    package: Mapped[str | None] = mapped_column(String(120))
    package_version: Mapped[str | None] = mapped_column(String(60))
    fix_versions: Mapped[list[str]] = mapped_column(JSON, default=list)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class TrackedFinding(Base):
    __tablename__ = "tracked_findings"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_tracked_project_fp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(40))
    rule_id: Mapped[str] = mapped_column(String(300))
    cwe: Mapped[str | None] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    file_path: Mapped[str] = mapped_column(String(500))
    start_line: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text, default="")
    # "file:<path>" or "package:<name>": what a later scan must have examined
    # for this finding's absence to count as evidence of a fix.
    scope_key: Mapped[str] = mapped_column(String(520))
    status: Mapped[LifecycleState] = mapped_column(_enum(LifecycleState))
    first_seen_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    last_seen_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    resolved_in_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"))
    regression_count: Mapped[int] = mapped_column(Integer, default=0)
    suppressed_reason: Mapped[str | None] = mapped_column(Text)
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="tracked")
    events: Mapped[list[LifecycleEvent]] = relationship(
        back_populates="tracked_finding", order_by="LifecycleEvent.id", cascade="all, delete-orphan"
    )


class LifecycleEvent(Base):
    __tablename__ = "lifecycle_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    tracked_finding_id: Mapped[int] = mapped_column(ForeignKey("tracked_findings.id"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"))   # None for manual actions
    from_status: Mapped[LifecycleState | None] = mapped_column(_enum(LifecycleState))
    to_status: Mapped[LifecycleState] = mapped_column(_enum(LifecycleState))
    # True when the finding was absent but its scanner failed, so absence proved nothing.
    unverified: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    tracked_finding: Mapped[TrackedFinding] = relationship(back_populates="events")
