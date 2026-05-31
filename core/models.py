"""SQLAlchemy ORM models — the persisted shape of OmniScan's domain.

Key invariants (AGENT.md §2):
  * A ``Finding`` is **immutable** once persisted. Triage state lives in separate
    additive ``TriageRecord`` rows; the latest one is the effective state.
  * Secrets never land here in plaintext (resolved by ref at runtime only).
  * A ``Scan`` fans out to many ``ScanJob`` rows (one per adapter). A ``Finding``
    belongs to a ``Scan`` (post-dedup), not a ``ScanJob``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.db import Base
from core.enums import (
    IastSessionStatus,
    JobStatus,
    Role,
    ScanClass,
    ScanStatus,
    Severity,
    TriageStatus,
)
from core.ids import new_id


def _now() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("user"))
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    role: Mapped[Role] = mapped_column(String, default=Role.viewer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("proj"))
    name: Mapped[str] = mapped_column(String, index=True)
    slug: Mapped[str] = mapped_column(String, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    targets: Mapped[list[Target]] = relationship(back_populates="project")


class Target(Base):
    """A repo or running system + its authorized scope. ``scope_guard`` reads this."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("tgt"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String)  # "git" | "url"
    identifier: Mapped[str] = mapped_column(String)  # repo url or base url
    # Explicit allowlist/denylist of hosts/paths this target is authorized for.
    scope_allow: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_deny: Mapped[list[str]] = mapped_column(JSON, default=list)
    ownership_verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="targets")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("scan"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    scan_class: Mapped[ScanClass] = mapped_column(String, index=True)
    status: Mapped[ScanStatus] = mapped_column(String, default=ScanStatus.queued, index=True)
    # The original request payload (already scrubbed of inline secrets).
    request: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    correlation_id: Mapped[str] = mapped_column(String, default=lambda: new_id("corr"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    jobs: Mapped[list[ScanJob]] = relationship(back_populates="scan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan")


class ScanJob(Base):
    """One adapter execution within a scan's fan-out."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("job"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    adapter: Mapped[str] = mapped_column(String)  # e.g. "demoscan", "semgrep"
    scan_class: Mapped[ScanClass] = mapped_column(String)
    status: Mapped[JobStatus] = mapped_column(String, default=JobStatus.queued, index=True)
    depends_on: Mapped[list[str]] = mapped_column(JSON, default=list)  # job ids
    raw_output_ref: Mapped[str | None] = mapped_column(String, nullable=True)  # object store key
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    scan: Mapped[Scan] = relationship(back_populates="jobs")


class Finding(Base):
    """IMMUTABLE once persisted. Triage layers on top via TriageRecord."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("find"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    project_id: Mapped[str] = mapped_column(String, index=True)
    scan_class: Mapped[ScanClass] = mapped_column(String, index=True)
    fingerprint: Mapped[str] = mapped_column(String, index=True)  # stable across re-scans
    rule_id: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(String, index=True)
    # location is polymorphic by scan class: file/line/symbol, url/route/param, or runtime flow.
    location: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # which tools/sources reported this (post-dedup).
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    # RVD enrichment: reasoning trace, composition path, chainability, encrypted poc ref.
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    chainability_score: Mapped[float] = mapped_column(default=0.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    triage_records: Mapped[list[TriageRecord]] = relationship(back_populates="finding")
    comments: Mapped[list[Comment]] = relationship(back_populates="finding")


class TriageRecord(Base):
    """Additive triage state layered on an immutable Finding (latest wins)."""

    __tablename__ = "triage_records"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("tri"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    status: Mapped[TriageStatus] = mapped_column(String)
    severity_override: Mapped[Severity | None] = mapped_column(String, nullable=True)
    assignee_id: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_id: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    finding: Mapped[Finding] = relationship(back_populates="triage_records")


class Comment(Base):
    """Threaded collaboration on a finding. Edits keep revision history via the audit log."""

    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("cmt"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(String, nullable=True)  # threading
    author_id: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(Text)  # markdown
    mentions: Mapped[list[str]] = mapped_column(JSON, default=list)
    edited: Mapped[bool] = mapped_column(default=False)
    deleted: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    finding: Mapped[Finding] = relationship(back_populates="comments")


class IastSession(Base):
    """An IAST instrumentation session.

    The platform issues a session + a short-lived collector token (by ref) and an
    injection snippet; a language agent attaches to the running app and streams
    runtime security telemetry to the collector for the session's lifetime. The agent
    only streams (never opens an inbound port) and the session expires.
    """

    __tablename__ = "iast_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("sess"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    runtime: Mapped[str] = mapped_column(String)  # jvm | python | node | dotnet | go
    status: Mapped[IastSessionStatus] = mapped_column(
        String, default=IastSessionStatus.active, index=True
    )
    collector_token_ref: Mapped[str] = mapped_column(String)  # secret reference, never the token
    # SHA-256 of the collector token — the agent authenticates events against this; the
    # plaintext token is returned once at creation and never persisted.
    collector_token_hash: Mapped[str] = mapped_column(String, default="")
    # IAST findings stream into this scan as the agent reports source->sink flows.
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Immutable record of who triggered/triaged/commented on what."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: new_id("aud"))
    actor_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String, index=True)
    resource_type: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # already redacted
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
