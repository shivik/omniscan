"""Request/response schemas for every resource."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from core.enums import (
    IastSessionStatus,
    Role,
    ScanClass,
    ScanStatus,
    Severity,
    TriageStatus,
)

# --- auth ---


class TokenRequest(BaseModel):
    email: str
    role: Role = Role.viewer


class TokenResponse(BaseModel):
    token: str
    user_id: str
    role: Role


# --- projects & targets ---


class ProjectCreate(BaseModel):
    name: str
    slug: str


class ProjectOut(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime


class TargetCreate(BaseModel):
    kind: str = Field(description="'git' or 'url'")
    identifier: str
    scope_allow: list[str] = Field(default_factory=list)
    scope_deny: list[str] = Field(default_factory=list)
    ownership_verified: bool = False


class TargetOut(BaseModel):
    id: str
    project_id: str
    kind: str
    identifier: str
    scope_allow: list[str]
    scope_deny: list[str]
    ownership_verified: bool


# --- scans ---


class SourceSpec(BaseModel):
    type: str = Field(description="'git' | 'path' | 'image'")
    url: str | None = None
    ref: str | None = None
    path: str | None = None
    image: str | None = None  # container image ref for image-SCA (e.g. Clair)


class TargetSpec(BaseModel):
    base_url: str | None = None


class ScopeSpec(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class AuthSpec(BaseModel):
    ref: str | None = Field(default=None, description="secret reference, never inline credentials")


class RVDSpec(BaseModel):
    depth: str = "standard"
    budget: str = "1h"
    focus: list[str] = Field(default_factory=list)
    backend: str | None = None
    generate_poc: bool = False


class DriveSpec(BaseModel):
    """How an IAST scan drives traffic against the instrumented app."""

    mode: str = "dast"  # "dast" (drive with the DAST engine) | "tests" (external traffic)
    target: TargetSpec | None = None
    scope: ScopeSpec | None = None
    tools: list[str] | None = None


class ScanCreate(BaseModel):
    scan_class: ScanClass
    project_id: str
    source: SourceSpec | None = None
    target: TargetSpec | None = None
    scope: ScopeSpec | None = None
    auth: AuthSpec | None = None
    tools: list[str] | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    rvd: RVDSpec | None = None
    iast_session: str | None = None
    drive: DriveSpec | None = None
    idempotency_key: str | None = None


# --- IAST sessions ---


class IastSessionCreate(BaseModel):
    project_id: str
    runtime: str = Field(description="jvm | python | node | dotnet | go")


class IastSessionOut(BaseModel):
    id: str
    project_id: str
    runtime: str
    status: IastSessionStatus
    created_at: datetime
    expires_at: datetime
    finalized_at: datetime | None = None


class IastSessionCreated(IastSessionOut):
    # Returned ONCE at creation: the collector token (plaintext) + injection snippet.
    # Only a reference to the token is persisted server-side.
    collector_token: str
    injection_snippet: str


class IastEvent(BaseModel):
    """A runtime source->sink event reported by the IAST agent."""

    sink: str
    rule_id: str | None = None
    severity: str = "medium"
    file: str | None = None
    line: int | None = None
    function: str | None = None
    route: str | None = None
    param: str | None = None
    tainted: bool = False
    evidence: str | None = None


class IastEventBatch(BaseModel):
    events: list[IastEvent] = Field(default_factory=list)


class JobOut(BaseModel):
    id: str
    adapter: str
    scan_class: ScanClass
    status: str


class ScanOut(BaseModel):
    id: str
    project_id: str
    scan_class: ScanClass
    status: ScanStatus
    correlation_id: str
    error: str | None = None
    created_at: datetime
    jobs: list[JobOut] = Field(default_factory=list)


# --- findings, triage, comments ---


class TriageOut(BaseModel):
    status: TriageStatus
    severity_override: Severity | None = None
    assignee_id: str | None = None
    reason: str | None = None
    actor_id: str
    created_at: datetime


class FindingOut(BaseModel):
    id: str
    scan_id: str
    project_id: str
    scan_class: ScanClass
    fingerprint: str
    rule_id: str
    title: str
    message: str
    severity: Severity
    effective_severity: Severity
    effective_status: TriageStatus
    location: dict[str, Any]
    sources: list[str]
    chainability_score: float
    extra: dict[str, Any]
    first_seen: datetime


class TriageRequest(BaseModel):
    status: TriageStatus | None = None
    severity_override: Severity | None = None
    reason: str | None = None


class AssignRequest(BaseModel):
    assignee_id: str | None = None


class CommentCreate(BaseModel):
    body: str
    parent_id: str | None = None
    mentions: list[str] = Field(default_factory=list)


class CommentOut(BaseModel):
    id: str
    finding_id: str
    parent_id: str | None
    author_id: str
    body: str
    mentions: list[str]
    edited: bool
    deleted: bool
    created_at: datetime


class HistoryEvent(BaseModel):
    action: str
    actor_id: str
    detail: dict[str, Any]
    created_at: datetime
