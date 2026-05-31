"""Canonical enums shared across every layer (API, engine, normalize, adapters)."""

from __future__ import annotations

from enum import StrEnum


class ScanClass(StrEnum):
    SAST = "SAST"
    DAST = "DAST"
    IAST = "IAST"
    RVD = "RVD"


class ScanStatus(StrEnum):
    queued = "queued"
    planning = "planning"
    running = "running"
    normalizing = "normalizing"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    normalizing = "normalizing"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class IastSessionStatus(StrEnum):
    active = "active"
    finalized = "finalized"
    expired = "expired"


class TriageStatus(StrEnum):
    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    fixed = "fixed"
    # RVD findings default here until a triager reviews them.
    embargoed = "embargoed"


class Role(StrEnum):
    viewer = "viewer"
    scanner = "scanner"
    triager = "triager"
    admin = "admin"

    @property
    def rank(self) -> int:
        return {"viewer": 0, "scanner": 1, "triager": 2, "admin": 3}[self.value]


class RiskTier(StrEnum):
    """RVD's residual-risk taxonomy (see SKILLS.md §R.0)."""

    known_known = "known_known"
    known_unknown = "known_unknown"
    unknown_unknown = "unknown_unknown"
