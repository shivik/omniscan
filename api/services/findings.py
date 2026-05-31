"""Findings + triage. Findings are immutable; triage is additive (latest wins)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.services import audit
from core.enums import ScanClass, Severity, TriageStatus
from core.models import AuditLog, Finding, TriageRecord


@dataclass
class EffectiveFinding:
    finding: Finding
    effective_severity: Severity
    effective_status: TriageStatus


async def _latest_triage(session: AsyncSession, finding_id: str) -> TriageRecord | None:
    record: TriageRecord | None = await session.scalar(
        select(TriageRecord)
        .where(TriageRecord.finding_id == finding_id)
        .order_by(TriageRecord.created_at.desc())
        .limit(1)
    )
    return record


def _default_status(finding: Finding) -> TriageStatus:
    # RVD findings default to embargoed; everything else opens.
    return (
        TriageStatus.embargoed
        if ScanClass(finding.scan_class) is ScanClass.RVD
        else TriageStatus.open
    )


async def effective(session: AsyncSession, finding: Finding) -> EffectiveFinding:
    latest = await _latest_triage(session, finding.id)
    if latest is None:
        return EffectiveFinding(finding, Severity(finding.severity), _default_status(finding))
    sev = (
        Severity(latest.severity_override)
        if latest.severity_override
        else Severity(finding.severity)
    )
    return EffectiveFinding(finding, sev, TriageStatus(latest.status))


async def get(session: AsyncSession, finding_id: str) -> Finding | None:
    return await session.get(Finding, finding_id)


async def list_findings(
    session: AsyncSession,
    *,
    project_id: str | None = None,
    scan_id: str | None = None,
    scan_class: ScanClass | None = None,
    min_severity: Severity | None = None,
    chainable_only: bool = False,
    query: str | None = None,
) -> list[EffectiveFinding]:
    stmt = select(Finding).order_by(Finding.severity, Finding.created_at.desc())
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if scan_class:
        stmt = stmt.where(Finding.scan_class == scan_class)
    rows = list(await session.scalars(stmt))

    out: list[EffectiveFinding] = []
    for f in rows:
        if chainable_only and f.chainability_score <= 0:
            continue
        if query and query.lower() not in (f.title + " " + f.message).lower():
            continue
        eff = await effective(session, f)
        if min_severity and eff.effective_severity.rank < min_severity.rank:
            continue
        out.append(eff)
    return out


async def triage(
    session: AsyncSession,
    *,
    finding_id: str,
    actor_id: str,
    status: TriageStatus | None,
    severity_override: Severity | None,
    reason: str | None,
) -> TriageRecord:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"unknown finding: {finding_id}")
    current = await effective(session, finding)
    record = TriageRecord(
        finding_id=finding_id,
        status=status or current.effective_status,
        severity_override=severity_override,
        reason=reason,
        actor_id=actor_id,
        assignee_id=None,
    )
    session.add(record)
    await session.flush()  # populate server/Python-side defaults (created_at) for the response
    await audit.record(
        session,
        actor_id=actor_id,
        action="triage",
        resource_type="finding",
        resource_id=finding_id,
        detail={"status": record.status, "severity_override": severity_override, "reason": reason},
    )
    return record


async def assign(
    session: AsyncSession, *, finding_id: str, actor_id: str, assignee_id: str | None
) -> TriageRecord:
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"unknown finding: {finding_id}")
    current = await effective(session, finding)
    record = TriageRecord(
        finding_id=finding_id,
        status=current.effective_status,
        assignee_id=assignee_id,
        actor_id=actor_id,
    )
    session.add(record)
    await session.flush()
    await audit.record(
        session,
        actor_id=actor_id,
        action="assign",
        resource_type="finding",
        resource_id=finding_id,
        detail={"assignee_id": assignee_id},
    )
    return record


async def history(session: AsyncSession, finding_id: str) -> list[AuditLog]:
    return list(
        await session.scalars(
            select(AuditLog)
            .where(AuditLog.resource_id == finding_id)
            .order_by(AuditLog.created_at.asc())
        )
    )
