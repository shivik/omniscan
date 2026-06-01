"""Security-dashboard aggregation — powers the Mend-style overview widgets.

Produces one payload for the dashboard: overview counts, findings-by-severity (+ by
engine), remediation analysis, a findings-over-time trend, and top-10 applications /
projects by risk. Aggregated from existing findings/scans/projects so the dashboard
stays a thin client.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.services import findings as finding_svc
from core.enums import ScanClass, TriageStatus
from core.models import Application, Project, Scan

_RESOLVED = {TriageStatus.fixed, TriageStatus.false_positive, TriageStatus.accepted_risk}
_SUPPRESSED = {TriageStatus.false_positive, TriageStatus.accepted_risk}
_SEV_KEYS = ["critical", "high", "medium", "low", "info"]


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _empty_sev() -> dict[str, int]:
    return {k: 0 for k in _SEV_KEYS}


async def build(
    session: AsyncSession, *, engines: list[ScanClass] | None, trend_days: int
) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(days=trend_days)
    engine_set = set(engines) if engines else set(ScanClass)

    # All findings (effective severity + status), filtered to selected engines + window.
    effs = [
        e
        for e in await finding_svc.list_findings(session)
        if ScanClass(e.finding.scan_class) in engine_set and _as_utc(e.finding.first_seen) >= since
    ]

    # name/grouping lookups
    projects = {p.id: p for p in await session.scalars(select(Project))}
    apps = {a.id: a for a in await session.scalars(select(Application))}

    # --- findings by severity (+ by engine for the donut hover) ---
    by_sev = _empty_sev()
    by_engine: dict[str, dict[str, int]] = {c.value: _empty_sev() for c in ScanClass}
    remediations = suppressions = 0
    for e in effs:
        sev = e.effective_severity.value
        by_sev[sev] += 1
        by_engine[e.finding.scan_class][sev] += 1
        if e.effective_status == TriageStatus.fixed:
            remediations += 1
        if e.effective_status in _SUPPRESSED:
            suppressions += 1

    # --- per-project + per-application rollups ---
    proj_roll: dict[str, dict[str, Any]] = {}
    app_roll: dict[str, dict[str, Any]] = {}
    for e in effs:
        pid = e.finding.project_id
        pr = proj_roll.setdefault(pid, {"total": 0, **_empty_sev()})
        pr["total"] += 1
        pr[e.effective_severity.value] += 1
        app_id = projects[pid].application_id if pid in projects else None
        if app_id:
            ar = app_roll.setdefault(app_id, {"total": 0, "projects": set(), **_empty_sev()})
            ar["total"] += 1
            ar[e.effective_severity.value] += 1
            ar["projects"].add(pid)

    def _rank(d: dict[str, dict[str, Any]]) -> list[str]:
        return sorted(d, key=lambda k: (-d[k]["total"], k))[:10]

    def _app_name(pid: str) -> str | None:
        proj = projects.get(pid)
        app = apps.get(proj.application_id) if proj and proj.application_id else None
        return app.name if app else None

    top_projects = [
        {
            "id": pid,
            "name": projects[pid].name if pid in projects else pid,
            "application": _app_name(pid),
            "total": proj_roll[pid]["total"],
            **{k: proj_roll[pid][k] for k in _SEV_KEYS},
        }
        for pid in _rank(proj_roll)
    ]
    top_applications = [
        {
            "id": aid,
            "name": apps[aid].name if aid in apps else aid,
            "projects": len(app_roll[aid]["projects"]),
            "total": app_roll[aid]["total"],
            **{k: app_roll[aid][k] for k in _SEV_KEYS},
        }
        for aid in _rank(app_roll)
    ]

    # --- findings trend (per-day new findings, split open vs resolved) ---
    per_day: dict[str, dict[str, int]] = defaultdict(lambda: {"open": 0, "resolved": 0})
    for e in effs:
        day = _as_utc(e.finding.first_seen).date().isoformat()
        bucket = "resolved" if e.effective_status in _RESOLVED else "open"
        per_day[day][bucket] += 1
    trends = [{"date": d, **per_day[d]} for d in sorted(per_day)]

    # --- overview counts ---
    scans_in_window = (
        await session.scalar(select(func.count()).select_from(Scan).where(Scan.created_at >= since))
    ) or 0
    total_projects = (await session.scalar(select(func.count()).select_from(Project))) or 0
    total_apps = (await session.scalar(select(func.count()).select_from(Application))) or 0

    return {
        "trend_days": trend_days,
        "engines": sorted(c.value for c in engine_set),
        "overview": {
            "applications": int(total_apps),
            "projects": int(total_projects),
            "scans": int(scans_in_window),
        },
        "findings_by_severity": by_sev,
        "findings_by_engine": by_engine,
        "remediation": {"remediations": remediations, "suppressions": suppressions},
        "trends": trends,
        "top_applications": top_applications,
        "top_projects": top_projects,
        "total_findings": len(effs),
    }
