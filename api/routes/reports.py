from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from api.deps import PrincipalDep, SessionDep
from api.errors import Problem
from api.services import findings as finding_svc
from api.services import scans as scan_svc
from core.enums import Severity
from normalize.sarif import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

router = APIRouter(prefix="/api/v1", tags=["reports"])

_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "none",
}


@router.get("/scans/{scan_id}/report")
async def report(
    scan_id: str,
    session: SessionDep,
    _: PrincipalDep,
    format: str = Query(default="json", pattern="^(json|sarif)$"),
) -> dict[str, Any]:
    scan = await scan_svc.get_scan(session, scan_id)
    if scan is None:
        raise Problem(404, "Not found", f"unknown scan: {scan_id}")
    effs = await finding_svc.list_findings(session, scan_id=scan_id)

    if format == "sarif":
        # Reports never contain secrets; findings are already scrubbed.
        results = [
            Result(
                ruleId=e.finding.rule_id,
                level=_LEVEL[e.effective_severity],
                message=Message(text=e.finding.title),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(uri=e.finding.location.get("file")),
                            region=Region(startLine=e.finding.location.get("start_line")),
                        )
                    )
                ],
                properties={"severity": e.effective_severity, "status": e.effective_status},
            )
            for e in effs
        ]
        sarif = SarifLog(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="omniscan", version="0.1.0")),
                    results=results,
                )
            ]
        )
        return sarif.model_dump(by_alias=True, exclude_none=True)

    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for e in effs:
        counts[e.effective_severity.value] += 1
    return {
        "scan_id": scan_id,
        "scan_class": scan.scan_class,
        "status": scan.status,
        "totals": {"findings": len(effs), "by_severity": counts},
        "findings": [
            {
                "id": e.finding.id,
                "rule_id": e.finding.rule_id,
                "title": e.finding.title,
                "severity": e.effective_severity,
                "status": e.effective_status,
                "chainability_score": e.finding.chainability_score,
                "location": e.finding.location,
            }
            for e in effs
        ],
    }


@router.get("/scans/{scan_id}/gate")
async def gate(
    scan_id: str,
    session: SessionDep,
    _: PrincipalDep,
    policy: str = Query(default="default"),
) -> dict[str, Any]:
    """CI gate: default policy fails on any open high+ finding."""
    scan = await scan_svc.get_scan(session, scan_id)
    if scan is None:
        raise Problem(404, "Not found", f"unknown scan: {scan_id}")
    effs = await finding_svc.list_findings(session, scan_id=scan_id, min_severity=Severity.high)
    blocking = [e for e in effs if e.effective_status.value in {"open", "confirmed", "embargoed"}]
    return {
        "scan_id": scan_id,
        "policy": policy,
        "passed": len(blocking) == 0,
        "blocking_findings": [e.finding.id for e in blocking],
    }
