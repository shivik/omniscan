from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from api.deps import PrincipalDep, SessionDep, requires
from api.errors import Problem
from api.schemas.models import JobOut, ScanCreate, ScanOut
from api.services import projects, scans
from core.enums import Role, ScanClass
from engine import planner, scheduler

router = APIRouter(prefix="/api/v1", tags=["scans"])


async def _to_out(session, scan) -> ScanOut:  # type: ignore[no-untyped-def]
    jobs = await scans.get_jobs(session, scan.id)
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        scan_class=ScanClass(scan.scan_class),
        status=scan.status,
        correlation_id=scan.correlation_id,
        error=scan.error,
        created_at=scan.created_at,
        jobs=[
            JobOut(id=j.id, adapter=j.adapter, scan_class=ScanClass(j.scan_class), status=j.status)
            for j in jobs
        ],
    )


@router.post("/scans", response_model=ScanOut, dependencies=[Depends(requires(Role.scanner))])
async def create_scan(
    body: ScanCreate,
    session: SessionDep,
    dry_run: bool = Query(default=False),
) -> ScanOut | dict[str, Any]:
    if dry_run:
        # Planning runs scope_guard; an unauthorized target fails here, no job enqueued.
        source = body.source.model_dump(exclude_none=True) if body.source else {}
        target = body.target.model_dump(exclude_none=True) if body.target else {}
        scope_override = body.scope.model_dump() if body.scope else None
        scope = await projects.resolve_scope(
            session, project_id=body.project_id, override=scope_override
        )
        plan = planner.plan(
            scan_class=body.scan_class,
            tools=body.tools,
            source=source,
            target=target,
            ownership_verified=scope["ownership_verified"],
            scope_allow=scope["allow"],
            scope_deny=scope["deny"],
        )
        return {
            "dry_run": True,
            "scan_class": plan.scan_class,
            "jobs": [pj.adapter for pj in plan.jobs],
        }

    scan = await scans.create_scan(session, body)
    out = await _to_out(session, scan)
    # Enqueue after the creating transaction commits (request session closes post-return).
    scheduler.enqueue_scan(scan.id)
    return out


@router.get("/scans", response_model=list[ScanOut])
async def list_scans(
    session: SessionDep,
    _: PrincipalDep,
    project_id: str | None = Query(default=None),
) -> list[ScanOut]:
    return [await _to_out(session, s) for s in await scans.list_scans(session, project_id)]


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, session: SessionDep, _: PrincipalDep) -> ScanOut:
    scan = await scans.get_scan(session, scan_id)
    if scan is None:
        raise Problem(404, "Not found", f"unknown scan: {scan_id}")
    return await _to_out(session, scan)
