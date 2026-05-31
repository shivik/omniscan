"""Scan creation + retrieval. scope_guard is enforced before persisting a scan."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas.models import ScanCreate
from api.services import projects
from core import scope_guard
from core.enums import ScanClass
from core.models import Scan, ScanJob


def _requested_hosts(
    scan_class: ScanClass, source: dict[str, Any], target: dict[str, Any]
) -> list[str]:
    hosts: list[str] = []
    if target.get("base_url"):
        hosts.append(target["base_url"])
    if source.get("url"):
        url = source["url"]
        hosts.append(
            url.split("@", 1)[1].split(":", 1)[0]
            if url.startswith("git@")
            else (urlparse(url).hostname or url)
        )
    return hosts


async def create_scan(session: AsyncSession, body: ScanCreate) -> Scan:
    # Idempotency: replaying the same key returns the same scan.
    if body.idempotency_key:
        existing = await session.scalar(
            select(Scan).where(Scan.idempotency_key == body.idempotency_key)
        )
        if existing:
            return existing

    if await projects.get_project(session, body.project_id) is None:
        raise ValueError(f"unknown project: {body.project_id}")

    source = body.source.model_dump(exclude_none=True) if body.source else {}
    target = body.target.model_dump(exclude_none=True) if body.target else {}
    scope_override = body.scope.model_dump() if body.scope else None
    scope = await projects.resolve_scope(
        session, project_id=body.project_id, override=scope_override
    )

    # --- scope_guard FIRST, before any persistence (Golden Rule #1) ---
    scope_guard.enforce(
        scan_class=body.scan_class,
        ownership_verified=scope["ownership_verified"],
        scope_allow=scope["allow"],
        scope_deny=scope["deny"],
        requested_hosts=_requested_hosts(body.scan_class, source, target),
    )

    # Build the stored request — credentials only by ref, never inline.
    request: dict[str, Any] = {
        "scan_class": body.scan_class.value,
        "source": source,
        "target": target,
        "tools": body.tools,
        "options": body.options,
        "auth": {"ref": body.auth.ref} if body.auth and body.auth.ref else {},
        "_scope": scope,
    }
    if body.scan_class is ScanClass.RVD and body.rvd:
        request["rvd"] = body.rvd.model_dump()

    scan = Scan(
        project_id=body.project_id,
        scan_class=body.scan_class,
        # The schema admits credentials only by ref (never inline), so the request
        # carries no plaintext secret to scrub. redact() is applied at the logging /
        # error / SARIF boundaries, not here, since the ref must survive for the
        # secrets manager to resolve it inside the adapter container.
        request=request,
        idempotency_key=body.idempotency_key,
    )
    session.add(scan)
    await session.flush()
    return scan


async def get_scan(session: AsyncSession, scan_id: str) -> Scan | None:
    return await session.get(Scan, scan_id)


async def list_scans(session: AsyncSession, project_id: str | None = None) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.created_at.desc())
    if project_id:
        stmt = stmt.where(Scan.project_id == project_id)
    return list(await session.scalars(stmt))


async def get_jobs(session: AsyncSession, scan_id: str) -> list[ScanJob]:
    return list(
        await session.scalars(
            select(ScanJob).where(ScanJob.scan_id == scan_id).order_by(ScanJob.created_at.asc())
        )
    )
