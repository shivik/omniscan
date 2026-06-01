"""Projects & targets — register apps/repos/targets and their authorized scope."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import Application, Project, Target


async def create_application(session: AsyncSession, *, name: str, slug: str) -> Application:
    if await session.scalar(select(Application).where(Application.slug == slug)):
        raise ValueError(f"application slug already exists: {slug}")
    app = Application(name=name, slug=slug)
    session.add(app)
    await session.flush()
    return app


async def list_applications(session: AsyncSession) -> list[Application]:
    return list(await session.scalars(select(Application).order_by(Application.created_at.desc())))


async def create_project(
    session: AsyncSession, *, name: str, slug: str, application_id: str | None = None
) -> Project:
    existing = await session.scalar(select(Project).where(Project.slug == slug))
    if existing:
        raise ValueError(f"project slug already exists: {slug}")
    if application_id and await session.get(Application, application_id) is None:
        raise ValueError(f"unknown application: {application_id}")
    project = Project(name=name, slug=slug, application_id=application_id)
    session.add(project)
    await session.flush()
    return project


async def list_projects(session: AsyncSession) -> list[Project]:
    return list(await session.scalars(select(Project).order_by(Project.created_at.desc())))


async def get_project(session: AsyncSession, project_id: str) -> Project | None:
    return await session.get(Project, project_id)


async def create_target(
    session: AsyncSession,
    *,
    project_id: str,
    kind: str,
    identifier: str,
    scope_allow: list[str],
    scope_deny: list[str],
    ownership_verified: bool,
) -> Target:
    if await session.get(Project, project_id) is None:
        raise ValueError(f"unknown project: {project_id}")
    target = Target(
        project_id=project_id,
        kind=kind,
        identifier=identifier,
        scope_allow=scope_allow,
        scope_deny=scope_deny,
        ownership_verified=ownership_verified,
    )
    session.add(target)
    await session.flush()
    return target


async def list_targets(session: AsyncSession, project_id: str) -> list[Target]:
    return list(await session.scalars(select(Target).where(Target.project_id == project_id)))


async def resolve_scope(
    session: AsyncSession, *, project_id: str, override: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge a project's registered target scope with any per-scan override.

    Ownership is only ever taken from a registered, ownership-verified target — a
    request cannot self-assert ownership. The allowlist is the union of registered
    target allowlists plus the (narrowing) request override; denylist is the union.
    """
    targets = await list_targets(session, project_id)
    allow: set[str] = set()
    deny: set[str] = set()
    ownership = False
    for t in targets:
        allow.update(t.scope_allow)
        deny.update(t.scope_deny)
        ownership = ownership or t.ownership_verified
    if override:
        allow.update(override.get("allow", []))
        deny.update(override.get("deny", []))
    return {"allow": sorted(allow), "deny": sorted(deny), "ownership_verified": ownership}
