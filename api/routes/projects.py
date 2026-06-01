from __future__ import annotations

from fastapi import APIRouter, Depends

from api.deps import PrincipalDep, SessionDep, requires
from api.errors import Problem
from api.schemas.models import (
    ApplicationCreate,
    ApplicationOut,
    ProjectCreate,
    ProjectOut,
    TargetCreate,
    TargetOut,
)
from api.services import projects
from core.enums import Role

router = APIRouter(prefix="/api/v1", tags=["projects"])


@router.post(
    "/applications", response_model=ApplicationOut, dependencies=[Depends(requires(Role.scanner))]
)
async def create_application(body: ApplicationCreate, session: SessionDep) -> ApplicationOut:
    app = await projects.create_application(session, name=body.name, slug=body.slug)
    return ApplicationOut.model_validate(app, from_attributes=True)


@router.get("/applications", response_model=list[ApplicationOut])
async def list_applications(session: SessionDep, _: PrincipalDep) -> list[ApplicationOut]:
    return [
        ApplicationOut.model_validate(a, from_attributes=True)
        for a in await projects.list_applications(session)
    ]


@router.post("/projects", response_model=ProjectOut, dependencies=[Depends(requires(Role.scanner))])
async def create_project(body: ProjectCreate, session: SessionDep) -> ProjectOut:
    project = await projects.create_project(
        session, name=body.name, slug=body.slug, application_id=body.application_id
    )
    return ProjectOut.model_validate(project, from_attributes=True)


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(session: SessionDep, _: PrincipalDep) -> list[ProjectOut]:
    return [
        ProjectOut.model_validate(p, from_attributes=True)
        for p in await projects.list_projects(session)
    ]


@router.post(
    "/projects/{project_id}/targets",
    response_model=TargetOut,
    dependencies=[Depends(requires(Role.scanner))],
)
async def create_target(project_id: str, body: TargetCreate, session: SessionDep) -> TargetOut:
    target = await projects.create_target(
        session,
        project_id=project_id,
        kind=body.kind,
        identifier=body.identifier,
        scope_allow=body.scope_allow,
        scope_deny=body.scope_deny,
        ownership_verified=body.ownership_verified,
    )
    return TargetOut.model_validate(target, from_attributes=True)


@router.get("/projects/{project_id}/targets", response_model=list[TargetOut])
async def list_targets(project_id: str, session: SessionDep, _: PrincipalDep) -> list[TargetOut]:
    if await projects.get_project(session, project_id) is None:
        raise Problem(404, "Not found", f"unknown project: {project_id}")
    return [
        TargetOut.model_validate(t, from_attributes=True)
        for t in await projects.list_targets(session, project_id)
    ]
