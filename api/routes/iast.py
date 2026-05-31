from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header

from api.deps import PrincipalDep, SessionDep, requires
from api.errors import Problem
from api.schemas.models import (
    IastEventBatch,
    IastSessionCreate,
    IastSessionCreated,
    IastSessionOut,
)
from api.services import iast
from core.enums import Role

router = APIRouter(prefix="/api/v1/iast", tags=["iast"])


@router.post(
    "/sessions",
    response_model=IastSessionCreated,
    dependencies=[Depends(requires(Role.scanner))],
)
async def create_session(body: IastSessionCreate, session: SessionDep) -> IastSessionCreated:
    try:
        record, token, snippet = await iast.create_session(
            session, project_id=body.project_id, runtime=body.runtime
        )
    except iast.IastError as exc:
        raise Problem(400, "Invalid request", str(exc), "urn:omniscan:validation") from exc
    return IastSessionCreated(
        id=record.id,
        project_id=record.project_id,
        runtime=record.runtime,
        status=record.status,
        created_at=record.created_at,
        expires_at=record.expires_at,
        finalized_at=record.finalized_at,
        collector_token=token,  # returned once for agent injection
        injection_snippet=snippet,
    )


@router.get("/sessions/{session_id}", response_model=IastSessionOut)
async def get_session(session_id: str, session: SessionDep, _: PrincipalDep) -> IastSessionOut:
    record = await iast.get_session(session, session_id)
    if record is None:
        raise Problem(404, "Not found", f"unknown IAST session: {session_id}")
    return IastSessionOut.model_validate(record, from_attributes=True)


@router.post("/sessions/{session_id}/events")
async def ingest_events(
    session_id: str,
    body: IastEventBatch,
    session: SessionDep,
    x_omniscan_iast_token: Annotated[str | None, Header()] = None,
) -> dict[str, int | str]:
    """Collector endpoint — the agent POSTs runtime source->sink events here.

    Authenticated by the per-session collector token (NOT a user bearer token): the
    agent runs inside the target app and only holds the token issued at session create.
    """
    try:
        record = await iast.authenticate_collector(session, session_id, x_omniscan_iast_token)
        added = await iast.ingest_events(session, record, [e.model_dump() for e in body.events])
    except iast.IastError as exc:
        raise Problem(401, "Unauthorized", str(exc), "urn:omniscan:iast") from exc
    return {"ingested": added, "session": session_id}


@router.post(
    "/sessions/{session_id}/finalize",
    response_model=IastSessionOut,
    dependencies=[Depends(requires(Role.scanner))],
)
async def finalize_session(session_id: str, session: SessionDep) -> IastSessionOut:
    try:
        record = await iast.finalize_session(session, session_id)
    except iast.IastError as exc:
        raise Problem(404, "Not found", str(exc)) from exc
    return IastSessionOut.model_validate(record, from_attributes=True)
