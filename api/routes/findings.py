from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.deps import PrincipalDep, SessionDep, requires
from api.errors import Problem
from api.schemas.models import (
    AssignRequest,
    CommentCreate,
    CommentOut,
    FindingOut,
    HistoryEvent,
    TriageOut,
    TriageRequest,
)
from api.services import comments as comment_svc
from api.services import findings as finding_svc
from core.enums import Role, ScanClass, Severity
from core.security import can_view_poc

router = APIRouter(prefix="/api/v1", tags=["findings"])


def _to_out(eff: finding_svc.EffectiveFinding, *, redact_poc: bool) -> FindingOut:
    f = eff.finding
    extra = dict(f.extra)
    # PoC artifacts (RVD) are admin-gated; strip the reference for non-admins.
    if redact_poc and "poc_ref" in extra:
        extra["poc_ref"] = "<restricted: requires admin>"
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        project_id=f.project_id,
        scan_class=ScanClass(f.scan_class),
        fingerprint=f.fingerprint,
        rule_id=f.rule_id,
        title=f.title,
        message=f.message,
        severity=Severity(f.severity),
        effective_severity=eff.effective_severity,
        effective_status=eff.effective_status,
        location=f.location,
        sources=f.sources,
        chainability_score=f.chainability_score,
        extra=extra,
        first_seen=f.first_seen,
    )


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    session: SessionDep,
    principal: PrincipalDep,
    project_id: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    scan_class: ScanClass | None = Query(default=None),
    min_severity: Severity | None = Query(default=None),
    chainable_only: bool = Query(default=False),
    q: str | None = Query(default=None),
) -> list[FindingOut]:
    effs = await finding_svc.list_findings(
        session,
        project_id=project_id,
        scan_id=scan_id,
        scan_class=scan_class,
        min_severity=min_severity,
        chainable_only=chainable_only,
        query=q,
    )
    redact_poc = not can_view_poc(principal)
    return [_to_out(e, redact_poc=redact_poc) for e in effs]


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, session: SessionDep, principal: PrincipalDep) -> FindingOut:
    finding = await finding_svc.get(session, finding_id)
    if finding is None:
        raise Problem(404, "Not found", f"unknown finding: {finding_id}")
    eff = await finding_svc.effective(session, finding)
    return _to_out(eff, redact_poc=not can_view_poc(principal))


@router.patch(
    "/findings/{finding_id}/triage",
    response_model=TriageOut,
    dependencies=[Depends(requires(Role.triager))],
)
async def triage(
    finding_id: str, body: TriageRequest, session: SessionDep, principal: PrincipalDep
) -> TriageOut:
    record = await finding_svc.triage(
        session,
        finding_id=finding_id,
        actor_id=principal.user_id,
        status=body.status,
        severity_override=body.severity_override,
        reason=body.reason,
    )
    return TriageOut.model_validate(record, from_attributes=True)


@router.patch(
    "/findings/{finding_id}/assignee",
    response_model=TriageOut,
    dependencies=[Depends(requires(Role.triager))],
)
async def assign(
    finding_id: str, body: AssignRequest, session: SessionDep, principal: PrincipalDep
) -> TriageOut:
    record = await finding_svc.assign(
        session, finding_id=finding_id, actor_id=principal.user_id, assignee_id=body.assignee_id
    )
    return TriageOut.model_validate(record, from_attributes=True)


@router.get("/findings/{finding_id}/history", response_model=list[HistoryEvent])
async def history(finding_id: str, session: SessionDep, _: PrincipalDep) -> list[HistoryEvent]:
    events = await finding_svc.history(session, finding_id)
    return [HistoryEvent.model_validate(e, from_attributes=True) for e in events]


# --- comments / collaboration (viewer may read + post) ---


@router.get("/findings/{finding_id}/comments", response_model=list[CommentOut])
async def list_comments(finding_id: str, session: SessionDep, _: PrincipalDep) -> list[CommentOut]:
    rows = await comment_svc.list_for_finding(session, finding_id)
    return [CommentOut.model_validate(c, from_attributes=True) for c in rows]


@router.post("/findings/{finding_id}/comments", response_model=CommentOut)
async def add_comment(
    finding_id: str, body: CommentCreate, session: SessionDep, principal: PrincipalDep
) -> CommentOut:
    comment = await comment_svc.add(
        session,
        finding_id=finding_id,
        author_id=principal.user_id,
        body=body.body,
        parent_id=body.parent_id,
        mentions=body.mentions,
    )
    return CommentOut.model_validate(comment, from_attributes=True)
