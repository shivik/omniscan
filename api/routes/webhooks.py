from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request

from api.deps import PrincipalDep, SessionDep, requires
from api.errors import Problem
from api.schemas.models import WebhookCreate, WebhookCreated, WebhookOut
from api.services import webhooks
from core.enums import Role
from core.models import Webhook

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


@router.post("", response_model=WebhookCreated, dependencies=[Depends(requires(Role.scanner))])
async def create_webhook(body: WebhookCreate, session: SessionDep) -> WebhookCreated:
    try:
        hook, secret = await webhooks.create(
            session,
            direction=body.direction,
            project_id=body.project_id,
            target_url=body.target_url,
            events=body.events,
        )
    except webhooks.WebhookError as exc:
        raise Problem(400, "Invalid request", str(exc), "urn:omniscan:validation") from exc
    return WebhookCreated(
        id=hook.id,
        direction=hook.direction,
        project_id=hook.project_id,
        target_url=hook.target_url,
        events=hook.events,
        active=hook.active,
        created_at=hook.created_at,
        signing_secret=secret,  # returned once
    )


@router.get("", response_model=list[WebhookOut])
async def list_webhooks(session: SessionDep, _: PrincipalDep) -> list[WebhookOut]:
    return [
        WebhookOut.model_validate(h, from_attributes=True)
        for h in await webhooks.list_webhooks(session)
    ]


@router.delete("/{webhook_id}", dependencies=[Depends(requires(Role.scanner))])
async def delete_webhook(webhook_id: str, session: SessionDep) -> dict[str, bool]:
    return {"deleted": await webhooks.delete(session, webhook_id)}


@router.post("/{webhook_id}/inbound")
async def inbound(
    webhook_id: str,
    request: Request,
    session: SessionDep,
    x_omniscan_signature: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Signature-verified trigger. No bearer token — authenticated by HMAC signature
    over the raw body using the webhook's signing secret (like a git provider hook)."""
    hook = await session.get(Webhook, webhook_id)
    if hook is None or hook.direction != "inbound":
        raise Problem(404, "Not found", "unknown inbound webhook")
    raw = await request.body()
    if not webhooks.verify(hook.signing_secret, raw, x_omniscan_signature):
        raise Problem(401, "Unauthorized", "invalid webhook signature", "urn:omniscan:webhook")
    import json

    payload = json.loads(raw or b"{}")
    try:
        scan = await webhooks.trigger_inbound(session, hook, payload)
    except webhooks.WebhookError as exc:
        raise Problem(400, "Invalid request", str(exc), "urn:omniscan:webhook") from exc
    # enqueue after commit
    from engine import scheduler

    scan_id = scan.id
    request.state.enqueue_scan_id = scan_id  # noqa: (kept for clarity)
    scheduler.enqueue_scan(scan_id)
    return {"triggered": True, "scan_id": scan_id}
