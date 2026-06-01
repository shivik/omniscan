"""Webhooks — trigger scans on push (inbound) + notify on completion (outbound).

Outbound: on subscribed events, POST a JSON payload to each matching webhook with an
HMAC-SHA256 signature header so the receiver can verify authenticity. Delivery is
best-effort and never blocks/crashes the platform.

Inbound: an external system POSTs a signed payload to trigger a scan on the webhook's
project (using the project's registered git target for scope).

The signing secret is OmniScan-owned, returned once at creation, never serialized again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets as _secrets
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.enums import ScanClass
from core.models import Project, Scan, Target, Webhook
from core.redact import redact

log = logging.getLogger("omniscan.webhooks")


class WebhookError(Exception):
    pass


def sign(secret: str, body: bytes) -> str:
    """GitHub-style signature: 'sha256=<hex hmac>'."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(secret, body), signature)


async def create(
    session: AsyncSession,
    *,
    direction: str,
    project_id: str | None,
    target_url: str | None,
    events: list[str],
) -> tuple[Webhook, str]:
    if direction not in ("outbound", "inbound"):
        raise WebhookError("direction must be 'outbound' or 'inbound'")
    if direction == "outbound" and not target_url:
        raise WebhookError("outbound webhooks require target_url")
    if project_id and await session.get(Project, project_id) is None:
        raise WebhookError(f"unknown project: {project_id}")
    secret = "whsec_" + _secrets.token_urlsafe(32)
    hook = Webhook(
        direction=direction,
        project_id=project_id,
        target_url=target_url,
        signing_secret=secret,
        events=events or ["scan.completed"],
    )
    session.add(hook)
    await session.flush()
    return hook, secret


async def list_webhooks(session: AsyncSession) -> list[Webhook]:
    return list(await session.scalars(select(Webhook).order_by(Webhook.created_at.desc())))


async def delete(session: AsyncSession, webhook_id: str) -> bool:
    hook = await session.get(Webhook, webhook_id)
    if hook is None:
        return False
    await session.delete(hook)
    return True


# Indirection so tests can capture deliveries without real network.
async def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, content=body, headers=headers)
        return resp.status_code


async def deliver(
    session: AsyncSession, *, event: str, project_id: str | None, payload: dict[str, Any]
) -> int:
    """Deliver an event to every matching active outbound webhook. Best-effort."""
    hooks = await list_webhooks(session)
    body = json.dumps(payload).encode()
    delivered = 0
    for hook in hooks:
        if hook.direction != "outbound" or not hook.active or not hook.target_url:
            continue
        if event not in hook.events:
            continue
        # match org-wide hooks (project_id None) or the specific project
        if hook.project_id is not None and hook.project_id != project_id:
            continue
        headers = {
            "Content-Type": "application/json",
            "X-OmniScan-Event": event,
            "X-OmniScan-Signature": sign(hook.signing_secret, body),
        }
        try:
            await _post(hook.target_url, body, headers)
            delivered += 1
        except Exception as exc:  # noqa: BLE001 - telemetry must not crash the platform
            log.warning("webhook %s delivery failed: %s", hook.id, redact(str(exc)))
    return delivered


async def notify_scan_completed(session: AsyncSession, scan: Scan) -> int:
    return await deliver(
        session,
        event="scan.completed",
        project_id=scan.project_id,
        payload={
            "event": "scan.completed",
            "scan_id": scan.id,
            "project_id": scan.project_id,
            "scan_class": str(scan.scan_class),
            "status": str(scan.status),
        },
    )


async def trigger_inbound(session: AsyncSession, hook: Webhook, payload: dict[str, Any]) -> Scan:
    """Create a SAST scan for an inbound webhook from a push-style payload.

    Uses the webhook project's registered git target for the repo + scope. The payload
    may supply a ``ref`` (branch/tag) to scan.
    """
    if hook.direction != "inbound" or hook.project_id is None:
        raise WebhookError("not an inbound webhook bound to a project")
    target = await session.scalar(
        select(Target).where(Target.project_id == hook.project_id, Target.kind == "git")
    )
    if target is None:
        raise WebhookError("project has no registered git target to scan")
    ref = str(payload.get("ref", "")).split("/")[-1] or None
    scan = Scan(
        project_id=hook.project_id,
        scan_class=ScanClass.SAST,
        request={
            "scan_class": "SAST",
            "source": {"type": "git", "url": target.identifier, **({"ref": ref} if ref else {})},
            "tools": None,
            "options": {},
            "auth": {},
            "_scope": {
                "allow": target.scope_allow,
                "deny": target.scope_deny,
                "ownership_verified": target.ownership_verified,
            },
        },
    )
    session.add(scan)
    await session.flush()
    return scan
