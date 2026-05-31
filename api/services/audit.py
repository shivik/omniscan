"""Audit logging — immutable record of who did what (already redacted)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from core.models import AuditLog
from core.redact import redact


async def record(
    session: AsyncSession,
    *,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditLog(
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=redact(detail or {}),
        )
    )
