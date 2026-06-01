from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from api.deps import PrincipalDep, SessionDep
from api.services import dashboard
from core.enums import ScanClass

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

_VALID_TREND = {7, 30, 90, 180, 365}


@router.get("/dashboard")
async def security_dashboard(
    session: SessionDep,
    _: PrincipalDep,
    trend: int = Query(default=30),
    engines: str | None = Query(default=None, description="comma-separated: SAST,DAST,IAST,RVD"),
) -> dict[str, Any]:
    trend_days = trend if trend in _VALID_TREND else 30
    selected: list[ScanClass] | None = None
    if engines:
        valid = {c.value for c in ScanClass}
        selected = [ScanClass(e) for e in engines.split(",") if e in valid]
    return await dashboard.build(session, engines=selected, trend_days=trend_days)
