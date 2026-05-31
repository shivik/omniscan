from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from adapters import registry

router = APIRouter(tags=["meta"])


@router.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok"}


@router.get("/api/v1/capabilities")
async def capabilities() -> dict[str, Any]:
    """Advertise the adapters available across every surface (CLI/API/dashboard)."""
    return {
        "adapters": [
            {"name": a.name, "scan_class": a.scan_class, "capabilities": a.capabilities}
            for a in registry.all_adapters()
        ]
    }
