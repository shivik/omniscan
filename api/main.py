"""OmniScan API — the single source of truth.

Everything is the API: the CLI, the dashboard, and CI are all thin clients over
these endpoints. Business logic lives in services/engine, never in routes.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.errors import register_exception_handlers
from api.routes import auth, findings, health, iast, projects, reports, scans
from core.db import init_db
from core.security import bootstrap

logging.basicConfig(
    level=logging.INFO, format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
)


@asynccontextmanager
async def lifespan(_: FastAPI):  # type: ignore[no-untyped-def]
    await init_db()  # dev: create tables. prod: Alembic migrations.
    bootstrap()  # register the dev admin token
    yield


app = FastAPI(
    title="OmniScan API",
    version="0.1.0",
    description="One-stop application security scanner orchestration (SAST/DAST/IAST/RVD).",
    lifespan=lifespan,
)

register_exception_handlers(app)

for r in (
    health.router,
    auth.router,
    projects.router,
    scans.router,
    findings.router,
    reports.router,
    iast.router,
):
    app.include_router(r)
