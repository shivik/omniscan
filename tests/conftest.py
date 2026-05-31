from __future__ import annotations

import os
import tempfile

import pytest

# Point the app at an isolated temp SQLite db BEFORE any core module is imported.
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.environ["OMNISCAN_DATABASE_URL"] = f"sqlite+aiosqlite:///{_db_path}"
os.environ["OMNISCAN_OBJECT_STORE_URL"] = f"file://{tempfile.mkdtemp()}"
os.environ["OMNISCAN_BOOTSTRAP_ADMIN_TOKEN"] = "test-admin-token"


@pytest.fixture
async def client():
    import httpx

    from api.main import app
    from core.db import init_db
    from core.security import bootstrap

    await init_db()
    bootstrap()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        c.headers["Authorization"] = "Bearer test-admin-token"
        yield c
