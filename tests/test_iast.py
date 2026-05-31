"""IAST session lifecycle through the public API.

Exercises the real, complete part of IAST: session creation (token + injection
snippet issuance), retrieval, finalize, and that the plaintext collector token is
returned only once (a reference is persisted, not the token).
"""

from __future__ import annotations

import os


async def test_iast_session_lifecycle(client):
    proj = (
        await client.post("/api/v1/projects", json={"name": "iast", "slug": f"iast-{os.getpid()}"})
    ).json()

    # create
    resp = await client.post(
        "/api/v1/iast/sessions", json={"project_id": proj["id"], "runtime": "jvm"}
    )
    assert resp.status_code == 200, resp.text
    created = resp.json()
    sid = created["id"]
    assert created["status"] == "active"
    # one-time secrets are returned at creation
    assert created["collector_token"].startswith("iastk_")
    assert sid in created["injection_snippet"]
    assert "-javaagent" in created["injection_snippet"]

    # get — the token is NOT echoed back on subsequent reads
    got = (await client.get(f"/api/v1/iast/sessions/{sid}")).json()
    assert got["status"] == "active"
    assert "collector_token" not in got

    # finalize
    fin = (await client.post(f"/api/v1/iast/sessions/{sid}/finalize")).json()
    assert fin["status"] == "finalized"
    assert fin["finalized_at"] is not None


async def test_iast_unknown_runtime_rejected(client):
    proj = (
        await client.post(
            "/api/v1/projects", json={"name": "iast2", "slug": f"iast2-{os.getpid()}"}
        )
    ).json()
    resp = await client.post(
        "/api/v1/iast/sessions", json={"project_id": proj["id"], "runtime": "cobol"}
    )
    assert resp.status_code == 400, resp.text
