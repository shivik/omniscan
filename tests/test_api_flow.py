"""End-to-end: project -> target -> SAST scan -> findings -> triage -> comment.

Exercises the whole vertical slice through the public API (the single source of
truth), the same way the CLI/dashboard would.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest


async def _wait_completed(client, scan_id: str, timeout: float = 15.0) -> dict:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        scan = (await client.get(f"/api/v1/scans/{scan_id}")).json()
        if scan["status"] in {"completed", "failed", "cancelled"}:
            return scan
        await asyncio.sleep(0.2)
    raise AssertionError(f"scan {scan_id} did not finish in time")


@pytest.fixture
def vuln_repo():
    d = tempfile.mkdtemp(prefix="omniscan-vuln-")
    Path(d, "app.py").write_text(
        "import subprocess, pickle\n"
        "password = 'hunter2'\n"
        "subprocess.run(cmd, shell=True)\n"
        "obj = pickle.loads(data)\n"
    )
    return d


async def test_full_sast_flow(client, vuln_repo):
    # 1) project
    proj = (
        await client.post("/api/v1/projects", json={"name": "demo", "slug": f"demo-{os.getpid()}"})
    ).json()
    pid = proj["id"]

    # 2) SAST scan against a local checkout (no network scope needed)
    scan_resp = await client.post(
        "/api/v1/scans",
        json={
            "scan_class": "SAST",
            "project_id": pid,
            "source": {"type": "path", "path": vuln_repo},
            "tools": ["demoscan"],
        },
    )
    assert scan_resp.status_code == 200, scan_resp.text
    scan_id = scan_resp.json()["id"]

    # 3) it completes
    scan = await _wait_completed(client, scan_id)
    assert scan["status"] == "completed", scan

    # 4) findings exist and are readable
    findings = (await client.get("/api/v1/findings", params={"scan_id": scan_id})).json()
    assert findings, "expected findings from demoscan"
    rule_ids = {f["rule_id"] for f in findings}
    assert {"DS002", "DS003", "DS004"} & rule_ids

    target = findings[0]
    assert target["effective_status"] == "open"

    # 5) triage (additive — finding stays immutable)
    triaged = await client.patch(
        f"/api/v1/findings/{target['id']}/triage",
        json={"status": "false_positive", "reason": "test fixture"},
    )
    assert triaged.status_code == 200, triaged.text
    refetched = (await client.get(f"/api/v1/findings/{target['id']}")).json()
    assert refetched["effective_status"] == "false_positive"
    assert refetched["severity"] == target["severity"]  # underlying finding unchanged

    # 6) comment
    c = await client.post(
        f"/api/v1/findings/{target['id']}/comments", json={"body": "looking into this"}
    )
    assert c.status_code == 200, c.text

    # 7) history reflects the triage + comment
    history = (await client.get(f"/api/v1/findings/{target['id']}/history")).json()
    actions = {h["action"] for h in history}
    assert "triage" in actions and "comment" in actions


async def test_dast_without_scope_is_rejected(client):
    proj = (
        await client.post("/api/v1/projects", json={"name": "d2", "slug": f"d2-{os.getpid()}"})
    ).json()
    resp = await client.post(
        "/api/v1/scans",
        json={
            "scan_class": "DAST",
            "project_id": proj["id"],
            "target": {"base_url": "https://staging.example.test"},
        },
    )
    # no registered owned target + no allowlist -> scope_guard blocks at creation
    assert resp.status_code == 403, resp.text
    assert resp.json()["type"] == "urn:omniscan:scope"


async def test_rvd_findings_are_embargoed(client, vuln_repo):
    proj = (
        await client.post("/api/v1/projects", json={"name": "r1", "slug": f"r1-{os.getpid()}"})
    ).json()
    # RVD runs only on owned/authorized assets — register the repo as an owned target.
    await client.post(
        f"/api/v1/projects/{proj['id']}/targets",
        json={"kind": "git", "identifier": vuln_repo, "ownership_verified": True},
    )
    scan_resp = await client.post(
        "/api/v1/scans",
        json={
            "scan_class": "RVD",
            "project_id": proj["id"],
            "source": {"type": "path", "path": vuln_repo},
            "rvd": {"focus": ["isolation", "deserialization"], "budget": "1h"},
        },
    )
    assert scan_resp.status_code == 200, scan_resp.text
    scan = await _wait_completed(client, scan_resp.json()["id"])
    assert scan["status"] == "completed"
    findings = (await client.get("/api/v1/findings", params={"scan_id": scan["id"]})).json()
    # RVD may or may not raise heuristic hypotheses on a tiny repo; if it does,
    # they must be embargoed by default.
    for f in findings:
        assert f["effective_status"] == "embargoed"
