"""Webhooks: CRUD, signed outbound delivery on scan.completed, signed inbound trigger."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

from api.services import webhooks


async def _wait_completed(client, scan_id: str, timeout: float = 15.0) -> dict:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        scan = (await client.get(f"/api/v1/scans/{scan_id}")).json()
        if scan["status"] in {"completed", "failed", "cancelled"}:
            return scan
        await asyncio.sleep(0.2)
    raise AssertionError("scan did not finish")


def test_signature_roundtrip():
    sig = webhooks.sign("s3cr3t", b'{"a":1}')
    assert sig.startswith("sha256=")
    assert webhooks.verify("s3cr3t", b'{"a":1}', sig)
    assert not webhooks.verify("s3cr3t", b'{"a":1}', "sha256=deadbeef")
    assert not webhooks.verify("wrong", b'{"a":1}', sig)


async def test_webhook_crud_hides_secret(client):
    proj = (
        await client.post("/api/v1/projects", json={"name": "wh", "slug": f"wh-{os.getpid()}"})
    ).json()
    created = (
        await client.post(
            "/api/v1/webhooks",
            json={
                "direction": "outbound",
                "project_id": proj["id"],
                "target_url": "http://x.test/hook",
            },
        )
    ).json()
    assert created["signing_secret"].startswith("whsec_")  # returned once
    listed = (await client.get("/api/v1/webhooks")).json()
    row = next(h for h in listed if h["id"] == created["id"])
    assert "signing_secret" not in row  # never serialized again
    deleted = (await client.delete(f"/api/v1/webhooks/{created['id']}")).json()
    assert deleted["deleted"] is True


async def test_outbound_delivery_on_scan_completed(client, monkeypatch):
    captured: list[dict] = []

    async def fake_post(url: str, body: bytes, headers: dict) -> int:
        captured.append({"url": url, "body": body, "headers": headers})
        return 200

    monkeypatch.setattr(webhooks, "_post", fake_post)

    proj = (
        await client.post("/api/v1/projects", json={"name": "whd", "slug": f"whd-{os.getpid()}"})
    ).json()
    secret = (
        await client.post(
            "/api/v1/webhooks",
            json={
                "direction": "outbound",
                "project_id": proj["id"],
                "target_url": "http://recv.test/hook",
            },
        )
    ).json()["signing_secret"]

    ws = tempfile.mkdtemp()
    Path(ws, "v.py").write_text("eval(x)\n")  # noqa: ASYNC240 - test fixture file write
    scan = (
        await client.post(
            "/api/v1/scans",
            json={
                "scan_class": "SAST",
                "project_id": proj["id"],
                "source": {"type": "path", "path": ws},
                "tools": ["demoscan"],
            },
        )
    ).json()
    await _wait_completed(client, scan["id"])
    await asyncio.sleep(0.3)  # let the post-completion notification run

    assert captured, "expected an outbound webhook delivery"
    d = captured[-1]
    assert d["url"] == "http://recv.test/hook"
    assert d["headers"]["X-OmniScan-Event"] == "scan.completed"
    # signature must verify with the secret the receiver holds
    assert webhooks.verify(secret, d["body"], d["headers"]["X-OmniScan-Signature"])


async def test_inbound_trigger_requires_valid_signature(client):
    proj = (
        await client.post("/api/v1/projects", json={"name": "whi", "slug": f"whi-{os.getpid()}"})
    ).json()
    await client.post(
        f"/api/v1/projects/{proj['id']}/targets",
        json={
            "kind": "git",
            "identifier": "https://github.com/octocat/Hello-World",
            "scope_allow": ["github.com"],
            "ownership_verified": True,
        },
    )
    secret = (
        await client.post(
            "/api/v1/webhooks", json={"direction": "inbound", "project_id": proj["id"]}
        )
    ).json()["signing_secret"]
    wid = (await client.get("/api/v1/webhooks")).json()[0]["id"]

    body = b'{"ref":"refs/heads/main"}'
    # bad signature rejected
    bad = await client.post(
        f"/api/v1/webhooks/{wid}/inbound",
        content=body,
        headers={"X-OmniScan-Signature": "sha256=nope"},
    )
    assert bad.status_code == 401
    # valid signature triggers a scan
    ok = await client.post(
        f"/api/v1/webhooks/{wid}/inbound",
        content=body,
        headers={
            "X-OmniScan-Signature": webhooks.sign(secret, body),
            "Content-Type": "application/json",
        },
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["triggered"] is True and ok.json()["scan_id"].startswith("scan_")
