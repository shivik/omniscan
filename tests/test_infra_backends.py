"""Pluggable production backends: object store (file/S3), secrets (env/Vault),
and the job queue (inprocess/arq) — selection + routing logic.

Live S3/Vault/Redis aren't exercised here (they need external services); these tests
pin the selection logic and graceful failure when a backend's dep/service is absent.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from core import objectstore, secrets


# ---- object store ----
def test_objectstore_file_roundtrip():
    ref = objectstore.put("test/roundtrip.bin", b"hello-omniscan")
    assert ref == "obj://test/roundtrip.bin"
    assert objectstore.get(ref) == b"hello-omniscan"


def test_objectstore_s3_scheme_selected(monkeypatch):
    fake = types.SimpleNamespace(object_store_url="s3://my-bucket/prefix/")
    monkeypatch.setattr(objectstore, "get_settings", lambda: fake)
    assert objectstore._scheme() == "s3"
    try:
        import boto3  # noqa: F401
    except ImportError:
        # without the prod extra, S3 ops fail with a clear, actionable error
        with pytest.raises(RuntimeError, match="boto3"):
            objectstore.put("k", b"x")


# ---- secrets ----
def test_secrets_env_backend_resolves(monkeypatch):
    monkeypatch.setenv("OMNISCAN_SECRET_ACME_LOGIN", "s3kret")
    backend = secrets.EnvSecretsBackend()
    assert backend.resolve("vault://omniscan/acme/login") == "s3kret"


def test_secrets_vault_backend_selected(monkeypatch):
    fake = types.SimpleNamespace(secrets_backend="vault")
    monkeypatch.setattr(secrets, "get_settings", lambda: fake)
    # Vault needs hvac + VAULT_ADDR/TOKEN; absent either, construction errors clearly.
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    with pytest.raises(RuntimeError):
        secrets.get_secrets_backend()


# ---- job queue routing ----
def _capture_tasks(monkeypatch, q):
    captured: list[str] = []

    def fake_create_task(coro):  # type: ignore[no-untyped-def]
        captured.append(getattr(coro, "__qualname__", str(coro)))
        coro.close()  # avoid "never awaited" warning
        return types.SimpleNamespace()

    monkeypatch.setattr(q.asyncio, "create_task", fake_create_task)
    return captured


def test_queue_inprocess_routes_to_execute_scan(monkeypatch):
    import workers.queue as q

    monkeypatch.setattr(q, "get_settings", lambda: types.SimpleNamespace(job_backend="inprocess"))
    captured = _capture_tasks(monkeypatch, q)
    q.enqueue_scan("scan_x")
    assert any("execute_scan" in c for c in captured)


def test_queue_arq_routes_to_arq_enqueue(monkeypatch):
    import workers.queue as q

    monkeypatch.setattr(
        q, "get_settings", lambda: types.SimpleNamespace(job_backend="arq", redis_url="redis://x")
    )
    captured = _capture_tasks(monkeypatch, q)
    q.enqueue_scan("scan_y")
    assert any("_arq_enqueue" in c for c in captured)


def test_arq_worker_run_scan_delegates(monkeypatch):
    """The arq job body delegates to the same idempotent execute_scan."""
    import workers.arq_worker as w

    called: list[str] = []

    async def fake_execute(scan_id: str) -> None:
        called.append(scan_id)

    monkeypatch.setattr("engine.scheduler.execute_scan", fake_execute)
    asyncio.run(w.run_scan({}, "scan_z"))
    assert called == ["scan_z"]
