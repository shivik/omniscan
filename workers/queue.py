"""Job-queue abstraction.

``OMNISCAN_JOB_BACKEND`` selects how a created scan is executed:
  * ``inprocess`` (dev, default) — run in an asyncio background task in the API process.
  * ``arq`` (prod) — enqueue to Redis; dedicated arq workers (``workers/arq_worker.py``)
    pull and execute. ``arq`` is imported lazily and only required for this backend.

Either way the execution body (``engine.scheduler.execute_scan``) is identical and
idempotent, so a worker crash re-runs the job without duplicating findings.
"""

from __future__ import annotations

import asyncio
import logging

from core.config import get_settings

log = logging.getLogger("omniscan.queue")

_arq_pool = None  # lazily created arq Redis pool


async def _arq_enqueue(scan_id: str) -> None:
    global _arq_pool
    try:
        from arq import create_pool  # noqa: PLC0415  (optional prod dependency)
        from arq.connections import RedisSettings  # noqa: PLC0415
    except ImportError:
        log.error("job_backend=arq but 'arq' is not installed (pip install 'omniscan[prod]')")
        return
    if _arq_pool is None:
        _arq_pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
    await _arq_pool.enqueue_job("run_scan", scan_id)


def enqueue_scan(scan_id: str) -> None:
    """Dispatch a scan for execution per the configured backend."""
    backend = get_settings().job_backend
    if backend == "arq":
        # Fire-and-forget enqueue onto the running loop (API request context).
        asyncio.create_task(_arq_enqueue(scan_id))
        return
    # in-process default
    from engine.scheduler import execute_scan

    asyncio.create_task(execute_scan(scan_id))
