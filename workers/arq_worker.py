"""arq worker — executes scans pulled from the Redis queue (prod job backend).

Run with:  uv run arq workers.arq_worker.WorkerSettings
(requires the ``prod`` extra and a reachable Redis at ``OMNISCAN_REDIS_URL``.)

The job body delegates to the same idempotent ``execute_scan`` the in-process backend
uses, so behavior is identical regardless of where it runs.
"""

from __future__ import annotations

from typing import Any

from core.config import get_settings


async def run_scan(ctx: dict[str, Any], scan_id: str) -> None:
    from engine.scheduler import execute_scan

    await execute_scan(scan_id)


def _redis_settings() -> Any:
    from arq.connections import RedisSettings

    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    """arq worker configuration (discovered by the ``arq`` CLI)."""

    functions = [run_scan]

    @staticmethod
    def redis_settings() -> Any:  # arq reads this attribute
        return _redis_settings()
