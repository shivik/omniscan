"""Reporter — ships runtime events to the OmniScan collector.

The agent never opens an inbound port; it only makes outbound POSTs to the collector,
authenticated with the per-session collector token. Events are buffered and flushed in
small batches. Raw tainted values are never sent — evidence is redacted to a hint.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Protocol


class Reporter(Protocol):
    def report(self, event: dict[str, Any]) -> None: ...
    def flush(self) -> None: ...


class HttpReporter:
    """Default reporter — POSTs to /api/v1/iast/sessions/{id}/events via httpx."""

    def __init__(self, collector_url: str, session_id: str, token: str, batch: int = 10) -> None:
        self._url = collector_url.rstrip("/") + f"/api/v1/iast/sessions/{session_id}/events"
        self._token = token
        self._batch = batch
        self._buf: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def report(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._buf.append(event)
            if len(self._buf) >= self._batch:
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buf:
            return
        events, self._buf = self._buf, []
        try:
            import httpx

            httpx.post(
                self._url,
                json={"events": events},
                headers={"X-OmniScan-IAST-Token": self._token},
                timeout=10.0,
            )
        except Exception:
            # Telemetry must never crash the host app. Drop on failure.
            pass


class BufferReporter:
    """In-process reporter (no network) — used for tests and embedding."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def report(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def flush(self) -> None:  # nothing to flush
        pass


def from_env() -> Reporter | None:
    url = os.environ.get("OMNISCAN_COLLECTOR_URL")
    sid = os.environ.get("OMNISCAN_IAST_SESSION")
    token = os.environ.get("OMNISCAN_IAST_TOKEN")
    if url and sid and token:
        return HttpReporter(url, sid, token)
    return None
