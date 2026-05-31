"""IAST session lifecycle (SKILLS.md §4).

Create a session → the platform issues a session id, a short-lived collector token
(stored by reference; the plaintext is returned once to the caller for agent
injection) and a runtime-specific injection snippet. The agent attaches to the
running app and streams telemetry to the collector. Finalize flushes + tears down.

What is real here: the session lifecycle, token issuance, expiry, scope-gating, and
the injection snippet. What is NOT built (and cannot be faked): the language agent
that instruments the running app and the collector that ingests runtime taint flows
— that requires a real per-runtime agent (JVM ``-javaagent``, Python/Node hooks).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.enums import IastSessionStatus, ScanClass, ScanStatus
from core.ids import new_id
from core.models import Finding, IastSession, Project, Scan
from normalize.finding import NormalizedFinding, dedup, normalize_sarif
from normalize.sarif import Location, Message, Result, Run, SarifLog, Tool, ToolComponent

_DEFAULT_TTL = timedelta(hours=2)

_SNIPPETS = {
    "jvm": "java -javaagent:/opt/omniscan/iast-agent.jar "
    "-Domniscan.session={sid} -Domniscan.collector=$OMNISCAN_COLLECTOR_URL -jar app.jar",
    "python": "OMNISCAN_IAST_SESSION={sid} python -m omniscan_iast.bootstrap your_app:app",
    "node": "node -r @omniscan/iast-agent/register app.js  # OMNISCAN_IAST_SESSION={sid}",
    "dotnet": "CORECLR_PROFILER=omniscan OMNISCAN_IAST_SESSION={sid} dotnet App.dll",
    "go": "omniscan-iast run --session {sid} -- ./app  # requires build-time instrumentation",
}


class IastError(Exception):
    pass


def injection_snippet(runtime: str, session_id: str) -> str:
    template = _SNIPPETS.get(runtime)
    if template is None:
        raise IastError(f"unsupported runtime: {runtime} (expected one of {sorted(_SNIPPETS)})")
    return template.format(sid=session_id)


async def create_session(
    session: AsyncSession, *, project_id: str, runtime: str
) -> tuple[IastSession, str, str]:
    """Create a session. Returns (record, plaintext_collector_token, injection_snippet).

    The plaintext token is returned ONCE for agent injection; only a reference is
    persisted. The agent streams to the collector with this token; it never opens an
    inbound port and the session expires.
    """
    if await session.get(Project, project_id) is None:
        raise IastError(f"unknown project: {project_id}")
    if runtime not in _SNIPPETS:
        raise IastError(f"unsupported runtime: {runtime}")

    sid = new_id("sess")
    token = "iastk_" + secrets.token_urlsafe(32)  # short-lived collector token
    token_ref = f"ref://iast/{sid}/collector-token"  # reference persisted, not the token

    # Findings stream into a dedicated IAST scan for this session.
    scan = Scan(
        project_id=project_id,
        scan_class=ScanClass.IAST,
        status=ScanStatus.running,
        request={"iast_session": sid, "runtime": runtime},
    )
    session.add(scan)
    await session.flush()

    record = IastSession(
        id=sid,
        project_id=project_id,
        runtime=runtime,
        status=IastSessionStatus.active,
        collector_token_ref=token_ref,
        collector_token_hash=hashlib.sha256(token.encode()).hexdigest(),
        scan_id=scan.id,
        expires_at=datetime.now(UTC) + _DEFAULT_TTL,
    )
    session.add(record)
    await session.flush()
    return record, token, injection_snippet(runtime, sid)


def _as_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes even for tz-aware columns; treat naive as UTC.
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


async def get_session(session: AsyncSession, session_id: str) -> IastSession | None:
    record = await session.get(IastSession, session_id)
    if record is None:
        return None
    # Lazily reflect expiry.
    if record.status == IastSessionStatus.active and _as_utc(record.expires_at) < datetime.now(UTC):
        record.status = IastSessionStatus.expired
    return record


async def is_live(session: AsyncSession, session_id: str) -> bool:
    record = await get_session(session, session_id)
    return record is not None and record.status == IastSessionStatus.active


async def finalize_session(session: AsyncSession, session_id: str) -> IastSession:
    record = await session.get(IastSession, session_id)
    if record is None:
        raise IastError(f"unknown IAST session: {session_id}")
    if record.status == IastSessionStatus.active:
        record.status = IastSessionStatus.finalized
        record.finalized_at = datetime.now(UTC)
    if record.scan_id is not None:
        scan = await session.get(Scan, record.scan_id)
        if scan is not None and scan.status == ScanStatus.running:
            scan.status = ScanStatus.completed
    return record


async def authenticate_collector(
    session: AsyncSession, session_id: str, token: str | None
) -> IastSession:
    """Validate the agent's collector token against the session (constant-time)."""
    record = await get_session(session, session_id)
    if record is None:
        raise IastError(f"unknown IAST session: {session_id}")
    if record.status != IastSessionStatus.active:
        raise IastError(f"IAST session is not active ({record.status})")
    expected = record.collector_token_hash
    got = hashlib.sha256((token or "").encode()).hexdigest()
    if not secrets.compare_digest(expected, got):
        raise IastError("invalid collector token")
    return record


def _event_to_result(event: dict[str, Any]) -> Result:
    sink = str(event.get("sink", "sink"))
    severity = str(event.get("severity", "medium")).lower()
    level = {"critical": "error", "high": "error", "medium": "warning"}.get(severity, "note")
    tainted = bool(event.get("tainted", False))
    route = event.get("route")
    param = event.get("param")
    flow = f"{param or 'request'} → {sink}" if tainted else f"reached {sink}"
    return Result(
        ruleId=str(event.get("rule_id", f"IAST-{sink}")),
        level=level,
        message=Message(
            text=f"Runtime: tainted source reached sink {sink}"
            if tainted
            else f"Runtime: sink {sink} exercised"
        ),
        locations=[
            Location(
                properties={
                    "file": event.get("file"),
                    "start_line": event.get("line"),
                    "symbol": event.get("function"),
                    "route": route,
                    "param": param,
                    "sink": sink,
                    "runtime_flow": flow,
                    "tainted": tainted,
                }
            )
        ],
        properties={"severity": severity, "tainted": tainted, "evidence": event.get("evidence")},
    )


async def ingest_events(
    session: AsyncSession, record: IastSession, events: list[dict[str, Any]]
) -> int:
    """Convert agent-reported runtime events into IAST Findings (dedup by fingerprint).

    This is the collector. The agent observes source->sink flows from inside the running
    app and POSTs them here; we normalize them through the same SARIF -> Finding pipeline
    as every other scan class and attach them to the session's IAST scan.
    """
    if record.scan_id is None:
        raise IastError("session has no collection scan")
    sarif = SarifLog(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="omniscan-iast", version="0.1.0")),
                results=[_event_to_result(e) for e in events],
            )
        ]
    )
    normalized: list[NormalizedFinding] = dedup(normalize_sarif(sarif, ScanClass.IAST))

    # Skip fingerprints already recorded for this scan (idempotent re-emission).
    existing = set(
        (
            await session.scalars(
                select(Finding.fingerprint).where(Finding.scan_id == record.scan_id)
            )
        ).all()
    )
    added = 0
    for nf in normalized:
        if nf.fingerprint in existing:
            continue
        session.add(
            Finding(
                scan_id=record.scan_id,
                project_id=record.project_id,
                scan_class=ScanClass.IAST,
                fingerprint=nf.fingerprint,
                rule_id=nf.rule_id,
                title=nf.title,
                message=nf.message,
                severity=nf.severity,
                location=nf.location,
                sources=["iast-agent"],
                extra=nf.extra,
            )
        )
        existing.add(nf.fingerprint)
        added += 1
    return added
