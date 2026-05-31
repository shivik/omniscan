"""Scheduler — execute a ScanPlan and drive the lifecycle.

Dev (``job_backend=inprocess``) runs the scan in an asyncio background task,
executing each adapter in a worker thread (adapters may be CPU-bound). Prod enqueues
to ``arq``/Redis and dedicated workers pull jobs — the execution body
(``execute_scan``) is identical and idempotent.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from adapters import registry
from adapters.base import ScanRequest
from adapters.runner import get_runner
from core import objectstore
from core.db import session_scope
from core.enums import JobStatus, ScanClass, ScanStatus, TriageStatus
from core.ids import new_id
from core.models import Finding, Scan, ScanJob, TriageRecord
from core.redact import redact
from engine import lifecycle, planner, workspace
from normalize.finding import NormalizedFinding, dedup, normalize_sarif

log = logging.getLogger("omniscan.scheduler")


def enqueue_scan(scan_id: str) -> None:
    """Schedule execution. In-process backend uses an asyncio task."""
    asyncio.create_task(execute_scan(scan_id))


async def execute_scan(scan_id: str) -> None:
    try:
        await _run(scan_id)
    except Exception as exc:  # noqa: BLE001 - top-level guard; record & mark failed
        log.exception("scan %s failed", scan_id)
        await _fail(scan_id, str(exc))


async def _run(scan_id: str) -> None:
    # --- load scan + scope context ---
    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None:
            return
        if scan.status != ScanStatus.queued:
            return  # already being processed / terminal
        req = scan.request
        scan_class = ScanClass(scan.scan_class)
        project_id = scan.project_id
        scope = req.get("_scope", {})
        lifecycle.assert_scan_transition(ScanStatus(scan.status), ScanStatus.planning)
        scan.status = ScanStatus.planning

    # --- plan (scope_guard runs here, again — defense in depth) ---
    plan = planner.plan(
        scan_class=scan_class,
        tools=req.get("tools"),
        source=req.get("source", {}),
        target=req.get("target", {}),
        ownership_verified=scope.get("ownership_verified", False),
        scope_allow=scope.get("allow", []),
        scope_deny=scope.get("deny", []),
    )

    # --- prepare read-only workspace for source-based scans ---
    ws_path = (
        workspace.prepare(req.get("source", {}))
        if scan_class in {ScanClass.SAST, ScanClass.RVD}
        else None
    )

    # --- create job rows + move to running ---
    job_ids: list[str] = []
    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        assert scan is not None
        for pj in plan.jobs:
            job = ScanJob(scan_id=scan_id, adapter=pj.adapter, scan_class=pj.scan_class)
            s.add(job)
            await s.flush()
            job_ids.append(job.id)
        lifecycle.assert_scan_transition(ScanStatus(scan.status), ScanStatus.running)
        scan.status = ScanStatus.running

    # --- execute each job, collect normalized findings ---
    all_findings: list[NormalizedFinding] = []
    for job_id in job_ids:
        findings = await _run_job(job_id, scan_id, scan_class, project_id, req, ws_path)
        all_findings.extend(findings)

    # --- normalize phase: dedup across jobs + persist immutable findings ---
    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        assert scan is not None
        lifecycle.assert_scan_transition(ScanStatus(scan.status), ScanStatus.normalizing)
        scan.status = ScanStatus.normalizing

    deduped = dedup(all_findings)
    await _persist_findings(scan_id, project_id, deduped)

    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        assert scan is not None
        lifecycle.assert_scan_transition(ScanStatus(scan.status), ScanStatus.completed)
        scan.status = ScanStatus.completed


async def _run_job(
    job_id: str,
    scan_id: str,
    scan_class: ScanClass,
    project_id: str,
    req: dict[str, Any],
    ws_path: str | None,
) -> list[NormalizedFinding]:
    async with session_scope() as s:
        job = await s.get(ScanJob, job_id)
        assert job is not None
        adapter_name = job.adapter
        lifecycle.assert_job_transition(JobStatus(job.status), JobStatus.running)
        job.status = JobStatus.running

    adapter = registry.get(adapter_name)
    scan_request = ScanRequest(
        scan_id=scan_id,
        job_id=job_id,
        scan_class=scan_class,
        project_id=project_id,
        tool=adapter_name,
        source=req.get("source", {}),
        target=req.get("target", {}),
        scope_allow=req.get("_scope", {}).get("allow", []),
        scope_deny=req.get("_scope", {}).get("deny", []),
        auth_ref=req.get("auth", {}).get("ref"),
        options=req.get("options", {})
        | (req.get("rvd", {}) if scan_class is ScanClass.RVD else {}),
        workspace_path=ws_path,
    )

    try:
        adapter.validate_inputs(scan_request)
        spec = adapter.build_invocation(scan_request)
        runner = get_runner(adapter)
        # Adapters may be CPU-bound; run off the event loop.
        raw = await asyncio.to_thread(runner.run, adapter, spec, scan_request)
        raw_ref = objectstore.put(f"raw/{job_id}.json", raw)
        sarif = adapter.parse_output(raw)
        normalized = normalize_sarif(sarif, scan_class)
    except Exception as exc:  # noqa: BLE001
        async with session_scope() as s:
            job = await s.get(ScanJob, job_id)
            assert job is not None
            job.status = JobStatus.failed
            job.error = str(redact(str(exc)))
        log.warning("job %s (%s) failed: %s", job_id, adapter_name, redact(str(exc)))
        return []

    async with session_scope() as s:
        job = await s.get(ScanJob, job_id)
        assert job is not None
        job.raw_output_ref = raw_ref
        lifecycle.assert_job_transition(JobStatus(job.status), JobStatus.normalizing)
        job.status = JobStatus.normalizing
        lifecycle.assert_job_transition(JobStatus(job.status), JobStatus.completed)
        job.status = JobStatus.completed
    return normalized


async def _persist_findings(
    scan_id: str, project_id: str, findings: list[NormalizedFinding]
) -> None:
    async with session_scope() as s:
        for nf in findings:
            finding = Finding(
                scan_id=scan_id,
                project_id=project_id,
                scan_class=nf.scan_class,
                fingerprint=nf.fingerprint,
                rule_id=nf.rule_id,
                title=nf.title,
                message=nf.message,
                severity=nf.severity,
                location=nf.location,
                sources=nf.sources,
                extra=nf.extra,
                chainability_score=nf.chainability_score,
            )
            s.add(finding)
            await s.flush()
            # RVD findings default to embargoed status until a triager reviews them.
            if nf.scan_class is ScanClass.RVD:
                s.add(
                    TriageRecord(
                        id=new_id("tri"),
                        finding_id=finding.id,
                        status=TriageStatus.embargoed,
                        actor_id="system",
                        reason="RVD finding embargoed pending triage",
                    )
                )


async def _fail(scan_id: str, message: str) -> None:
    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None or lifecycle.is_terminal_scan(ScanStatus(scan.status)):
            return
        scan.status = ScanStatus.failed
        scan.error = str(redact(message))
