"""Scan/job state machine.

queued -> planning -> running -> normalizing -> completed | failed | cancelled
Jobs:   queued -> running -> normalizing -> completed | failed | cancelled

Transitions are validated so a buggy worker can't drive a scan into an impossible
state. Jobs are idempotent and resumable: re-running a job never duplicates
findings (dedup by fingerprint handles re-emission).
"""

from __future__ import annotations

from core.enums import JobStatus, ScanStatus

_SCAN_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.queued: {ScanStatus.planning, ScanStatus.cancelled, ScanStatus.failed},
    ScanStatus.planning: {ScanStatus.running, ScanStatus.failed, ScanStatus.cancelled},
    ScanStatus.running: {ScanStatus.normalizing, ScanStatus.failed, ScanStatus.cancelled},
    ScanStatus.normalizing: {ScanStatus.completed, ScanStatus.failed},
    ScanStatus.completed: set(),
    ScanStatus.failed: set(),
    ScanStatus.cancelled: set(),
}

_JOB_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.queued: {JobStatus.running, JobStatus.cancelled, JobStatus.failed},
    JobStatus.running: {JobStatus.normalizing, JobStatus.failed, JobStatus.cancelled},
    JobStatus.normalizing: {JobStatus.completed, JobStatus.failed},
    JobStatus.completed: set(),
    JobStatus.failed: set(),
    JobStatus.cancelled: set(),
}


class InvalidTransition(Exception):
    pass


def assert_scan_transition(current: ScanStatus, target: ScanStatus) -> None:
    if target not in _SCAN_TRANSITIONS[current]:
        raise InvalidTransition(f"scan: {current} -> {target} not allowed")


def assert_job_transition(current: JobStatus, target: JobStatus) -> None:
    if target not in _JOB_TRANSITIONS[current]:
        raise InvalidTransition(f"job: {current} -> {target} not allowed")


def is_terminal_scan(status: ScanStatus) -> bool:
    return not _SCAN_TRANSITIONS[status]
