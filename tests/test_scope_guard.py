"""scope_guard is load-bearing — these tests pin its non-negotiable behavior."""

from __future__ import annotations

import pytest

from core import scope_guard
from core.enums import ScanClass


def test_sast_local_checkout_allowed_without_network_scope():
    decision = scope_guard.check(
        scan_class=ScanClass.SAST,
        ownership_verified=False,
        scope_allow=[],
        scope_deny=[],
        requested_hosts=[],
    )
    assert decision.allowed


def test_dast_requires_ownership():
    decision = scope_guard.check(
        scan_class=ScanClass.DAST,
        ownership_verified=False,
        scope_allow=["*.staging.acme.test"],
        scope_deny=[],
        requested_hosts=["https://staging.acme.test"],
    )
    assert not decision.allowed


def test_dast_requires_allowlist():
    decision = scope_guard.check(
        scan_class=ScanClass.DAST,
        ownership_verified=True,
        scope_allow=[],
        scope_deny=[],
        requested_hosts=["https://staging.acme.test"],
    )
    assert not decision.allowed


def test_dast_rejects_host_outside_allowlist():
    decision = scope_guard.check(
        scan_class=ScanClass.DAST,
        ownership_verified=True,
        scope_allow=["*.staging.acme.test"],
        scope_deny=[],
        requested_hosts=["https://evil.example.com"],
    )
    assert not decision.allowed


def test_dast_in_scope_allowed():
    decision = scope_guard.check(
        scan_class=ScanClass.DAST,
        ownership_verified=True,
        scope_allow=["*.staging.acme.test"],
        scope_deny=["admin.staging.acme.test"],
        requested_hosts=["https://app.staging.acme.test"],
    )
    assert decision.allowed


def test_denylist_wins():
    decision = scope_guard.check(
        scan_class=ScanClass.DAST,
        ownership_verified=True,
        scope_allow=["*.staging.acme.test"],
        scope_deny=["admin.staging.acme.test"],
        requested_hosts=["https://admin.staging.acme.test"],
    )
    assert not decision.allowed


def test_rvd_against_target_needs_ownership():
    decision = scope_guard.check(
        scan_class=ScanClass.RVD,
        ownership_verified=False,
        scope_allow=["*.acme.test"],
        scope_deny=[],
        requested_hosts=["https://app.acme.test"],
    )
    assert not decision.allowed


def test_enforce_raises():
    with pytest.raises(scope_guard.ScopeViolation):
        scope_guard.enforce(
            scan_class=ScanClass.DAST,
            ownership_verified=False,
            scope_allow=[],
            scope_deny=[],
            requested_hosts=["https://x.test"],
        )
