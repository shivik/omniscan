"""Scope guard — Golden Rule #1, load-bearing.

Runs FIRST on every scan, before any job is enqueued. A scan may only run against
targets the requester is authorized for: verified ownership + an explicit scope
allowlist. There is no bypass. Scanning out-of-scope hosts is a legal/safety
problem, not a feature.

DAST/IAST/RVD can hit live systems or find weaponizable flaws, so the gate is
strict: no allowlist -> no scan; ownership unverified -> no scan; any requested
host/path not matching the allowlist (or matching the denylist) -> rejected.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import urlparse

from core.enums import ScanClass


class ScopeViolation(Exception):
    """Raised when a scan request falls outside its authorized scope."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


def _host_of(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower()


def _matches_any(host: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(host, p.lower()) for p in patterns)


def check(
    *,
    scan_class: ScanClass,
    ownership_verified: bool,
    scope_allow: list[str],
    scope_deny: list[str],
    requested_hosts: list[str],
) -> ScopeDecision:
    """Authorize a scan. Returns a decision; callers must raise on ``allowed=False``.

    Rules:
      * Ownership must be verified for any class that can touch a live system or
        produce weaponizable output (DAST, IAST, RVD). SAST on a checkout still
        requires the target to be registered, but is less dangerous.
      * An allowlist is mandatory for network-touching classes.
      * Every requested host must match the allowlist and miss the denylist.
    """
    # Classes that can touch a live system or produce weaponizable output must run
    # only on assets whose ownership is verified — even when the run is source-only
    # (e.g. RVD over a checkout you must own).
    dangerous_class = scan_class in {ScanClass.DAST, ScanClass.IAST, ScanClass.RVD}

    if dangerous_class and not ownership_verified:
        return ScopeDecision(False, f"{scan_class}: target ownership is not verified")

    # An allowlist is mandatory whenever we will actually reach network hosts.
    if requested_hosts and not scope_allow:
        return ScopeDecision(
            False, f"{scan_class}: no scope allowlist — refusing to scan network hosts"
        )

    for host in requested_hosts:
        h = _host_of(host)
        if scope_deny and _matches_any(h, scope_deny):
            return ScopeDecision(False, f"host '{h}' matches denylist")
        if scope_allow and not _matches_any(h, scope_allow):
            return ScopeDecision(False, f"host '{h}' is outside the allowlist")

    return ScopeDecision(True, "in scope")


def enforce(**kwargs: object) -> None:
    """Convenience wrapper that raises ``ScopeViolation`` on denial."""
    decision = check(**kwargs)  # type: ignore[arg-type]
    if not decision.allowed:
        raise ScopeViolation(decision.reason)
