"""Scan planner — request -> ScanPlan.

Turns a validated scan request into the ordered set of adapter jobs to run, with
dependency edges (e.g. an IAST agent session must be live *before* the correlated
DAST run). **scope_guard runs here, first** — an unauthorized target fails during
planning, before any job is enqueued (SKILLS.md §1.1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from adapters import registry
from core import scope_guard
from core.enums import ScanClass


@dataclass
class PlannedJob:
    adapter: str
    scan_class: ScanClass
    depends_on: list[str] = field(default_factory=list)  # adapter names


@dataclass
class ScanPlan:
    scan_class: ScanClass
    jobs: list[PlannedJob]


def _requested_hosts(
    scan_class: ScanClass, source: dict[str, Any], target: dict[str, Any]
) -> list[str]:
    hosts: list[str] = []
    if target.get("base_url"):
        hosts.append(target["base_url"])
    if source.get("url"):
        url = source["url"]
        # git@host:org/repo -> host
        if url.startswith("git@"):
            hosts.append(url.split("@", 1)[1].split(":", 1)[0])
        else:
            hosts.append(urlparse(url).hostname or url)
    return hosts


def plan(
    *,
    scan_class: ScanClass,
    tools: list[str] | None,
    source: dict[str, Any],
    target: dict[str, Any],
    ownership_verified: bool,
    scope_allow: list[str],
    scope_deny: list[str],
) -> ScanPlan:
    # 1) Authorization + scope FIRST. No bypass.
    scope_guard.enforce(
        scan_class=scan_class,
        ownership_verified=ownership_verified,
        scope_allow=scope_allow,
        scope_deny=scope_deny,
        requested_hosts=_requested_hosts(scan_class, source, target),
    )

    # 2) Resolve adapters: requested tools, else class defaults.
    requested = tools or registry.default_tools(scan_class)
    if not requested:
        raise ValueError(f"no adapters available for scan_class {scan_class}")

    available = set(registry.names_for_class(scan_class))
    unknown = [t for t in requested if t not in available]
    if unknown:
        raise ValueError(f"tools not available for {scan_class}: {unknown}")

    # 3) Order + dependencies. SAST/RVD jobs are independent; IAST drives after agent
    #    session is live (modeled when IAST sessions are added).
    jobs = [PlannedJob(adapter=name, scan_class=scan_class) for name in requested]
    return ScanPlan(scan_class=scan_class, jobs=jobs)
