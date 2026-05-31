"""Stable fingerprints for dedup.

A fingerprint must be stable across re-scans so triage state carries over, and
identical across tools that find the same issue so they collapse into one Finding.
It is derived from rule + normalized location (file/symbol or route/param), never
from volatile data like line numbers alone or timestamps.
"""

from __future__ import annotations

import hashlib

from normalize.sarif import Result


def _location_key(result: Result) -> str:
    if not result.locations:
        return "noloc"
    loc = result.locations[0]
    parts: list[str] = []
    if loc.physicalLocation and loc.physicalLocation.artifactLocation:
        parts.append(loc.physicalLocation.artifactLocation.uri or "")
    for ll in loc.logicalLocations:
        parts.append(ll.fullyQualifiedName or ll.name or "")
    # DAST/IAST/RVD route/param/flow signals live in location.properties.
    for key in ("url", "route", "param", "sink", "composition_path"):
        if key in loc.properties:
            parts.append(f"{key}={loc.properties[key]}")
    return "|".join(p for p in parts if p) or "noloc"


def fingerprint(scan_class: str, result: Result) -> str:
    """Stable hash over (scan_class, ruleId, normalized location)."""
    basis = f"{scan_class}::{result.ruleId}::{_location_key(result)}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]
