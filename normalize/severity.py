"""Severity mapping — the one place non-standard tool scales become ``Severity``.

Add per-tool overrides here when a scanner uses an idiosyncratic scale.
"""

from __future__ import annotations

from typing import Any

from core.enums import Severity

# SARIF result.level -> Severity (default mapping).
_SARIF_LEVEL = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
    "none": Severity.info,
}

# Common textual severities scanners emit in result.properties["severity"].
_TEXTUAL = {
    "critical": Severity.critical,
    "blocker": Severity.critical,
    "high": Severity.high,
    "error": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "warning": Severity.medium,
    "low": Severity.low,
    "minor": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
    "note": Severity.info,
}


def from_sarif_level(level: str) -> Severity:
    return _SARIF_LEVEL.get(level.lower(), Severity.medium)


def from_text(value: str) -> Severity | None:
    return _TEXTUAL.get(value.strip().lower())


def from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.info


def resolve(*, level: str, properties: dict[str, Any]) -> Severity:
    """Prefer an explicit textual/CVSS severity in properties, else SARIF level."""
    if "cvss" in properties:
        try:
            return from_cvss(float(properties["cvss"]))
        except (TypeError, ValueError):
            pass
    if "severity" in properties and isinstance(properties["severity"], str):
        mapped = from_text(properties["severity"])
        if mapped is not None:
            return mapped
    return from_sarif_level(level)
