"""SARIF -> internal Finding conversion + dedup.

Produces ``NormalizedFinding`` value objects (not ORM rows) so the engine can
dedup across jobs before persisting. A Finding belongs to a Scan, not a ScanJob.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.enums import ScanClass, Severity
from normalize import severity as severity_map
from normalize.fingerprint import fingerprint
from normalize.sarif import Result, SarifLog


@dataclass
class NormalizedFinding:
    fingerprint: str
    scan_class: ScanClass
    rule_id: str
    title: str
    message: str
    severity: Severity
    location: dict[str, Any]
    sources: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    chainability_score: float = 0.0


def _location_dict(result: Result) -> dict[str, Any]:
    if not result.locations:
        return {}
    loc = result.locations[0]
    out: dict[str, Any] = dict(loc.properties)  # carries DAST url/param, IAST flow, RVD path
    if loc.physicalLocation:
        if loc.physicalLocation.artifactLocation:
            out["file"] = loc.physicalLocation.artifactLocation.uri
        if loc.physicalLocation.region:
            out["start_line"] = loc.physicalLocation.region.startLine
            out["end_line"] = loc.physicalLocation.region.endLine
    if loc.logicalLocations:
        ll = loc.logicalLocations[0]
        out["symbol"] = ll.fullyQualifiedName or ll.name
        if ll.kind:
            out["symbol_kind"] = ll.kind
    return out


def normalize_sarif(sarif: SarifLog, scan_class: ScanClass) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for run in sarif.runs:
        tool = run.tool.driver.name
        rule_titles = {
            r.id: (r.shortDescription.text if r.shortDescription else r.name)
            for r in run.tool.driver.rules
        }
        for result in run.results:
            sev = severity_map.resolve(level=result.level, properties=result.properties)
            findings.append(
                NormalizedFinding(
                    fingerprint=fingerprint(scan_class.value, result),
                    scan_class=scan_class,
                    rule_id=result.ruleId,
                    title=rule_titles.get(result.ruleId) or result.ruleId,
                    message=result.message.text,
                    severity=sev,
                    location=_location_dict(result),
                    sources=[tool],
                    extra={
                        k: v for k, v in result.properties.items() if k not in {"severity", "cvss"}
                    },
                    chainability_score=float(result.properties.get("chainability_score", 0.0)),
                )
            )
    return findings


def dedup(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Collapse findings sharing a fingerprint; merge sources, keep highest severity."""
    by_fp: dict[str, NormalizedFinding] = {}
    for f in findings:
        existing = by_fp.get(f.fingerprint)
        if existing is None:
            by_fp[f.fingerprint] = f
            continue
        for src in f.sources:
            if src not in existing.sources:
                existing.sources.append(src)
        if f.severity.rank > existing.severity.rank:
            existing.severity = f.severity
        existing.chainability_score = max(existing.chainability_score, f.chainability_score)
    return list(by_fp.values())
