"""Clair container-image SCA adapter — contract tests.

Clair is a heavy multi-service stack (server + Postgres + GBs of feeds), so the live
scan is not run here; the report→SARIF normalization and isolation contract are tested.
A full compose stack lives in deploy/scanners/clair/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.sast.clair.adapter import ClairAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIX = Path(__file__).parent / "fixtures" / "clair_report.json"


def _req(image: str | None) -> ScanRequest:
    src = {"type": "image", "image": image} if image else {"type": "image"}
    return ScanRequest(
        scan_id="s", job_id="j", scan_class=ScanClass.SAST, project_id="p", tool="clair", source=src
    )


def test_clair_parse_contract_maps_severity_and_location():
    findings = normalize_sarif(ClairAdapter().parse_output(FIX.read_bytes()), ScanClass.SAST)
    by_rule = {f.rule_id: f for f in findings}
    assert "CVE-2022-0778" in by_rule and "CVE-2021-22947" in by_rule
    assert by_rule["CVE-2021-22947"].severity == Severity.critical  # Clair "Critical"
    assert by_rule["CVE-2022-0778"].severity == Severity.high
    assert by_rule["CVE-2020-0000"].severity == Severity.info  # "Negligible" -> info
    # SCA findings are located by package, not file/line.
    loc = by_rule["CVE-2022-0778"].location
    assert loc["package"] == "openssl"
    assert loc["fixed_in_version"] == "1.1.1n-r0"


def test_clair_build_invocation_is_image_sca():
    spec = ClairAdapter().build_invocation(_req("alpine:3.18"))
    assert spec.network == "egress"  # reach Clair host + registry (SCA exception)
    assert "report" in spec.args and "alpine:3.18" in spec.args
    assert not spec.image.endswith(":latest")


def test_clair_requires_image_source():
    with pytest.raises(ValueError):
        ClairAdapter().validate_inputs(_req(None))
