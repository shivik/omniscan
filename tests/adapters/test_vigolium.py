"""Vigolium DAST adapter — contract tests.

The live image is heavy and a real scan needs a target, so the JSONL→SARIF logic is
contract-tested here; a vendored Dockerfile lives in deploy/scanners/vigolium/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.dast.vigolium.adapter import VigoliumAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIX = Path(__file__).parent / "fixtures" / "vigolium_jsonl.txt"


def _req(base_url: str, scope: list[str] | None = None) -> ScanRequest:
    return ScanRequest(
        scan_id="s",
        job_id="j",
        scan_class=ScanClass.DAST,
        project_id="p",
        tool="vigolium",
        target={"base_url": base_url},
        scope_allow=scope if scope is not None else ["*"],
    )


def test_vigolium_parse_contract_and_redaction():
    findings = normalize_sarif(VigoliumAdapter().parse_output(FIX.read_bytes()), ScanClass.DAST)
    by_rule = {f.rule_id: f for f in findings}
    assert "sqli.error-based" in by_rule and "xss.reflected" in by_rule
    assert by_rule["sqli.error-based"].severity == Severity.critical
    assert by_rule["headers.missing-csp"].severity == Severity.low
    # DAST findings located by URL/param.
    assert by_rule["xss.reflected"].location["param"] == "q"
    assert by_rule["sqli.error-based"].location["url"].startswith("http")
    # evidence may carry secrets → must be redacted everywhere we store it.
    blob = " ".join(f.message + str(f.location) + str(f.extra) for f in findings)
    assert "ghp_should0123456789" not in blob


def test_vigolium_build_invocation_native_scoped():
    spec = VigoliumAdapter().build_invocation(_req("https://staging.acme.test"))
    assert spec.network == "target"  # deterministic scan, egress to target only
    assert spec.args[0] == "scan"  # native mode, not the LLM `agent` mode
    assert "jsonl" in spec.args
    assert not spec.image.endswith(":latest")


def test_vigolium_requires_scope():
    with pytest.raises(ValueError):
        VigoliumAdapter().validate_inputs(_req("https://x.test", scope=[]))
