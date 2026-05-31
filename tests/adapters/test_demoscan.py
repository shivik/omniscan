"""Adapter contract test: native output -> SARIF -> Finding against a fixture."""

from __future__ import annotations

from pathlib import Path

from adapters.base import ScanRequest
from adapters.sast.demoscan.adapter import DemoScanAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif


def _request(workspace: str) -> ScanRequest:
    return ScanRequest(
        scan_id="scan_test",
        job_id="job_test",
        scan_class=ScanClass.SAST,
        project_id="proj_test",
        tool="demoscan",
        source={"type": "path", "path": workspace},
        workspace_path=workspace,
    )


def test_demoscan_finds_insecure_patterns(tmp_path: Path):
    target = tmp_path / "vuln.py"
    target.write_text(
        "\n".join(
            [
                "import hashlib, pickle, subprocess",
                "password = 'hunter2'",
                "subprocess.run(cmd, shell=True)",
                "data = pickle.loads(blob)",
                "h = hashlib.md5(x)",
            ]
        )
    )
    adapter = DemoScanAdapter()
    req = _request(str(tmp_path))
    adapter.validate_inputs(req)

    raw = adapter.run_native(req)
    sarif = adapter.parse_output(raw)
    findings = normalize_sarif(sarif, ScanClass.SAST)

    rule_ids = {f.rule_id for f in findings}
    assert {"DS002", "DS003", "DS004", "DS005"}.issubset(rule_ids)
    # high-severity rules map correctly
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["DS002"].severity == Severity.high
    assert by_rule["DS005"].severity == Severity.low


def test_demoscan_rejects_missing_workspace():
    adapter = DemoScanAdapter()
    req = _request("/nonexistent/path/xyz")
    try:
        adapter.validate_inputs(req)
    except ValueError:
        return
    raise AssertionError("expected ValueError for missing workspace")
