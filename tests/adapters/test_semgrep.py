"""Semgrep adapter tests.

Two layers:
  * Contract test (always runs): parse a recorded semgrep SARIF fixture and assert
    the produced SARIF + normalized Findings match expectations. No Docker needed.
  * Integration test (skipped without Docker): actually run the pinned semgrep image
    in an isolated container against a tiny vulnerable repo and assert findings.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.runner import DockerContainerRunner
from adapters.sast.semgrep.adapter import SemgrepAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sarif.json"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _request(workspace: str) -> ScanRequest:
    return ScanRequest(
        scan_id="scan_t",
        job_id="job_t",
        scan_class=ScanClass.SAST,
        project_id="proj_t",
        tool="semgrep",
        source={"type": "path", "path": workspace},
        workspace_path=workspace,
    )


def test_parse_output_contract():
    adapter = SemgrepAdapter()
    raw = FIXTURE.read_bytes()
    sarif = adapter.parse_output(raw)
    findings = normalize_sarif(sarif, ScanClass.SAST)

    rule_ids = {f.rule_id for f in findings}
    assert "omniscan.python.subprocess-shell-true" in rule_ids
    assert "omniscan.python.weak-hash-md5" in rule_ids

    by_rule = {f.rule_id: f for f in findings}
    # rule defaultConfiguration.level lifted onto results: ERROR -> high, WARNING -> medium
    assert by_rule["omniscan.python.subprocess-shell-true"].severity == Severity.high
    assert by_rule["omniscan.python.weak-hash-md5"].severity == Severity.medium

    # absolute container path (/src/...) rewritten to repo-relative
    assert by_rule["omniscan.python.subprocess-shell-true"].location["file"] == "app.py"

    # human-readable title promoted from semgrep's fullDescription (not "Semgrep Finding: ...")
    deser = by_rule["omniscan.python.insecure-deserialization"]
    assert "Insecure deserialization" in deser.title
    assert not deser.title.startswith("Semgrep Finding")


def test_build_invocation_is_isolated_and_pinned():
    adapter = SemgrepAdapter()
    spec = adapter.build_invocation(_request("/tmp"))
    assert spec.network == "none"  # SAST: no network
    assert spec.read_only_root is True
    assert ":" in spec.image and not spec.image.endswith(":latest")  # pinned
    assert spec.success_exit_codes == (0, 1)  # findings-present is not a failure


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_semgrep_runs_in_container(tmp_path: Path):
    (tmp_path / "vuln.py").write_text(
        "import subprocess, pickle, hashlib\n"
        "def f(cmd, blob, x):\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    pickle.loads(blob)\n"
        "    hashlib.md5(x)\n"
        "    eval(x)\n"
    )
    adapter = SemgrepAdapter()
    req = _request(str(tmp_path))
    adapter.validate_inputs(req)
    spec = adapter.build_invocation(req)
    raw = DockerContainerRunner().run(adapter, spec, req)
    findings = normalize_sarif(adapter.parse_output(raw), ScanClass.SAST)
    rule_ids = {f.rule_id for f in findings}
    assert {
        "omniscan.python.subprocess-shell-true",
        "omniscan.python.insecure-deserialization",
        "omniscan.python.eval-call",
    }.issubset(rule_ids)
