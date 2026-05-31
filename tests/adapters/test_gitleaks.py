"""Gitleaks adapter tests.

* Contract test (always runs): parse a recorded gitleaks SARIF fixture, assert
  secrets normalize to high-severity Findings AND that no raw secret value leaks
  into the normalized output (golden rule #2).
* Integration test (skipped without Docker): run the pinned gitleaks image in an
  isolated container against a planted secret and assert it's detected + redacted.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.runner import DockerContainerRunner
from adapters.sast.gitleaks.adapter import GitleaksAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIXTURE = Path(__file__).parent / "fixtures" / "gitleaks_sarif.json"


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
        tool="gitleaks",
        source={"type": "path", "path": workspace},
        workspace_path=workspace,
    )


def test_parse_output_contract_and_redaction():
    adapter = GitleaksAdapter()
    raw = FIXTURE.read_bytes()
    sarif = adapter.parse_output(raw)
    findings = normalize_sarif(sarif, ScanClass.SAST)

    assert findings, "expected at least one secret finding"
    # Secrets are high severity by policy.
    assert all(f.severity == Severity.high for f in findings)
    # Paths rewritten to repo-relative.
    assert all(not f.location.get("file", "").startswith("/src/") for f in findings)
    # The raw planted secret must never appear in normalized output (was --redact'd).
    blob = " ".join(f.message + str(f.location) + str(f.extra) for f in findings)
    assert "wJalrXUtnFEMI" not in blob


def test_build_invocation_redacts_and_isolates():
    adapter = GitleaksAdapter()
    spec = adapter.build_invocation(_request("/tmp"))
    assert "--redact" in spec.args  # never emit raw secrets
    assert spec.network == "none"
    assert spec.success_exit_codes == (0, 1)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_gitleaks_detects_and_redacts_in_container(tmp_path: Path):
    (tmp_path / "leak.py").write_text('github_pat = "ghp_1234567890abcdefghijklmnopqrstuv1234"\n')
    adapter = GitleaksAdapter()
    req = _request(str(tmp_path))
    adapter.validate_inputs(req)
    spec = adapter.build_invocation(req)
    raw = DockerContainerRunner().run(adapter, spec, req)
    findings = normalize_sarif(adapter.parse_output(raw), ScanClass.SAST)
    assert findings, "gitleaks should detect the planted token"
    # Redacted: the literal token must not appear in the raw scanner output.
    assert b"ghp_1234567890abcdefghijklmnopqrstuv1234" not in raw
