"""Contract tests for bandit, trivy, codeql, and zap adapters.

bandit + trivy additionally have docker-gated integration tests below. codeql + zap
images are huge/slow, so they are covered by SARIF contract tests only (the live
container run is documented as not executed here).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.dast.zap.adapter import ZapAdapter
from adapters.runner import DockerContainerRunner
from adapters.sast.bandit.adapter import BanditAdapter
from adapters.sast.codeql.adapter import CodeQLAdapter
from adapters.sast.trivy.adapter import TrivyAdapter
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIX = Path(__file__).parent / "fixtures"


def _docker() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _sast_req(ws: str) -> ScanRequest:
    return ScanRequest(
        scan_id="s",
        job_id="j",
        scan_class=ScanClass.SAST,
        project_id="p",
        tool="x",
        source={"type": "path", "path": ws},
        workspace_path=ws,
    )


# --- bandit -----------------------------------------------------------------
def test_bandit_parse_contract():
    findings = normalize_sarif(
        BanditAdapter().parse_output((FIX / "bandit_json.json").read_bytes()), ScanClass.SAST
    )
    rule_ids = {f.rule_id for f in findings}
    assert "B602" in rule_ids  # subprocess shell=True (HIGH)
    by = {f.rule_id: f for f in findings}
    assert by["B602"].severity == Severity.high
    assert not by["B602"].location["file"].startswith("/src/")


@pytest.mark.skipif(not _docker(), reason="docker not available")
def test_bandit_runs_in_container(tmp_path: Path):
    subprocess.run(
        [
            "docker",
            "build",
            "-q",
            "-t",
            "omniscan/bandit:0.1.0",
            str(Path(__file__).resolve().parents[2] / "deploy/scanners/bandit"),
        ],
        check=True,
        capture_output=True,
        timeout=300,
    )
    (tmp_path / "v.py").write_text("import subprocess\nsubprocess.call(c, shell=True)\n")
    a = BanditAdapter()
    req = _sast_req(str(tmp_path))
    raw = DockerContainerRunner().run(a, a.build_invocation(req), req)
    findings = normalize_sarif(a.parse_output(raw), ScanClass.SAST)
    assert any(f.rule_id == "B602" for f in findings)


# --- trivy (SCA) ------------------------------------------------------------
def test_trivy_parse_contract_maps_cvss():
    findings = normalize_sarif(
        TrivyAdapter().parse_output((FIX / "trivy_sarif.json").read_bytes()), ScanClass.SAST
    )
    assert findings
    # at least one critical (CVSS >= 9.0 lifted from security-severity)
    assert any(f.severity == Severity.critical for f in findings)


def test_trivy_declares_sca_egress():
    spec = TrivyAdapter().build_invocation(_sast_req("/tmp"))
    assert spec.network == "egress"  # SCA exception: advisory DB feeds


@pytest.mark.skipif(not _docker(), reason="docker not available")
def test_trivy_runs_in_container(tmp_path: Path):
    from adapters.runner import RunnerError

    (tmp_path / "requirements.txt").write_text("Django==2.0\n")
    a = TrivyAdapter()
    req = _sast_req(str(tmp_path))
    try:
        raw = DockerContainerRunner().run(a, a.build_invocation(req), req)
    except RunnerError as exc:
        # The advisory DB download is an environment concern (network/disk), not adapter
        # logic — which is covered by the contract test. Skip rather than fail.
        if any(s in str(exc) for s in ("download", "no space", "DB error", "timed out")):
            pytest.skip(f"trivy DB unavailable in this environment: {exc}")
        raise
    findings = normalize_sarif(a.parse_output(raw), ScanClass.SAST)
    assert findings, "trivy should find vulns in Django==2.0"


# --- codeql (SARIF contract only) ------------------------------------------
def test_codeql_parse_contract():
    findings = normalize_sarif(
        CodeQLAdapter().parse_output((FIX / "codeql_sarif.json").read_bytes()), ScanClass.SAST
    )
    assert findings
    f = findings[0]
    assert f.rule_id == "py/command-line-injection"
    assert f.severity == Severity.critical  # CVSS 9.8 lifted to cvss -> critical
    assert f.location["file"] == "app/handlers.py"  # /src/ stripped


# --- zap (SARIF contract only) ---------------------------------------------
def test_zap_parse_contract_redacts_url():
    findings = normalize_sarif(
        ZapAdapter().parse_output((FIX / "zap_sarif.json").read_bytes()), ScanClass.DAST
    )
    assert findings
    f = findings[0]
    assert f.rule_id == "40012"
    # URL is redacted (query string could carry a secret-shaped value)
    assert "ghp_shouldberedacted" not in str(f.location)
