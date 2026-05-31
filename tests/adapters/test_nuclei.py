"""Nuclei DAST adapter tests.

* Contract test (always runs): parse recorded nuclei JSONL → SARIF → Findings;
  assert DAST findings carry URL/route location and no raw secret leaks.
* Integration test (skipped without Docker): build the vendored offline image, run
  nuclei against a controlled local target, assert detection + no raw secret in
  the scanner output.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from adapters.base import ScanRequest
from adapters.dast.nuclei.adapter import NucleiAdapter
from adapters.runner import DockerContainerRunner
from core.enums import ScanClass, Severity
from normalize.finding import normalize_sarif

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_jsonl.txt"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _request(base_url: str) -> ScanRequest:
    return ScanRequest(
        scan_id="scan_t",
        job_id="job_t",
        scan_class=ScanClass.DAST,
        project_id="proj_t",
        tool="nuclei",
        target={"base_url": base_url},
        scope_allow=["*"],
    )


def test_parse_output_contract():
    adapter = NucleiAdapter()
    sarif = adapter.parse_output(FIXTURE.read_bytes())
    findings = normalize_sarif(sarif, ScanClass.DAST)
    assert findings, "expected a finding from the recorded nuclei output"
    f = findings[0]
    assert f.rule_id == "omniscan-exposed-secret-marker"
    assert f.severity == Severity.high
    # DAST findings are located by URL/route, not file/line.
    assert f.location.get("url", "").startswith("http")
    # No raw secret value should ever appear in the normalized output.
    assert "ghp_abcdefghij" not in (f.message + str(f.location) + str(f.extra))


def test_build_invocation_scopes_egress_and_disables_update():
    adapter = NucleiAdapter()
    spec = adapter.build_invocation(_request("https://staging.example.test"))
    assert spec.network == "target"  # egress to the authorized target only
    assert "-disable-update-check" in spec.args  # no remote template fetch
    assert "-no-interactsh" in spec.args  # no out-of-band callbacks
    assert "-omit-raw" in spec.args  # never emit raw request/response
    assert not spec.image.endswith(":latest")


def test_validate_requires_scope():
    adapter = NucleiAdapter()
    req = _request("https://x.test")
    req.scope_allow = []
    with pytest.raises(ValueError):
        adapter.validate_inputs(req)


@pytest.mark.skipif(not _docker_available(), reason="docker not available")
def test_nuclei_runs_against_controlled_target():
    # Build the vendored offline image (idempotent).
    subprocess.run(
        [
            "docker",
            "build",
            "-q",
            "-t",
            "omniscan/nuclei:0.1.0",
            str(REPO_ROOT / "deploy/scanners/nuclei"),
        ],
        check=True,
        capture_output=True,
        timeout=300,
    )
    # Stand up a controlled target that exposes the marker.
    import tempfile

    tgt = tempfile.mkdtemp()
    Path(tgt, "index.html").write_text(
        "welcome\nOMNISCAN_EXPOSED_SECRET=ghp_planted0123456789abcdefghij\n"
    )
    subprocess.run(["docker", "rm", "-f", "omni-dast-test"], capture_output=True)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            "omni-dast-test",
            "-p",
            "8987:80",
            "-v",
            f"{tgt}:/usr/share/nginx/html:ro",
            "nginx:alpine",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    try:
        time.sleep(2)
        adapter = NucleiAdapter()
        req = _request("http://host.docker.internal:8987")
        spec = adapter.build_invocation(req)
        raw = DockerContainerRunner().run(adapter, spec, req)
        findings = normalize_sarif(adapter.parse_output(raw), ScanClass.DAST)
        assert any(f.rule_id == "omniscan-exposed-secret-marker" for f in findings)
        # -omit-raw means the planted secret never appears in scanner output.
        assert b"ghp_planted0123456789abcdefghij" not in raw
    finally:
        subprocess.run(["docker", "rm", "-f", "omni-dast-test"], capture_output=True)
