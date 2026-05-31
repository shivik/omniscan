"""Gitleaks SAST adapter — containerized secret detection.

Runs the pinned upstream gitleaks image in an isolated container and emits SARIF.

Secret-scanner output is doubly sensitive (AGENT.md §2.2, SKILLS.md §2): we run
gitleaks with ``--redact`` so the raw secret never appears in its output, and we
store only a redacted finding + a stable fingerprint. The plaintext secret is never
written to logs, SARIF, or the DB.

Isolation: pinned image, ``network="none"`` (gitleaks uses embedded rules — no
registry fetch), read-only root + read-only workspace mount + writable tmpfs.
gitleaks exits 1 when leaks are found — that is success, not failure.
"""

from __future__ import annotations

from pathlib import Path

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import SarifLog

GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.21.2"
_CONTAINER_SRC = "/src"


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    scan_class = ScanClass.SAST
    capabilities = ["secret-detection", "redacted-output"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("gitleaks only handles SAST")
        if not request.workspace_path or not Path(request.workspace_path).is_dir():
            raise ValueError("gitleaks requires a checked-out workspace path")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        return ContainerSpec(
            image=GITLEAKS_IMAGE,
            args=[
                "dir",
                _CONTAINER_SRC,
                "--report-format",
                "sarif",
                "--report-path",
                "/dev/stdout",
                "--redact",  # never emit the raw secret value
                "--no-banner",
                "--exit-code",
                "1",
            ],
            env={"HOME": "/tmp"},
            mounts={str(request.workspace_path): _CONTAINER_SRC},
            read_only_root=True,
            writable_tmp=True,
            network="none",
            limits=ResourceLimits(cpu=1.0, memory_mb=2048, timeout_seconds=600),
            # 0 = no leaks, 1 = leaks found (both success); >=2 = error.
            success_exit_codes=(0, 1),
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            # gitleaks emits nothing on a clean tree with --report-path /dev/stdout.
            return SarifLog()
        sarif = SarifLog.model_validate_json(raw)
        for run in sarif.runs:
            for result in run.results:
                # Secrets are high severity by policy; gitleaks omits result-level level.
                result.level = "error"
                result.properties.setdefault("severity", "high")
                for loc in result.locations:
                    phys = loc.physicalLocation
                    if phys and phys.artifactLocation and phys.artifactLocation.uri:
                        prefix = _CONTAINER_SRC + "/"
                        if phys.artifactLocation.uri.startswith(prefix):
                            phys.artifactLocation.uri = phys.artifactLocation.uri[len(prefix) :]
        return sarif
