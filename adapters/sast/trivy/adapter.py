"""Trivy SCA adapter — vulnerable-dependency scanning, SARIF-native.

SCA is the one SAST skill permitted **limited egress** (advisory DB feeds) per
SKILLS.md §2, so this adapter declares ``network="egress"`` to let trivy fetch its
vulnerability DB. (Air-gap it by vendoring the DB into the image — see
``deploy/scanners/trivy/README.md``.) trivy emits SARIF natively; ``parse_output``
lifts each rule's CVSS ``security-severity`` onto the result so dedup/severity mapping
classifies critical-vs-high correctly.
"""

from __future__ import annotations

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import SarifLog

TRIVY_IMAGE = "aquasec/trivy:0.58.1"
_CONTAINER_SRC = "/src"


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    scan_class = ScanClass.SAST
    capabilities = ["sca", "cve", "dependencies", "sarif-native"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("trivy only handles SAST (SCA)")
        if not request.workspace_path:
            raise ValueError("trivy requires a checked-out workspace path")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        return ContainerSpec(
            image=TRIVY_IMAGE,
            args=["fs", "--scanners", "vuln", "--format", "sarif", "--quiet", _CONTAINER_SRC],
            env={"HOME": "/tmp"},
            mounts={str(request.workspace_path): _CONTAINER_SRC},
            read_only_root=True,
            writable_tmp=True,
            network="egress",  # SCA exception: fetch advisory DB feeds (SKILLS.md §2)
            limits=ResourceLimits(cpu=2.0, memory_mb=4096, timeout_seconds=900),
            success_exit_codes=(0,),
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            return SarifLog()
        sarif = SarifLog.model_validate_json(raw)
        for run in sarif.runs:
            # CVSS score lives on rule.properties["security-severity"]; lift it onto each
            # result so normalize maps 9.8 -> critical, 7.x -> high, etc.
            cvss_by_rule: dict[str, float] = {}
            for rule in run.tool.driver.rules:
                score = rule.properties.get("security-severity")
                if score is not None:
                    try:
                        cvss_by_rule[rule.id] = float(score)
                    except (TypeError, ValueError):
                        pass
            for result in run.results:
                if result.ruleId in cvss_by_rule:
                    result.properties["cvss"] = cvss_by_rule[result.ruleId]
        return sarif
