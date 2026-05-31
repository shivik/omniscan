"""OWASP ZAP DAST adapter — full passive+active web scan, SARIF-native.

ZAP is the DAST workhorse (spidering, passive + active scanning, auth flows). The
vendored image (``deploy/scanners/zap/``) runs ZAP's automation framework / baseline
against the authorized target and emits a SARIF report, which ``parse_output`` loads.

Operational note: the ZAP image is large (~1.5GB, JVM) and an active scan is slow. The
image build + a live scan are NOT exercised in the test suite; the adapter's
normalization is covered by a SARIF contract test. Credentials are passed by ``auth_ref``
(resolved by the runner into the container), never inline.
"""

from __future__ import annotations

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from core.redact import redact
from normalize.sarif import SarifLog

ZAP_IMAGE = "omniscan/zap:0.1.0"


class ZapAdapter(ScannerAdapter):
    name = "zap"
    scan_class = ScanClass.DAST
    capabilities = ["spider", "passive", "active", "auth", "sarif-native"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.DAST:
            raise ValueError("zap only handles DAST")
        if not request.target.get("base_url"):
            raise ValueError("zap requires a target base_url")
        if not request.scope_allow:
            raise ValueError("DAST requires an explicit scope allowlist")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        base_url = str(request.target["base_url"])
        strength = str(request.options.get("attack_strength", "medium"))
        args = ["--target", base_url, "--attack-strength", strength, "--format", "sarif"]
        spec = ContainerSpec(
            image=ZAP_IMAGE,
            args=args,
            env={"HOME": "/tmp"},
            read_only_root=False,  # ZAP writes its session/workdir
            writable_tmp=True,
            network="target",  # egress to the authorized target only
            limits=ResourceLimits(cpu=2.0, memory_mb=4096, timeout_seconds=3600),
            success_exit_codes=(0, 1, 2),  # ZAP uses nonzero to signal warnings/findings
        )
        if request.auth_ref:
            # Resolved by the runner into the container; never inline, never logged.
            spec.secret_refs["ZAP_AUTH"] = request.auth_ref
        return spec

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            return SarifLog()
        sarif = SarifLog.model_validate_json(raw)
        for run in sarif.runs:
            for result in run.results:
                for loc in result.locations:
                    # redact URLs defensively (query strings can carry secrets).
                    if loc.properties.get("url"):
                        loc.properties["url"] = str(redact(loc.properties["url"]))
        return sarif
