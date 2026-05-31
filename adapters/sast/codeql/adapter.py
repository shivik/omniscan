"""CodeQL SAST adapter — deep dataflow/taint analysis, SARIF-native.

CodeQL builds a queryable database of the codebase and runs query suites against it.
For compiled languages it needs a build command; for interpreted languages (python,
js/ts, ruby) the database builds without one. It emits SARIF natively
(``database analyze --format=sarif-latest``), so ``parse_output`` loads that SARIF and
normalizes paths.

Operational note: CodeQL is heavy (large CLI bundle, builds a DB, minutes-to-run). The
vendored image (``deploy/scanners/codeql/``) wraps ``database create`` + ``analyze`` and
writes SARIF to stdout. The image build + a live scan are NOT exercised in the test
suite (size/time); the adapter's normalization is covered by a SARIF contract test.
"""

from __future__ import annotations

from pathlib import Path

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import SarifLog

CODEQL_IMAGE = "omniscan/codeql:0.1.0"
_CONTAINER_SRC = "/src"
_SUPPORTED_LANGS = {"python", "javascript", "typescript", "java", "go", "ruby", "csharp", "cpp"}


class CodeQLAdapter(ScannerAdapter):
    name = "codeql"
    scan_class = ScanClass.SAST
    capabilities = ["dataflow", "taint", "deep", "sarif-native"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("codeql only handles SAST")
        if not request.workspace_path or not Path(request.workspace_path).is_dir():
            raise ValueError("codeql requires a checked-out workspace path")
        lang = request.options.get("language")
        if lang and lang not in _SUPPORTED_LANGS:
            raise ValueError(f"unsupported codeql language: {lang}")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        lang = str(request.options.get("language", "python"))
        build_cmd = str(request.options.get("build_cmd", ""))
        # The vendored entrypoint runs: database create (with build_cmd for compiled
        # langs) -> database analyze --format=sarif-latest -> SARIF to stdout.
        args = ["--src", _CONTAINER_SRC, "--language", lang]
        if build_cmd:
            args += ["--build-command", build_cmd]
        return ContainerSpec(
            image=CODEQL_IMAGE,
            args=args,
            env={"HOME": "/tmp"},
            mounts={str(request.workspace_path): _CONTAINER_SRC},
            read_only_root=False,  # codeql writes its database to a scratch dir
            writable_tmp=True,
            network="none",
            limits=ResourceLimits(cpu=4.0, memory_mb=8192, timeout_seconds=3600),
            success_exit_codes=(0,),
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            return SarifLog()
        sarif = SarifLog.model_validate_json(raw)
        for run in sarif.runs:
            # CodeQL rules carry severity in properties["security-severity"] (CVSS-like).
            cvss = {r.id: r.properties.get("security-severity") for r in run.tool.driver.rules}
            for result in run.results:
                score = cvss.get(result.ruleId)
                if score is not None:
                    try:
                        result.properties["cvss"] = float(score)
                    except (TypeError, ValueError):
                        pass
                for loc in result.locations:
                    phys = loc.physicalLocation
                    if phys and phys.artifactLocation and phys.artifactLocation.uri:
                        prefix = _CONTAINER_SRC + "/"
                        if phys.artifactLocation.uri.startswith(prefix):
                            phys.artifactLocation.uri = phys.artifactLocation.uri[len(prefix) :]
        return sarif
