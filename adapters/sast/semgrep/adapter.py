"""Semgrep SAST adapter — a real, containerized scanner.

Unlike the built-in demoscan, this runs the pinned upstream semgrep image in an
isolated container (via ``DockerContainerRunner``) and emits SARIF natively.

Isolation (AGENT.md §2.3 / §8):
  * pinned image, never ``:latest``
  * ``network="none"`` — SAST must not touch the network. We therefore cannot use
    ``--config auto`` (which fetches the registry); instead we mount a vendored,
    version-pinned ruleset read-only (``deploy/scanners/semgrep/rules.yml``).
  * read-only root + read-only workspace mount + writable tmpfs for scratch
  * semgrep exits 1 when findings are present — that is success, not failure.

``parse_output`` adapts semgrep's SARIF to OmniScan's expectations: it lifts each
rule's ``defaultConfiguration.level`` onto the result (semgrep omits result-level
``level``) and rewrites absolute container paths back to repo-relative paths.
"""

from __future__ import annotations

from pathlib import Path

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import SarifLog

SEMGREP_IMAGE = "semgrep/semgrep:1.97.0"
_CONTAINER_SRC = "/src"
_CONTAINER_RULES = "/rules.yml"

# Vendored ruleset shipped alongside the pinned image (repo-root relative).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_RULES_PATH = _REPO_ROOT / "deploy" / "scanners" / "semgrep" / "rules.yml"


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    scan_class = ScanClass.SAST
    capabilities = ["pattern-match", "dataflow", "multi-language", "sarif-native"]
    native = False  # runs in a container, not in-process

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("semgrep only handles SAST")
        if not request.workspace_path:
            raise ValueError("semgrep requires a checked-out workspace path")
        if not Path(request.workspace_path).is_dir():
            raise ValueError("workspace_path does not exist or is not a directory")
        if not _RULES_PATH.is_file():
            raise ValueError(f"vendored ruleset missing: {_RULES_PATH}")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        return ContainerSpec(
            image=SEMGREP_IMAGE,
            args=[
                "semgrep",
                "--sarif",
                "--config",
                _CONTAINER_RULES,
                _CONTAINER_SRC,
                "--quiet",
                "--no-git-ignore",
                "--metrics",
                "off",
                "--disable-version-check",
            ],
            env={"HOME": "/tmp", "SEMGREP_SEND_METRICS": "off"},
            mounts={
                str(request.workspace_path): _CONTAINER_SRC,
                str(_RULES_PATH): _CONTAINER_RULES,
            },
            read_only_root=True,
            writable_tmp=True,
            network="none",
            limits=ResourceLimits(cpu=2.0, memory_mb=4096, timeout_seconds=900),
            # semgrep: 0 = no findings, 1 = findings present (both success); >=2 = error.
            success_exit_codes=(0, 1),
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            raise ValueError("semgrep produced no output")
        sarif = SarifLog.model_validate_json(raw)
        for run in sarif.runs:
            # Lift each rule's default level onto results (semgrep omits result.level).
            rule_levels = {
                r.id: str(r.defaultConfiguration.get("level", "warning"))
                for r in run.tool.driver.rules
            }
            # semgrep's shortDescription is a generic "Semgrep Finding: <id>"; promote
            # the human-readable fullDescription so it becomes the Finding title.
            for r in run.tool.driver.rules:
                if r.fullDescription and r.fullDescription.text:
                    r.shortDescription = r.fullDescription
            for result in run.results:
                if result.ruleId in rule_levels:
                    result.level = rule_levels[result.ruleId]
                for loc in result.locations:
                    phys = loc.physicalLocation
                    if phys and phys.artifactLocation and phys.artifactLocation.uri:
                        uri = phys.artifactLocation.uri
                        prefix = _CONTAINER_SRC + "/"
                        if uri.startswith(prefix):
                            phys.artifactLocation.uri = uri[len(prefix) :]
        return sarif
