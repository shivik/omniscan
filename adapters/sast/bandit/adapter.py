"""Bandit SAST adapter — Python security linter, containerized + offline.

bandit is pure-Python and ships its rules in-package, so it runs with no network.
We run it with ``-f json`` and convert its native JSON to SARIF in ``parse_output``.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

BANDIT_IMAGE = "omniscan/bandit:0.1.0"
_CONTAINER_SRC = "/src"

_SEVERITY_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SEVERITY_TEXT = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    scan_class = ScanClass.SAST
    capabilities = ["python", "ast", "cwe"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("bandit only handles SAST")
        if not request.workspace_path or not Path(request.workspace_path).is_dir():
            raise ValueError("bandit requires a checked-out workspace path")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        return ContainerSpec(
            image=BANDIT_IMAGE,
            args=["-r", _CONTAINER_SRC, "-f", "json", "-q"],
            mounts={str(request.workspace_path): _CONTAINER_SRC},
            read_only_root=True,
            writable_tmp=True,
            network="none",
            limits=ResourceLimits(cpu=1.0, memory_mb=2048, timeout_seconds=600),
            success_exit_codes=(0, 1),  # 1 = issues found
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            return SarifLog()
        data = json.loads(raw)
        rules: dict[str, ReportingDescriptor] = {}
        results: list[Result] = []
        for item in data.get("results", []):
            rid = item["test_id"]
            sev = str(item.get("issue_severity", "LOW")).upper()
            text = item.get("issue_text", rid)
            rules.setdefault(
                rid,
                ReportingDescriptor(
                    id=rid, name=item.get("test_name"), shortDescription=Message(text=text)
                ),
            )
            uri = str(item.get("filename", "")).removeprefix(_CONTAINER_SRC + "/")
            results.append(
                Result(
                    ruleId=rid,
                    level=_SEVERITY_LEVEL.get(sev, "note"),
                    message=Message(text=text),
                    locations=[
                        Location(
                            physicalLocation=PhysicalLocation(
                                artifactLocation=ArtifactLocation(uri=uri),
                                region=Region(startLine=item.get("line_number")),
                            )
                        )
                    ],
                    properties={
                        "severity": _SEVERITY_TEXT.get(sev, "low"),
                        "cwe": (item.get("issue_cwe") or {}).get("id"),
                        "confidence": item.get("issue_confidence"),
                    },
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="bandit", version="1.8.0", rules=list(rules.values())
                        )
                    ),
                    results=results,
                )
            ]
        )
