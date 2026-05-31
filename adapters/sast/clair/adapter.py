"""Clair container-image SCA adapter — the open-source Quay/Red Hat engine.

Clair statically indexes a **container image**'s layers and matches installed OS +
language packages against security advisory feeds. Unlike trivy (which reads manifests/
lockfiles in a source tree), Clair scans a built image by reference.

Architecture: Clair v4 is a service (indexer + matcher + a feed updater backed by
Postgres); the ``clairctl`` client submits an image and pulls back a VulnerabilityReport.
This adapter runs the pinned ``clairctl`` client against a configured Clair host and
converts the report JSON to SARIF. The Clair service itself is provisioned out-of-band
(see ``deploy/scanners/clair/docker-compose.yml``).

SCA egress: like trivy, this needs network (to the Clair host + the image registry) —
it declares ``network="egress"`` (SKILLS.md §2 SCA exception). Input is a container
image ref (``source = {"type": "image", "image": "registry/repo:tag"}``).

Operational note: standing up Clair (service + Postgres + GBs of advisory data) is heavy,
so the live scan is not exercised in the test suite — the report→SARIF normalization is
covered by a contract test, and a full compose stack is provided in ``deploy/``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from normalize.sarif import (
    Location,
    Message,
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

CLAIRCTL_IMAGE = "omniscan/clairctl:0.1.0"
_CONTAINER_CONFIG = "/etc/clairctl/config.yaml"

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "deploy" / "scanners" / "clair" / "config.yaml"

# Clair normalized_severity -> OmniScan severity text.
_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "info",
}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


class ClairAdapter(ScannerAdapter):
    name = "clair"
    scan_class = ScanClass.SAST
    capabilities = ["sca", "container-image", "cve", "os-packages"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.SAST:
            raise ValueError("clair only handles SAST (container-image SCA)")
        image = request.source.get("image")
        if request.source.get("type") != "image" or not image:
            raise ValueError(
                "clair requires source.type='image' and source.image (a container ref)"
            )

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        image_ref = str(request.source["image"])
        clair_host = str(
            request.options.get("clair_host")
            or os.environ.get("OMNISCAN_CLAIR_URL", "http://clair:6060")
        )
        spec = ContainerSpec(
            image=CLAIRCTL_IMAGE,
            args=["--config", _CONTAINER_CONFIG, "report", "--out", "json", image_ref],
            env={"CLAIR_API": clair_host, "HOME": "/tmp"},
            mounts={str(_CONFIG_PATH): _CONTAINER_CONFIG},
            read_only_root=True,
            writable_tmp=True,
            network="egress",  # reach the Clair host + the image registry (SCA exception)
            limits=ResourceLimits(cpu=2.0, memory_mb=2048, timeout_seconds=1200),
            success_exit_codes=(0,),
        )
        # Registry pull credentials, if any, by reference only — never inline.
        if request.auth_ref:
            spec.secret_refs["CLAIRCTL_REGISTRY_AUTH"] = request.auth_ref
        return spec

    def parse_output(self, raw: bytes) -> SarifLog:
        if not raw.strip():
            return SarifLog()
        report = json.loads(raw)
        image = report.get("manifest_hash") or report.get("name") or "image"
        vulns: dict[str, Any] = report.get("vulnerabilities", {})
        rules: dict[str, ReportingDescriptor] = {}
        results: list[Result] = []
        for vuln in vulns.values():
            name = vuln.get("name") or vuln.get("id") or "vulnerability"
            sev_text = _SEVERITY.get(str(vuln.get("normalized_severity", "Unknown")), "info")
            pkg = vuln.get("package", {}) or {}
            desc = vuln.get("description") or name
            rules.setdefault(
                name,
                ReportingDescriptor(id=name, shortDescription=Message(text=desc[:160])),
            )
            results.append(
                Result(
                    ruleId=name,
                    level=_LEVEL.get(sev_text, "note"),
                    message=Message(
                        text=f"{name} in {pkg.get('name', '?')} {pkg.get('version', '')}".strip()
                    ),
                    locations=[
                        Location(
                            properties={
                                "image": image,
                                "package": pkg.get("name"),
                                "installed_version": pkg.get("version"),
                                "fixed_in_version": vuln.get("fixed_in_version"),
                                "link": vuln.get("links"),
                            }
                        )
                    ],
                    properties={"severity": sev_text},
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(name="clair", version="4", rules=list(rules.values()))
                    ),
                    results=results,
                )
            ]
        )
