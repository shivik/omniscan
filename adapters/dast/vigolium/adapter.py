"""Vigolium DAST adapter — open-source (AGPL) high-fidelity web vulnerability scanner.

Vigolium (https://github.com/vigolium/vigolium) fuses a deterministic multi-phase web
scan (content discovery, browser spidering, active + passive auditing — think
Nuclei/ZAP/Burp/Semgrep in one) with an optional LLM-driven *agentic* mode.

This adapter wires Vigolium's **native, deterministic** mode (``vigolium scan``): it
needs no model and no API key, and its egress stays scoped to the authorized target.
The agentic mode (``vigolium agent``) is intentionally NOT wired here — it requires an
LLM harness; OmniScan's model-driven discovery lives in the open-source RVD `ollama`
backend instead.

Output: Vigolium emits JSONL (``--format jsonl``); ``parse_output`` converts the line
findings (module/severity/confidence/url/parameter/evidence/description) to SARIF,
redacting URLs/evidence defensively (golden rule #2).

Operational note: the live image is heavy and a real scan needs a running target, so the
live run isn't executed in the test suite — the JSONL→SARIF logic is contract-tested and
a vendored Dockerfile is provided in ``deploy/scanners/vigolium/``.
"""

from __future__ import annotations

import json
from typing import Any

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from core.redact import redact
from normalize.sarif import Location, Message, Result, Run, SarifLog, Tool, ToolComponent

VIGOLIUM_IMAGE = "omniscan/vigolium:0.1.0"

_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}


def _field(item: dict[str, Any], *names: str) -> Any:
    """Return the first present, non-null value among ``names`` (case/alias tolerant)."""
    for n in names:
        if item.get(n) is not None:
            return item[n]
    return None


class VigoliumAdapter(ScannerAdapter):
    name = "vigolium"
    scan_class = ScanClass.DAST
    capabilities = ["spider", "active", "passive", "content-discovery", "high-fidelity"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.DAST:
            raise ValueError("vigolium only handles DAST")
        if not request.target.get("base_url"):
            raise ValueError("vigolium requires a target base_url")
        if not request.scope_allow:
            raise ValueError("DAST requires an explicit scope allowlist")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        base_url = str(request.target["base_url"])
        args = [
            "scan",
            "--target",
            base_url,
            "--format",
            "jsonl",
            "-o",
            "/dev/stdout",
            "--no-color",
        ]
        rate = request.options.get("rate_limit")
        if rate:
            digits = "".join(ch for ch in str(rate) if ch.isdigit())
            if digits:
                args += ["--rate-limit", digits]
        return ContainerSpec(
            image=VIGOLIUM_IMAGE,
            args=args,
            env={"HOME": "/tmp"},
            read_only_root=True,
            writable_tmp=True,
            network="target",  # deterministic scan: egress to the authorized target only
            limits=ResourceLimits(cpu=2.0, memory_mb=4096, timeout_seconds=3600),
            success_exit_codes=(0, 1),  # nonzero may signal findings present
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        results: list[Result] = []
        for line in raw.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue  # skip any banner/non-JSON noise
            try:
                item: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue
            severity = str(_field(item, "severity", "Severity") or "info").lower()
            module = str(_field(item, "module", "Module", "name", "template") or "vigolium")
            url = str(redact(_field(item, "url", "URL", "matched_at") or ""))
            results.append(
                Result(
                    ruleId=module,
                    level=_SEVERITY_LEVEL.get(severity, "note"),
                    message=Message(
                        text=str(redact(_field(item, "description", "Description") or module))
                    ),
                    locations=[
                        Location(
                            properties={
                                "url": url,
                                "route": url,
                                "param": _field(item, "parameter", "Parameter", "param"),
                            }
                        )
                    ],
                    properties={
                        "severity": severity if severity in _SEVERITY_LEVEL else "info",
                        "confidence": _field(item, "confidence", "Confidence"),
                        # evidence may contain response snippets → redact before storing
                        "evidence": str(redact(_field(item, "evidence", "Evidence") or "")) or None,
                    },
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="vigolium", version="0.1.0")),
                    results=results,
                )
            ]
        )
