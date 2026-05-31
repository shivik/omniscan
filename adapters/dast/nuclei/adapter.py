"""Nuclei DAST adapter — containerized, template-based dynamic scanning.

Runs the pinned, vendored ``omniscan/nuclei`` image against a running, **authorized**
target and emits SARIF. Open source, no API key.

DAST contract (SKILLS.md §3):
  * requires network egress **to the target** — scope_guard verifies ownership + the
    allowlist upstream, before any job is enqueued.
  * egress stays scoped: we do NOT fetch the remote nuclei-templates registry at scan
    time. Templates are vendored into the pinned image (``deploy/scanners/nuclei/``)
    and nuclei runs with ``-disable-update-check`` + an explicit ``-t`` dir and
    ``-no-interactsh`` (no out-of-band callbacks).
  * ``rate_limit`` is honored to avoid degrading the live system.

Output discipline: nuclei can echo raw request/response (which may contain secrets),
so we run it with ``-omit-raw -omit-template`` and additionally ``redact()`` every
field we keep before it becomes a Finding (golden rule #2).
"""

from __future__ import annotations

import json

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from core.enums import ScanClass
from core.redact import redact
from normalize.sarif import (
    Location,
    Message,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)

NUCLEI_IMAGE = "omniscan/nuclei:0.1.0"
_CONTAINER_TEMPLATES = "/omniscan-templates"

_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "note",
}


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    scan_class = ScanClass.DAST
    capabilities = ["template-based", "misconfig", "exposure", "cve"]
    native = False

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.DAST:
            raise ValueError("nuclei only handles DAST")
        if not request.target.get("base_url"):
            raise ValueError("nuclei requires a target base_url")
        # Defense in depth — the planner already enforced scope_guard.
        if not request.scope_allow:
            raise ValueError("DAST requires an explicit scope allowlist")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        base_url = str(request.target["base_url"])
        args = [
            "-u",
            base_url,
            "-t",
            _CONTAINER_TEMPLATES,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-no-interactsh",  # no out-of-band callbacks (egress stays to target)
            "-omit-raw",  # do not emit raw request/response (may contain secrets)
            "-omit-template",
        ]
        rate = request.options.get("rate_limit")
        if rate:
            # accept "20rps" or 20
            digits = "".join(ch for ch in str(rate) if ch.isdigit())
            if digits:
                args += ["-rl", digits]
        return ContainerSpec(
            image=NUCLEI_IMAGE,
            args=args,
            env={"HOME": "/tmp"},
            read_only_root=True,
            writable_tmp=True,
            network="target",  # egress to the authorized target only
            limits=ResourceLimits(cpu=2.0, memory_mb=2048, timeout_seconds=1800),
            success_exit_codes=(0,),  # nuclei exits 0 whether or not findings are present
        )

    def parse_output(self, raw: bytes) -> SarifLog:
        results: list[Result] = []
        for line in raw.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            severity = str(info.get("severity", "info")).lower()
            level = _SEVERITY_LEVEL.get(severity, "note")
            rule_id = str(item.get("template-id", "nuclei"))
            # redact() everything we keep — defense in depth against secret leakage.
            url = str(redact(item.get("matched-at") or item.get("url") or ""))
            name = str(redact(info.get("name", rule_id)))
            results.append(
                Result(
                    ruleId=rule_id,
                    level=level,
                    message=Message(text=name),
                    locations=[
                        Location(
                            properties={
                                "url": url,
                                "route": url,
                                "host": str(redact(item.get("host", ""))),
                                "param": item.get("matcher-name"),
                            }
                        )
                    ],
                    properties={"severity": severity},
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="nuclei", version="3.8.0")), results=results
                )
            ]
        )
