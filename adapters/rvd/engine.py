"""The RVD adapter — drives the agentic discovery loop and normalizes to SARIF.

Loop: comprehend -> hypothesize -> probe/verify -> score chainability -> normalize.
Reasoning is delegated to a pluggable ``RVDBackend``; this engine owns orchestration,
chainability scoring, PoC handling, and SARIF emission.

Output discipline (AGENT.md §2.6): findings default to EMBARGOED; unverified
hypotheses are LOW confidence; PoCs are stored encrypted by reference only.
"""

from __future__ import annotations

import json

from adapters.base import ContainerSpec, ResourceLimits, ScannerAdapter, ScanRequest
from adapters.rvd import chainability
from adapters.rvd.backends import get_backend
from adapters.rvd.poc import store_poc
from core.enums import ScanClass
from normalize.sarif import (
    Location,
    Message,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)


class RVDAdapter(ScannerAdapter):
    name = "rvd"
    scan_class = ScanClass.RVD
    capabilities = ["agentic", "compositional", "chainability", "poc"]
    native = True  # the loop runs in-engine; the *backend* is where the model lives

    def validate_inputs(self, request: ScanRequest) -> None:
        if request.scan_class is not ScanClass.RVD:
            raise ValueError("rvd adapter only handles RVD scans")
        # RVD needs something to reason over: a checkout and/or a running target.
        if not request.workspace_path and not request.target:
            raise ValueError("rvd requires a workspace (repo) and/or a running target")
        # Scope is enforced upstream by the planner; this is a defense-in-depth check.
        if request.target and not request.scope_allow:
            raise ValueError("rvd against a running target requires an explicit scope allowlist")

    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        # RVD reasoning + sandboxed probes run in an isolated, resource-capped
        # container. Egress is constrained; PoC probes run in a nested sandbox.
        return ContainerSpec(
            image="omniscan/rvd-engine:0.1.0",
            args=["rvd", "--workspace", "/workspace"],
            mounts={request.workspace_path or ".": "/workspace"},
            read_only_root=True,
            network="egress" if request.target else "none",
            limits=ResourceLimits(cpu=4.0, memory_mb=8192, timeout_seconds=8 * 3600),
        )

    def run_native(self, request: ScanRequest) -> bytes:
        opts = request.options or {}
        focus: list[str] = opts.get("focus") or []
        budget: str = opts.get("budget", "1h")
        generate_poc: bool = bool(opts.get("generate_poc", False))
        backend = get_backend(opts.get("backend"))

        # 1) comprehend  2) hypothesize  3) probe/verify
        model = backend.comprehend(request.workspace_path, focus)
        hypotheses = backend.hypothesize(model, budget, focus)
        observations = {
            h.id: backend.probe(h, model, generate_poc=generate_poc) for h in hypotheses
        }

        # 4) score chainability across all hypotheses
        chain_scores, edges = chainability.score(hypotheses)

        results = []
        for h in hypotheses:
            obs = observations[h.id]
            poc_ref = store_poc(obs.poc_artifact) if obs.poc_artifact else None
            results.append(
                {
                    "rule_id": f"RVD-{h.focus or 'general'}",
                    "title": h.title,
                    "rationale": h.rationale,
                    "verified": obs.verified,
                    "confidence": obs.confidence,
                    "evidence": obs.evidence,
                    "composition_path": h.composition_path,
                    "chainability_score": round(chain_scores.get(h.id, 0.0), 3),
                    "suspected_severity": h.suspected_severity,
                    "risk_tier": h.risk_tier,
                    "locations": h.locations,
                    "poc_ref": poc_ref,  # opaque, encrypted reference only
                    "backend": backend.name,
                }
            )
        return json.dumps(
            {
                "tool": "rvd",
                "backend": backend.name,
                "results": results,
                "chain_edges": [vars(e) for e in edges],
            }
        ).encode()

    def parse_output(self, raw: bytes) -> SarifLog:
        data = json.loads(raw.decode())
        sarif_results: list[Result] = []
        for item in data.get("results", []):
            verified = item.get("verified", False)
            confidence = float(item.get("confidence", 0.0))
            # Unverified -> note (low); verified -> level by confidence.
            if not verified:
                level = "note"
            else:
                level = "error" if confidence >= 0.8 else "warning"
            loc = item.get("locations", [{}])[0]
            sarif_results.append(
                Result(
                    ruleId=item["rule_id"],
                    level=level,
                    message=Message(text=item["title"]),
                    locations=[Location(properties=loc)],
                    properties={
                        "severity": item.get("suspected_severity", "medium"),
                        "chainability_score": item.get("chainability_score", 0.0),
                        "risk_tier": item.get("risk_tier", "unknown_unknown"),
                        # RVD enrichment surfaced under the finding in the dashboard:
                        "reasoning_trace": item.get("rationale"),
                        "composition_path": item.get("composition_path"),
                        "verified": verified,
                        "confidence": confidence,
                        "evidence": item.get("evidence"),
                        "poc_ref": item.get("poc_ref"),  # admin-gated retrieval
                        "embargoed": True,  # RVD findings default to embargoed
                        "backend": item.get("backend"),
                    },
                )
            )
        return SarifLog(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="rvd", version="0.1.0")),
                    results=sarif_results,
                    properties={"chain_edges": data.get("chain_edges", [])},
                )
            ]
        )
