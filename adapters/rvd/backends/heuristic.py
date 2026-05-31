"""Heuristic RVD backend — dependency-free fallback for the dev slice.

This is NOT the real engine. The model-backed path is the open-source ``ollama``
backend (a local Llama/Qwen/DeepSeek model), which actually reasons about composition.
This fallback does only a shallow structural pass so the
RVD pipeline (comprehend -> hypothesize -> probe -> chainability -> normalize) is
exercisable end-to-end without a model. Every hypothesis it raises is reported at
LOW confidence and the findings stay embargoed — it must not flood triage with
speculation dressed up as discovery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapters.rvd.backends.base import RVDBackend, RVDHypothesis, RVDObservation, TargetModel
from core.ids import new_id

_INTERESTING = {
    "isolation": ["subprocess", "container", "sandbox", "exec(", "os.system"],
    "deserialization": ["pickle", "yaml.load", "marshal", "__reduce__"],
    "auth": ["session", "token", "authorize", "permission", "is_admin"],
    "memory-safety": ["memcpy", "strcpy", "unsafe", "ctypes", "malloc"],
}


class HeuristicBackend(RVDBackend):
    name = "heuristic"

    def comprehend(self, workspace_path: str | None, focus: list[str]) -> TargetModel:
        files: list[str] = []
        components: list[dict[str, Any]] = []
        if workspace_path and Path(workspace_path).is_dir():
            root = Path(workspace_path)
            for p in root.rglob("*"):
                if p.is_file() and p.suffix in {".py", ".js", ".ts", ".go", ".c", ".cpp", ".rb"}:
                    if any(part in {".git", "node_modules", ".venv"} for part in p.parts):
                        continue
                    rel = str(p.relative_to(root))
                    files.append(rel)
                    components.append({"file": rel})
        return TargetModel(
            workspace_path=workspace_path, files=files[:2000], components=components[:2000]
        )

    def hypothesize(self, model: TargetModel, budget: str, focus: list[str]) -> list[RVDHypothesis]:
        focuses = focus or list(_INTERESTING.keys())
        hyps: list[RVDHypothesis] = []
        for comp in model.components:
            path = comp.get("file", "")
            if not model.workspace_path:
                continue
            try:
                text = (Path(model.workspace_path) / path).read_text("utf-8", errors="ignore")
            except OSError:
                continue
            for area in focuses:
                markers = _INTERESTING.get(area, [])
                hits = [m for m in markers if m in text]
                if len(hits) >= 2:  # composition signal: multiple interacting markers
                    hyps.append(
                        RVDHypothesis(
                            id=new_id("hyp"),
                            title=f"Possible {area} composition weakness in {path}",
                            rationale=(
                                f"Heuristic only: file combines {hits} which can "
                                "interact unsafely. Requires model-backed "
                                "verification before treating as real."
                            ),
                            composition_path=[path],
                            suspected_severity="medium",
                            locations=[{"file": path, "composition_path": path}],
                            focus=area,
                        )
                    )
        return hyps[:50]

    def probe(
        self, hypothesis: RVDHypothesis, model: TargetModel, *, generate_poc: bool
    ) -> RVDObservation:
        # The heuristic backend cannot truly verify — never claims verification,
        # never generates a PoC. Real backends run an isolated probe here.
        return RVDObservation(
            hypothesis_id=hypothesis.id,
            verified=False,
            confidence=0.2,
            evidence="unverified heuristic hypothesis (no model backend wired)",
            poc_artifact=None,
        )
