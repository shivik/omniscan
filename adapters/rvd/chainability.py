"""Chainability scoring — a first-class RVD dimension (SKILLS.md §R.1.4).

Single-point scanners ignore whether findings combine. RVD treats a chainable
medium as potentially more dangerous than an isolated high. We score each finding
0..1 by how readily it composes with others (shared component/path, complementary
focus areas forming a known kill-chain shape) and emit graph edges between them.
"""

from __future__ import annotations

from dataclasses import dataclass

from adapters.rvd.backends.base import RVDHypothesis

# Focus-area pairs that frequently chain into a multi-step exploit.
_CHAIN_AFFINITY = {
    frozenset({"auth", "isolation"}): 0.4,
    frozenset({"deserialization", "isolation"}): 0.5,
    frozenset({"auth", "deserialization"}): 0.3,
    frozenset({"memory-safety", "isolation"}): 0.5,
}


@dataclass
class ChainEdge:
    src: str  # hypothesis id
    dst: str
    weight: float
    reason: str


def score(hypotheses: list[RVDHypothesis]) -> tuple[dict[str, float], list[ChainEdge]]:
    """Return per-hypothesis chainability scores and the chain graph edges."""
    scores: dict[str, float] = {h.id: 0.0 for h in hypotheses}
    edges: list[ChainEdge] = []
    for i, a in enumerate(hypotheses):
        for b in hypotheses[i + 1 :]:
            weight = _affinity(a, b)
            if weight <= 0:
                continue
            edges.append(ChainEdge(a.id, b.id, weight, f"{a.focus}+{b.focus} on shared path"))
            scores[a.id] = min(1.0, scores[a.id] + weight)
            scores[b.id] = min(1.0, scores[b.id] + weight)
    return scores, edges


def _affinity(a: RVDHypothesis, b: RVDHypothesis) -> float:
    base = _CHAIN_AFFINITY.get(frozenset({a.focus or "", b.focus or ""}), 0.0)
    # Same component/path raises the odds the two actually chain.
    shared_path = bool(set(a.composition_path) & set(b.composition_path))
    return base + (0.2 if shared_path else 0.0)
