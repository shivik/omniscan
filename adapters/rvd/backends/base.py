"""The ``RVDBackend`` interface — implement to wire a frontier model into RVD.

A backend drives the agentic loop's reasoning steps over a semantic model of the
target. The engine owns orchestration, sandboxing, chainability, and normalization;
the backend owns *comprehension and hypothesis generation* (and, where a real model
is wired, probe planning).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class BackendUnavailable(RuntimeError):
    """Raised when a backend can't be constructed (e.g. the local model server is
    not reachable, or the configured model isn't pulled). The registry catches this
    and degrades gracefully to the heuristic backend."""


@dataclass
class TargetModel:
    """A semantic model of the target the backend reasons over."""

    workspace_path: str | None
    files: list[str] = field(default_factory=list)
    # trust boundaries, data flows, component interactions, auth surfaces ...
    components: list[dict[str, Any]] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass
class RVDHypothesis:
    """A candidate residual/compositional weakness proposed by the backend."""

    id: str
    title: str
    rationale: str  # the reasoning trace
    composition_path: list[str] = field(default_factory=list)
    suspected_severity: str = "medium"
    locations: list[dict[str, Any]] = field(default_factory=list)
    focus: str | None = None
    # Residual-risk taxonomy (SKILLS.md §R.0). RVD's whole point is the third tier:
    # known_known | known_unknown | unknown_unknown
    risk_tier: str = "unknown_unknown"


@dataclass
class RVDObservation:
    """Result of probing a hypothesis in the sandbox."""

    hypothesis_id: str
    verified: bool
    confidence: float  # 0..1
    evidence: str = ""
    poc_artifact: bytes | None = None  # sensitive — encrypted by the engine, never logged


class RVDBackend(ABC):
    name: str

    @abstractmethod
    def comprehend(self, workspace_path: str | None, focus: list[str]) -> TargetModel:
        """Build a semantic model of the target."""

    @abstractmethod
    def hypothesize(self, model: TargetModel, budget: str, focus: list[str]) -> list[RVDHypothesis]:
        """Propose candidate residual weaknesses, especially compositional ones."""

    @abstractmethod
    def probe(
        self, hypothesis: RVDHypothesis, model: TargetModel, *, generate_poc: bool
    ) -> RVDObservation:
        """Attempt to confirm a hypothesis in an isolated sandbox."""
