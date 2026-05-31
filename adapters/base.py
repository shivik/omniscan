"""The adapter contract every scanner implements (AGENT.md §8).

Subclass ``ScannerAdapter`` and implement:
  * ``name`` / ``scan_class`` / ``capabilities``
  * ``validate_inputs(request)`` — reject bad/out-of-scope input early
  * ``build_invocation(request) -> ContainerSpec`` — image, args, mounts, env (secrets by ref)
  * ``parse_output(raw) -> SarifLog`` — convert native output to SARIF 2.1.0

Isolation: adapters declare a ``ContainerSpec`` and are executed by a Runner in an
isolated container. SAST gets ``network="none"``; DAST gets egress to the target
only. The worker never runs scanner binaries in-process.

Built-in, dependency-free adapters (e.g. the demo SAST scanner) may set
``native=True`` and implement ``run_native`` for a pure-Python, no-subprocess,
no-network execution path used in dev — still sandboxed by the runner.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from core.enums import ScanClass
from normalize.sarif import SarifLog

NetworkMode = Literal["none", "egress", "target"]


@dataclass
class ScanRequest:
    """Normalized, in-engine representation of a scan request for one adapter.

    Built by the engine from the validated API request. Secrets appear only as
    references (``vault://...``); the runner resolves them into the container.
    """

    scan_id: str
    job_id: str
    scan_class: ScanClass
    project_id: str
    tool: str
    source: dict[str, Any] = field(default_factory=dict)  # {type, url, ref, path}
    target: dict[str, Any] = field(default_factory=dict)  # {base_url}
    scope_allow: list[str] = field(default_factory=list)
    scope_deny: list[str] = field(default_factory=list)
    auth_ref: str | None = None  # secret reference, never inline
    options: dict[str, Any] = field(
        default_factory=dict
    )  # tool-specific + rvd {depth,budget,focus,backend}
    workspace_path: str | None = None  # read-only checkout mount (SAST/RVD repo)


@dataclass
class ResourceLimits:
    cpu: float = 1.0
    memory_mb: int = 2048
    timeout_seconds: int = 1800


@dataclass
class ContainerSpec:
    """How to run an adapter in an isolated container."""

    image: str  # pinned, never :latest
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)  # secret values injected by runner, by ref
    secret_refs: dict[str, str] = field(default_factory=dict)  # env_var -> vault ref
    mounts: dict[str, str] = field(default_factory=dict)  # host_path -> container_path
    read_only_root: bool = True
    # Mount a writable tmpfs at /tmp even with a read-only root, so scanners that need
    # scratch space (caches, temp files) work without a writable image layer.
    writable_tmp: bool = True
    network: NetworkMode = "none"
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    # Exit codes the runner treats as success. Many scanners (e.g. semgrep) use a
    # nonzero code to mean "findings present", which is not a failure.
    success_exit_codes: tuple[int, ...] = (0,)


class ScannerAdapter(ABC):
    #: stable adapter name, used in the API ``tools`` enum and CLI flags
    name: str
    scan_class: ScanClass
    capabilities: list[str] = []
    #: built-in pure-Python adapters set this and implement run_native
    native: bool = False

    @abstractmethod
    def validate_inputs(self, request: ScanRequest) -> None:
        """Raise ValueError/ScopeViolation for bad or out-of-scope input."""

    @abstractmethod
    def build_invocation(self, request: ScanRequest) -> ContainerSpec:
        """Describe the container that runs this scan."""

    @abstractmethod
    def parse_output(self, raw: bytes) -> SarifLog:
        """Convert the scanner's native output into SARIF 2.1.0."""

    def run_native(self, request: ScanRequest) -> bytes:  # pragma: no cover - overridden
        """Pure-Python execution path for ``native`` adapters (dev runner)."""
        raise NotImplementedError(f"{self.name} is not a native adapter")
