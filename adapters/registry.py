"""Adapter registry — the single place adapters are registered + discovered.

The API ``tools`` enum, the CLI ``--tools`` flag, and the engine planner all read
from here, so a registered adapter is exposed consistently across surfaces.
"""

from __future__ import annotations

from adapters.base import ScannerAdapter
from adapters.dast.nuclei.adapter import NucleiAdapter
from adapters.dast.vigolium.adapter import VigoliumAdapter
from adapters.dast.zap.adapter import ZapAdapter
from adapters.rvd.engine import RVDAdapter
from adapters.sast.bandit.adapter import BanditAdapter
from adapters.sast.clair.adapter import ClairAdapter
from adapters.sast.codeql.adapter import CodeQLAdapter
from adapters.sast.demoscan.adapter import DemoScanAdapter
from adapters.sast.gitleaks.adapter import GitleaksAdapter
from adapters.sast.semgrep.adapter import SemgrepAdapter
from adapters.sast.trivy.adapter import TrivyAdapter
from core.enums import ScanClass

_ADAPTERS: dict[str, ScannerAdapter] = {}


def register(adapter: ScannerAdapter) -> None:
    if adapter.name in _ADAPTERS:
        raise ValueError(f"adapter already registered: {adapter.name}")
    _ADAPTERS[adapter.name] = adapter


def get(name: str) -> ScannerAdapter:
    try:
        return _ADAPTERS[name]
    except KeyError:
        raise KeyError(f"unknown adapter: {name}") from None


def all_adapters() -> list[ScannerAdapter]:
    return list(_ADAPTERS.values())


def for_class(scan_class: ScanClass) -> list[ScannerAdapter]:
    return [a for a in _ADAPTERS.values() if a.scan_class is scan_class]


def names_for_class(scan_class: ScanClass) -> list[str]:
    return [a.name for a in for_class(scan_class)]


def default_tools(scan_class: ScanClass) -> list[str]:
    """Default adapter set for a class when the request omits ``tools``."""
    names = names_for_class(scan_class)
    return names[:1] if names else []


# --- register adapters ---
# demoscan stays first so it remains the zero-infra default for SAST; semgrep is
# opt-in via `tools=["semgrep"]` and requires Docker.
register(DemoScanAdapter())
register(SemgrepAdapter())
register(GitleaksAdapter())
register(BanditAdapter())  # SAST (Python)
register(TrivyAdapter())  # SCA (source manifests)
register(ClairAdapter())  # SCA (container images)
register(CodeQLAdapter())  # SAST (deep dataflow)
register(NucleiAdapter())  # DAST
register(ZapAdapter())  # DAST
register(VigoliumAdapter())  # DAST (high-fidelity, AGPL)
register(RVDAdapter())
