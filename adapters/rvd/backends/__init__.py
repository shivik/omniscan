"""Pluggable, fully open-source backends for RVD.

The engine, chainability scoring, sandboxing, and normalization are identical
regardless of backend — only capability/cost change. Design for graceful
degradation (SKILLS.md §R.2).

Backends here are 100% open source and run locally — no proprietary API, no API key:
  * ``ollama``    — a local open-source LLM (Llama/Qwen/DeepSeek/...) via Ollama's REST API.
  * ``heuristic`` — dependency-free structural fallback (no model at all).

Resolution: a requested backend that can't be constructed (e.g. ``ollama`` with no
local server / model) falls back rather than failing the scan — the pipeline must
always run. Default preference is ``ollama`` → ``heuristic``.
"""

from __future__ import annotations

import logging

from adapters.rvd.backends.base import (
    BackendUnavailable,
    RVDBackend,
    RVDHypothesis,
    RVDObservation,
)
from adapters.rvd.backends.heuristic import HeuristicBackend
from adapters.rvd.backends.ollama import OllamaBackend

log = logging.getLogger("omniscan.rvd")

_BACKENDS: dict[str, type[RVDBackend]] = {
    "ollama": OllamaBackend,  # local open-source LLM (no API key)
    "heuristic": HeuristicBackend,  # dependency-free fallback
}

# Preference order when no specific backend is requested.
_PREFERENCE = ("ollama", "heuristic")


def get_backend(name: str | None) -> RVDBackend:
    """Resolve a backend, degrading gracefully to the heuristic fallback.

    A requested backend that can't be constructed (missing local server/model) falls
    back rather than failing the scan.
    """
    order = [name] if name else list(_PREFERENCE)
    for candidate in order:
        cls = _BACKENDS.get(candidate or "")
        if cls is None:
            continue
        try:
            backend = cls()
            if name and candidate != name:
                log.info("RVD backend '%s' selected (fallback)", candidate)
            return backend
        except BackendUnavailable as exc:
            log.info("RVD backend '%s' unavailable: %s", candidate, exc)
            continue
    return HeuristicBackend()


__all__ = [
    "BackendUnavailable",
    "RVDBackend",
    "RVDHypothesis",
    "RVDObservation",
    "get_backend",
]
