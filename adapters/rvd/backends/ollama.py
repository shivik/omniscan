"""Ollama RVD backend — fully open-source, local, no API key, no proprietary SDK.

This is RVD's "best-available agentic backend" (SKILLS.md §R.2) implemented against
a **local open-source LLM** served by Ollama (https://ollama.com). It talks to
Ollama's REST API over plain HTTP (httpx) — there is no vendor SDK and nothing leaves
your machine. Point it at any open model you've pulled (e.g. ``qwen2.5-coder``,
``llama3.1``, ``deepseek-r1``, ``mistral``).

It drives the comprehend → hypothesize → probe loop over the *authorized* target's
source, proposing residual / compositional weaknesses that signature scanners miss.

Honest framing (unchanged from any backend):
  * It proposes CANDIDATE weaknesses with a reasoning trace, composition path,
    residual-risk tier, and self-assessed confidence. Discovery *assistance*.
  * It makes no guarantee of finding novel zero-days. Quality is bounded by the local
    model you run. Every hypothesis is a lead for human triage, not a fact.
  * It does NOT execute exploits or synthesize PoCs — ``probe`` returns the model's
    self-assessment with ``verified=False``.

Config (env):
  * ``OMNISCAN_OLLAMA_URL``  — default ``http://localhost:11434``
  * ``OMNISCAN_RVD_MODEL``   — default ``qwen2.5-coder:7b``

If Ollama isn't reachable or the model isn't pulled, construction raises
``BackendUnavailable`` and the registry falls back to the heuristic backend.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx

from adapters.rvd.backends.base import (
    BackendUnavailable,
    RVDBackend,
    RVDHypothesis,
    RVDObservation,
    TargetModel,
)
from core.ids import new_id

log = logging.getLogger("omniscan.rvd.ollama")

DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"  # open-source, code-focused; override via env
_MAX_DIGEST_CHARS = 120_000
_MAX_FILE_CHARS = 10_000
_MAX_HYPOTHESES = 20
_REQUEST_TIMEOUT = 600.0  # local inference can be slow

_SCANNABLE = {".py", ".js", ".ts", ".go", ".c", ".cpp", ".h", ".rb", ".java", ".rs", ".php"}

_SYSTEM = """\
You are the reasoning core of OmniScan's Residual Vulnerability Discovery (RVD) engine.

You are analyzing source code that the requester OWNS and is AUTHORIZED to test. Find
RESIDUAL risk that signature/pattern scanners (SAST/DAST) miss — especially COMPOSITIONAL
flaws: where individually-safe components interact unsafely, multi-step chains, broken
trust-boundary assumptions, and latent defects that survive review.

Classify each finding into a residual-risk tier:
  - known_known: standard, signature-detectable class (SQLi, XSS, hardcoded secret).
  - known_unknown: a class tools cover only partially (stateful logic, auth-boundary confusion).
  - unknown_unknown: emerges from composition/interaction; no single signature matches it.
RVD exists for the third tier — prioritize genuinely compositional, non-obvious findings.

Rules:
  - Be precise and conservative. Do NOT invent vulnerabilities. An empty list is a valid,
    correct answer for clean code.
  - Every hypothesis is UNVERIFIED until a human reproduces it. Reflect real doubt in
    `confidence` (0..1); reserve >0.7 for a clear, concrete exploitation path.
  - Cite concrete files and the composition path.
  - Never include secrets, raw credentials, or working exploit payloads.
Respond ONLY with JSON matching the requested schema."""

# JSON schema passed to Ollama's `format` field for structured output.
_FORMAT_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "rationale": {"type": "string"},
                    "composition_path": {"type": "array", "items": {"type": "string"}},
                    "suspected_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "risk_tier": {
                        "type": "string",
                        "enum": ["known_known", "known_unknown", "unknown_unknown"],
                    },
                    "focus": {"type": "string"},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                    "primary_file": {"type": "string"},
                },
                "required": ["title", "rationale", "suspected_severity", "risk_tier", "confidence"],
            },
        }
    },
    "required": ["hypotheses"],
}


class OllamaBackend(RVDBackend):
    name = "ollama"

    def __init__(self) -> None:
        self._url = os.environ.get("OMNISCAN_OLLAMA_URL", DEFAULT_URL).rstrip("/")
        self._model = os.environ.get("OMNISCAN_RVD_MODEL", DEFAULT_MODEL)
        self._verify_available()
        self._assessments: dict[str, RVDObservation] = {}

    def _verify_available(self) -> None:
        try:
            resp = httpx.get(f"{self._url}/api/tags", timeout=5.0)
            resp.raise_for_status()
            tags = {m.get("name", "") for m in resp.json().get("models", [])}
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendUnavailable(
                f"Ollama not reachable at {self._url} (start it with `ollama serve`)"
            ) from exc
        # Accept exact match or a name that matches ignoring the implicit :latest tag.
        base = self._model.split(":")[0]
        if self._model not in tags and not any(t.split(":")[0] == base for t in tags):
            raise BackendUnavailable(
                f"model '{self._model}' not pulled — run `ollama pull {self._model}`"
            )

    # --- comprehend ---------------------------------------------------------
    def comprehend(self, workspace_path: str | None, focus: list[str]) -> TargetModel:
        files: list[str] = []
        if workspace_path and Path(workspace_path).is_dir():
            root = Path(workspace_path)
            for p in sorted(root.rglob("*")):
                if not p.is_file() or p.suffix not in _SCANNABLE:
                    continue
                if any(
                    part in {".git", "node_modules", ".venv", "venv", "dist"} for part in p.parts
                ):
                    continue
                files.append(str(p.relative_to(root)))
        return TargetModel(workspace_path=workspace_path, files=files[:400])

    def _build_digest(self, model: TargetModel) -> str:
        parts: list[str] = []
        total = 0
        root = Path(model.workspace_path) if model.workspace_path else None
        for rel in model.files:
            if root is None:
                break
            try:
                text = (root / rel).read_text("utf-8", errors="ignore")[:_MAX_FILE_CHARS]
            except OSError:
                continue
            block = f"\n===== FILE: {rel} =====\n{text}\n"
            if total + len(block) > _MAX_DIGEST_CHARS:
                break
            parts.append(block)
            total += len(block)
        return "".join(parts)

    # --- hypothesize --------------------------------------------------------
    def hypothesize(self, model: TargetModel, budget: str, focus: list[str]) -> list[RVDHypothesis]:
        digest = self._build_digest(model)
        if not digest.strip():
            return []
        focus_line = ", ".join(focus) if focus else "no specific focus — survey broadly"
        prompt = (
            f"Focus areas: {focus_line}.\nCompute budget: {budget}.\n"
            f"Analyze the following source for residual/compositional weaknesses. "
            f"Return at most {_MAX_HYPOTHESES} hypotheses, best first.\n{digest}"
        )

        try:
            resp = httpx.post(
                f"{self._url}/api/chat",
                json={
                    "model": self._model,
                    "stream": False,
                    "format": _FORMAT_SCHEMA,
                    "options": {"temperature": 0.2, "num_ctx": 16384},
                    "messages": [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                },
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
        except httpx.HTTPError as exc:
            log.warning("Ollama RVD hypothesize failed: %s", exc)
            raise BackendUnavailable(f"Ollama call failed: {exc}") from exc

        try:
            raw = json.loads(content).get("hypotheses", [])
        except (json.JSONDecodeError, AttributeError):
            return []

        hyps: list[RVDHypothesis] = []
        for item in raw[:_MAX_HYPOTHESES]:
            if not isinstance(item, dict):
                continue
            hyp_id = new_id("hyp")
            path = item.get("composition_path") or []
            primary = item.get("primary_file") or (path[0] if path else "")
            hyps.append(
                RVDHypothesis(
                    id=hyp_id,
                    title=str(item.get("title", "Residual weakness")),
                    rationale=str(item.get("rationale", "")),
                    composition_path=[str(p) for p in path],
                    suspected_severity=str(item.get("suspected_severity", "medium")),
                    risk_tier=str(item.get("risk_tier", "unknown_unknown")),
                    focus=item.get("focus"),
                    locations=[
                        {"file": primary, "composition_path": " → ".join(str(p) for p in path)}
                    ],
                )
            )
            try:
                conf = max(0.0, min(1.0, float(item.get("confidence", 0.3))))
            except (TypeError, ValueError):
                conf = 0.3
            self._assessments[hyp_id] = RVDObservation(
                hypothesis_id=hyp_id,
                verified=False,  # never claim verification without a real sandbox PoC
                confidence=conf,
                evidence=str(item.get("evidence", "")),
                poc_artifact=None,
            )
        return hyps

    # --- probe --------------------------------------------------------------
    def probe(
        self, hypothesis: RVDHypothesis, model: TargetModel, *, generate_poc: bool
    ) -> RVDObservation:
        return self._assessments.get(
            hypothesis.id,
            RVDObservation(hypothesis_id=hypothesis.id, verified=False, confidence=0.2),
        )
