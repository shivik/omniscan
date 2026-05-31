"""RVD — Residual Vulnerability Discovery (flagship).

An agentic comprehend -> hypothesize -> probe/verify -> score-chainability ->
normalize loop, not a ruleset. Reasoning is delegated to a pluggable frontier-model
backend (``backends/``) so the engine is model-agnostic. See SKILLS.md §R.

Safety (AGENT.md §2.6): RVD runs only on owned/authorized assets (same scope_guard
gate, no exceptions), PoCs are encrypted + RBAC-gated, findings default to embargoed,
and there is no third-party/public mass-scan mode.
"""
