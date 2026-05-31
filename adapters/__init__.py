"""Scanner adapters — the main extension point.

Each adapter wraps one scanner (SAST/DAST/IAST) or the RVD engine, normalizing
its native output to SARIF. Adapters never touch the findings DB and never emit a
non-SARIF format upstream of ``normalize/``. They run isolated (AGENT.md §2.3).
"""
