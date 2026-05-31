"""The agent: instrument dangerous sinks and report runtime flows.

When an instrumented sink is invoked, the agent captures the call site, checks the
argument against the active request's input values (taint), builds an event, reports
it, and then calls the original function (observe-only; it never blocks the app).
"""

from __future__ import annotations

import functools
import importlib
import sys
from collections.abc import Callable
from typing import Any

from omniscan_iast import context
from omniscan_iast.reporter import BufferReporter, Reporter, from_env

# (module, attribute, rule_id, severity, taint_arg_index_or_kwarg)
# taint_extractor returns the string to taint-check, or None (sink-reached only).
_SINKS: list[dict[str, Any]] = [
    {"mod": "os", "attr": "system", "rule": "IAST-cmd-injection", "sev": "high", "arg": 0},
    {"mod": "builtins", "attr": "eval", "rule": "IAST-code-injection", "sev": "high", "arg": 0},
    {"mod": "builtins", "attr": "exec", "rule": "IAST-code-injection", "sev": "high", "arg": 0},
    {
        "mod": "pickle",
        "attr": "loads",
        "rule": "IAST-insecure-deserialization",
        "sev": "high",
        "arg": None,
    },
    {
        "mod": "pickle",
        "attr": "load",
        "rule": "IAST-insecure-deserialization",
        "sev": "high",
        "arg": None,
    },
    # subprocess sinks only matter when shell=True (shell injection surface).
    {
        "mod": "subprocess",
        "attr": "run",
        "rule": "IAST-shell-injection",
        "sev": "high",
        "arg": 0,
        "shell_only": True,
    },
    {
        "mod": "subprocess",
        "attr": "call",
        "rule": "IAST-shell-injection",
        "sev": "high",
        "arg": 0,
        "shell_only": True,
    },
    {
        "mod": "subprocess",
        "attr": "Popen",
        "rule": "IAST-shell-injection",
        "sev": "high",
        "arg": 0,
        "shell_only": True,
    },
]

_installed: list[tuple[Any, str, Callable[..., Any]]] = []
_reporter: Reporter | None = None


def _candidate_string(
    spec: dict[str, Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> str | None:
    idx = spec.get("arg")
    if idx is None:
        return None
    val = args[idx] if len(args) > idx else None
    if isinstance(val, (list, tuple)):
        val = " ".join(str(v) for v in val)
    return val if isinstance(val, str) else (str(val) if val is not None else None)


def _make_wrapper(original: Callable[..., Any], spec: dict[str, Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            if not spec.get("shell_only") or kwargs.get("shell") is True:
                _record(spec, args, kwargs)
        except Exception:
            pass  # instrumentation must never break the host app
        return original(*args, **kwargs)

    return wrapper


def _record(spec: dict[str, Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    frame = sys._getframe(2)  # _record <- wrapper <- caller (the app code)
    candidate = _candidate_string(spec, args, kwargs)
    ctx = context.current()
    tainted = False
    param = None
    if ctx is not None and candidate:
        param = ctx.taint_match(candidate)
        tainted = param is not None
    event = {
        "sink": f"{spec['mod']}.{spec['attr']}",
        "rule_id": spec["rule"],
        "severity": spec["sev"],
        "file": frame.f_code.co_filename,
        "line": frame.f_lineno,
        "function": frame.f_code.co_name,
        "route": ctx.route if ctx else None,
        "param": param,
        "tainted": tainted,
        # evidence is a redacted hint — never the raw (possibly secret) tainted value.
        "evidence": f"sink {spec['mod']}.{spec['attr']} reached"
        + (f" with tainted input from '{param}'" if tainted else ""),
    }
    if _reporter is not None:
        _reporter.report(event)


def instrument(reporter: Reporter | None = None) -> Reporter:
    """Patch sinks. Returns the active reporter (a BufferReporter if none configured)."""
    global _reporter
    _reporter = reporter or from_env() or BufferReporter()
    for spec in _SINKS:
        try:
            module = importlib.import_module(spec["mod"])
        except ImportError:
            continue
        original = getattr(module, spec["attr"], None)
        if original is None or getattr(original, "__omniscan_wrapped__", False):
            continue
        wrapper = _make_wrapper(original, spec)
        wrapper.__omniscan_wrapped__ = True  # type: ignore[attr-defined]
        setattr(module, spec["attr"], wrapper)
        _installed.append((module, spec["attr"], original))
    return _reporter


def uninstrument() -> None:
    """Restore original functions (mainly for tests)."""
    global _reporter
    for module, attr, original in _installed:
        setattr(module, attr, original)
    _installed.clear()
    if _reporter is not None:
        _reporter.flush()
    _reporter = None
