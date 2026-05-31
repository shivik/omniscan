"""OmniScan Python IAST agent.

A real, working Interactive Application Security Testing agent for Python apps. It
instruments dangerous *sinks* (os.system, subprocess(shell=True), eval/exec,
pickle.loads, ...) from inside the running process and, when traffic exercises them,
reports a runtime source->sink event to the OmniScan collector — correlating the sink
with the active request (route/param) to flag tainted flows.

This is genuine IAST for the Python runtime: it observes the app from the inside while
it runs, not from static code or external traffic. Other runtimes (JVM, Node, .NET)
need their own language agents (bytecode/loader instrumentation) — not provided here.

Usage (see ``omniscan_iast.bootstrap``):

    import omniscan_iast
    omniscan_iast.instrument()              # reads OMNISCAN_IAST_* from the env
    app = omniscan_iast.wrap_wsgi(app)      # bind request context for taint correlation
"""

from __future__ import annotations

from omniscan_iast.agent import instrument, uninstrument
from omniscan_iast.context import bind_request, clear_request, wrap_wsgi

__all__ = ["instrument", "uninstrument", "bind_request", "clear_request", "wrap_wsgi"]
