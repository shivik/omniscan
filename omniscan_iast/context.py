"""Per-request context for taint correlation.

A WSGI middleware binds the current request's route + input values into a contextvar.
When a sink fires, the agent checks whether the sink's argument contains one of those
request-provided values — if so, it's a tainted source->sink flow (high confidence).
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

_current: ContextVar[RequestContext | None] = ContextVar("omniscan_iast_request", default=None)


@dataclass
class RequestContext:
    route: str
    # name -> value for every request-provided input (query/body/header params).
    params: dict[str, str] = field(default_factory=dict)

    def taint_match(self, value: str) -> str | None:
        """Return the param name whose value appears in ``value`` (tainted), else None."""
        for name, pval in self.params.items():
            if pval and len(pval) >= 3 and pval in value:
                return name
        return None


def bind_request(route: str, params: dict[str, str]) -> None:
    _current.set(RequestContext(route=route, params={k: str(v) for k, v in params.items()}))


def clear_request() -> None:
    _current.set(None)


def current() -> RequestContext | None:
    return _current.get()


def wrap_wsgi(app: Any) -> Any:
    """WSGI middleware that binds request route + query params for taint correlation."""

    def middleware(environ: dict[str, Any], start_response: Any) -> Any:
        route = environ.get("PATH_INFO", "/")
        params: dict[str, str] = {}
        for name, values in parse_qs(environ.get("QUERY_STRING", "")).items():
            if values:
                params[name] = values[0]
        bind_request(route, params)
        try:
            return app(environ, start_response)
        finally:
            clear_request()

    return middleware
