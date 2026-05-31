"""Structured problem responses (RFC 9457-style).

Never leak internal paths, secrets, or stack traces. Every error returned to a
client has ``type``, ``title``, ``detail``, ``status``.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.redact import redact
from core.scope_guard import ScopeViolation
from core.security import AuthError, Forbidden


class Problem(Exception):
    def __init__(self, status: int, title: str, detail: str, type_: str = "about:blank") -> None:
        self.status = status
        self.title = title
        self.detail = detail
        self.type = type_
        super().__init__(detail)


def _response(status: int, title: str, detail: str, type_: str = "about:blank") -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"type": type_, "title": title, "detail": str(redact(detail)), "status": status},
    )


async def _problem(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, Problem)
    return _response(exc.status, exc.title, exc.detail, exc.type)


async def _auth(_: Request, exc: Exception) -> JSONResponse:
    return _response(401, "Unauthorized", str(exc), "urn:omniscan:auth")


async def _forbidden(_: Request, exc: Exception) -> JSONResponse:
    return _response(403, "Forbidden", str(exc), "urn:omniscan:rbac")


async def _scope(_: Request, exc: Exception) -> JSONResponse:
    return _response(403, "Scope violation", str(exc), "urn:omniscan:scope")


async def _value(_: Request, exc: Exception) -> JSONResponse:
    return _response(400, "Invalid request", str(exc), "urn:omniscan:validation")


def register_exception_handlers(app: FastAPI) -> None:
    # add_exception_handler (vs the @decorator form) keeps the handlers properly typed.
    app.add_exception_handler(Problem, _problem)
    app.add_exception_handler(AuthError, _auth)
    app.add_exception_handler(Forbidden, _forbidden)
    app.add_exception_handler(ScopeViolation, _scope)
    app.add_exception_handler(ValueError, _value)
