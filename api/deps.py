"""Shared FastAPI dependencies: DB session, authenticated principal, RBAC guards."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from core.db import get_session
from core.enums import Role
from core.security import Principal, authenticate, require_role


async def db_session() -> AsyncIterator[AsyncSession]:
    async for s in get_session():
        yield s


SessionDep = Annotated[AsyncSession, Depends(db_session)]


async def current_principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    return authenticate(token)


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def requires(role: Role):  # type: ignore[no-untyped-def]
    async def _dep(principal: PrincipalDep) -> Principal:
        require_role(principal, role)
        return principal

    return _dep
