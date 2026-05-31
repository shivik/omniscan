"""Async database engine + session management (SQLAlchemy 2.0).

Dev uses SQLite via aiosqlite; prod uses PostgreSQL via asyncpg. The same models
and session API work against both. Schema is created with ``init_db`` in dev; prod
uses Alembic migrations (see ``migrations/``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _ensure_engine() -> async_sessionmaker[AsyncSession]:
    global _engine, _sessionmaker
    if _sessionmaker is None:
        settings = get_settings()
        _engine = create_async_engine(settings.database_url, echo=False, future=True)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional session scope: commit on success, rollback on error."""
    maker = _ensure_engine()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session."""
    async with session_scope() as session:
        yield session


async def init_db() -> None:
    """Ensure the schema exists.

    Dev (SQLite): create tables directly — zero-infra convenience. Other backends
    (PostgreSQL): the schema is owned by Alembic migrations (``make migrate``), so we
    do NOT ``create_all`` here — that would diverge from the migration history.
    """
    import core.models  # noqa: F401  (register models on the metadata)

    _ensure_engine()  # initializes the module-level engine
    assert _engine is not None
    if _engine.dialect.name != "sqlite":
        return  # migrations own the schema on Postgres/etc.
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
