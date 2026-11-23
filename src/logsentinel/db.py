"""Database engine and session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from logsentinel.config import get_settings, normalize_db_url


def make_engine(url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine.

    In-memory SQLite (used by unit tests) needs a StaticPool so every
    connection sees the same database.
    """
    url = normalize_db_url(url or get_settings().database_url)
    if url.startswith("sqlite") and ":memory:" in url:
        return create_engine(
            url, connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Process-wide engine built from DATABASE_URL."""
    return make_engine()


def get_sessionmaker(engine: Engine | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=engine or get_engine(), expire_on_commit=False)


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """Open a session, commit on success, roll back on error."""
    session = get_sessionmaker(engine)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(engine: Engine | None = None) -> None:
    """Create all tables directly (used for SQLite/tests; Postgres uses Alembic)."""
    from logsentinel.models import Base

    Base.metadata.create_all(engine or get_engine())
