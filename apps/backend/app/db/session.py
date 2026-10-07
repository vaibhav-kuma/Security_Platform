"""SQLAlchemy engine/session factory.

The engine is created lazily so tests can override the DSN (the test suite
points ``POSTGRES_DB`` at a dedicated database before settings are read).
The Phase 2 domain schema lives in ``app/models`` and is applied through the
Alembic migration chain.
"""

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def get_engine() -> Any:
    """Return the process-scoped engine. Not cached to allow worker reinitialization."""
    settings = get_settings()
    return create_engine(settings.postgres_dsn, pool_pre_ping=True)


def make_session_factory(engine: Any) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a database session (Phase 2 wiring)."""
    factory = make_session_factory(get_engine())
    session = factory()
    try:
        yield session
    finally:
        session.close()


# Kept as a small compatibility wrapper for callers that need the application
# engine.  Engine construction itself remains cached and process-scoped.
def make_engine(**kwargs: Any) -> Any:
    if kwargs:
        return create_engine(get_settings().postgres_dsn, pool_pre_ping=True, **kwargs)
    return get_engine()
