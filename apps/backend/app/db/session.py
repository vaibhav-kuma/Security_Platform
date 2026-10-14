"""SQLAlchemy engine/session factory.

The engine is created lazily so tests can override the DSN (the test suite
points ``POSTGRES_DB`` at a dedicated database before settings are read).
The Phase 2 domain schema lives in ``app/models`` and is applied through the
Alembic migration chain.
"""

from collections.abc import Iterator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def get_engine(**kwargs: Any) -> Any:
    """Return the process-scoped engine. Not cached to allow worker reinitialization."""
    settings = get_settings()

    # Default pool settings for production worker scaling
    pool_kwargs = {
        "pool_pre_ping": True,
        "pool_size": kwargs.pop("pool_size", 10),
        "max_overflow": kwargs.pop("max_overflow", 20),
        "pool_timeout": kwargs.pop("pool_timeout", 30),
        "pool_recycle": kwargs.pop("pool_recycle", 3600),  # 1 hour
        "pool_pre_ping": True,
    }
    pool_kwargs.update(kwargs)

    return create_engine(settings.postgres_dsn, **pool_kwargs)


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
    return get_engine(**kwargs)
