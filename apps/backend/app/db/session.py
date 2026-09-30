"""SQLAlchemy engine/session factory.

The engine is created lazily so tests can override the DSN. No models are
defined yet; Phase 2 introduces the domain schema and Alembic migrations.
"""

from collections.abc import Iterator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def make_engine(**kwargs: Any) -> Any:
    settings = get_settings()
    return create_engine(settings.postgres_dsn, pool_pre_ping=True, **kwargs)


def make_session_factory(engine: Any) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a database session (Phase 2 wiring)."""
    engine = make_engine()
    factory = make_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
