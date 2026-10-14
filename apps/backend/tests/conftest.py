"""Shared fixtures for database-backed tests.

A dedicated ``platform_test`` database is recreated once per pytest session
and migrated to head through the real Alembic migration chain, so tests
exercise exactly the schema a fresh deployment gets. Each test runs inside a
transaction that rolls back at teardown, keeping tests isolated without
rebuilding the schema between them.

Works identically against the local Docker Compose Postgres and the GitHub
Actions service container: both expose the configured user at
``POSTGRES_HOST:POSTGRES_PORT``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.models.identity import User

# Point the whole test process at a dedicated database before anything reads
# POSTGRES_DB (settings, the Alembic env, application modules).
os.environ["POSTGRES_DB"] = "platform_test"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"
os.environ["POSTGRES_USER"] = "platform"
os.environ["POSTGRES_PASSWORD"] = "change-me-dev-only"
os.environ["MINIO_ACCESS_KEY"] = "test-access-key"
os.environ["MINIO_SECRET_KEY"] = "test-secret-key"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["TESTING"] = "true"

from app.config import get_settings
from app.main import create_app

get_settings.cache_clear()

BACKEND_DIR = Path(__file__).resolve().parents[1]
TEST_DB = "platform_test"


def _create_test_database() -> None:
    """Recreate the test database from the ``postgres`` maintenance DB."""
    settings = get_settings()
    admin_dsn = (
        f"postgresql+psycopg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/postgres"
    )
    engine = create_engine(admin_dsn, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)"))
            conn.execute(text(f"CREATE DATABASE {TEST_DB}"))
    finally:
        engine.dispose()


def _run_migrations() -> None:
    """Apply the full Alembic chain to the test database."""
    from alembic.config import Config

    from alembic import command

    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(config, "head")


@pytest.fixture(scope="session")
def db_engine() -> Iterator[Engine]:
    """Engine bound to the freshly migrated test database."""
    _create_test_database()
    _run_migrations()

    from app.db.session import make_engine

    engine = make_engine()
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Session inside a transaction rolled back after each test.

    ``join_transaction_mode="create_savepoint"`` lets code under test call
    ``session.commit()`` (e.g. the RBAC seed) while the outer transaction
    survives until teardown.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db_session: Session) -> Iterator[TestClient]:
    """TestClient with dependency override for db_session."""
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    from app.db.session import get_db
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture()
def auth_headers(db_session: Session, test_user: User) -> dict:
    """Generate authentication headers for test requests."""
    from app.auth.token import create_token_pair
    tokens = create_token_pair(
        user_id=str(test_user.id),
        email=test_user.email,
        org_id=None,
    )
    return {"Authorization": f"Bearer {tokens.access_token}"}
