"""Alembic environment.

Migration convention (Phase 2 onward): append-only migrations, never rewrite
history. ``target_metadata`` comes from the model package so autogenerate
sees every registered table.
"""

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.config import get_settings
from app.models import Base

config = context.config

# Always drive migrations from application settings so the DSN has a single
# source of truth (environment variables / .env), never a stale ini value.
# ConfigParser treats percent signs as interpolation markers.  Passwords may
# legitimately contain them, so escape them before handing the URL to Alembic.
config.set_main_option("sqlalchemy.url", get_settings().postgres_dsn.replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
