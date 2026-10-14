"""Declarative base, shared mixins, and naming conventions for domain models.

All Phase 2 models derive from :class:`Base`. Constraint names follow a fixed
convention so Alembic autogenerate output is stable and reviewable.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, MetaData, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Deterministic constraint naming — required for reproducible migrations.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Shared declarative base for every domain model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Client-generated UUIDv4 primary key."""

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """created_at / updated_at audit timestamps (server clock, timezone-aware)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Soft deletion marker.

    Application code must never hard-delete rows carrying this mixin; the
    redaction pipeline (Phase 9+) may purge or mask data independently.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None
