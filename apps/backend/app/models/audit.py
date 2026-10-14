"""Audit log and security event models (append-only).

Rows here are never soft-deleted or updated; they are the platform's
accountability record. Secrets must be redacted before details are stored.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, event, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin
from app.models.enums import SecurityEventType, native_enum


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Immutable record of a user- or system-initiated action."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL")
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[uuid.UUID | None] = mapped_column()
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source_ip: Mapped[object | None] = mapped_column(INET)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class SecurityEvent(UUIDPrimaryKeyMixin, Base):
    """Platform security signal (auth failures, scope violations, ...)."""

    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_type: Mapped[SecurityEventType] = mapped_column(
        native_enum(SecurityEventType), nullable=False
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source_ip: Mapped[object | None] = mapped_column(INET)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


def _immutable(mapper: object, connection: object, target: object) -> None:
    raise ValueError(f"{target.__class__.__name__} rows are immutable")


for _model in (AuditLog, SecurityEvent):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
