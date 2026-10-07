"""Scan execution models: scans, scan jobs, and scan events.

A scan is a unit of assessment work against a target; jobs are the
individual worker tasks within it; events are the append-only log of
everything a scan observed or did.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text, event, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import ScanJobStatus, ScanStatus, ScanType, native_enum

if TYPE_CHECKING:
    from app.models.workers import Worker


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(native_enum(ScanType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        native_enum(ScanStatus), nullable=False, default=ScanStatus.PENDING
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="scan")


class ScanJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One worker task belonging to a scan."""

    __tablename__ = "scan_jobs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    worker_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workers.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ScanJobStatus] = mapped_column(
        native_enum(ScanJobStatus), nullable=False, default=ScanJobStatus.QUEUED
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped[Scan] = relationship(back_populates="jobs")
    events: Mapped[list["ScanEvent"]] = relationship(back_populates="job")
    worker: Mapped["Worker"] = relationship(back_populates="jobs")


class ScanEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only event emitted during scan execution."""

    __tablename__ = "scan_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE")
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    job: Mapped[ScanJob | None] = relationship(back_populates="events")


def _immutable(mapper: object, connection: object, target: object) -> None:
    raise ValueError("ScanEvent rows are immutable")


event.listen(ScanEvent, "before_update", _immutable)
event.listen(ScanEvent, "before_delete", _immutable)
