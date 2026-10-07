"""Worker registration and heartbeat models."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class Worker(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Registered scan worker."""

    __tablename__ = "workers"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    pid: Mapped[int | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")  # idle, busy, offline
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)  # supported scan types, max_concurrent_jobs, etc.
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="worker")


class WorkerHeartbeat(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Worker heartbeat log for monitoring."""

    __tablename__ = "worker_heartbeats"

    worker_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    cpu_percent: Mapped[float | None] = mapped_column(nullable=True)
    memory_mb: Mapped[int | None] = mapped_column(nullable=True)
    disk_mb: Mapped[int | None] = mapped_column(nullable=True)
    heartbeat_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    worker: Mapped[Worker] = relationship()


# Update ScanJob to reference worker
# (This will be done via migration - adding worker_id column)
