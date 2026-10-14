"""Plugin database models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from app.models.projects import Project


class Plugin(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Installed plugin record."""

    __tablename__ = "plugins"

    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(100), nullable=False)
    license: Mapped[str] = mapped_column(String(50), nullable=False, default="MIT")
    homepage: Mapped[str | None] = mapped_column(String(200))
    repository: Mapped[str | None] = mapped_column(String(200))

    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    min_core_version: Mapped[str] = mapped_column(String(50), nullable=False)
    max_core_version: Mapped[str | None] = mapped_column(String(50))
    python_version: Mapped[str] = mapped_column(String(50), nullable=False, default=">=3.12")

    capabilities: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    permissions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    resource_limits: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    config_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    entry_point: Mapped[str] = mapped_column(String(200), nullable=False)
    dependencies: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    checksum: Mapped[str | None] = mapped_column(String(64))  # SHA256

    enabled: Mapped[bool] = mapped_column(nullable=False, default=True, index=True)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Plugin file storage path
    plugin_path: Mapped[str] = mapped_column(String(500), nullable=False)

    # Configuration
    default_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    executions: Mapped[list["PluginExecution"]] = relationship(back_populates="plugin", lazy="dynamic")
    project_configs: Mapped[list["PluginProjectConfig"]] = relationship(back_populates="plugin", lazy="dynamic")


class PluginExecution(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Plugin execution log."""

    __tablename__ = "plugin_executions"

    plugin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("plugins.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), index=True
    )

    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)  # manual, scheduled, scan

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")  # running, succeeded, failed, timeout
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    input_context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    plugin_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    warnings: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    cpu_time_ms: Mapped[int | None] = mapped_column()
    memory_peak_mb: Mapped[int | None] = mapped_column()

    # Relationships
    plugin: Mapped["Plugin"] = relationship(back_populates="executions")


class PluginProjectConfig(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Plugin configuration per project."""

    __tablename__ = "plugin_project_configs"

    plugin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("plugins.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )

    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    overridden_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    # Relationships
    plugin: Mapped["Plugin"] = relationship(back_populates="project_configs")
    project: Mapped["Project"] = relationship()

    __table_args__ = (
        # Unique constraint: one config per plugin per project
        # (Implemented via unique index in migration)
    )


class PluginDependency(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Plugin dependency tracking."""

    __tablename__ = "plugin_dependencies"

    plugin_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("plugins.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dependency_name: Mapped[str] = mapped_column(String(100), nullable=False)
    dependency_version: Mapped[str] = mapped_column(String(50), nullable=False)
    dependency_type: Mapped[str] = mapped_column(String(32), nullable=False)  # python, system, plugin

    # Resolution status
    resolved: Mapped[bool] = mapped_column(nullable=False, default=False)
    resolved_version: Mapped[str | None] = mapped_column(String(50))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
