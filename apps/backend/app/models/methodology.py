"""Methodology engine models: versioned methodologies and test-case runs.

A methodology is a structured testing playbook. Versions are immutable;
each version owns its test cases. Runs link test cases to scans/projects.
"""

import uuid
from typing import Any, Literal

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    TestCaseRunStatus,
    native_enum,
)

# Type aliases for coverage status
CoverageStatus = Literal["tested", "not_tested", "needs_review", "not_applicable"]


class Methodology(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "methodologies"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    versions: Mapped[list["MethodologyVersion"]] = relationship(back_populates="methodology")


class MethodologyVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable numbered revision of a methodology definition."""

    __tablename__ = "methodology_versions"
    __table_args__ = (UniqueConstraint("methodology_id", "version", name="methodology_version"),)

    methodology_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("methodologies.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    methodology: Mapped[Methodology] = relationship(back_populates="versions")
    test_cases: Mapped[list["TestCase"]] = relationship(back_populates="methodology_version")


class TestCase(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual test case within a methodology version."""

    __tablename__ = "test_cases"

    methodology_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("methodology_versions.id", ondelete="CASCADE"), nullable=False
    )
    identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(128))
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Phase 10 fields
    supported_target_types: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    prerequisites: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    passive_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    safe_mode_compatible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    evidence_requirements: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    detection_rules: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    methodology_version: Mapped[MethodologyVersion] = relationship(back_populates="test_cases")
    runs: Mapped[list["TestCaseRun"]] = relationship(back_populates="test_case")


class TestCaseRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Execution record of one test case within a scan/project context."""

    __tablename__ = "test_case_runs"

    test_case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("test_cases.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[TestCaseRunStatus] = mapped_column(
        native_enum(TestCaseRunStatus),
        nullable=False,
        default=TestCaseRunStatus.PENDING,
    )
    # Phase 10: Coverage tracking
    coverage_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_tested"
    )
    coverage_reason: Mapped[str | None] = mapped_column(Text)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    test_case: Mapped[TestCase] = relationship(back_populates="runs")
