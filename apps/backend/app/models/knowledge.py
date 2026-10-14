"""Knowledge Base models for versioned security knowledge packs."""

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from app.models.identity import User


class KnowledgePackType(str, Enum):
    """Types of knowledge packs."""
    WSTG = "wstg"                    # OWASP Web Security Testing Guide
    API_SECURITY = "api_security"    # OWASP API Security Top 10
    MASTG = "mastg"                  # Mobile Application Security Testing Guide
    MASVS = "masvs"                  # Mobile Application Security Verification Standard
    CWE = "cwe"                      # Common Weakness Enumeration
    CVSS = "cvss"                    # CVSS metadata
    DETECTION_RULES = "detection_rules"  # Vulnerability detection rules
    REMEDIATION = "remediation"      # Remediation guidance
    METHODOLOGY = "methodology"      # Testing methodology
    FINGERPRINTS = "fingerprints"    # Technology fingerprints
    CUSTOM = "custom"                # Custom/third-party packs


class KnowledgePackStatus(str, Enum):
    """Knowledge pack installation status."""
    PENDING = "pending"
    INSTALLED = "installed"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class KnowledgePack(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Knowledge pack container."""

    __tablename__ = "knowledge_packs"

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    pack_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(100), nullable=False)
    license: Mapped[str] = mapped_column(String(50), nullable=False, default="MIT")
    homepage: Mapped[str | None] = mapped_column(String(200))
    repository: Mapped[str] = mapped_column(String(200), nullable=False)

    # Version compatibility
    min_core_version: Mapped[str] = mapped_column(String(50), nullable=False)
    max_core_version: Mapped[str | None] = mapped_column(String(50))
    schema_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")

    # Integrity
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA256
    signature: Mapped[str | None] = mapped_column(String(500))  # GPG signature

    # Status
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=KnowledgePackStatus.PENDING, index=True)
    is_official: Mapped[bool] = mapped_column(nullable=False, default=False)
    installed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    pack_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    contents: Mapped[list["PackContent"]] = relationship(back_populates="pack", lazy="dynamic", cascade="all, delete-orphan")
    versions: Mapped[list["PackVersion"]] = relationship(back_populates="pack", lazy="dynamic", cascade="all, delete-orphan")
    dependencies: Mapped[list["PackDependency"]] = relationship(
        back_populates="pack",
        lazy="dynamic",
        cascade="all, delete-orphan",
        foreign_keys="PackDependency.pack_id",
    )
    dependents: Mapped[list["PackDependency"]] = relationship(
        back_populates="depends_on_pack",
        lazy="dynamic",
        foreign_keys="PackDependency.depends_on_id",
    )
    installations: Mapped[list["PackInstallation"]] = relationship(back_populates="pack", lazy="dynamic", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_knowledge_pack_name_version"),
    )


class PackContent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual rule/content within a knowledge pack."""

    __tablename__ = "pack_contents"

    pack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Identity
    content_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # e.g., "WSTG-INFO-01"
    content_version: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    methodology: Mapped[str | None] = mapped_column(String(100))  # e.g., "OWASP WSTG v4.2"
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    subcategory: Mapped[str | None] = mapped_column(String(100))

    # Target applicability
    target_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    technologies: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Requirements
    prerequisites: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_requirements: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Guidance
    severity_guidance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    confidence_guidance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # References
    references: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    capec_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Detection behavior
    detection_behavior: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # e.g., {"type": "active", "technique": "fuzzing", "parameters": {}}

    # Remediation (for remediation packs)
    remediation_guidance: Mapped[str | None] = mapped_column(Text)
    remediation_complexity: Mapped[str | None] = mapped_column(String(50))
    remediation_references: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)

    # Content
    description: Mapped[str] = mapped_column(Text, nullable=False)
    long_description: Mapped[str | None] = mapped_column(Text)
    examples: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    content_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    pack: Mapped["KnowledgePack"] = relationship(back_populates="contents")

    __table_args__ = (
        UniqueConstraint("pack_id", "content_id", name="uq_pack_content"),
    )


class PackVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Version history for a knowledge pack."""

    __tablename__ = "pack_versions"

    pack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    changelog: Mapped[str] = mapped_column(Text, nullable=False)
    compatibility_notes: Mapped[str | None] = mapped_column(Text)
    breaking_changes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    deprecated_content: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    new_content: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    updated_content: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    # Relationships
    pack: Mapped["KnowledgePack"] = relationship(back_populates="versions")

    __table_args__ = (
        UniqueConstraint("pack_id", "version", name="uq_pack_version"),
    )


class PackDependency(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Dependencies between knowledge packs."""

    __tablename__ = "pack_dependencies"

    pack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    depends_on_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dependency_type: Mapped[str] = mapped_column(String(32), nullable=False)  # required, optional, conflicts
    min_version: Mapped[str | None] = mapped_column(String(50))
    max_version: Mapped[str | None] = mapped_column(String(50))
    reason: Mapped[str | None] = mapped_column(Text)

    # Relationships
    pack: Mapped["KnowledgePack"] = relationship(back_populates="dependencies", foreign_keys=[pack_id])
    depends_on_pack: Mapped["KnowledgePack"] = relationship(back_populates="dependents", foreign_keys=[depends_on_id])

    __table_args__ = (
        UniqueConstraint("pack_id", "depends_on_id", name="uq_pack_dependency"),
    )


class PackInstallation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Installation record for a knowledge pack."""

    __tablename__ = "pack_installations"

    pack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("knowledge_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    installed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # upload, registry, auto
    source_url: Mapped[str | None] = mapped_column(String(500))
    previous_version: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # success, failed, rolled_back
    error: Mapped[str | None] = mapped_column(Text)
    rollback_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rolled_back_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    # Relationships
    pack: Mapped["KnowledgePack"] = relationship(back_populates="installations")


class PackContentUsage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Track which content was used in which scan for reproducibility."""

    __tablename__ = "pack_content_usage"

    pack_content_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("pack_contents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    matched: Mapped[bool] = mapped_column(nullable=False, default=False)
    match_details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)