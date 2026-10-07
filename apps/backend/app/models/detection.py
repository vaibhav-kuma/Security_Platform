"""Detection and triage models: rules, observations, findings, evidence.

Invariants (non-negotiable):
- Observation and Finding are DISTINCT tables. An observation is a raw,
  unvalidated signal; a finding is a triaged, human- or rule-confirmed issue.
  Promotion is an explicit link (``Finding.promoted_from_observation_id``),
  never an in-place type change.
- severity and confidence are INDEPENDENT enum columns; one is never
  derived from the other.
- Evidence storage is backend-agnostic (inline or object storage) and carries
  redaction markers so the Phase 9+ redaction pipeline can operate on it.

Heuristic scanner input is untrusted: nothing here promotes an observation
to a confirmed finding automatically.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingRelationType,
    FindingStatus,
    ObservationType,
    ReviewPriority,
    ReviewReason,
    ReviewStatus,
    Severity,
    native_enum,
)


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Declarative rule that can produce observations from raw data."""

    __tablename__ = "detection_rules"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expression: Mapped[str] = mapped_column(Text, nullable=False)
    severity_hint: Mapped[Severity | None] = mapped_column(native_enum(Severity))
    confidence_hint: Mapped[Confidence | None] = mapped_column(native_enum(Confidence))
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )


class Observation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Raw, unvalidated signal. Never treated as a confirmed vulnerability."""

    __tablename__ = "observations"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    detection_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="SET NULL")
    )
    observation_type: Mapped[ObservationType] = mapped_column(
        native_enum(ObservationType), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Triaged, actionable issue. Promoted from an observation via an
    explicit FK — observations are never converted in place."""

    __tablename__ = "findings"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    promoted_from_observation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("observations.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        native_enum(FindingStatus), nullable=False, default=FindingStatus.OPEN
    )
    severity: Mapped[Severity] = mapped_column(native_enum(Severity), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(native_enum(Confidence), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    recommendation: Mapped[str | None] = mapped_column(Text)

    evidence: Mapped[list["Evidence"]] = relationship(back_populates="finding")
    comments: Mapped[list["FindingComment"]] = relationship(back_populates="finding")


class Evidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Proof attached to a finding. Storage is extensible: ``inline`` keeps
    the content in ``content``; object storage uses ``object_key``.
    Redaction markers are set by the Phase 9+ pipeline, never bypassed."""

    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[EvidenceType] = mapped_column(native_enum(EvidenceType), nullable=False)
    storage: Mapped[str] = mapped_column(String(16), nullable=False, default="inline")
    content: Mapped[str | None] = mapped_column(Text)
    object_key: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class FindingComment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "finding_comments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="comments")


class FindingRelationship(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Directed link between findings (duplicate-of, related-to, ...)."""

    __tablename__ = "finding_relationships"

    source_finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[FindingRelationType] = mapped_column(
        native_enum(FindingRelationType), nullable=False
    )


class CWE(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """CWE (Common Weakness Enumeration) reference data."""

    __tablename__ = "cwes"

    cwe_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extended_description: Mapped[str | None] = mapped_column(Text)
    related_weaknesses: Mapped[list[str]] = mapped_column(
        "related_weaknesses", JSONB, nullable=False, default=list
    )
    consequences: Mapped[list[str]] = mapped_column(
        "consequences", JSONB, nullable=False, default=list
    )
    mitigations: Mapped[list[str]] = mapped_column(
        "mitigations", JSONB, nullable=False, default=list
    )


class ManualReviewQueue(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Manual review queue for ambiguous observations."""

    __tablename__ = "manual_review_queue"

    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("observations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity_hint: Mapped[str | None] = mapped_column(String(16))
    confidence_hint: Mapped[str | None] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    review_reason: Mapped[ReviewReason] = mapped_column(native_enum(ReviewReason), nullable=False)
    priority: Mapped[ReviewPriority] = mapped_column(native_enum(ReviewPriority), nullable=False)
    status: Mapped[ReviewStatus] = mapped_column(
        native_enum(ReviewStatus), nullable=False, default=ReviewStatus.PENDING
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    reviewer_notes: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    promoted_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
