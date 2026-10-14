"""Report generation and bug-bounty workspace models.

Phase 15: Comprehensive reporting and bug-bounty research workspace.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    ReportStatus,
    ReportType,
    Severity,
    Confidence,
    native_enum,
)


class Report(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Report generation request and metadata."""

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("id", "project_id", name="id_project"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    report_type: Mapped[ReportType] = mapped_column(native_enum(ReportType), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        native_enum(ReportStatus), nullable=False, default=ReportStatus.DRAFT
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    object_key: Mapped[str | None] = mapped_column(String(1024))
    error: Mapped[str | None] = mapped_column(Text)

    # Report content (structured for multiple format rendering)
    executive_summary: Mapped[str | None] = mapped_column(Text)
    scope_summary: Mapped[str | None] = mapped_column(Text)
    methodology_summary: Mapped[str | None] = mapped_column(Text)
    test_coverage_summary: Mapped[str | None] = mapped_column(Text)
    asset_inventory_summary: Mapped[str | None] = mapped_column(Text)
    findings_summary: Mapped[str | None] = mapped_column(Text)
    risk_summary: Mapped[str | None] = mapped_column(Text)
    recommendations_summary: Mapped[str | None] = mapped_column(Text)
    appendix: Mapped[str | None] = mapped_column(Text)

    # Rendered outputs
    html_object_key: Mapped[str | None] = mapped_column(String(1024))
    markdown_object_key: Mapped[str | None] = mapped_column(String(1024))
    pdf_object_key: Mapped[str | None] = mapped_column(String(1024))
    json_object_key: Mapped[str | None] = mapped_column(String(1024))

    # Versioning
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("reports.id", ondelete="SET NULL")
    )

    # Relationships
    project: Mapped["Project"] = relationship(back_populates="reports")
    requested_by_user: Mapped["User"] = relationship()
    sections: Mapped[list["ReportSection"]] = relationship(back_populates="report", order_by="ReportSection.order")
    findings: Mapped[list["ReportFinding"]] = relationship(back_populates="report")
    versions: Mapped[list["ReportVersion"]] = relationship(back_populates="report", order_by="ReportVersion.version.desc()")


class ReportSection(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual sections within a report."""

    __tablename__ = "report_sections"
    __table_args__ = (
        UniqueConstraint("report_id", "slug", name="report_section_slug"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    slug: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    content: Mapped[str] = mapped_column(Text)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    content_type: Mapped[str] = mapped_column(String(64), default="markdown")  # markdown, html, text

    report: Mapped["Report"] = relationship(back_populates="sections")


class ReportFinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Finding included in a report (with report-specific overrides)."""

    __tablename__ = "report_findings"
    __table_args__ = (
        UniqueConstraint("report_id", "finding_id", name="report_finding"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Override fields for report-specific customization
    custom_title: Mapped[str | None] = mapped_column(String(512))
    custom_severity: Mapped[Severity | None] = mapped_column(native_enum(Severity))
    custom_confidence: Mapped[Confidence | None] = mapped_column(native_enum(Confidence))
    custom_impact: Mapped[str | None] = mapped_column(Text)
    custom_remediation: Mapped[str | None] = mapped_column(Text)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    affected_assets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSONB, default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    owasp_refs: Mapped[list[str]] = mapped_column(JSONB, default=list)
    mastg_refs: Mapped[list[str]] = mapped_column(JSONB, default=list)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_score: Mapped[float | None] = mapped_column()

    report: Mapped["Report"] = relationship(back_populates="findings")
    finding: Mapped["Finding"] = relationship()


class ReportVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Versioned snapshots of report content."""

    __tablename__ = "report_versions"
    __table_args__ = (
        UniqueConstraint("report_id", "version", name="report_version"),
        CheckConstraint("version > 0", name="positive_version"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    change_summary: Mapped[str | None] = mapped_column(Text)

    report: Mapped["Report"] = relationship(back_populates="versions")


# =============================================================================
# Bug-Bounty Workspace Models
# =============================================================================


class BugBountyProgram(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Bug bounty program configuration."""

    __tablename__ = "bug_bounty_programs"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="org_program_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(String(128))  # hackerone, bugcrowd, intigriti, custom
    platform_program_id: Mapped[str | None] = mapped_column(String(256))
    policy_url: Mapped[str | None] = mapped_column(String(1024))
    submission_url: Mapped[str | None] = mapped_column(String(1024))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allows_public_disclosure: Mapped[bool] = mapped_column(Boolean, default=False)
    disclosure_terms: Mapped[str | None] = mapped_column(Text)
    max_bounty: Mapped[float | None] = mapped_column()
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict
    )

    organization: Mapped["Organization"] = relationship()
    policies: Mapped[list["ProgramPolicy"]] = relationship(back_populates="program")
    scopes: Mapped[list["ProgramScope"]] = relationship(back_populates="program")
    excluded_targets: Mapped[list["ExcludedTarget"]] = relationship(back_populates="program")
    research_notes: Mapped[list["ResearchNote"]] = relationship(back_populates="program")
    workspaces: Mapped[list["ResearchWorkspace"]] = relationship(back_populates="program")


class ProgramPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Program-specific testing policies."""

    __tablename__ = "program_policies"

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bug_bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    policy_type: Mapped[str] = mapped_column(String(64), nullable=False)  # testing_rules, disclosure, payment, etc.
    rules: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    severity: Mapped[str] = mapped_column(String(16), default="mandatory")  # mandatory, recommended, informational

    program: Mapped["BugBountyProgram"] = relationship(back_populates="policies")


class ProgramScope(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Authorized scope for a bug bounty program."""

    __tablename__ = "program_scopes"
    __table_args__ = (
        UniqueConstraint("program_id", "name", name="program_scope_name"),
    )

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bug_bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)  # domain, url, api, ip, cidr, mobile, other
    target_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)
    max_bounty: Mapped[float | None] = mapped_column()
    tier: Mapped[str | None] = mapped_column(String(64))  # critical, high, medium, low
    notes: Mapped[str | None] = mapped_column(Text)

    program: Mapped["BugBountyProgram"] = relationship(back_populates="scopes")


class ExcludedTarget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Explicitly excluded targets from bug bounty scope."""

    __tablename__ = "excluded_targets"
    __table_args__ = (
        UniqueConstraint("program_id", "target_value", name="program_excluded_target"),
    )

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bug_bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    excluded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    program: Mapped["BugBountyProgram"] = relationship(back_populates="excluded_targets")


class ResearchWorkspace(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Researcher's workspace for a bug bounty program."""

    __tablename__ = "research_workspaces"
    __table_args__ = (
        UniqueConstraint("program_id", "user_id", name="program_user_workspace"),
    )

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bug_bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active")  # active, paused, completed, archived
    current_phase: Mapped[str] = mapped_column(String(32), default="recon")  # recon, testing, validation, reporting
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict
    )

    program: Mapped["BugBountyProgram"] = relationship(back_populates="workspaces")
    user: Mapped["User"] = relationship()
    project: Mapped["Project"] = relationship()
    notes: Mapped[list["ResearchNote"]] = relationship(back_populates="workspace")
    observations: Mapped[list["WorkspaceObservation"]] = relationship(back_populates="workspace")
    findings: Mapped[list["WorkspaceFinding"]] = relationship(back_populates="workspace")
    reports: Mapped[list["WorkspaceReport"]] = relationship(back_populates="workspace")
    attachments: Mapped[list["WorkspaceAttachment"]] = relationship(back_populates="workspace")


class ResearchNote(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Researcher's private notes."""

    __tablename__ = "research_notes"

    program_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bug_bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("research_workspaces.id", ondelete="SET NULL"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text)
    note_type: Mapped[str] = mapped_column(String(64), default="general")  # general, recon, testing, validation, finding, report
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)  # Shared with team
    linked_assets: Mapped[list[uuid.UUID]] = mapped_column(JSONB, default=list)
    linked_findings: Mapped[list[uuid.UUID]] = mapped_column(JSONB, default=list)

    program: Mapped["BugBountyProgram"] = relationship(back_populates="research_notes")
    workspace: Mapped["ResearchWorkspace"] = relationship(back_populates="notes")
    user: Mapped["User"] = relationship()


class WorkspaceObservation(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Observations made during research (pre-finding)."""

    __tablename__ = "workspace_observations"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64))
    target_value: Mapped[str] = mapped_column(String(2048))
    severity_hint: Mapped[Severity | None] = mapped_column(native_enum(Severity))
    confidence_hint: Mapped[Confidence | None] = mapped_column(native_enum(Confidence))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open, investigating, validated, dismissed, promoted
    linked_finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))

    workspace: Mapped["ResearchWorkspace"] = relationship(back_populates="observations")
    user: Mapped["User"] = relationship()


class WorkspaceFinding(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Finding within a research workspace (can be promoted to official Finding)."""

    __tablename__ = "workspace_findings"
    __table_args__ = (
        UniqueConstraint("workspace_id", "title", name="workspace_finding_title"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspace_observations.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(native_enum(Severity), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(native_enum(Confidence), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64))
    target_value: Mapped[str] = mapped_column(String(2048))
    affected_assets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    owasp_refs: Mapped[list[str]] = mapped_column(JSONB, default=list)
    mastg_refs: Mapped[list[str]] = mapped_column(JSONB, default=list)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_score: Mapped[float | None] = mapped_column()
    status: Mapped[str] = mapped_column(String(32), default="draft")  # draft, validated, ready_to_report, reported
    promoted_to_finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    program_scope_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("program_scopes.id", ondelete="SET NULL"))

    workspace: Mapped["ResearchWorkspace"] = relationship(back_populates="findings")
    user: Mapped["User"] = relationship()
    observation: Mapped["WorkspaceObservation"] = relationship()
    promoted_finding: Mapped["Finding"] = relationship()
    program_scope: Mapped["ProgramScope"] = relationship()
    attachments: Mapped[list["WorkspaceAttachment"]] = relationship(back_populates="finding")


class WorkspaceReport(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Draft reports within workspace (before official Report)."""

    __tablename__ = "workspace_reports"
    __table_args__ = (
        UniqueConstraint("workspace_id", "title", name="workspace_report_title"),
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), default="technical")  # executive, technical, full
    status: Mapped[str] = mapped_column(String(32), default="draft")  # draft, review, ready, submitted
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    included_findings: Mapped[list[uuid.UUID]] = mapped_column(JSONB, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    parent_report_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspace_reports.id", ondelete="SET NULL"))
    official_report_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("reports.id", ondelete="SET NULL"))

    workspace: Mapped["ResearchWorkspace"] = relationship(back_populates="reports")
    user: Mapped["User"] = relationship()
    official_report: Mapped["Report"] = relationship()


class WorkspaceAttachment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Evidence attachments for workspace items."""

    __tablename__ = "workspace_attachments"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspace_findings.id", ondelete="SET NULL")
    )
    observation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspace_observations.id", ondelete="SET NULL")
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128))
    size_bytes: Mapped[int] = mapped_column()
    sha256: Mapped[str] = mapped_column(String(64))
    object_key: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    attachment_type: Mapped[str] = mapped_column(String(64), default="evidence")  # evidence, screenshot, log, pcap, other

    workspace: Mapped["ResearchWorkspace"] = relationship(back_populates="attachments")
    user: Mapped["User"] = relationship()
    finding: Mapped["WorkspaceFinding"] = relationship(back_populates="attachments")
    observation: Mapped["WorkspaceObservation"] = relationship()


# Update existing models with new relationships (these will be added to existing model files)
# Project.reports -> Report.project
# User.reports_requested -> Report.requested_by_user
# Finding.report_findings -> ReportFinding.finding
# User.research_notes -> ResearchNote.user
# User.workspaces -> ResearchWorkspace.user
# Project.workspaces -> ResearchWorkspace.project
# Organization.bug_bounty_programs -> BugBountyProgram.organization