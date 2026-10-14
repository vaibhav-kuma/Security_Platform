"""Pydantic schemas for reports and bug-bounty workspace."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportStatus, ReportType, Severity, Confidence


# =============================================================================
# Report Schemas
# =============================================================================

class ReportSectionBase(BaseModel):
    slug: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    content: str | None = None
    order: int = 0
    is_required: bool = False
    content_type: str = "markdown"


class ReportSectionCreate(ReportSectionBase):
    pass


class ReportSectionUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=256)
    content: str | None = None
    order: int | None = None
    is_required: bool | None = None
    content_type: str | None = None


class ReportSectionResponse(ReportSectionBase):
    id: UUID
    report_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    report_type: ReportType
    configuration: dict[str, Any] = Field(default_factory=dict)


class ReportCreate(ReportBase):
    executive_summary: str | None = None
    scope_summary: str | None = None
    methodology_summary: str | None = None
    test_coverage_summary: str | None = None
    asset_inventory_summary: str | None = None
    findings_summary: str | None = None
    risk_summary: str | None = None
    recommendations_summary: str | None = None
    appendix: str | None = None
    sections: list[ReportSectionCreate] = Field(default_factory=list)


class ReportUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=512)
    report_type: ReportType | None = None
    configuration: dict[str, Any] | None = None
    executive_summary: str | None = None
    scope_summary: str | None = None
    methodology_summary: str | None = None
    test_coverage_summary: str | None = None
    asset_inventory_summary: str | None = None
    findings_summary: str | None = None
    risk_summary: str | None = None
    recommendations_summary: str | None = None
    appendix: str | None = None
    status: ReportStatus | None = None


class ReportFindingBase(BaseModel):
    finding_id: UUID
    custom_title: str | None = None
    custom_severity: Severity | None = None
    custom_confidence: Confidence | None = None
    custom_impact: str | None = None
    custom_remediation: str | None = None
    reproduction_steps: str | None = None
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_refs: list[str] = Field(default_factory=list)
    mastg_refs: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None


class ReportFindingCreate(ReportFindingBase):
    pass


class ReportFindingUpdate(BaseModel):
    custom_title: str | None = None
    custom_severity: Severity | None = None
    custom_confidence: Confidence | None = None
    custom_impact: str | None = None
    custom_remediation: str | None = None
    reproduction_steps: str | None = None
    affected_assets: list[dict[str, Any]] | None = None
    evidence_refs: list[str] | None = None
    cwe_ids: list[str] | None = None
    owasp_refs: list[str] | None = None
    mastg_refs: list[str] | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None


class ReportFindingResponse(ReportFindingBase):
    id: UUID
    report_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportVersionResponse(BaseModel):
    id: UUID
    report_id: UUID
    version: int
    payload: dict[str, Any]
    created_by: UUID | None
    change_summary: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportResponse(ReportBase):
    id: UUID
    project_id: UUID
    requested_by: UUID | None
    status: ReportStatus
    executive_summary: str | None
    scope_summary: str | None
    methodology_summary: str | None
    test_coverage_summary: str | None
    asset_inventory_summary: str | None
    findings_summary: str | None
    risk_summary: str | None
    recommendations_summary: str | None
    appendix: str | None
    html_object_key: str | None
    markdown_object_key: str | None
    pdf_object_key: str | None
    json_object_key: str | None
    version: int
    parent_report_id: UUID | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class ReportDetailResponse(ReportResponse):
    sections: list[ReportSectionResponse] = []
    findings: list[ReportFindingResponse] = []
    versions: list[ReportVersionResponse] = []


class ReportListResponse(BaseModel):
    items: list[ReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ReportFindingListResponse(BaseModel):
    items: list[ReportFindingResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ReportSectionListResponse(BaseModel):
    items: list[ReportSectionResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Report Generation Schemas
# =============================================================================

class ReportGenerateRequest(BaseModel):
    report_id: UUID
    formats: list[str] = Field(default=["html", "markdown", "pdf", "json"])  # html, markdown, pdf, json
    template: str | None = None
    include_evidence: bool = True
    sanitize_secrets: bool = True


class ReportGenerateResponse(BaseModel):
    report_id: UUID
    status: str
    formats_requested: list[str]
    generated_formats: dict[str, str] = Field(default_factory=dict)  # format -> object_key
    errors: list[str] = Field(default_factory=list)


# =============================================================================
# Bug-Bounty Program Schemas
# =============================================================================

class BugBountyProgramBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    platform: str | None = None
    platform_program_id: str | None = None
    policy_url: str | None = None
    submission_url: str | None = None
    is_active: bool = True
    allows_public_disclosure: bool = False
    disclosure_terms: str | None = None
    max_bounty: float | None = None
    currency: str = "USD"
    metadata: dict[str, Any] = Field(default_factory=dict)


class BugBountyProgramCreate(BugBountyProgramBase):
    organization_id: UUID


class BugBountyProgramUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    platform: str | None = None
    platform_program_id: str | None = None
    policy_url: str | None = None
    submission_url: str | None = None
    is_active: bool | None = None
    allows_public_disclosure: bool | None = None
    disclosure_terms: str | None = None
    max_bounty: float | None = None
    currency: str | None = None
    metadata: dict[str, Any] | None = None


class BugBountyProgramResponse(BugBountyProgramBase):
    id: UUID
    organization_id: UUID
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class BugBountyProgramListResponse(BaseModel):
    items: list[BugBountyProgramResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ProgramPolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    policy_type: str = Field(min_length=1, max_length=64)
    rules: dict[str, Any] = Field(default_factory=dict)
    severity: str = "mandatory"


class ProgramPolicyCreate(ProgramPolicyBase):
    program_id: UUID


class ProgramPolicyResponse(ProgramPolicyBase):
    id: UUID
    program_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProgramScopeBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    target_type: str = Field(min_length=1, max_length=64)
    target_value: str = Field(min_length=1, max_length=2048)
    is_wildcard: bool = False
    max_bounty: float | None = None
    tier: str | None = None
    notes: str | None = None


class ProgramScopeCreate(ProgramScopeBase):
    program_id: UUID


class ProgramScopeUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    target_type: str | None = Field(None, min_length=1, max_length=64)
    target_value: str | None = Field(None, min_length=1, max_length=2048)
    is_wildcard: bool | None = None
    max_bounty: float | None = None
    tier: str | None = None
    notes: str | None = None


class ProgramScopeResponse(ProgramScopeBase):
    id: UUID
    program_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProgramScopeListResponse(BaseModel):
    items: list[ProgramScopeResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ExcludedTargetBase(BaseModel):
    target_type: str = Field(min_length=1, max_length=64)
    target_value: str = Field(min_length=1, max_length=2048)
    reason: str | None = None


class ExcludedTargetCreate(ExcludedTargetBase):
    program_id: UUID


class ExcludedTargetResponse(ExcludedTargetBase):
    id: UUID
    program_id: UUID
    excluded_by: UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExcludedTargetUpdate(BaseModel):
    target_type: str | None = Field(None, min_length=1, max_length=64)
    target_value: str | None = Field(None, min_length=1, max_length=2048)
    reason: str | None = None


# =============================================================================
# Research Workspace Schemas
# =============================================================================

class ResearchWorkspaceBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    project_id: UUID | None = None


class ResearchWorkspaceCreate(ResearchWorkspaceBase):
    program_id: UUID


class ResearchWorkspaceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    project_id: UUID | None = None
    status: str | None = None
    current_phase: str | None = None
    metadata: dict[str, Any] | None = None


class ResearchWorkspaceResponse(ResearchWorkspaceBase):
    id: UUID
    program_id: UUID
    user_id: UUID
    status: str
    current_phase: str
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class ResearchWorkspaceListResponse(BaseModel):
    items: list[ResearchWorkspaceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ResearchNoteBase(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    content: str
    note_type: str = "general"
    tags: list[str] = Field(default_factory=list)
    is_shared: bool = False
    linked_assets: list[UUID] = Field(default_factory=list)
    linked_findings: list[UUID] = Field(default_factory=list)


class ResearchNoteCreate(ResearchNoteBase):
    program_id: UUID
    workspace_id: UUID | None = None


class ResearchNoteUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=255)
    content: str | None = None
    note_type: str | None = None
    tags: list[str] | None = None
    is_shared: bool | None = None
    linked_assets: list[UUID] | None = None
    linked_findings: list[UUID] | None = None


class ResearchNoteResponse(ResearchNoteBase):
    id: UUID
    program_id: UUID
    workspace_id: UUID | None
    user_id: UUID
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class ResearchNoteListResponse(BaseModel):
    items: list[ResearchNoteResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class WorkspaceObservationBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    observation_type: str = Field(min_length=1, max_length=64)
    target_type: str | None = None
    target_value: str | None = None
    severity_hint: Severity | None = None
    confidence_hint: Confidence | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    reproduction_steps: str | None = None
    tags: list[str] = Field(default_factory=list)
    status: str = "open"


class WorkspaceObservationCreate(WorkspaceObservationBase):
    workspace_id: UUID


class WorkspaceObservationUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=512)
    description: str | None = None
    observation_type: str | None = None
    target_type: str | None = None
    target_value: str | None = None
    severity_hint: Severity | None = None
    confidence_hint: Confidence | None = None
    evidence: dict[str, Any] | None = None
    reproduction_steps: str | None = None
    tags: list[str] | None = None
    status: str | None = None
    linked_finding_id: UUID | None = None


class WorkspaceObservationResponse(WorkspaceObservationBase):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    linked_finding_id: UUID | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class WorkspaceObservationListResponse(BaseModel):
    items: list[WorkspaceObservationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class WorkspaceFindingBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    description: str
    severity: Severity
    confidence: Confidence
    target_type: str | None = None
    target_value: str | None = None
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    reproduction_steps: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_refs: list[str] = Field(default_factory=list)
    mastg_refs: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    status: str = "draft"
    program_scope_id: UUID | None = None


class WorkspaceFindingCreate(WorkspaceFindingBase):
    workspace_id: UUID
    observation_id: UUID | None = None


class WorkspaceFindingUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=512)
    description: str | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    target_type: str | None = None
    target_value: str | None = None
    affected_assets: list[dict[str, Any]] | None = None
    evidence: dict[str, Any] | None = None
    reproduction_steps: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cwe_ids: list[str] | None = None
    owasp_refs: list[str] | None = None
    mastg_refs: list[str] | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    status: str | None = None
    program_scope_id: UUID | None = None


class WorkspaceFindingResponse(WorkspaceFindingBase):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    observation_id: UUID | None
    promoted_to_finding_id: UUID | None
    program_scope_id: UUID | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class WorkspaceFindingListResponse(BaseModel):
    items: list[WorkspaceFindingResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class WorkspaceReportBase(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    report_type: str = "technical"
    content: dict[str, Any] = Field(default_factory=dict)
    included_findings: list[UUID] = Field(default_factory=list)


class WorkspaceReportCreate(WorkspaceReportBase):
    workspace_id: UUID


class WorkspaceReportUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=512)
    report_type: str | None = None
    content: dict[str, Any] | None = None
    included_findings: list[UUID] | None = None
    status: str | None = None
    parent_report_id: UUID | None = None


class WorkspaceReportResponse(WorkspaceReportBase):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    status: str
    version: int
    parent_report_id: UUID | None
    official_report_id: UUID | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class WorkspaceReportListResponse(BaseModel):
    items: list[WorkspaceReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class WorkspaceAttachmentBase(BaseModel):
    filename: str
    content_type: str | None = None
    description: str | None = None
    attachment_type: str = "evidence"


class WorkspaceAttachmentResponse(WorkspaceAttachmentBase):
    id: UUID
    workspace_id: UUID
    user_id: UUID
    finding_id: UUID | None
    observation_id: UUID | None
    size_bytes: int
    sha256: str
    object_key: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)