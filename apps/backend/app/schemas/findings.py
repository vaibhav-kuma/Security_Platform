"""Pydantic schemas for findings, observations, evidence, and manual review."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Observation Schemas
# =============================================================================

class ObservationBase(BaseModel):
    """Base observation schema."""

    title: Annotated[str, Field(min_length=1, max_length=512)]
    detail: str | None = None
    observation_type: str
    payload: dict[str, Any] = {}
    severity_hint: str | None = None
    confidence_hint: str | None = None


class ObservationCreate(ObservationBase):
    """Create observation request."""

    project_id: UUID
    scan_id: UUID | None = None
    asset_id: UUID | None = None
    detection_rule_id: UUID | None = None
    evidence: list["EvidenceCreate"] = []


class ObservationUpdate(BaseModel):
    """Update observation request."""

    title: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    detail: str | None = None
    payload: dict[str, Any] | None = None
    severity_hint: str | None = None
    confidence_hint: str | None = None


class ObservationResponse(ObservationBase):
    """Observation response."""

    id: UUID
    project_id: UUID
    scan_id: UUID | None = None
    asset_id: UUID | None = None
    detection_rule_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ObservationDetailResponse(ObservationResponse):
    """Observation response with evidence."""

    evidence: list["EvidenceResponse"] = []


class ObservationListResponse(BaseModel):
    """Paginated observation list."""

    items: list[ObservationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Evidence Schemas
# =============================================================================

class EvidenceBase(BaseModel):
    """Base evidence schema."""

    evidence_type: Annotated[str, Field(pattern="^(http_request|http_response|screenshot|console_log|file|snippet|other)$")]
    storage: Annotated[str, Field(pattern="^(inline|object)$")] = "inline"
    content: str | None = None
    object_key: str | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = {}


class EvidenceCreate(EvidenceBase):
    """Create evidence request."""

    finding_id: UUID


class EvidenceUpdate(BaseModel):
    """Update evidence request."""

    content: str | None = None
    metadata: dict[str, Any] | None = None


class EvidenceResponse(EvidenceBase):
    """Evidence response."""

    id: UUID
    finding_id: UUID
    redacted: bool = False
    redacted_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceListResponse(BaseModel):
    """Paginated evidence list."""

    items: list[EvidenceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Finding Schemas
# =============================================================================

class FindingBase(BaseModel):
    """Base finding schema."""

    title: Annotated[str, Field(min_length=1, max_length=512)]
    status: Annotated[str, Field(pattern="^(open|needs_review|confirmed|false_positive|duplicate|accepted_risk|resolved)$")] = "open"
    severity: Annotated[str, Field(pattern="^(info|low|medium|high|critical)$")]
    confidence: Annotated[str, Field(pattern="^(very_low|low|medium|high|very_high)$")]
    cwe_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    recommendation: str | None = None


class FindingCreate(FindingBase):
    """Create finding request (manual creation)."""

    project_id: UUID
    promoted_from_observation_id: UUID | None = None
    asset_id: UUID | None = None
    evidence: list[EvidenceCreate] = []


class FindingUpdate(BaseModel):
    """Update finding request."""

    title: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    status: Annotated[str | None, Field(pattern="^(open|needs_review|confirmed|false_positive|duplicate|accepted_risk|resolved)$")] = None
    severity: Annotated[str | None, Field(pattern="^(info|low|medium|high|critical)$")] = None
    confidence: Annotated[str | None, Field(pattern="^(very_low|low|medium|high|very_high)$")] = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    recommendation: str | None = None


class FindingPromoteRequest(BaseModel):
    """Promote observation to finding request."""

    observation_id: UUID
    severity: Annotated[str, Field(pattern="^(info|low|medium|high|critical)$")]
    confidence: Annotated[str, Field(pattern="^(very_low|low|medium|high|very_high)$")]
    cwe_id: str | None = None
    cvss_vector: str | None = None
    recommendation: str | None = None


class FindingResponse(FindingBase):
    """Finding response."""

    id: UUID
    project_id: UUID
    promoted_from_observation_id: UUID | None = None
    asset_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingDetailResponse(FindingResponse):
    """Finding response with evidence and comments."""

    evidence: list[EvidenceResponse] = []
    comments: list["FindingCommentResponse"] = []
    relationships: list["FindingRelationshipResponse"] = []


class FindingListResponse(BaseModel):
    """Paginated finding list."""

    items: list[FindingResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Finding Comment Schemas
# =============================================================================

class FindingCommentBase(BaseModel):
    """Base finding comment schema."""

    body: Annotated[str, Field(min_length=1)]


class FindingCommentCreate(FindingCommentBase):
    """Create finding comment request."""

    finding_id: UUID
    author_id: UUID


class FindingCommentResponse(FindingCommentBase):
    """Finding comment response."""

    id: UUID
    finding_id: UUID
    author_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Finding Relationship Schemas
# =============================================================================

class FindingRelationshipBase(BaseModel):
    """Base finding relationship schema."""

    relationship_type: Annotated[str, Field(pattern="^(duplicate_of|related_to|prerequisite_of|variant_of)$")]


class FindingRelationshipCreate(FindingRelationshipBase):
    """Create finding relationship request."""

    source_finding_id: UUID
    target_finding_id: UUID


class FindingRelationshipResponse(FindingRelationshipBase):
    """Finding relationship response."""

    id: UUID
    source_finding_id: UUID
    target_finding_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Manual Review Queue Schemas
# =============================================================================

class ManualReviewItemResponse(BaseModel):
    """Manual review queue item response."""

    id: UUID
    observation_id: UUID
    project_id: UUID
    scan_id: UUID | None = None
    asset_id: UUID | None = None
    title: str
    description: str | None = None
    observation_type: str
    severity_hint: str | None = None
    confidence_hint: str | None = None
    payload: dict[str, Any]
    review_reason: str
    priority: str
    status: str
    assigned_to: UUID | None = None
    reviewer_notes: str | None = None
    created_at: datetime
    updated_at: datetime
    reviewed_at: datetime | None = None
    resolved_at: datetime | None = None
    promoted_finding_id: UUID | None = None
    metadata: dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)


class ManualReviewItemListResponse(BaseModel):
    """Paginated manual review queue list."""

    items: list[ManualReviewItemResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ManualReviewDecisionRequest(BaseModel):
    """Manual review decision request."""

    action: Annotated[str, Field(pattern="^(promote|dismiss|needs_more_info|escalate)$")]
    severity: Annotated[str | None, Field(pattern="^(info|low|medium|high|critical)$")] = None
    confidence: Annotated[str | None, Field(pattern="^(very_low|low|medium|high|very_high)$")] = None
    cwe_id: str | None = None
    cvss_vector: str | None = None
    notes: str | None = None


class ManualReviewDecisionResponse(BaseModel):
    """Manual review decision response."""

    review_item_id: UUID
    action: str
    finding_id: UUID | None = None
    message: str


class ReviewQueueStatsResponse(BaseModel):
    """Review queue statistics."""

    pending: int
    in_progress: int
    needs_more_info: int
    promoted: int
    dismissed: int
    escalated: int
    total: int
    avg_resolution_time_hours: float
    oldest_pending_hours: float


# =============================================================================
# Correlation Schemas
# =============================================================================

class CorrelationResultResponse(BaseModel):
    """Correlation result response."""

    finding_id: UUID
    correlated_finding_id: UUID
    correlation_type: Annotated[str, Field(pattern="^(duplicate|related|variant|prerequisite|chain|same_root_cause)$")]
    confidence: float
    evidence: dict[str, Any] = {}
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingClusterResponse(BaseModel):
    """Finding cluster response."""

    primary_finding_id: UUID
    duplicate_finding_ids: list[UUID] = []
    related_finding_ids: list[UUID] = []
    variant_finding_ids: list[UUID] = []
    total_count: int


class CorrelationAnalysisRequest(BaseModel):
    """Request to analyze correlations for a finding."""

    finding_id: UUID


class CorrelationAnalysisResponse(BaseModel):
    """Correlation analysis response."""

    finding_id: UUID
    clusters: list[FindingClusterResponse] = []
    correlations: list[CorrelationResultResponse] = []


# =============================================================================
# CVSS/CWE Schemas
# =============================================================================

class CVSSVectorRequest(BaseModel):
    """CVSS vector calculation request."""

    attack_vector: Annotated[str, Field(pattern="^(N|A|L|P)$")]
    attack_complexity: Annotated[str, Field(pattern="^(L|H)$")]
    privileges_required: Annotated[str, Field(pattern="^(N|L|H)$")]
    user_interaction: Annotated[str, Field(pattern="^(N|R)$")]
    scope: Annotated[str, Field(pattern="^(U|C)$")]
    confidentiality: Annotated[str, Field(pattern="^(N|L|H)$")]
    integrity: Annotated[str, Field(pattern="^(N|L|H)$")]
    availability: Annotated[str, Field(pattern="^(N|L|H)$")]


class CVSSScoreResponse(BaseModel):
    """CVSS score response."""

    base_score: float
    severity: str
    vector: str


class CWEEntryResponse(BaseModel):
    """CWE reference entry."""

    cwe_id: str
    name: str
    description: str
    extended_description: str | None = None
    related_weaknesses: list[str] = []
    consequences: list[str] = []
    mitigations: list[str] = []


# =============================================================================
# Batch Ingestion Schemas
# =============================================================================

class BatchObservationIngestRequest(BaseModel):
    """Batch observation ingestion request."""

    observations: list[ObservationCreate]


class BatchObservationIngestResponse(BaseModel):
    """Batch observation ingestion response."""

    total: int
    observations_created: int
    findings_promoted: int
    queued_for_review: int
    duplicates: int
    errors: int
    results: list[dict[str, Any]] = []


# =============================================================================
# Update forward references
# =============================================================================

ObservationDetailResponse.model_rebuild()
EvidenceResponse.model_rebuild()
FindingDetailResponse.model_rebuild()
FindingCommentResponse.model_rebuild()
FindingRelationshipResponse.model_rebuild()