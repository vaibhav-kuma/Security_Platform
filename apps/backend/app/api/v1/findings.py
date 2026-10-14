"""Findings API router (v1)."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.detection import Evidence, Finding, FindingComment, FindingRelationship, Observation
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingStatus,
    ObservationType,
    SecurityEventType,
    Severity,
)
from app.models.identity import User
from app.schemas.findings import (
    BatchObservationIngestRequest,
    BatchObservationIngestResponse,
    CorrelationAnalysisRequest,
    CorrelationAnalysisResponse,
    CorrelationResultResponse,
    CVSSScoreResponse,
    CVSSVectorRequest,
    EvidenceCreate,
    EvidenceResponse,
    EvidenceListResponse,
    FindingClusterResponse,
    FindingCommentResponse,
    FindingCreate,
    FindingDetailResponse,
    FindingListResponse,
    FindingPromoteRequest,
    FindingRelationshipCreate,
    FindingRelationshipResponse,
    FindingResponse,
    FindingUpdate,
    ManualReviewDecisionRequest,
    ManualReviewDecisionResponse,
    ManualReviewItemListResponse,
    ManualReviewItemResponse,
    ObservationCreate,
    ObservationDetailResponse,
    ObservationListResponse,
    ObservationResponse,
    ObservationUpdate,
    ReviewQueueStatsResponse,
)
from app.core.analysis_engine import IngestionContext
from app.core.cvss import CVSSVector
from app.services.findings import (
    CorrelationService,
    CVSSService,
    EvidenceService,
    FindingService,
    ManualReviewService,
    ObservationService,
)

router = APIRouter(prefix="/projects/{project_id}/findings", tags=["findings"])


# =============================================================================
# Finding Endpoints
# =============================================================================

@router.post(
    "",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create finding",
)
@strict_rate_limit()
def create_finding(
    project_id: UUID,
    data: FindingCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingResponse:
    """Create a finding manually."""
    if data.project_id != project_id:
        from app.core.exceptions import ConflictError
        raise ConflictError("Project ID mismatch")

    service = FindingService(db)
    finding = service.create_finding(
        project_id=project_id,
        title=data.title,
        severity=Severity(data.severity),
        confidence=Confidence(data.confidence),
        asset_id=data.asset_id,
        promoted_from_observation_id=data.promoted_from_observation_id,
        cwe_id=data.cwe_id,
        recommendation=data.recommendation,
        status=FindingStatus(data.status),
    )

    # Add evidence if provided
    for ev_data in data.evidence:
        service.add_evidence(
            finding_id=finding.id,
            evidence_type=EvidenceType(ev_data.evidence_type),
            content=ev_data.content,
            object_key=ev_data.object_key,
            sha256=ev_data.sha256,
            metadata=ev_data.metadata,
        )

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,  # Reusing event type
        entity_type="finding",
        entity_id=finding.id,
        details={"title": finding.title, "severity": data.severity, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(finding)

    return FindingResponse.model_validate(finding)


@router.get(
    "",
    response_model=FindingListResponse,
    summary="List findings",
)
def list_findings(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    severity_filter: str | None = Query(None, alias="severity"),
    confidence_filter: str | None = Query(None, alias="confidence"),
    asset_id: UUID | None = None,
) -> FindingListResponse:
    """List findings in a project."""
    service = FindingService(db)
    findings, total = service.list_findings(
        project_id=project_id,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        severity_filter=severity_filter,
        confidence_filter=confidence_filter,
        asset_id=asset_id,
    )

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/stats",
    summary="Get finding statistics",
)
def get_finding_stats(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, int]:
    """Get finding statistics for a project."""
    service = FindingService(db)
    return service.get_finding_stats(project_id)


@router.get(
    "/{finding_id}",
    response_model=FindingDetailResponse,
    summary="Get finding",
)
def get_finding(
    project_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> FindingDetailResponse:
    """Get finding by ID with evidence and comments."""
    service = FindingService(db)
    finding = service.get_finding_detail(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    return FindingDetailResponse.model_validate(finding)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding",
)
def update_finding(
    project_id: UUID,
    finding_id: UUID,
    data: FindingUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingResponse:
    """Update finding details."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    update_data = data.model_dump(exclude_unset=True)

    # Convert string enums to enum types
    if "status" in update_data:
        update_data["status"] = FindingStatus(update_data["status"])
    if "severity" in update_data:
        update_data["severity"] = Severity(update_data["severity"])
    if "confidence" in update_data:
        update_data["confidence"] = Confidence(update_data["confidence"])

    updated = service.update_finding(finding_id, update_data, current_user.id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="finding",
        entity_id=finding_id,
        details={"updated_fields": update_data},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingResponse.model_validate(updated)


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
    summary="Update finding status",
)
def update_finding_status(
    project_id: UUID,
    finding_id: UUID,
    status: FindingStatus,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    notes: str | None = None,
) -> FindingResponse:
    """Update finding status with audit trail."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    updated = service.update_finding_status(finding_id, status, current_user.id, notes)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="finding",
        entity_id=finding_id,
        details={"status_change": status.value, "notes": notes},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingResponse.model_validate(updated)


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete finding",
)
def delete_finding(
    project_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    service.delete_finding(finding_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_DELETE.value,
        entity_type="finding",
        entity_id=finding_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()


# =============================================================================
# Finding Evidence Endpoints
# =============================================================================

@router.post(
    "/{finding_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add evidence to finding",
)
@strict_rate_limit()
def add_finding_evidence(
    project_id: UUID,
    finding_id: UUID,
    data: EvidenceCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> EvidenceResponse:
    """Add evidence to a finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    evidence = service.add_evidence(
        finding_id=finding_id,
        evidence_type=EvidenceType(data.evidence_type),
        content=data.content,
        object_key=data.object_key,
        sha256=data.sha256,
        metadata=data.metadata,
    )

    if not evidence:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="evidence",
        entity_id=evidence.id,
        details={"finding_id": str(finding_id), "evidence_type": data.evidence_type},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return EvidenceResponse.model_validate(evidence)


@router.get(
    "/{finding_id}/evidence",
    response_model=EvidenceListResponse,
    summary="List finding evidence",
)
def list_finding_evidence(
    project_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    evidence_type: str | None = None,
) -> EvidenceListResponse:
    """List evidence for a finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    evidence_list = service.get_evidence(finding_id)

    # Filter by type if provided
    if evidence_type:
        try:
            ev_type = EvidenceType(evidence_type)
            evidence_list = [e for e in evidence_list if e.evidence_type == ev_type]
        except ValueError:
            pass

    total = len(evidence_list)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = evidence_list[start:end]

    return EvidenceListResponse(
        items=[EvidenceResponse.model_validate(e) for e in paginated],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{finding_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
    summary="Get evidence",
)
def get_finding_evidence(
    project_id: UUID,
    finding_id: UUID,
    evidence_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> EvidenceResponse:
    """Get specific evidence."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    evidence = db.get(Evidence, evidence_id)
    if not evidence or evidence.finding_id != finding_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Evidence", str(evidence_id))

    return EvidenceResponse.model_validate(evidence)


# =============================================================================
# Finding Comments Endpoints
# =============================================================================

@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add comment to finding",
)
@strict_rate_limit()
def add_finding_comment(
    project_id: UUID,
    finding_id: UUID,
    body: str,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingCommentResponse:
    """Add comment to finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    comment = service.add_comment(finding_id, current_user.id, body)

    if not comment:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="finding_comment",
        entity_id=comment.id,
        details={"finding_id": str(finding_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingCommentResponse.model_validate(comment)


@router.get(
    "/{finding_id}/comments",
    response_model=list[FindingCommentResponse],
    summary="List finding comments",
)
def list_finding_comments(
    project_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FindingCommentResponse]:
    """List comments for a finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    comments = service.get_comments(finding_id)
    return [FindingCommentResponse.model_validate(c) for c in comments]


# =============================================================================
# Finding Relationships Endpoints
# =============================================================================

@router.post(
    "/{finding_id}/relationships",
    response_model=FindingRelationshipResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add finding relationship",
)
@strict_rate_limit()
def add_finding_relationship(
    project_id: UUID,
    finding_id: UUID,
    data: FindingRelationshipCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingRelationshipResponse:
    """Add relationship between findings."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    # Verify target finding exists and is in same project
    target = service.get_finding(data.target_finding_id)
    if not target or target.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Target Finding", str(data.target_finding_id))

    relationship = service.add_relationship(
        source_finding_id=data.source_finding_id,
        target_finding_id=data.target_finding_id,
        relationship_type=data.relationship_type,
    )

    if not relationship:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="finding_relationship",
        entity_id=relationship.id,
        details={
            "source_finding_id": str(data.source_finding_id),
            "target_finding_id": str(data.target_finding_id),
            "relationship_type": data.relationship_type,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingRelationshipResponse.model_validate(relationship)


@router.get(
    "/{finding_id}/relationships",
    response_model=list[FindingRelationshipResponse],
    summary="List finding relationships",
)
def list_finding_relationships(
    project_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FindingRelationshipResponse]:
    """List relationships for a finding."""
    service = FindingService(db)
    finding = service.get_finding(finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))

    relationships = service.get_relationships(finding_id)
    return [FindingRelationshipResponse.model_validate(r) for r in relationships]


# =============================================================================
# Observation Endpoints
# =============================================================================

obs_router = APIRouter(prefix="/projects/{project_id}/observations", tags=["observations"])


@obs_router.post(
    "",
    response_model=ObservationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create observation",
)
@strict_rate_limit()
def create_observation(
    project_id: UUID,
    data: ObservationCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ObservationResponse:
    """Create an observation manually."""
    if data.project_id != project_id:
        from app.core.exceptions import ConflictError
        raise ConflictError("Project ID mismatch")

    service = ObservationService(db)
    observation = service.create_observation(
        project_id=project_id,
        title=data.title,
        observation_type=ObservationType(data.observation_type),
        scan_id=data.scan_id,
        asset_id=data.asset_id,
        detection_rule_id=data.detection_rule_id,
        detail=data.detail,
        payload=data.payload,
        severity_hint=Severity(data.severity_hint) if data.severity_hint else None,
        confidence_hint=Confidence(data.confidence_hint) if data.confidence_hint else None,
    )

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,
        entity_type="observation",
        entity_id=observation.id,
        details={"title": observation.title, "type": data.observation_type, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(observation)

    return ObservationResponse.model_validate(observation)


@obs_router.post(
    "/ingest",
    response_model=dict[str, Any],
    summary="Ingest observation through analysis engine",
)
@strict_rate_limit()
def ingest_observation(
    project_id: UUID,
    title: str,
    observation_type: str,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    detail: str | None = None,
    payload: dict[str, Any] | None = None,
    severity_hint: str | None = None,
    confidence_hint: str | None = None,
    detection_rule_id: UUID | None = None,
    scan_id: UUID | None = None,
    asset_id: UUID | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Ingest observation through the analysis engine (sanitization, correlation, auto-promotion)."""
    service = ObservationService(db)

    context = IngestionContext(
        project_id=project_id,
        scan_id=scan_id,
        asset_id=asset_id,
        source="api",
    )

    result = service.ingest_observation(
        context=context,
        title=title,
        observation_type=ObservationType(observation_type),
        detail=detail,
        payload=payload or {},
        severity_hint=Severity(severity_hint) if severity_hint else None,
        confidence_hint=Confidence(confidence_hint) if confidence_hint else None,
        detection_rule_id=detection_rule_id,
        evidence_items=evidence,
    )

    return {
        "result": result.result.value,
        "observation_id": str(result.observation_id) if result.observation_id else None,
        "finding_id": str(result.finding_id) if result.finding_id else None,
        "review_item_id": str(result.review_item_id) if result.review_item_id else None,
        "message": result.message,
        "errors": result.errors,
    }


@obs_router.post(
    "/ingest/batch",
    response_model=BatchObservationIngestResponse,
    summary="Batch ingest observations",
)
@strict_rate_limit()
def ingest_observations_batch_endpoint(
    project_id: UUID,
    data: BatchObservationIngestRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> BatchObservationIngestResponse:
    """Batch ingest multiple observations."""
    service = ObservationService(db)

    context = IngestionContext(
        project_id=project_id,
        source="api_batch",
    )

    result = service.ingest_batch(
        [obs.model_dump() for obs in data.observations], context
    )

    return BatchObservationIngestResponse(
        total=result.total,
        observations_created=result.observations_created,
        findings_promoted=result.findings_promoted,
        queued_for_review=result.queued_for_review,
        duplicates=result.duplicates,
        errors=result.errors,
        results=[
            {
                "result": r.result.value,
                "observation_id": str(r.observation_id) if r.observation_id else None,
                "finding_id": str(r.finding_id) if r.finding_id else None,
                "review_item_id": str(r.review_item_id) if r.review_item_id else None,
                "message": r.message,
                "errors": r.errors,
            }
            for r in result.results
        ],
    )


@obs_router.get(
    "",
    response_model=ObservationListResponse,
    summary="List observations",
)
def list_observations(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    scan_id: UUID | None = None,
    asset_id: UUID | None = None,
    observation_type: str | None = None,
) -> ObservationListResponse:
    """List observations in a project."""
    service = ObservationService(db)
    observations, total = service.list_observations(
        project_id=project_id,
        page=page,
        page_size=page_size,
        scan_id=scan_id,
        asset_id=asset_id,
        observation_type=observation_type,
    )

    return ObservationListResponse(
        items=[ObservationResponse.model_validate(o) for o in observations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@obs_router.get(
    "/{observation_id}",
    response_model=ObservationDetailResponse,
    summary="Get observation",
)
def get_observation(
    project_id: UUID,
    observation_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ObservationDetailResponse:
    """Get observation by ID."""
    service = ObservationService(db)
    observation = service.get_observation(observation_id)
    if not observation or observation.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Observation", str(observation_id))

    return ObservationDetailResponse.model_validate(observation)


@obs_router.patch(
    "/{observation_id}",
    response_model=ObservationResponse,
    summary="Update observation",
)
def update_observation(
    project_id: UUID,
    observation_id: UUID,
    data: ObservationUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ObservationResponse:
    """Update observation."""
    observation = db.get(Observation, observation_id)
    if not observation or observation.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Observation", str(observation_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if hasattr(observation, key):
            setattr(observation, key, value)

    observation.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(observation)

    return ObservationResponse.model_validate(observation)


@obs_router.post(
    "/{observation_id}/promote",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Promote observation to finding",
)
@strict_rate_limit()
def promote_observation(
    project_id: UUID,
    observation_id: UUID,
    data: FindingPromoteRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingResponse:
    """Manually promote an observation to a finding."""
    service = ObservationService(db)
    observation = service.get_observation(observation_id)
    if not observation or observation.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Observation", str(observation_id))

    cvss_vector = None
    if data.cvss_vector:
        cvss_vector = CVSSService.parse_vector(data.cvss_vector)

    finding = service.promote_observation(
        observation_id=observation_id,
        user_id=current_user.id,
        severity=Severity(data.severity),
        confidence=Confidence(data.confidence),
        cwe_id=data.cwe_id,
        cvss_vector=cvss_vector,
        recommendation=data.recommendation,
    )

    if not finding:
        from app.core.exceptions import ConflictError
        raise ConflictError("Failed to promote observation")

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,
        entity_type="finding",
        entity_id=finding.id,
        details={
            "promoted_from_observation": str(observation_id),
            "severity": data.severity,
            "confidence": data.confidence,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingResponse.model_validate(finding)


@obs_router.post(
    "/{observation_id}/dismiss",
    response_model=ObservationResponse,
    summary="Dismiss observation",
)
@strict_rate_limit()
def dismiss_observation(
    project_id: UUID,
    observation_id: UUID,
    reason: str,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ObservationResponse:
    """Dismiss an observation (not a finding)."""
    service = ObservationService(db)
    observation = service.get_observation(observation_id)
    if not observation or observation.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Observation", str(observation_id))

    dismissed = service.dismiss_observation(observation_id, current_user.id, reason)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="observation",
        entity_id=observation_id,
        details={"dismissed": True, "reason": reason},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ObservationResponse.model_validate(dismissed)


# =============================================================================
# Correlation Endpoints
# =============================================================================

corr_router = APIRouter(prefix="/projects/{project_id}/correlation", tags=["correlation"])


@corr_router.post(
    "/analyze",
    response_model=CorrelationAnalysisResponse,
    summary="Analyze correlations for a finding",
)
def analyze_correlation(
    project_id: UUID,
    data: CorrelationAnalysisRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> CorrelationAnalysisResponse:
    """Analyze correlations for a specific finding."""
    service = CorrelationService(db)

    # Verify finding exists and is in project
    finding = db.get(Finding, data.finding_id)
    if not finding or finding.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(data.finding_id))

    correlations = service.correlate_finding(data.finding_id)
    clusters = service.get_finding_clusters(project_id)

    return CorrelationAnalysisResponse(
        finding_id=data.finding_id,
        clusters=[
            FindingClusterResponse(
                primary_finding_id=c.primary_finding_id,
                duplicate_finding_ids=c.duplicate_finding_ids,
                related_finding_ids=c.related_finding_ids,
                variant_finding_ids=c.variant_finding_ids,
                total_count=c.total_count,
            )
            for c in clusters
        ],
        correlations=[
            CorrelationResultResponse(
                finding_id=c["finding_id"],
                correlated_finding_id=c["correlated_finding_id"],
                correlation_type=c["correlation_type"],
                confidence=c["confidence"],
                evidence=c["evidence"],
                created_at=datetime.now(UTC),
            )
            for c in correlations
        ],
    )


@corr_router.get(
    "/clusters",
    response_model=list[FindingClusterResponse],
    summary="Get all finding clusters",
)
def get_correlation_clusters(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[FindingClusterResponse]:
    """Get all finding correlation clusters for a project."""
    service = CorrelationService(db)
    clusters = service.get_finding_clusters(project_id)

    return [
        FindingClusterResponse(
            primary_finding_id=c.primary_finding_id,
            duplicate_finding_ids=c.duplicate_finding_ids,
            related_finding_ids=c.related_finding_ids,
            variant_finding_ids=c.variant_finding_ids,
            total_count=c.total_count,
        )
        for c in clusters
    ]


@corr_router.post(
    "/{finding_id}/mark-duplicate",
    response_model=FindingRelationshipResponse,
    summary="Mark finding as duplicate",
)
@strict_rate_limit()
def mark_finding_duplicate(
    project_id: UUID,
    finding_id: UUID,
    target_finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> FindingRelationshipResponse:
    """Mark a finding as duplicate of another finding."""
    service = CorrelationService(db)

    # Verify both findings exist and are in project
    source = db.get(Finding, finding_id)
    target = db.get(Finding, target_finding_id)
    if not source or source.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Finding", str(finding_id))
    if not target or target.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Target Finding", str(target_finding_id))

    relationship = service.mark_duplicate(finding_id, target_finding_id, current_user.id)

    if not relationship:
        from app.core.exceptions import ConflictError
        raise ConflictError("Failed to mark finding as duplicate")

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="finding_relationship",
        entity_id=relationship.id,
        details={
            "source_finding_id": str(finding_id),
            "target_finding_id": str(target_finding_id),
            "relationship_type": "duplicate_of",
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return FindingRelationshipResponse.model_validate(relationship)


# =============================================================================
# Manual Review Queue Endpoints
# =============================================================================

review_router = APIRouter(prefix="/projects/{project_id}/review", tags=["manual-review"])


@review_router.get(
    "",
    response_model=ManualReviewItemListResponse,
    summary="List manual review queue",
)
def list_review_queue(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
    priority: str | None = None,
) -> ManualReviewItemListResponse:
    """List manual review queue items."""
    service = ManualReviewService(db)
    items, total = service.get_pending_reviews(
        project_id=project_id,
        page=page,
        page_size=page_size,
        status_filter=status,
        priority_filter=priority,
    )

    return ManualReviewItemListResponse(
        items=[ManualReviewItemResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@review_router.get(
    "/stats",
    response_model=ReviewQueueStatsResponse,
    summary="Get review queue statistics",
)
def get_review_queue_stats(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReviewQueueStatsResponse:
    """Get review queue statistics."""
    service = ManualReviewService(db)
    stats = service.get_queue_stats(project_id)

    return ReviewQueueStatsResponse(
        pending=stats.get("pending", 0),
        in_progress=stats.get("in_progress", 0),
        needs_more_info=stats.get("needs_more_info", 0),
        promoted=stats.get("promoted", 0),
        dismissed=stats.get("dismissed", 0),
        escalated=stats.get("escalated", 0),
        total=stats.get("total", 0),
        avg_resolution_time_hours=stats.get("avg_resolution_time_hours", 0.0),
        oldest_pending_hours=stats.get("oldest_pending_hours", 0.0),
    )


@review_router.get(
    "/{item_id}",
    response_model=ManualReviewItemResponse,
    summary="Get review queue item",
)
def get_review_item(
    project_id: UUID,
    item_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ManualReviewItemResponse:
    """Get review queue item by ID."""
    service = ManualReviewService(db)
    item = service.get_review_item(item_id)
    if not item:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Review Item", str(item_id))

    return ManualReviewItemResponse.model_validate(item)


@review_router.post(
    "/{item_id}/assign",
    response_model=ManualReviewItemResponse,
    summary="Assign review item",
)
def assign_review_item(
    project_id: UUID,
    item_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ManualReviewItemResponse:
    """Assign review item to current user."""
    service = ManualReviewService(db)
    item = service.assign_reviewer(item_id, current_user.id)
    if not item:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Review Item", str(item_id))

    return ManualReviewItemResponse.model_validate(item)


@review_router.post(
    "/{item_id}/decide",
    response_model=ManualReviewDecisionResponse,
    summary="Make review decision",
)
@strict_rate_limit()
def decide_review_item(
    project_id: UUID,
    item_id: UUID,
    data: ManualReviewDecisionRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ManualReviewDecisionResponse:
    """Make a decision on a review queue item."""
    service = ManualReviewService(db)

    if data.action == "promote":
        if not data.severity or not data.confidence:
            from app.core.exceptions import ValidationError
            raise ValidationError("Severity and confidence required for promotion")

        cvss_vector = None
        if data.cvss_vector:
            cvss_vector = CVSSService.parse_vector(data.cvss_vector)

        finding = service.promote_from_review(
            review_item_id=item_id,
            reviewer_id=current_user.id,
            severity=Severity(data.severity),
            confidence=Confidence(data.confidence),
            cwe_id=data.cwe_id,
            cvss_vector=cvss_vector,
            recommendation=data.notes,
        )

        if not finding:
            from app.core.exceptions import ConflictError
            raise ConflictError("Failed to promote observation")

        return ManualReviewDecisionResponse(
            review_item_id=item_id,
            action="promote",
            finding_id=finding.id,
            message="Observation promoted to finding",
        )

    elif data.action == "dismiss":
        observation = service.dismiss_from_review(item_id, current_user.id, data.notes or "Dismissed by reviewer")
        if not observation:
            from app.core.exceptions import ConflictError
            raise ConflictError("Failed to dismiss observation")

        return ManualReviewDecisionResponse(
            review_item_id=item_id,
            action="dismiss",
            message="Observation dismissed",
        )

    elif data.action in ("needs_more_info", "escalate"):
        # Would update review item status
        return ManualReviewDecisionResponse(
            review_item_id=item_id,
            action=data.action,
            message=f"Review item marked as {data.action.replace('_', ' ')}",
        )

    else:
        from app.core.exceptions import ValidationError
        raise ValidationError(f"Invalid action: {data.action}")


# =============================================================================
# CVSS Endpoints
# =============================================================================

cvss_router = APIRouter(prefix="/cvss", tags=["cvss"])


@cvss_router.post(
    "/calculate",
    response_model=CVSSScoreResponse,
    summary="Calculate CVSS score",
)
def calculate_cvss(
    data: CVSSVectorRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> CVSSScoreResponse:
    """Calculate CVSS score from vector."""
    from app.core.cvss import (
        AttackVector,
        AttackComplexity,
        PrivilegesRequired,
        UserInteraction,
        Scope,
        Impact,
    )
    vector = CVSSVector(
        attack_vector=AttackVector(data.attack_vector),
        attack_complexity=AttackComplexity(data.attack_complexity),
        privileges_required=PrivilegesRequired(data.privileges_required),
        user_interaction=UserInteraction(data.user_interaction),
        scope=Scope(data.scope),
        confidentiality=Impact(data.confidentiality),
        integrity=Impact(data.integrity),
        availability=Impact(data.availability),
    )

    score, severity = CVSSService.calculate(vector)

    return CVSSScoreResponse(
        base_score=score,
        severity=severity,
        vector=vector.to_string(),
    )


@cvss_router.get(
    "/default/{category}",
    response_model=CVSSScoreResponse,
    summary="Get default CVSS for category",
)
def get_default_cvss(
    category: str,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> CVSSScoreResponse:
    """Get default CVSS score for a vulnerability category."""
    result = CVSSService.calculate_for_category(category)
    if not result:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("CVSS category", category)

    score, severity = result
    vector = CVSSService.get_default_vector(category)

    return CVSSScoreResponse(
        base_score=score,
        severity=severity,
        vector=vector.to_string() if vector else "",
    )


# Import datetime for the update_observation endpoint
from datetime import UTC, datetime