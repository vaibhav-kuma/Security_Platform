"""Report and bug-bounty workspace API endpoints (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.db.session import get_db
from app.models.identity import User
from app.models.enums import SecurityEventType
from app.models.audit import AuditLog
from app.schemas.reports import (
    BugBountyProgramCreate,
    BugBountyProgramListResponse,
    BugBountyProgramResponse,
    BugBountyProgramUpdate,
    ExcludedTargetCreate,
    ExcludedTargetResponse,
    ProgramPolicyCreate,
    ProgramPolicyResponse,
    ProgramScopeCreate,
    ProgramScopeListResponse,
    ProgramScopeResponse,
    ProgramScopeUpdate,
    ResearchNoteCreate,
    ResearchNoteListResponse,
    ResearchNoteResponse,
    ResearchNoteUpdate,
    ResearchWorkspaceCreate,
    ResearchWorkspaceListResponse,
    ResearchWorkspaceResponse,
    ResearchWorkspaceUpdate,
    ReportCreate,
    ReportDetailResponse,
    ReportFindingCreate,
    ReportFindingListResponse,
    ReportFindingResponse,
    ReportFindingUpdate,
    ReportGenerateRequest,
    ReportGenerateResponse,
    ReportListResponse,
    ReportResponse,
    ReportSectionCreate,
    ReportSectionListResponse,
    ReportSectionResponse,
    ReportSectionUpdate,
    ReportUpdate,
    WorkspaceAttachmentResponse,
    WorkspaceFindingCreate,
    WorkspaceFindingListResponse,
    WorkspaceFindingResponse,
    WorkspaceFindingUpdate,
    WorkspaceObservationCreate,
    WorkspaceObservationListResponse,
    WorkspaceObservationResponse,
    WorkspaceObservationUpdate,
    WorkspaceReportCreate,
    WorkspaceReportListResponse,
    WorkspaceReportResponse,
    WorkspaceReportUpdate,
)
from app.services.reports import (
    BugBountyProgramService,
    ReportService,
    ResearchWorkspaceService,
)

router = APIRouter(prefix="/reports", tags=["reports"])


# =============================================================================
# Report Endpoints
# =============================================================================

@router.post(
    "/projects/{project_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create report",
)
def create_report(
    project_id: UUID,
    data: ReportCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ReportResponse:
    """Create a new report within a project."""
    service = ReportService(db)
    report = service.create(project_id, data.model_dump(), current_user.id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.REPORT_CREATE if hasattr(SecurityEventType, "REPORT_CREATE") else "report_create",
        entity_type="report",
        entity_id=report.id,
        details={"title": report.title, "report_type": data.report_type.value, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(report)

    return ReportResponse.model_validate(report)


@router.get(
    "/projects/{project_id}/reports",
    response_model=ReportListResponse,
    summary="List reports",
)
def list_reports(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
    report_type: str | None = None,
) -> ReportListResponse:
    """List reports in a project."""
    service = ReportService(db)
    offset = (page - 1) * page_size
    reports = service.list(project_id, limit=page_size, offset=offset, status=status, report_type=report_type)
    total = service.count(project_id, status=status, report_type=report_type)

    return ReportListResponse(
        items=[ReportResponse.model_validate(r) for r in reports],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/projects/{project_id}/reports/{report_id}",
    response_model=ReportDetailResponse,
    summary="Get report",
)
def get_report(
    project_id: UUID,
    report_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportDetailResponse:
    """Get report by ID with all sections, findings, and versions."""
    service = ReportService(db)
    report = service.get_detail(report_id)
    return ReportDetailResponse.model_validate(report)


@router.patch(
    "/projects/{project_id}/reports/{report_id}",
    response_model=ReportResponse,
    summary="Update report",
)
def update_report(
    project_id: UUID,
    report_id: UUID,
    data: ReportUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ReportResponse:
    """Update report metadata."""
    service = ReportService(db)
    report = service.update(report_id, data.model_dump(exclude_unset=True))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.REPORT_UPDATE if hasattr(SecurityEventType, "REPORT_UPDATE") else "report_update",
        entity_type="report",
        entity_id=report_id,
        details={"updated_fields": list(data.model_dump(exclude_unset=True).keys())},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(report)

    return ReportResponse.model_validate(report)


@router.post(
    "/projects/{project_id}/reports/{report_id}/generate",
    response_model=ReportGenerateResponse,
    summary="Generate report in specified formats",
)
def generate_report(
    project_id: UUID,
    report_id: UUID,
    payload: ReportGenerateRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportGenerateResponse:
    """Generate report in specified formats (HTML, Markdown, PDF, JSON)."""
    service = ReportService(db)
    generated = service.generate_report(
        report_id,
        formats=payload.formats,
        template=payload.template,
        include_evidence=payload.include_evidence,
        sanitize_secrets=payload.sanitize_secrets,
    )

    return ReportGenerateResponse(
        report_id=report_id,
        status="completed",
        formats_requested=payload.formats,
        generated_formats=generated,
    )


# =============================================================================
# Report Sections
# =============================================================================

@router.post(
    "/projects/{project_id}/reports/{report_id}/sections",
    response_model=ReportSectionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add report section",
)
def add_report_section(
    project_id: UUID,
    report_id: UUID,
    data: ReportSectionCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportSectionResponse:
    """Add a section to a report."""
    service = ReportService(db)
    section = service.add_section(report_id, data.model_dump())
    return ReportSectionResponse.model_validate(section)


@router.get(
    "/projects/{project_id}/reports/{report_id}/sections",
    response_model=ReportSectionListResponse,
    summary="List report sections",
)
def list_report_sections(
    project_id: UUID,
    report_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> ReportSectionListResponse:
    """List sections in a report."""
    service = ReportService(db)
    report = service.get_detail(report_id)

    # Sections are already loaded
    sections = sorted(report.sections, key=lambda s: s.order)
    total = len(sections)
    offset = (page - 1) * page_size
    paginated = sections[offset:offset + page_size]

    return ReportSectionListResponse(
        items=[ReportSectionResponse.model_validate(s) for s in paginated],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.patch(
    "/projects/{project_id}/reports/{report_id}/sections/{section_id}",
    response_model=ReportSectionResponse,
    summary="Update report section",
)
def update_report_section(
    project_id: UUID,
    report_id: UUID,
    section_id: UUID,
    data: ReportSectionUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportSectionResponse:
    """Update a report section."""
    service = ReportService(db)
    section = service.update_section(section_id, data.model_dump(exclude_unset=True))
    return ReportSectionResponse.model_validate(section)


# =============================================================================
# Report Findings
# =============================================================================

@router.post(
    "/projects/{project_id}/reports/{report_id}/findings",
    response_model=ReportFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add finding to report",
)
def add_report_finding(
    project_id: UUID,
    report_id: UUID,
    data: ReportFindingCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportFindingResponse:
    """Add a finding to a report."""
    service = ReportService(db)
    finding = service.add_finding(report_id, data.model_dump())
    return ReportFindingResponse.model_validate(finding)


@router.get(
    "/projects/{project_id}/reports/{report_id}/findings",
    response_model=ReportFindingListResponse,
    summary="List report findings",
)
def list_report_findings(
    project_id: UUID,
    report_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> ReportFindingListResponse:
    """List findings in a report."""
    service = ReportService(db)
    report = service.get_detail(report_id)

    findings = report.findings
    total = len(findings)
    offset = (page - 1) * page_size
    paginated = findings[offset:offset + page_size]

    return ReportFindingListResponse(
        items=[ReportFindingResponse.model_validate(f) for f in paginated],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.patch(
    "/projects/{project_id}/reports/{report_id}/findings/{finding_id}",
    response_model=ReportFindingResponse,
    summary="Update report finding",
)
def update_report_finding(
    project_id: UUID,
    report_id: UUID,
    finding_id: UUID,
    data: ReportFindingUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ReportFindingResponse:
    """Update a finding in a report."""
    service = ReportService(db)
    finding = service.update_finding(finding_id, data.model_dump(exclude_unset=True))
    return ReportFindingResponse.model_validate(finding)


# =============================================================================
# Bug Bounty Program Endpoints
# =============================================================================

program_router = APIRouter(prefix="/organizations/{org_id}/programs", tags=["bug-bounty-programs"])


@program_router.post(
    "",
    response_model=BugBountyProgramResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create bug bounty program",
)
def create_program(
    org_id: UUID,
    data: BugBountyProgramCreate,
    current_user: Annotated[User, Depends(require_project_member)],  # Will change to org member
    db: Annotated[Session, Depends(get_db)],
) -> BugBountyProgramResponse:
    """Create a new bug bounty program."""
    service = BugBountyProgramService(db)
    program = service.create(org_id, data.model_dump())
    return BugBountyProgramResponse.model_validate(program)


@program_router.get(
    "",
    response_model=BugBountyProgramListResponse,
    summary="List bug bounty programs",
)
def list_programs(
    org_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],  # Will change to org member
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    is_active: bool | None = None,
) -> BugBountyProgramListResponse:
    """List bug bounty programs in an organization."""
    service = BugBountyProgramService(db)
    offset = (page - 1) * page_size
    programs = service.list(org_id, limit=page_size, offset=offset, is_active=is_active)

    # Get total count
    from sqlalchemy import func, select
    total_stmt = select(func.count(BugBountyProgram.id)).where(BugBountyProgram.organization_id == org_id)
    if is_active is not None:
        total_stmt = total_stmt.where(BugBountyProgram.is_active == is_active)
    total = db.scalar(total_stmt) or 0

    return BugBountyProgramListResponse(
        items=[BugBountyProgramResponse.model_validate(p) for p in programs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@program_router.get(
    "/{program_id}",
    response_model=BugBountyProgramResponse,
    summary="Get bug bounty program",
)
def get_program(
    org_id: UUID,
    program_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> BugBountyProgramResponse:
    """Get bug bounty program by ID."""
    service = BugBountyProgramService(db)
    program = service.get(program_id)
    return BugBountyProgramResponse.model_validate(program)


@program_router.patch(
    "/{program_id}",
    response_model=BugBountyProgramResponse,
    summary="Update bug bounty program",
)
def update_program(
    org_id: UUID,
    program_id: UUID,
    data: BugBountyProgramUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> BugBountyProgramResponse:
    """Update bug bounty program."""
    from app.models.reports import BugBountyProgram

    program = db.get(BugBountyProgram, program_id)
    if not program or program.organization_id != org_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Bug bounty program", str(program_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(program, key, value)

    db.commit()
    db.refresh(program)

    return BugBountyProgramResponse.model_validate(program)


# =============================================================================
# Program Scopes
# =============================================================================

@program_router.post(
    "/{program_id}/scopes",
    response_model=ProgramScopeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add program scope",
)
def add_program_scope(
    org_id: UUID,
    program_id: UUID,
    data: ProgramScopeCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ProgramScopeResponse:
    """Add a scope to a bug bounty program."""
    service = BugBountyProgramService(db)
    scope = service.add_scope(program_id, data.model_dump())
    return ProgramScopeResponse.model_validate(scope)


@program_router.get(
    "/{program_id}/scopes",
    response_model=ProgramScopeListResponse,
    summary="List program scopes",
)
def list_program_scopes(
    org_id: UUID,
    program_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> ProgramScopeListResponse:
    """List scopes for a bug bounty program."""
    from app.models.reports import ProgramScope

    service = BugBountyProgramService(db)
    service.get(program_id)  # Verify program exists

    stmt = (
        select(ProgramScope)
        .where(ProgramScope.program_id == program_id)
        .order_by(ProgramScope.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    scopes = db.scalars(stmt).all()

    total = db.scalar(
        select(func.count(ProgramScope.id)).where(ProgramScope.program_id == program_id)
    ) or 0

    return ProgramScopeListResponse(
        items=[ProgramScopeResponse.model_validate(s) for s in scopes],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@program_router.patch(
    "/{program_id}/scopes/{scope_id}",
    response_model=ProgramScopeResponse,
    summary="Update program scope",
)
def update_program_scope(
    org_id: UUID,
    program_id: UUID,
    scope_id: UUID,
    data: ProgramScopeUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ProgramScopeResponse:
    """Update a program scope."""
    from app.models.reports import ProgramScope

    scope = db.get(ProgramScope, scope_id)
    if not scope or scope.program_id != program_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Program scope", str(scope_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(scope, key, value)

    db.commit()
    db.refresh(scope)

    return ProgramScopeResponse.model_validate(scope)


# =============================================================================
# Excluded Targets
# =============================================================================

@program_router.post(
    "/{program_id}/excluded-targets",
    response_model=ExcludedTargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add excluded target",
)
def add_excluded_target(
    org_id: UUID,
    program_id: UUID,
    data: ExcludedTargetCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ExcludedTargetResponse:
    """Add an excluded target to a program."""
    service = BugBountyProgramService(db)
    excluded = service.add_excluded_target(program_id, data.model_dump())
    return ExcludedTargetResponse.model_validate(excluded)


# =============================================================================
# Program Policies
# =============================================================================

@program_router.post(
    "/{program_id}/policies",
    response_model=ProgramPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add program policy",
)
def add_program_policy(
    org_id: UUID,
    program_id: UUID,
    data: ProgramPolicyCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ProgramPolicyResponse:
    """Add a policy to a bug bounty program."""
    service = BugBountyProgramService(db)
    policy = service.add_policy(program_id, data.model_dump())
    return ProgramPolicyResponse.model_validate(policy)


# =============================================================================
# Research Workspace Endpoints
# =============================================================================

workspace_router = APIRouter(prefix="/programs/{program_id}/workspaces", tags=["research-workspaces"])


@workspace_router.post(
    "",
    response_model=ResearchWorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create research workspace",
)
def create_workspace(
    program_id: UUID,
    data: ResearchWorkspaceCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ResearchWorkspaceResponse:
    """Create a research workspace for the current user."""
    service = ResearchWorkspaceService(db)
    workspace = service.create(program_id, current_user.id, data.model_dump())
    return ResearchWorkspaceResponse.model_validate(workspace)


@workspace_router.get(
    "",
    response_model=ResearchWorkspaceListResponse,
    summary="List research workspaces",
)
def list_workspaces(
    program_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ResearchWorkspaceListResponse:
    """List research workspaces for a program."""
    service = ResearchWorkspaceService(db)
    offset = (page - 1) * page_size
    workspaces = service.list(program_id, limit=page_size, offset=offset)

    from sqlalchemy import func, select
    from app.models.reports import ResearchWorkspace

    total = db.scalar(
        select(func.count(ResearchWorkspace.id)).where(
            ResearchWorkspace.program_id == program_id,
            ResearchWorkspace.deleted_at.is_(None),
        )
    ) or 0

    return ResearchWorkspaceListResponse(
        items=[ResearchWorkspaceResponse.model_validate(w) for w in workspaces],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@workspace_router.get(
    "/{workspace_id}",
    response_model=ResearchWorkspaceResponse,
    summary="Get research workspace",
)
def get_workspace(
    program_id: UUID,
    workspace_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ResearchWorkspaceResponse:
    """Get research workspace by ID."""
    service = ResearchWorkspaceService(db)
    workspace = service.get(workspace_id)
    return ResearchWorkspaceResponse.model_validate(workspace)


@workspace_router.patch(
    "/{workspace_id}",
    response_model=ResearchWorkspaceResponse,
    summary="Update research workspace",
)
def update_workspace(
    program_id: UUID,
    workspace_id: UUID,
    data: ResearchWorkspaceUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ResearchWorkspaceResponse:
    """Update research workspace."""
    from app.models.reports import ResearchWorkspace

    workspace = db.get(ResearchWorkspace, workspace_id)
    if not workspace or workspace.program_id != program_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Research workspace", str(workspace_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(workspace, key, value)

    db.commit()
    db.refresh(workspace)

    return ResearchWorkspaceResponse.model_validate(workspace)


# =============================================================================
# Research Notes
# =============================================================================

@workspace_router.post(
    "/{workspace_id}/notes",
    response_model=ResearchNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add research note",
)
def add_research_note(
    program_id: UUID,
    workspace_id: UUID,
    data: ResearchNoteCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ResearchNoteResponse:
    """Add a research note."""
    service = ResearchWorkspaceService(db)
    note = service.add_note(workspace_id, current_user.id, data.model_dump())
    return ResearchNoteResponse.model_validate(note)


@workspace_router.get(
    "/{workspace_id}/notes",
    response_model=ResearchNoteListResponse,
    summary="List research notes",
)
def list_research_notes(
    program_id: UUID,
    workspace_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> ResearchNoteListResponse:
    """List research notes in a workspace."""
    from app.models.reports import ResearchNote
    from sqlalchemy import func, select

    service = ResearchWorkspaceService(db)
    service.get(workspace_id)  # Verify workspace exists

    stmt = (
        select(ResearchNote)
        .where(
            ResearchNote.workspace_id == workspace_id,
            ResearchNote.deleted_at.is_(None),
        )
        .order_by(ResearchNote.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    notes = db.scalars(stmt).all()

    total = db.scalar(
        select(func.count(ResearchNote.id)).where(
            ResearchNote.workspace_id == workspace_id,
            ResearchNote.deleted_at.is_(None),
        )
    ) or 0

    return ResearchNoteListResponse(
        items=[ResearchNoteResponse.model_validate(n) for n in notes],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


# =============================================================================
# Workspace Observations
# =============================================================================

@workspace_router.post(
    "/{workspace_id}/observations",
    response_model=WorkspaceObservationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add observation",
)
def add_observation(
    program_id: UUID,
    workspace_id: UUID,
    data: WorkspaceObservationCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceObservationResponse:
    """Add an observation to a workspace."""
    service = ResearchWorkspaceService(db)
    obs = service.add_observation(workspace_id, current_user.id, data.model_dump())
    return WorkspaceObservationResponse.model_validate(obs)


@workspace_router.get(
    "/{workspace_id}/observations",
    response_model=WorkspaceObservationListResponse,
    summary="List observations",
)
def list_observations(
    program_id: UUID,
    workspace_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
) -> WorkspaceObservationListResponse:
    """List observations in a workspace."""
    from app.models.reports import WorkspaceObservation
    from sqlalchemy import func, select

    service = ResearchWorkspaceService(db)
    service.get(workspace_id)

    stmt = (
        select(WorkspaceObservation)
        .where(
            WorkspaceObservation.workspace_id == workspace_id,
            WorkspaceObservation.deleted_at.is_(None),
        )
        .order_by(WorkspaceObservation.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    if status:
        stmt = stmt.where(WorkspaceObservation.status == status)

    observations = db.scalars(stmt).all()

    total = db.scalar(
        select(func.count(WorkspaceObservation.id)).where(
            WorkspaceObservation.workspace_id == workspace_id,
            WorkspaceObservation.deleted_at.is_(None),
        )
    ) or 0

    return WorkspaceObservationListResponse(
        items=[WorkspaceObservationResponse.model_validate(o) for o in observations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@workspace_router.patch(
    "/{workspace_id}/observations/{observation_id}",
    response_model=WorkspaceObservationResponse,
    summary="Update observation",
)
def update_observation(
    program_id: UUID,
    workspace_id: UUID,
    observation_id: UUID,
    data: WorkspaceObservationUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceObservationResponse:
    """Update an observation."""
    from app.models.reports import WorkspaceObservation

    obs = db.get(WorkspaceObservation, observation_id)
    if not obs or obs.workspace_id != workspace_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Workspace observation", str(observation_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(obs, key, value)

    obs.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(obs)

    return WorkspaceObservationResponse.model_validate(obs)


# =============================================================================
# Workspace Findings
# =============================================================================

@workspace_router.post(
    "/{workspace_id}/findings",
    response_model=WorkspaceFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add finding",
)
def add_workspace_finding(
    program_id: UUID,
    workspace_id: UUID,
    data: WorkspaceFindingCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceFindingResponse:
    """Add a finding to a workspace."""
    service = ResearchWorkspaceService(db)
    finding = service.add_finding(workspace_id, current_user.id, data.model_dump())
    return WorkspaceFindingResponse.model_validate(finding)


@workspace_router.get(
    "/{workspace_id}/findings",
    response_model=WorkspaceFindingListResponse,
    summary="List workspace findings",
)
def list_workspace_findings(
    program_id: UUID,
    workspace_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
) -> WorkspaceFindingListResponse:
    """List findings in a workspace."""
    from app.models.reports import WorkspaceFinding
    from sqlalchemy import func, select

    service = ResearchWorkspaceService(db)
    service.get(workspace_id)

    stmt = (
        select(WorkspaceFinding)
        .where(
            WorkspaceFinding.workspace_id == workspace_id,
            WorkspaceFinding.deleted_at.is_(None),
        )
        .order_by(WorkspaceFinding.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    if status:
        stmt = stmt.where(WorkspaceFinding.status == status)

    findings = db.scalars(stmt).all()

    total = db.scalar(
        select(func.count(WorkspaceFinding.id)).where(
            WorkspaceFinding.workspace_id == workspace_id,
            WorkspaceFinding.deleted_at.is_(None),
        )
    ) or 0

    return WorkspaceFindingListResponse(
        items=[WorkspaceFindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@workspace_router.patch(
    "/{workspace_id}/findings/{finding_id}",
    response_model=WorkspaceFindingResponse,
    summary="Update workspace finding",
)
def update_workspace_finding(
    program_id: UUID,
    workspace_id: UUID,
    finding_id: UUID,
    data: WorkspaceFindingUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceFindingResponse:
    """Update a workspace finding."""
    from app.models.reports import WorkspaceFinding

    finding = db.get(WorkspaceFinding, finding_id)
    if not finding or finding.workspace_id != workspace_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Workspace finding", str(finding_id))

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(finding, key, value)

    finding.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(finding)

    return WorkspaceFindingResponse.model_validate(finding)


@workspace_router.post(
    "/{workspace_id}/findings/{finding_id}/promote",
    response_model=WorkspaceFindingResponse,
    summary="Promote finding to official Finding",
)
def promote_finding(
    program_id: UUID,
    workspace_id: UUID,
    finding_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceFindingResponse:
    """Promote a workspace finding to an official Finding."""
    service = ResearchWorkspaceService(db)
    finding = service.promote_finding(finding_id, current_user.id)
    return WorkspaceFindingResponse.model_validate(finding)


# =============================================================================
# Workspace Reports
# =============================================================================

@workspace_router.post(
    "/{workspace_id}/reports",
    response_model=WorkspaceReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create workspace report",
)
def create_workspace_report(
    program_id: UUID,
    workspace_id: UUID,
    data: WorkspaceReportCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceReportResponse:
    """Create a draft report in workspace."""
    from app.models.reports import WorkspaceReport

    service = ResearchWorkspaceService(db)
    service.get(workspace_id)

    report = WorkspaceReport(
        workspace_id=workspace_id,
        user_id=current_user.id,
        **data.model_dump(),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return WorkspaceReportResponse.model_validate(report)


@workspace_router.get(
    "/{workspace_id}/reports",
    response_model=WorkspaceReportListResponse,
    summary="List workspace reports",
)
def list_workspace_reports(
    program_id: UUID,
    workspace_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> WorkspaceReportListResponse:
    """List reports in a workspace."""
    from app.models.reports import WorkspaceReport
    from sqlalchemy import func, select

    service = ResearchWorkspaceService(db)
    service.get(workspace_id)

    stmt = (
        select(WorkspaceReport)
        .where(
            WorkspaceReport.workspace_id == workspace_id,
            WorkspaceReport.deleted_at.is_(None),
        )
        .order_by(WorkspaceReport.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    reports = db.scalars(stmt).all()

    total = db.scalar(
        select(func.count(WorkspaceReport.id)).where(
            WorkspaceReport.workspace_id == workspace_id,
            WorkspaceReport.deleted_at.is_(None),
        )
    ) or 0

    return WorkspaceReportListResponse(
        items=[WorkspaceReportResponse.model_validate(r) for r in reports],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


# Register all routers
reports_router = APIRouter(prefix="/api/v1", tags=["reports"])
reports_router.include_router(router)
reports_router.include_router(program_router)
reports_router.include_router(workspace_router)

# Export
__all__ = ["reports_router"]