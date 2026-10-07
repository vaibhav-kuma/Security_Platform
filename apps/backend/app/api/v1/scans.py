"""Scan API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.enums import ScanStatus, ScanType, SecurityEventType
from app.models.identity import User
from app.models.scans import Scan
from app.schemas.scans import (
    ScanCreate,
    ScanDetailResponse,
    ScanListResponse,
    ScanProgressResponse,
    ScanResponse,
    ScanUpdate,
)
from app.services.scans import ScanExecutionService, create_scan_with_validation

router = APIRouter(prefix="/projects/{project_id}/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scan",
)
@strict_rate_limit()
def create_scan(
    project_id: UUID,
    data: ScanCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Create a new scan within a project.

    Requires project membership.
    """
    scan = create_scan_with_validation(
        db=db,
        project_id=project_id,
        name=data.name,
        scan_type=ScanType(data.scan_type),
        target_id=data.target_id,
        configuration=data.configuration or {},
        initiated_by=current_user.id,
    )

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_CREATE.value,
        entity_type="scan",
        entity_id=scan.id,
        details={"name": scan.name, "scan_type": data.scan_type, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List scans",
)
def list_scans(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
    status_filter: str | None = None,
    scan_type: str | None = None,
) -> ScanListResponse:
    """List scans in a project.

    Requires project membership.
    """
    stmt = select(Scan).where(Scan.project_id == project_id)

    if status_filter:
        try:
            stmt = stmt.where(Scan.status == ScanStatus(status_filter))
        except ValueError:
            pass

    if scan_type:
        try:
            stmt = stmt.where(Scan.scan_type == ScanType(scan_type))
        except ValueError:
            pass

    stmt = stmt.order_by(Scan.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
    scans = db.scalars(stmt).all()

    total_stmt = select(func.count(Scan.id)).where(Scan.project_id == project_id)
    if status_filter:
        try:
            total_stmt = total_stmt.where(Scan.status == ScanStatus(status_filter))
        except ValueError:
            pass
    total = db.scalar(total_stmt) or 0

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get scan",
)
def get_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScanDetailResponse:
    """Get scan by ID with jobs.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    return ScanDetailResponse.model_validate(scan)


@router.get(
    "/{scan_id}/progress",
    response_model=ScanProgressResponse,
    summary="Get scan progress",
)
def get_scan_progress(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScanProgressResponse:
    """Get real-time progress of a scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    service = ScanExecutionService(db)
    progress = service.get_scan_progress(scan)

    return ScanProgressResponse(**progress)


@router.patch(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Update scan",
)
def update_scan(
    project_id: UUID,
    scan_id: UUID,
    data: ScanUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Update scan details.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    if data.name is not None:
        scan.name = data.name
    if data.configuration is not None:
        scan.configuration = data.configuration

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="scan",
        entity_id=scan_id,
        details={"updated_fields": data.model_dump(exclude_unset=True)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ScanResponse.model_validate(scan)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete scan",
)
def delete_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    from app.repositories.base import SoftDeleteRepository
    repo = SoftDeleteRepository(db, Scan)
    repo.soft_delete(scan)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_DELETE.value,
        entity_type="scan",
        entity_id=scan_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()


@router.post(
    "/{scan_id}/start",
    response_model=ScanResponse,
    summary="Start scan",
)
@strict_rate_limit()
def start_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Start a pending scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    if scan.status != ScanStatus.PENDING:
        from app.core.exceptions import ConflictError
        raise ConflictError(f"Cannot start scan with status: {scan.status.value}")

    service = ScanExecutionService(db)
    try:
        service.start_scan(scan)
    except ValueError as e:
        from app.core.exceptions import ConflictError
        raise ConflictError(str(e)) from e

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_START.value,
        entity_type="scan",
        entity_id=scan_id,
        details={"name": scan.name},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel scan",
)
def cancel_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Cancel a running or pending scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        from app.core.exceptions import ConflictError
        raise ConflictError(f"Cannot cancel scan with status: {scan.status.value}")

    service = ScanExecutionService(db)
    try:
        service.cancel_scan(scan)
    except ValueError as e:
        from app.core.exceptions import ConflictError
        raise ConflictError(str(e)) from e

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_CANCEL.value,
        entity_type="scan",
        entity_id=scan_id,
        details={"name": scan.name},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.post(
    "/{scan_id}/pause",
    response_model=ScanResponse,
    summary="Pause scan",
)
def pause_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Pause a running scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    if scan.status != ScanStatus.RUNNING:
        from app.core.exceptions import ConflictError
        raise ConflictError(f"Cannot pause scan with status: {scan.status.value}")

    service = ScanExecutionService(db)
    try:
        service.pause_scan(scan)
    except ValueError as e:
        from app.core.exceptions import ConflictError
        raise ConflictError(str(e)) from e

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_PAUSE.value,
        entity_type="scan",
        entity_id=scan_id,
        details={"name": scan.name},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.post(
    "/{scan_id}/resume",
    response_model=ScanResponse,
    summary="Resume scan",
)
def resume_scan(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ScanResponse:
    """Resume a paused scan.

    Requires project membership.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scan", str(scan_id))

    if scan.status != ScanStatus.PAUSED:
        from app.core.exceptions import ConflictError
        raise ConflictError(f"Cannot resume scan with status: {scan.status.value}")

    service = ScanExecutionService(db)
    try:
        service.resume_scan(scan)
    except ValueError as e:
        from app.core.exceptions import ConflictError
        raise ConflictError(str(e)) from e

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_RESUME.value,
        entity_type="scan",
        entity_id=scan_id,
        details={"name": scan.name},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


