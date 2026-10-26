"""Scan confirmation API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.db.session import get_db
from app.models.identity import User
from app.schemas.targets import TargetResponse
from app.services.scan_confirmation import ScanConfirmationService

router = APIRouter(
    prefix="/projects/{project_id}/targets/{target_id}/scan-confirmation",
    tags=["scan-confirmation"],
)


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get security confirmation for target scan",
)
def get_scan_confirmation(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    source_ip: str | None = None,
) -> TargetResponse:
    """Get security confirmation data for a target before active scan execution.

    This endpoint provides a security confirmation view that must be acknowledged
    before any active scan can be initiated. It displays:
    - Exact target being scanned
    - Applicable scope rules and status
    - Testing profile and rate limits
    - Authorization disclaimer

    Server-side validation is the ultimate authority - client-side checks
    are for UX only and can be bypassed.

    Requires project membership.
    """
    service = ScanConfirmationService(db)
    confirmation = service.get_scan_confirmation(
        project_id=project_id,
        target_id=target_id,
        user_id=current_user.id,
        source_ip=source_ip,
    )
    return TargetResponse.model_validate(confirmation["target_response"])


@router.post(
    "/validate",
    response_model=TargetResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate target for scan and update scope status",
)
def validate_target_for_scan(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    source_ip: str | None = None,
) -> TargetResponse:
    """Validate target for scanning and update its scope status.

    This is a convenience endpoint that combines validation and confirmation
    in a single call. Returns the target with updated scope_status.

    Returns ForbiddenError if target is out of scope or third-party.

    Requires project membership.
    """
    service = ScanConfirmationService(db)
    target = service.validate_target_for_scan(
        target_id=target_id,
        project_id=project_id,
        user_id=current_user.id,
        source_ip=source_ip,
    )
    return TargetResponse.model_validate(target)