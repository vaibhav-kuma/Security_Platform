"""Scope evaluation API endpoints."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.identity import User
from app.schemas.targets import TargetResponse, TargetStatusUpdate
from app.services.target_validation import TargetValidationService

router = APIRouter(prefix="/projects/{project_id}/scope", tags=["scope-evaluation"])


@router.post(
    "/evaluate/{target_id}",
    response_model=TargetResponse,
    summary="Evaluate target against scope rules",
)
@strict_rate_limit()
def evaluate_target(
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> TargetResponse:
    """Evaluate a specific target against the project's scope rules.

    Updates the target's scope_status based on the evaluation.
    Requires project membership.
    """
    service = TargetValidationService(db)
    source_ip = request.client.host if request.client else None
    target = service.validate_target(
        target_id, project_id, user_id=current_user.id, source_ip=source_ip
    )
    return TargetResponse.model_validate(target)


@router.post(
    "/evaluate-all",
    summary="Evaluate all targets in project",
)
@strict_rate_limit()
def evaluate_all_targets(
    project_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> dict:
    """Evaluate all targets in the project against scope rules.

    Returns paginated summary of evaluation results.
    Requires project membership.
    """
    service = TargetValidationService(db)
    targets = service.validate_targets_in_project(
        project_id, page=page, page_size=page_size
    )

    # Get total count for pagination
    from sqlalchemy import func, select

    from app.models.projects import Target

    total = (
        db.scalar(
            select(func.count(Target.id)).where(
                Target.project_id == project_id, Target.deleted_at.is_(None)
            )
        )
        or 0
    )

    # Count by status
    status_counts: dict[str, int] = {}
    for target in targets:
        status = target.scope_status.value
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "project_id": str(project_id),
        "total_evaluated": len(targets),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
        "status_breakdown": status_counts,
        "targets": [
            {
                "id": str(t.id),
                "name": t.name,
                "scope_status": t.scope_status.value,
            }
            for t in targets
        ],
    }


@router.post(
    "/evaluate-scope/{scope_id}",
    summary="Evaluate all targets in a specific scope",
)
@strict_rate_limit()
def evaluate_scope_targets(
    project_id: uuid.UUID,
    scope_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Evaluate all targets associated with a specific scope.

    Requires project membership.
    """
    service = TargetValidationService(db)
    source_ip = request.client.host if request.client else None
    targets = service.validate_targets_in_scope(
        scope_id, user_id=current_user.id, source_ip=source_ip
    )

    status_counts: dict[str, int] = {}
    for target in targets:
        status = target.scope_status.value
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "project_id": str(project_id),
        "scope_id": str(scope_id),
        "total_evaluated": len(targets),
        "status_breakdown": status_counts,
        "targets": [
            {
                "id": str(t.id),
                "name": t.name,
                "scope_status": t.scope_status.value,
            }
            for t in targets
        ],
    }


@router.patch(
    "/targets/{target_id}/status",
    response_model=TargetResponse,
    summary="Manually override target scope status",
)
@strict_rate_limit()
def override_target_status(
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: TargetStatusUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> TargetResponse:
    """Manually override a target's scope status.

    Useful for exceptions or when automatic evaluation needs correction.
    Requires project membership.
    """
    service = TargetValidationService(db)
    source_ip = request.client.host if request.client else None
    target = service.update_target_status_manually(
        target_id, payload.status, user_id=current_user.id, source_ip=source_ip
    )
    return TargetResponse.model_validate(target)
