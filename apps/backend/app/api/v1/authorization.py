"""Authorization confirmation and scope preview endpoints (Phase 6 minimal)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.identity import User
from app.services.target_validation import validate_target_for_scan
from app.schemas.targets import TargetResponse

router = APIRouter(prefix="/projects/{project_id}", tags=["authorization"])


@router.post(
    "/scans/confirm",
    summary="Confirm authorization before scan creation",
)
@strict_rate_limit()
def confirm_scan_authorization(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Server-side validation: target scope is the ultimate authority.

    shortcut: only confirms authorization; does not enforce scan-time rate limits or sandbox isolation yet. Upgrade when full Phase 6 scanning engine is implemented.
    """
    is_valid, error = validate_target_for_scan(db, project_id, target_id)
    return {
        "project_id": str(project_id),
        "target_id": str(target_id),
        "authorized": is_valid,
        "authorization_source": "server_side_scope_engine",
        "error": error,
        "restrictions": ["scope_engine_is_authority", "client_validation_is_not_sufficient"],
    }


@router.get(
    "/scope/preview/{scope_id}",
    summary="Scope preview for authorization visibility",
)
def scope_preview(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Preview scope rules without modifying state."""
    from app.models.projects import Scope
    scope = db.get(Scope, scope_id)
    if not scope or scope.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Scope", str(scope_id))
    rules_preview = [
        {"effect": r.effect.value, "target_type": r.target_type.value, "pattern": r.pattern}
        for r in scope.rules
    ]
    return {
        "scope_id": str(scope_id),
        "scope_name": scope.name,
        "is_active": scope.is_active,
        "rules": rules_preview,
        "restriction": "scope_preview_only_no_changes_applied",
    }
