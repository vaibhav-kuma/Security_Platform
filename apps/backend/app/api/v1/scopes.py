"""Scope API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.db.session import get_db
from app.models.identity import User
from app.models.projects import ScopeRule, ScopeSnapshot
from app.schemas.scopes import (
    ScopeCreate,
    ScopeDetailResponse,
    ScopeListResponse,
    ScopeResponse,
    ScopeRuleCreate,
    ScopeRuleListResponse,
    ScopeRuleResponse,
    ScopeRuleUpdate,
    ScopeSnapshotResponse,
    ScopeUpdate,
)
from app.services.scopes import ScopeService

router = APIRouter(prefix="/projects/{project_id}/scopes", tags=["scopes"])


@router.post(
    "",
    response_model=ScopeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scope",
)
def create_scope(
    project_id: UUID,
    data: ScopeCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeResponse:
    """Create a new scope within a project.

    Requires project membership.
    """
    service = ScopeService(db)
    scope = service.create(project_id, data)
    return ScopeResponse.model_validate(scope)


@router.get(
    "",
    response_model=ScopeListResponse,
    summary="List scopes",
)
def list_scopes(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
    is_active: bool | None = None,
) -> ScopeListResponse:
    """List scopes in a project.

    Requires project membership.
    """
    service = ScopeService(db)
    offset = (page - 1) * page_size
    scopes = service.list(
        project_id, limit=page_size, offset=offset, is_active=is_active
    )
    total = service.count(project_id, is_active=is_active)

    return ScopeListResponse(
        items=[ScopeResponse.model_validate(s) for s in scopes],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{scope_id}",
    response_model=ScopeDetailResponse,
    summary="Get scope",
)
def get_scope(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeDetailResponse:
    """Get scope by ID with rules.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    scope = service.get_detail(scope_id)
    return ScopeDetailResponse.model_validate(scope)


@router.patch(
    "/{scope_id}",
    response_model=ScopeResponse,
    summary="Update scope",
)
def update_scope(
    project_id: UUID,
    scope_id: UUID,
    data: ScopeUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeResponse:
    """Update scope details.

    Requires project membership. Updating rules requires version increment.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    scope = service.update(scope_id, data)
    return ScopeResponse.model_validate(scope)


@router.delete(
    "/{scope_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete scope",
)
def delete_scope(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Soft delete scope.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    service.delete(scope_id)


@router.post(
    "/{scope_id}/version",
    response_model=ScopeResponse,
    summary="Increment scope version",
)
def increment_scope_version(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeResponse:
    """Increment scope version and create snapshot.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    scope = service.increment_version(scope_id)
    return ScopeResponse.model_validate(scope)


# ---- Scope Rules ----

@router.post(
    "/{scope_id}/rules",
    response_model=ScopeRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scope rule",
)
def create_scope_rule(
    project_id: UUID,
    scope_id: UUID,
    data: ScopeRuleCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeRuleResponse:
    """Add a rule to a scope.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    rule = service.add_rule(scope_id, data)
    return ScopeRuleResponse.model_validate(rule)


@router.get(
    "/{scope_id}/rules",
    response_model=ScopeRuleListResponse,
    summary="List scope rules",
)
def list_scope_rules(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 50,
) -> ScopeRuleListResponse:
    """List rules in a scope.

    Requires project membership.
    """
    service = ScopeService(db)
    rules = service.list_rules(scope_id, limit=page_size, offset=(page - 1) * page_size)

    # Get total count
    total = db.scalar(select(func.count(ScopeRule.id)).where(ScopeRule.scope_id == scope_id)) or 0

    return ScopeRuleListResponse(
        items=[ScopeRuleResponse.model_validate(r) for r in rules],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.patch(
    "/{scope_id}/rules/{rule_id}",
    response_model=ScopeRuleResponse,
    summary="Update scope rule",
)
def update_scope_rule(
    project_id: UUID,
    scope_id: UUID,
    rule_id: UUID,
    data: ScopeRuleUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeRuleResponse:
    """Update a scope rule.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    rule = service.update_rule(rule_id, data)
    return ScopeRuleResponse.model_validate(rule)


@router.delete(
    "/{scope_id}/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete scope rule",
)
def delete_scope_rule(
    project_id: UUID,
    scope_id: UUID,
    rule_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Delete a scope rule.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    service.delete_rule(rule_id)


# ---- Scope Snapshots ----

@router.get(
    "/{scope_id}/snapshots",
    summary="List scope snapshots",
)
def list_scope_snapshots(
    project_id: UUID,
    scope_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
):
    """List versioned snapshots of a scope.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    offset = (page - 1) * page_size
    snapshots = service.list_snapshots(scope_id, limit=page_size, offset=offset)

    # Get total count
    total = (
        db.scalar(
            select(func.count(ScopeSnapshot.id)).where(
                ScopeSnapshot.scope_id == scope_id
            )
        )
        or 0
    )

    return {
        "items": [ScopeSnapshotResponse.model_validate(s) for s in snapshots],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.get(
    "/{scope_id}/snapshots/{version}",
    response_model=ScopeSnapshotResponse,
    summary="Get scope snapshot",
)
def get_scope_snapshot(
    project_id: UUID,
    scope_id: UUID,
    version: int,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ScopeSnapshotResponse:
    """Get a specific scope snapshot by version.

    Requires project membership.
    """
    service = ScopeService(db)
    service.verify_scope_in_project(scope_id, project_id)
    snapshot = service.get_snapshot(scope_id, version)
    return ScopeSnapshotResponse.model_validate(snapshot)
