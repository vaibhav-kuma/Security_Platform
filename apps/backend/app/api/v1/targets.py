"""Target API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.db.session import get_db
from app.models.identity import User
from app.schemas.targets import (
    AssetListResponse,
    AssetResponse,
    TargetCreate,
    TargetDetailResponse,
    TargetListResponse,
    TargetResponse,
    TargetUpdate,
)
from app.services.targets import AssetService, TargetService

router = APIRouter(prefix="/projects/{project_id}/targets", tags=["targets"])


@router.post(
    "",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create target",
)
def create_target(
    project_id: UUID,
    data: TargetCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    """Create a new target within a project.

    Requires project membership.
    """
    service = TargetService(db)
    target = service.create(project_id, data)
    return TargetResponse.model_validate(target)


@router.get(
    "",
    response_model=TargetListResponse,
    summary="List targets",
)
def list_targets(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
    scope_id: UUID | None = None,
    scope_status: str | None = None,
) -> TargetListResponse:
    """List targets in a project.

    Requires project membership.
    """
    service = TargetService(db)
    targets = service.list(
        project_id,
        limit=page_size,
        offset=(page - 1) * page_size,
        scope_id=scope_id,
        scope_status=scope_status,
    )
    total = service.count(project_id, scope_id=scope_id, scope_status=scope_status)

    return TargetListResponse(
        items=[TargetResponse.model_validate(t) for t in targets],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{target_id}",
    response_model=TargetDetailResponse,
    summary="Get target",
)
def get_target(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetDetailResponse:
    """Get target by ID with asset count.

    Requires project membership.
    """
    service = TargetService(db)
    service.verify_target_in_project(target_id, project_id)
    target = service.get_detail(target_id)
    return TargetDetailResponse.model_validate(target)


@router.patch(
    "/{target_id}",
    response_model=TargetResponse,
    summary="Update target",
)
def update_target(
    project_id: UUID,
    target_id: UUID,
    data: TargetUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> TargetResponse:
    """Update target details.

    Requires project membership.
    """
    service = TargetService(db)
    service.verify_target_in_project(target_id, project_id)
    target = service.update(target_id, data)
    return TargetResponse.model_validate(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete target",
)
def delete_target(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Soft delete target.

    Requires project membership.
    """
    service = TargetService(db)
    service.verify_target_in_project(target_id, project_id)
    service.delete(target_id)


# ---- Assets ----

@router.get(
    "/{target_id}/assets",
    response_model=AssetListResponse,
    summary="List assets for target",
)
def list_target_assets(
    project_id: UUID,
    target_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 50,
    kind: str | None = None,
) -> AssetListResponse:
    """List assets associated with a target.

    Requires project membership.
    """
    service = AssetService(db)
    assets = service.list(
        project_id,
        limit=page_size,
        offset=(page - 1) * page_size,
        target_id=target_id,
        kind=kind,
    )
    total = service.count(project_id, target_id=target_id, kind=kind)

    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/assets",
    response_model=AssetListResponse,
    summary="List all assets in project",
)
def list_project_assets(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 50,
    target_id: UUID | None = None,
    kind: str | None = None,
) -> AssetListResponse:
    """List all assets in a project.

    Requires project membership.
    """
    service = AssetService(db)
    assets = service.list(
        project_id,
        limit=page_size,
        offset=(page - 1) * page_size,
        target_id=target_id,
        kind=kind,
    )
    total = service.count(project_id, target_id=target_id, kind=kind)

    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Get asset",
)
def get_asset(
    project_id: UUID,
    asset_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> AssetResponse:
    """Get asset by ID.

    Requires project membership.
    """
    service = AssetService(db)
    asset = service.get(asset_id)
    return AssetResponse.model_validate(asset)
