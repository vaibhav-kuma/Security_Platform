"""Organization API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user, require_organization_member
from app.core.pagination import PageParams
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.enums import SecurityEventType
from app.models.identity import User
from app.schemas.organizations import (
    OrganizationCreate,
    OrganizationListResponse,
    OrganizationResponse,
    OrganizationUpdate,
)
from app.services.organizations import OrganizationService

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post(
    "",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create organization",
)
def create_organization(
    data: OrganizationCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> OrganizationResponse:
    """Create a new organization.

    Requires authentication. The creator becomes an owner.
    """
    service = OrganizationService(db)
    org = service.create(data)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.ORG_CREATE.value,
        entity_type="organization",
        entity_id=org.id,
        details={"name": org.name},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return OrganizationResponse.model_validate(org)


@router.get(
    "",
    response_model=OrganizationListResponse,
    summary="List organizations",
)
def list_organizations(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
) -> OrganizationListResponse:
    """List organizations accessible to the current user.

    Returns organizations where the user is a member.
    """
    page_params = PageParams(page=page, page_size=page_size)
    service = OrganizationService(db)
    offset = (page_params.page - 1) * page_params.page_size
    orgs = service.list_for_user(
        current_user.id, limit=page_params.page_size, offset=offset
    )
    total = service.count_for_user(current_user.id)

    return OrganizationListResponse(
        items=[OrganizationResponse.model_validate(o) for o in orgs],
        total=total,
        page=page_params.page,
        page_size=page_params.page_size,
        total_pages=(total + page_params.page_size - 1) // page_params.page_size,
    )


@router.get(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Get organization",
)
def get_organization(
    org_id: UUID,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
) -> OrganizationResponse:
    """Get organization by ID.

    Requires organization membership.
    """
    service = OrganizationService(db)
    org = service.get(org_id)
    return OrganizationResponse.model_validate(org)


@router.patch(
    "/{org_id}",
    response_model=OrganizationResponse,
    summary="Update organization",
)
def update_organization(
    org_id: UUID,
    data: OrganizationUpdate,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> OrganizationResponse:
    """Update organization details.

    Requires organization membership.
    """
    service = OrganizationService(db)
    org = service.update(org_id, data)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.ORG_UPDATE.value,
        entity_type="organization",
        entity_id=org_id,
        details={"updated_fields": data.model_dump(exclude_unset=True)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return OrganizationResponse.model_validate(org)


@router.delete(
    "/{org_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete organization",
)
def delete_organization(
    org_id: UUID,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete organization.

    Requires organization membership.
    """
    service = OrganizationService(db)
    service.delete(org_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.ORG_DELETE.value,
        entity_type="organization",
        entity_id=org_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
