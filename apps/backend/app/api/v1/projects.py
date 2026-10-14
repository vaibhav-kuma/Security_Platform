"""Project API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import (
    require_organization_member,
    require_project_member,
)
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.enums import SecurityEventType
from app.models.identity import User
from app.models.projects import ProjectMember
from app.schemas.projects import (
    ProjectCreate,
    ProjectDetailResponse,
    ProjectListResponse,
    ProjectMemberCreate,
    ProjectMemberListResponse,
    ProjectMemberResponse,
    ProjectResponse,
    ProjectUpdate,
)
from app.services.projects import ProjectService

router = APIRouter(prefix="/organizations/{org_id}/projects", tags=["projects"])


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create project",
)
def create_project(
    org_id: UUID,
    data: ProjectCreate,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ProjectResponse:
    """Create a new project within an organization.

    Requires organization membership.
    """
    service = ProjectService(db)
    project = service.create(org_id, data)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.PROJECT_CREATE.value,
        entity_type="project",
        entity_id=project.id,
        details={"name": project.name, "organization_id": str(org_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ProjectResponse.model_validate(project)


@router.get(
    "",
    response_model=ProjectListResponse,
    summary="List projects",
)
def list_projects(
    org_id: UUID,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 20,
    status_filter: str | None = None,
) -> ProjectListResponse:
    """List projects in an organization.

    Requires organization membership.
    """
    service = ProjectService(db)
    offset = (page - 1) * page_size
    projects = service.list(
        org_id, limit=page_size, offset=offset, status=status_filter
    )
    total = service.count(org_id, status=status_filter)

    return ProjectListResponse(
        items=[ProjectResponse.model_validate(p) for p in projects],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{project_id}",
    response_model=ProjectDetailResponse,
    summary="Get project",
)
def get_project(
    org_id: UUID,
    project_id: UUID,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ProjectDetailResponse:
    """Get project by ID with details.

    Requires organization membership.
    """
    service = ProjectService(db)
    service.verify_project_in_org(project_id, org_id)
    project = service.get_detail(project_id)
    return ProjectDetailResponse.model_validate(project)


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Update project",
)
def update_project(
    org_id: UUID,
    project_id: UUID,
    data: ProjectUpdate,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ProjectResponse:
    """Update project details.

    Requires organization membership.
    """
    service = ProjectService(db)
    service.verify_project_in_org(project_id, org_id)
    project = service.update(project_id, data)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.PROJECT_UPDATE.value,
        entity_type="project",
        entity_id=project_id,
        details={"updated_fields": data.model_dump(exclude_unset=True)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ProjectResponse.model_validate(project)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete project",
)
def delete_project(
    org_id: UUID,
    project_id: UUID,
    current_user: Annotated[User, Depends(require_organization_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete project.

    Requires organization membership.
    """
    service = ProjectService(db)
    service.verify_project_in_org(project_id, org_id)
    service.delete(project_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.PROJECT_DELETE.value,
        entity_type="project",
        entity_id=project_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()


# ---- Project Members ----

@router.post(
    "/{project_id}/members",
    response_model=ProjectMemberResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add project member",
)
def add_project_member(
    org_id: UUID,
    project_id: UUID,
    data: ProjectMemberCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ProjectMemberResponse:
    """Add a member to a project.

    Requires project membership.
    """
    service = ProjectService(db)
    member = service.add_member(project_id, data)
    # Load user details
    user = db.get(User, data.user_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.PROJECT_MEMBER_ADD.value,
        entity_type="project_member",
        entity_id=member.id,
        details={"user_id": str(data.user_id), "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ProjectMemberResponse(
        id=member.id,
        project_id=member.project_id,
        user_id=member.user_id,
        user_email=user.email if user else "",
        user_full_name=user.full_name if user else "",
        created_at=member.created_at,
    )


@router.get(
    "/{project_id}/members",
    response_model=ProjectMemberListResponse,
    summary="List project members",
)
def list_project_members(
    org_id: UUID,
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = 1,
    page_size: int = 50,
) -> ProjectMemberListResponse:
    """List members of a project.

    Requires project membership.
    """
    service = ProjectService(db)
    offset = (page - 1) * page_size
    members = service.list_members(project_id, limit=page_size, offset=offset)

    # Get total count
    total = (
        db.scalar(
            select(func.count(ProjectMember.id)).where(
                ProjectMember.project_id == project_id
            )
        )
        or 0
    )

    return ProjectMemberListResponse(
        items=[
            ProjectMemberResponse(
                id=m.id,
                project_id=m.project_id,
                user_id=m.user_id,
                user_email=m.user.email if m.user else "",
                user_full_name=m.user.full_name if m.user else "",
                created_at=m.created_at,
            )
            for m in members
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.delete(
    "/{project_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove project member",
)
def remove_project_member(
    org_id: UUID,
    project_id: UUID,
    user_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Remove a member from a project.

    Requires project membership.
    """
    service = ProjectService(db)
    service.remove_member(project_id, user_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.PROJECT_MEMBER_REMOVE.value,
        entity_type="project_member",
        entity_id=user_id,
        details={"project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
