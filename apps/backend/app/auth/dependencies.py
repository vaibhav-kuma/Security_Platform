"""FastAPI dependencies for authentication and authorization."""

import uuid
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.token import TokenPayload, validate_access_token, validate_refresh_token
from app.db.session import get_db
from app.models.identity import Organization, RoleScope, User, UserRole
from app.models.projects import Project, ProjectMember
from app.repositories.base import SoftDeleteRepository


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    access_token: Annotated[str | None, Cookie(alias="access_token")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """Extract and validate the current user from access token (cookie or header)."""
    token = _extract_token(access_token, authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = validate_access_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    repo = SoftDeleteRepository(db, User)
    user = repo.get(uuid.UUID(payload.sub))
    if user is None or user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    # Attach token payload for downstream use
    request.state.token_payload = payload
    request.state.current_user = user
    return user


def get_current_user_optional(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    access_token: Annotated[str | None, Cookie(alias="access_token")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User | None:
    """Like get_current_user but returns None instead of raising on missing/invalid token."""
    token = _extract_token(access_token, authorization)
    if not token:
        return None

    try:
        payload = validate_access_token(token)
    except ValueError:
        return None

    repo = SoftDeleteRepository(db, User)
    user = repo.get(uuid.UUID(payload.sub))
    if user is None or user.is_deleted or not user.is_active:
        return None

    request.state.token_payload = payload
    request.state.current_user = user
    return user


def get_refresh_token(
    refresh_token: Annotated[str | None, Cookie(alias="refresh_token")] = None,
) -> TokenPayload:
    """Extract and validate refresh token from cookie."""
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )
    try:
        return validate_refresh_token(refresh_token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


def require_organization_member(
    current_user: Annotated[User, Depends(get_current_user)],
    organization_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Require that the current user is a member of the given organization.

    Phase 3 enforcement: minimal check; full RBAC arrives in later phases.
    """
    org_uuid = uuid.UUID(organization_id)

    # Check for system role (owner/admin at system level)
    system_role = db.scalar(
        select(UserRole).where(
            UserRole.user_id == current_user.id,
            UserRole.role.has(scope=RoleScope.SYSTEM),
        )
    )
    if system_role:
        return current_user

    # Check for organization-level role
    org_role = db.scalar(
        select(UserRole).where(
            UserRole.user_id == current_user.id,
            UserRole.organization_id == org_uuid,
        )
    )
    if org_role:
        # Verify org exists and is not deleted
        org = db.get(Organization, org_uuid)
        if org and not org.is_deleted:
            return current_user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="FORBIDDEN_RESOURCE_ACCESS",
    )


def require_project_member(
    current_user: Annotated[User, Depends(get_current_user)],
    project_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Require that the current user is a member of the given project.

    Requires explicit project membership (or system role).
    Organization-level roles are NOT sufficient.
    """
    proj_uuid = uuid.UUID(project_id)

    # Check for system role
    system_role = db.scalar(
        select(UserRole).where(
            UserRole.user_id == current_user.id,
            UserRole.role.has(scope=RoleScope.SYSTEM),
        )
    )
    if system_role:
        return current_user

    # Check for project membership
    membership = db.scalar(
        select(ProjectMember).where(
            ProjectMember.user_id == current_user.id,
            ProjectMember.project_id == proj_uuid,
        )
    )
    if membership:
        # Verify project exists and is not deleted
        project = db.get(Project, proj_uuid)
        if project and not project.is_deleted:
            return current_user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="FORBIDDEN_RESOURCE_ACCESS",
    )


def _extract_token(cookie_token: str | None, header_token: str | None) -> str | None:
    """Extract token from cookie (preferred) or Authorization header."""
    if cookie_token:
        return cookie_token
    if header_token and header_token.startswith("Bearer "):
        return header_token[7:]
    return None


# Re-export for convenience
__all__ = [
    "get_current_user",
    "get_current_user_optional",
    "get_refresh_token",
    "require_organization_member",
    "require_project_member",
]
