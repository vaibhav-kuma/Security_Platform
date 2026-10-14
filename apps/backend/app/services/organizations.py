"""Organization service layer."""

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError
from app.models.identity import Organization, UserRole
from app.repositories.base import SoftDeleteRepository
from app.schemas.organizations import OrganizationCreate, OrganizationUpdate


class OrganizationService:
    """Business logic for organizations."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SoftDeleteRepository[Organization](session, Organization)

    def create(self, data: OrganizationCreate) -> Organization:
        """Create a new organization."""
        # Check for duplicate name
        existing = self.session.scalar(
            select(Organization).where(Organization.name == data.name)
        )
        if existing:
            raise ConflictError("Organization with this name already exists")

        org = Organization(name=data.name, description=data.description)
        return self.repo.add(org)

    def get(self, org_id: uuid.UUID) -> Organization:
        """Get organization by ID."""
        org = self.repo.get(org_id)
        if not org:
            raise NotFoundError("Organization", str(org_id))
        return org

    def list(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[Organization]:
        """List organizations with pagination."""
        return self.repo.list_all(limit=limit, offset=offset)

    def list_for_user(
        self,
        user_id: uuid.UUID,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[Organization]:
        """List organizations where the user is a member."""
        from sqlalchemy import select
        stmt = (
            select(Organization)
            .join(UserRole, UserRole.organization_id == Organization.id)
            .where(UserRole.user_id == user_id)
            .order_by(Organization.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def count(self) -> int:
        """Count total organizations."""
        from sqlalchemy import func, select
        return self.session.scalar(select(func.count(Organization.id))) or 0

    def count_for_user(self, user_id: uuid.UUID) -> int:
        """Count organizations where the user is a member."""
        from sqlalchemy import func, select
        stmt = (
            select(func.count(Organization.id))
            .join(UserRole, UserRole.organization_id == Organization.id)
            .where(UserRole.user_id == user_id)
        )
        return self.session.scalar(stmt) or 0

    def update(self, org_id: uuid.UUID, data: OrganizationUpdate) -> Organization:
        """Update organization."""
        org = self.get(org_id)

        if data.name is not None and data.name != org.name:
            existing = self.session.scalar(
                select(Organization).where(Organization.name == data.name)
            )
            if existing:
                raise ConflictError("Organization with this name already exists")
            org.name = data.name

        if data.description is not None:
            org.description = data.description

        self.session.flush()
        return org

    def delete(self, org_id: uuid.UUID) -> None:
        """Soft delete organization."""
        org = self.get(org_id)
        self.repo.soft_delete(org)
