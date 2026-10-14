"""Target service layer."""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.assets import Asset
from app.models.projects import Project, Scope, ScopeStatus, Target
from app.repositories.base import SoftDeleteRepository
from app.schemas.targets import TargetCreate, TargetUpdate


class TargetService:
    """Business logic for targets."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SoftDeleteRepository[Target](session, Target)

    def create(self, project_id: uuid.UUID, data: TargetCreate) -> Target:
        """Create a new target within a project."""
        project = self.session.get(Project, project_id)
        if not project:
            raise NotFoundError("Project", str(project_id))

        # Verify scope if provided
        if data.scope_id:
            scope = self.session.get(Scope, data.scope_id)
            if not scope or scope.project_id != project_id:
                raise NotFoundError("Scope", str(data.scope_id))

        target = Target(
            project_id=project_id,
            scope_id=data.scope_id,
            name=data.name,
            description=data.description,
            scope_status=ScopeStatus.UNKNOWN,
            target_type=data.target_type.value,
        )
        return self.repo.add(target)

    def get(self, target_id: uuid.UUID) -> Target:
        """Get target by ID."""
        target = self.repo.get(target_id)
        if not target:
            raise NotFoundError("Target", str(target_id))
        return target

    def get_detail(self, target_id: uuid.UUID) -> Target:
        """Get target with asset count."""
        target = self.session.query(Target).options(
            joinedload(Target.assets)
        ).filter(Target.id == target_id).first()
        if not target:
            raise NotFoundError("Target", str(target_id))
        return target

    def list(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 20,
        offset: int = 0,
        scope_id: uuid.UUID | None = None,
        scope_status: str | None = None,
    ) -> Sequence[Target]:
        """List targets in a project."""
        stmt = select(Target).where(Target.project_id == project_id)

        if scope_id:
            stmt = stmt.where(Target.scope_id == scope_id)

        if scope_status:
            try:
                stmt = stmt.where(Target.scope_status == ScopeStatus(scope_status))
            except ValueError:
                pass

        stmt = stmt.order_by(Target.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count(
        self,
        project_id: uuid.UUID,
        scope_id: uuid.UUID | None = None,
        scope_status: str | None = None,
    ) -> int:
        """Count targets in a project."""
        stmt = select(func.count(Target.id)).where(Target.project_id == project_id)

        if scope_id:
            stmt = stmt.where(Target.scope_id == scope_id)

        if scope_status:
            try:
                stmt = stmt.where(Target.scope_status == ScopeStatus(scope_status))
            except ValueError:
                pass

        return self.session.scalar(stmt) or 0

    def update(self, target_id: uuid.UUID, data: TargetUpdate) -> Target:
        """Update target."""
        target = self.get(target_id)

        if data.name is not None and data.name != target.name:
            target.name = data.name

        if data.description is not None:
            target.description = data.description

        if data.scope_id is not None:
            if data.scope_id:
                scope = self.session.get(Scope, data.scope_id)
                if not scope or scope.project_id != target.project_id:
                    raise NotFoundError("Scope", str(data.scope_id))
            target.scope_id = data.scope_id

        if data.scope_status is not None:
            try:
                target.scope_status = ScopeStatus(data.scope_status)
            except ValueError as e:
                raise ConflictError(f"Invalid scope status: {data.scope_status}") from e

        self.session.flush()
        return target

    def delete(self, target_id: uuid.UUID) -> None:
        """Soft delete target."""
        target = self.get(target_id)
        self.repo.soft_delete(target)

    def verify_target_in_project(self, target_id: uuid.UUID, project_id: uuid.UUID) -> Target:
        """Verify that a target belongs to the given project."""
        target = self.get(target_id)
        if target.project_id != project_id:
            raise NotFoundError("Target", str(target_id))
        return target


class AssetService:
    """Business logic for basic assets."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SoftDeleteRepository[Asset](session, Asset)

    def list(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
        target_id: uuid.UUID | None = None,
        kind: str | None = None,
    ) -> Sequence[Asset]:
        """List assets in a project."""
        stmt = select(Asset).where(Asset.project_id == project_id)

        if target_id:
            stmt = stmt.where(Asset.target_id == target_id)

        if kind:
            from app.models.enums import AssetKind
            try:
                stmt = stmt.where(Asset.kind == AssetKind(kind))
            except ValueError:
                pass

        stmt = stmt.order_by(Asset.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count(
        self,
        project_id: uuid.UUID,
        target_id: uuid.UUID | None = None,
        kind: str | None = None,
    ) -> int:
        """Count assets in a project."""
        stmt = select(func.count(Asset.id)).where(Asset.project_id == project_id)

        if target_id:
            stmt = stmt.where(Asset.target_id == target_id)

        if kind:
            from app.models.enums import AssetKind
            try:
                stmt = stmt.where(Asset.kind == AssetKind(kind))
            except ValueError:
                pass

        return self.session.scalar(stmt) or 0

    def get(self, asset_id: uuid.UUID) -> Asset:
        """Get asset by ID."""
        asset = self.repo.get(asset_id)
        if not asset:
            raise NotFoundError("Asset", str(asset_id))
        return asset
