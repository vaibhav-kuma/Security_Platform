"""Project service layer."""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.identity import Organization, User
from app.models.projects import Project, ProjectMember, ProjectStatus
from app.repositories.base import SoftDeleteRepository
from app.schemas.projects import ProjectCreate, ProjectMemberCreate, ProjectUpdate


class ProjectService:
    """Business logic for projects."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SoftDeleteRepository[Project](session, Project)

    def create(self, organization_id: uuid.UUID, data: ProjectCreate) -> Project:
        """Create a new project within an organization."""
        # Verify organization exists
        org = self.session.get(Organization, organization_id)
        if not org:
            raise NotFoundError("Organization", str(organization_id))

        # Check for duplicate name within organization
        existing = self.session.scalar(
            select(Project).where(
                Project.organization_id == organization_id,
                Project.name == data.name,
            )
        )
        if existing:
            raise ConflictError("Project with this name already exists in this organization")

        project = Project(
            organization_id=organization_id,
            name=data.name,
            description=data.description,
            status=ProjectStatus.DRAFT,
        )
        return self.repo.add(project)

    def get(self, project_id: uuid.UUID) -> Project:
        """Get project by ID."""
        project = self.repo.get(project_id)
        if not project:
            raise NotFoundError("Project", str(project_id))
        return project

    def get_detail(self, project_id: uuid.UUID) -> Project:
        """Get project with counts."""
        project = self.session.query(Project).options(
            joinedload(Project.members),
            joinedload(Project.scopes),
        ).filter(Project.id == project_id).first()
        if not project:
            raise NotFoundError("Project", str(project_id))
        return project

    def list(
        self,
        organization_id: uuid.UUID,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
    ) -> Sequence[Project]:
        """List projects in an organization with pagination."""
        from app.models.projects import ProjectStatus as PS

        stmt = select(Project).where(Project.organization_id == organization_id)
        if status:
            try:
                stmt = stmt.where(Project.status == PS(status))
            except ValueError as e:
                raise ConflictError(f"Invalid project status: {status}") from e
        stmt = stmt.order_by(Project.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count(self, organization_id: uuid.UUID, status: str | None = None) -> int:
        """Count projects in an organization."""
        from app.models.projects import ProjectStatus as PS

        stmt = select(func.count(Project.id)).where(Project.organization_id == organization_id)
        if status:
            try:
                stmt = stmt.where(Project.status == PS(status))
            except ValueError as e:
                raise ConflictError(f"Invalid project status: {status}") from e
        return self.session.scalar(stmt) or 0

    def update(self, project_id: uuid.UUID, data: ProjectUpdate) -> Project:
        """Update project."""
        project = self.get(project_id)

        if data.name is not None and data.name != project.name:
            existing = self.session.scalar(
                select(Project).where(
                    Project.organization_id == project.organization_id,
                    Project.name == data.name,
                )
            )
            if existing:
                raise ConflictError("Project with this name already exists in this organization")
            project.name = data.name

        if data.description is not None:
            project.description = data.description

        if data.status is not None:
            from app.models.projects import ProjectStatus as PS
            try:
                project.status = PS(data.status)
            except ValueError as e:
                raise ConflictError("Invalid project status") from e

        self.session.flush()
        return project

    def delete(self, project_id: uuid.UUID) -> None:
        """Soft delete project."""
        project = self.get(project_id)
        self.repo.soft_delete(project)

    def verify_project_in_org(self, project_id: uuid.UUID, organization_id: uuid.UUID) -> Project:
        """Verify that a project belongs to the given organization."""
        project = self.get(project_id)
        if project.organization_id != organization_id:
            raise NotFoundError("Project", str(project_id))
        return project

    # ---- Members ----

    def add_member(self, project_id: uuid.UUID, data: ProjectMemberCreate) -> ProjectMember:
        """Add a member to a project."""
        self.get(project_id)

        # Verify user exists
        user = self.session.get(User, data.user_id)
        if not user:
            raise NotFoundError("User", str(data.user_id))

        # Check if already a member
        existing = self.session.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == data.user_id,
            )
        )
        if existing:
            raise ConflictError("User is already a member of this project")

        member = ProjectMember(project_id=project_id, user_id=data.user_id)
        self.session.add(member)
        self.session.flush()
        return member

    def remove_member(self, project_id: uuid.UUID, user_id: uuid.UUID) -> None:
        """Remove a member from a project."""
        member = self.session.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id,
            )
        )
        if not member:
            raise NotFoundError("Project member", f"user={user_id}, project={project_id}")

        self.session.delete(member)
        self.session.flush()

    def list_members(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[ProjectMember]:
        """List project members."""
        self.get(project_id)  # Verify project exists

        stmt = (
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id)
            .options(joinedload(ProjectMember.user))
            .order_by(ProjectMember.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()
