"""Scope service layer."""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.projects import (
    Project,
    Scope,
    ScopeRule,
    ScopeRuleEffect,
    ScopeRuleTargetType,
    ScopeSnapshot,
)
from app.repositories.base import SoftDeleteRepository
from app.schemas.scopes import ScopeCreate, ScopeRuleCreate, ScopeRuleUpdate, ScopeUpdate


class ScopeService:
    """Business logic for scopes and scope rules."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = SoftDeleteRepository[Scope](session, Scope)

    def create(self, project_id: uuid.UUID, data: ScopeCreate) -> Scope:
        """Create a new scope within a project."""
        project = self.session.get(Project, project_id)
        if not project:
            raise NotFoundError("Project", str(project_id))

        # Check for duplicate name within project
        existing = self.session.scalar(
            select(Scope).where(
                Scope.project_id == project_id,
                Scope.name == data.name,
            )
        )
        if existing:
            raise ConflictError("Scope with this name already exists in this project")

        scope = Scope(
            project_id=project_id,
            name=data.name,
            description=data.description,
            is_active=True,
            version=1,
        )
        scope = self.repo.add(scope)

        # Create initial snapshot
        self._create_snapshot(scope)

        return scope

    def get(self, scope_id: uuid.UUID) -> Scope:
        """Get scope by ID."""
        scope = self.repo.get(scope_id)
        if not scope:
            raise NotFoundError("Scope", str(scope_id))
        return scope

    def get_detail(self, scope_id: uuid.UUID) -> Scope:
        """Get scope with rules."""
        scope = self.session.query(Scope).options(
            joinedload(Scope.rules)
        ).filter(Scope.id == scope_id).first()
        if not scope:
            raise NotFoundError("Scope", str(scope_id))
        return scope

    def list(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 20,
        offset: int = 0,
        is_active: bool | None = None,
    ) -> Sequence[Scope]:
        """List scopes in a project."""
        stmt = select(Scope).where(Scope.project_id == project_id)
        if is_active is not None:
            stmt = stmt.where(Scope.is_active == is_active)
        stmt = stmt.order_by(Scope.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count(self, project_id: uuid.UUID, is_active: bool | None = None) -> int:
        """Count scopes in a project."""
        stmt = select(func.count(Scope.id)).where(Scope.project_id == project_id)
        if is_active is not None:
            stmt = stmt.where(Scope.is_active == is_active)
        return self.session.scalar(stmt) or 0

    def update(self, scope_id: uuid.UUID, data: ScopeUpdate) -> Scope:
        """Update scope."""
        scope = self.get(scope_id)

        if data.name is not None and data.name != scope.name:
            existing = self.session.scalar(
                select(Scope).where(
                    Scope.project_id == scope.project_id,
                    Scope.name == data.name,
                )
            )
            if existing:
                raise ConflictError("Scope with this name already exists in this project")
            scope.name = data.name

        if data.description is not None:
            scope.description = data.description

        if data.is_active is not None:
            scope.is_active = data.is_active

        self.session.flush()
        return scope

    def delete(self, scope_id: uuid.UUID) -> None:
        """Soft delete scope."""
        scope = self.get(scope_id)
        self.repo.soft_delete(scope)

    def verify_scope_in_project(self, scope_id: uuid.UUID, project_id: uuid.UUID) -> Scope:
        """Verify that a scope belongs to the given project."""
        scope = self.get(scope_id)
        if scope.project_id != project_id:
            raise NotFoundError("Scope", str(scope_id))
        return scope

    def increment_version(self, scope_id: uuid.UUID) -> Scope:
        """Increment scope version and create snapshot."""
        scope = self.get(scope_id)
        scope.version += 1
        self.session.flush()
        self._create_snapshot(scope)
        return scope

    def _create_snapshot(self, scope: Scope) -> ScopeSnapshot:
        """Create an immutable snapshot of current scope rules."""
        rules = self.session.scalars(
            select(ScopeRule).where(ScopeRule.scope_id == scope.id)
        ).all()

        payload = {
            "scope_id": str(scope.id),
            "name": scope.name,
            "description": scope.description,
            "is_active": scope.is_active,
            "version": scope.version,
            "rules": [
                {
                    "effect": rule.effect.value,
                    "target_type": rule.target_type.value,
                    "pattern": rule.pattern,
                    "note": rule.note,
                }
                for rule in rules
            ],
        }

        snapshot = ScopeSnapshot(
            scope_id=scope.id,
            version=scope.version,
            payload=payload,
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

    # ---- Rules ----

    def add_rule(self, scope_id: uuid.UUID, data: ScopeRuleCreate) -> ScopeRule:
        """Add a rule to a scope."""
        self.get(scope_id)

        # Determine the next order value
        max_order = self.session.scalar(
            select(func.max(ScopeRule.order)).where(ScopeRule.scope_id == scope_id)
        ) or -1

        rule = ScopeRule(
            scope_id=scope_id,
            order=max_order + 1,
            effect=ScopeRuleEffect(data.effect),
            target_type=ScopeRuleTargetType(data.target_type),
            pattern=data.pattern,
            note=data.note,
        )
        self.session.add(rule)
        self.session.flush()
        return rule

    def update_rule(self, rule_id: uuid.UUID, data: ScopeRuleUpdate) -> ScopeRule:
        """Update a scope rule."""
        rule = self.session.get(ScopeRule, rule_id)
        if not rule:
            raise NotFoundError("Scope rule", str(rule_id))

        if data.effect is not None:
            rule.effect = ScopeRuleEffect(data.effect)
        if data.target_type is not None:
            rule.target_type = ScopeRuleTargetType(data.target_type)
        if data.pattern is not None:
            rule.pattern = data.pattern
        if data.note is not None:
            rule.note = data.note
        if data.order is not None:
            rule.order = data.order

        self.session.flush()
        return rule

    def delete_rule(self, rule_id: uuid.UUID) -> None:
        """Delete a scope rule."""
        rule = self.session.get(ScopeRule, rule_id)
        if not rule:
            raise NotFoundError("Scope rule", str(rule_id))

        self.session.delete(rule)
        self.session.flush()

    def list_rules(
        self,
        scope_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[ScopeRule]:
        """List scope rules."""
        self.get(scope_id)  # Verify scope exists

        stmt = (
            select(ScopeRule)
            .where(ScopeRule.scope_id == scope_id)
            .order_by(ScopeRule.created_at)
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    # ---- Snapshots ---

    def list_snapshots(
        self,
        scope_id: uuid.UUID,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[ScopeSnapshot]:
        """List scope snapshots."""
        self.get(scope_id)  # Verify scope exists

        stmt = (
            select(ScopeSnapshot)
            .where(ScopeSnapshot.scope_id == scope_id)
            .order_by(ScopeSnapshot.version.desc())
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(stmt).all()

    def get_snapshot(self, scope_id: uuid.UUID, version: int) -> ScopeSnapshot:
        """Get a specific scope snapshot."""
        snapshot = self.session.scalar(
            select(ScopeSnapshot).where(
                ScopeSnapshot.scope_id == scope_id,
                ScopeSnapshot.version == version,
            )
        )
        if not snapshot:
            raise NotFoundError("Scope snapshot", f"scope={scope_id}, version={version}")
        return snapshot
