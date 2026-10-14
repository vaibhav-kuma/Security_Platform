"""Project, membership, and scope models.

Scope snapshots are stored as versioned JSON payloads so the exact
authorization boundary at any point in time can be reproduced.
"""

import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    ProjectStatus,
    ScopeRuleEffect,
    ScopeRuleTargetType,
    ScopeStatus,
    native_enum,
)


class Project(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A security assessment engagement within one organization."""

    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="org_name"),
        UniqueConstraint("id", "organization_id", name="id_organization"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ProjectStatus] = mapped_column(
        native_enum(ProjectStatus), nullable=False, default=ProjectStatus.DRAFT
    )

    scopes: Mapped[list["Scope"]] = relationship(back_populates="project")
    members: Mapped[list["ProjectMember"]] = relationship(back_populates="project")
    reports: Mapped[list["Report"]] = relationship(back_populates="project")


class ProjectMember(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Membership of a user in a project (role assignment is Phase 3)."""

    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="membership"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    project: Mapped[Project] = relationship(back_populates="members")


class Scope(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Authorization boundary for a project: what may and may not be tested."""

    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="project_name"),
        UniqueConstraint("id", "project_id", name="id_project"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    project: Mapped[Project] = relationship(back_populates="scopes")
    rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="scope",
        order_by="ScopeRule.order"
    )
    snapshots: Mapped[list["ScopeSnapshot"]] = relationship(back_populates="scope")


class ScopeRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Include/exclude pattern evaluated by the ScopeEngine (Phase 4+)."""

    __tablename__ = "scope_rules"
    __table_args__ = (
        UniqueConstraint("scope_id", "order", name="scope_rule_order"),
    )

    scope_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    effect: Mapped[ScopeRuleEffect] = mapped_column(native_enum(ScopeRuleEffect), nullable=False)
    target_type: Mapped[ScopeRuleTargetType] = mapped_column(
        native_enum(ScopeRuleTargetType), nullable=False
    )
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)

    scope: Mapped[Scope] = relationship(back_populates="rules")


class ScopeSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable versioned copy of a scope's rules at a point in time."""

    __tablename__ = "scope_snapshots"
    __table_args__ = (
        UniqueConstraint("scope_id", "version", name="scope_version"),
        CheckConstraint("version > 0", name="positive_version"),
    )

    scope_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    scope: Mapped[Scope] = relationship(back_populates="snapshots")


def _immutable(mapper: object, connection: object, target: object) -> None:
    raise ValueError("ScopeSnapshot rows are immutable")


event.listen(ScopeSnapshot, "before_update", _immutable)
event.listen(ScopeSnapshot, "before_delete", _immutable)


class Target(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Declared assessment target inside a project scope."""

    __tablename__ = "targets"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scopes.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    scope_status: Mapped[ScopeStatus] = mapped_column(
        native_enum(ScopeStatus), nullable=False, default=ScopeStatus.UNKNOWN
    )
    target_type: Mapped[ScopeRuleTargetType] = mapped_column(
        native_enum(ScopeRuleTargetType), nullable=False
    )
