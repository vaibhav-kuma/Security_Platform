"""Identity and RBAC models: organizations, users, permissions, roles.

Phase 3 builds authentication on top of these tables; the schema lands in
Phase 2 so migrations are complete. ``password_hash`` stores a hash only —
plaintext credentials must never be persisted.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import RoleScope, native_enum

# Pure many-to-many association between roles and permissions.
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        Uuid(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Top-level tenant. Projects and user assignments hang off it."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class User(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Platform user account. Authentication mechanics arrive in Phase 3."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Permission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Atomic grantable capability, e.g. ``project:create``."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class Role(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Named bundle of permissions scoped to system, org, or project level."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("name", "scope", name="name_scope"),)

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    scope: Mapped[RoleScope] = mapped_column(native_enum(RoleScope), nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str | None] = mapped_column(Text)

    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions)


class UserRole(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Assignment of a role to a user, optionally bound to an org or project.

    Exactly one of ``organization_id`` / ``project_id`` should be set for
    non-system roles; enforcement of that rule is application-level (Phase 3).
    """

    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "organization_id", "project_id", name="assignment"),
        CheckConstraint(
            "(organization_id IS NULL AND project_id IS NULL) OR "
            "(organization_id IS NOT NULL AND project_id IS NULL) OR "
            "(organization_id IS NOT NULL AND project_id IS NOT NULL)",
            name="valid_assignment_scope",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE")
    )

    user: Mapped[User] = relationship()
    role: Mapped[Role] = relationship()
