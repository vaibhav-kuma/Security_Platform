"""Database tests for the Phase 2 domain model.

Runs against a real PostgreSQL migrated by the Alembic chain (see
conftest.py). Covers CRUD and relationships, unique constraints, foreign-key
cascade/SET NULL behavior, native enum storage, and the timestamp and
soft-delete mixins.
"""

import uuid

import pytest
from sqlalchemy import delete, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.models import Base
from app.models.audit import AuditLog
from app.models.enums import RoleScope, Severity
from app.models.identity import Organization, Permission, Role, User, UserRole
from app.models.projects import Project


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def organization(db_session: Session) -> Organization:
    org = Organization(name=_unique("org"))
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture()
def user(db_session: Session) -> User:
    account = User(email=f"{_unique('user')}@example.com", full_name="Test User")
    db_session.add(account)
    db_session.flush()
    return account


class TestCrudAndRelationships:
    def test_organization_round_trip(self, db_session: Session, organization: Organization) -> None:
        loaded = db_session.get(Organization, organization.id)
        assert loaded is not None
        assert loaded.name == organization.name
        # TimestampMixin server defaults populated on insert.
        assert loaded.created_at is not None
        assert loaded.updated_at is not None
        assert loaded.is_deleted is False

    def test_soft_delete_sets_flag(self, db_session: Session, organization: Organization) -> None:
        from datetime import UTC, datetime

        organization.deleted_at = datetime.now(UTC)
        db_session.flush()

        assert organization.is_deleted is True

    def test_user_role_relationships(
        self, db_session: Session, user: User, organization: Organization
    ) -> None:
        permission = Permission(code=_unique("perm"))
        role = Role(name=_unique("role"), scope=RoleScope.ORGANIZATION)
        role.permissions.append(permission)
        db_session.add_all([permission, role])
        db_session.flush()

        assignment = UserRole(user_id=user.id, role_id=role.id, organization_id=organization.id)
        db_session.add(assignment)
        db_session.flush()

        loaded = db_session.get(UserRole, assignment.id)
        assert loaded is not None
        assert loaded.user.id == user.id
        assert loaded.role.id == role.id
        assert {p.code for p in loaded.role.permissions} == {permission.code}


class TestUniqueConstraints:
    def test_duplicate_organization_name_rejected(
        self, db_session: Session, organization: Organization
    ) -> None:
        db_session.add(Organization(name=organization.name))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_duplicate_user_email_rejected(self, db_session: Session, user: User) -> None:
        db_session.add(User(email=user.email, full_name="Duplicate"))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_duplicate_permission_code_rejected(self, db_session: Session) -> None:
        code = _unique("perm")
        db_session.add(Permission(code=code))
        db_session.flush()
        db_session.add(Permission(code=code))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_role_name_unique_per_scope_but_reusable_across_scopes(
        self, db_session: Session
    ) -> None:
        name = _unique("role")
        db_session.add(Role(name=name, scope=RoleScope.SYSTEM))
        db_session.flush()

        # Same name, same scope -> rejected.
        db_session.add(Role(name=name, scope=RoleScope.SYSTEM))
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()

        # Same name, different scope -> allowed (name_scope constraint).
        db_session.add(Role(name=name, scope=RoleScope.ORGANIZATION))
        db_session.flush()

    def test_duplicate_user_role_assignment_rejected(
        self, db_session: Session, user: User, organization: Organization
    ) -> None:
        role = Role(name=_unique("role"), scope=RoleScope.PROJECT)
        project = Project(organization_id=organization.id, name=_unique("project"))
        db_session.add_all([role, project])
        db_session.flush()

        first = UserRole(
            user_id=user.id,
            role_id=role.id,
            organization_id=organization.id,
            project_id=project.id,
        )
        db_session.add(first)
        db_session.flush()

        # Every column of the ``assignment`` unique constraint must be
        # non-null: PostgreSQL treats NULLs as distinct in unique
        # constraints, so a NULL project_id would not trigger the violation.
        db_session.add(
            UserRole(
                user_id=user.id,
                role_id=role.id,
                organization_id=organization.id,
                project_id=project.id,
            )
        )
        with pytest.raises(IntegrityError):
            db_session.flush()


class TestForeignKeyBehavior:
    def test_user_role_scope_must_match_role(
        self, db_session: Session, user: User, organization: Organization
    ) -> None:
        role = Role(name=_unique("project-role"), scope=RoleScope.PROJECT)
        db_session.add(role)
        db_session.flush()
        db_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=organization.id))
        with pytest.raises((IntegrityError, ProgrammingError)):
            db_session.flush()

    def test_audit_log_is_immutable(self, db_session: Session) -> None:
        entry = AuditLog(action="test.action")
        db_session.add(entry)
        db_session.flush()
        entry.action = "changed"
        with pytest.raises((ValueError, IntegrityError)):
            db_session.flush()

    def test_user_delete_cascades_to_user_roles(self, db_session: Session, user: User) -> None:
        role = Role(name=_unique("role"), scope=RoleScope.SYSTEM)
        db_session.add(role)
        db_session.flush()
        assignment = UserRole(user_id=user.id, role_id=role.id)
        db_session.add(assignment)
        db_session.flush()
        assignment_id = assignment.id

        db_session.delete(user)
        db_session.flush()

        # ON DELETE CASCADE fires at the database level; query with raw SQL
        # to bypass the ORM identity map, which still holds the stale
        # instance and would raise ObjectDeletedError on refresh.
        surviving = db_session.execute(
            text("SELECT id FROM user_roles WHERE id = :id"), {"id": assignment_id}
        ).first()
        assert surviving is None

    def test_audit_log_actor_set_null_on_user_delete(self, db_session: Session, user: User) -> None:
        entry = AuditLog(actor_id=user.id, action="test.action")
        db_session.add(entry)
        db_session.flush()
        entry_id = entry.id

        # Bypass the ORM so ON DELETE SET NULL fires at the database level.
        db_session.execute(delete(User).where(User.id == user.id))
        db_session.flush()
        db_session.expire_all()

        surviving = db_session.get(AuditLog, entry_id)
        assert surviving is not None
        assert surviving.actor_id is None


class TestEnumStorage:
    def test_role_scope_stored_as_lowercase_native_enum(self, db_session: Session) -> None:
        role = Role(name=_unique("role"), scope=RoleScope.SYSTEM)
        db_session.add(role)
        db_session.flush()

        stored = db_session.execute(
            text("SELECT scope FROM roles WHERE id = :id"), {"id": role.id}
        ).scalar_one()
        assert stored == "system"

    def test_severity_enum_values_match_database(self, db_engine: Engine) -> None:
        with db_engine.connect() as conn:
            stored = (
                conn.execute(text("SELECT unnest(enum_range(NULL::severity))::text"))
                .scalars()
                .all()
            )
        assert stored == [member.value for member in Severity]


class TestMigrationModelParity:
    def test_every_model_table_exists_after_migration(self, db_engine: Engine) -> None:
        inspector = inspect(db_engine)
        db_tables = set(inspector.get_table_names())
        missing = set(Base.metadata.tables) - db_tables
        assert not missing, f"Model tables missing from migrated database: {missing}"
