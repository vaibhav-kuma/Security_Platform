"""Tests for the idempotent system RBAC seed."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.seed import PERMISSIONS, ROLE_GRANTS, seed_system_rbac
from app.models.enums import RoleScope
from app.models.identity import Permission, Role


def _system_roles(db_session: Session) -> list[Role]:
    return list(
        db_session.scalars(
            select(Role).where(Role.scope == RoleScope.SYSTEM, Role.is_system.is_(True))
        ).all()
    )


def _role_by_name(db_session: Session, name: str) -> Role:
    role = db_session.scalar(select(Role).where(Role.name == name, Role.scope == RoleScope.SYSTEM))
    assert role is not None
    return role


def test_seed_creates_all_permissions_and_roles(db_session: Session) -> None:
    seed_system_rbac(db_session)

    codes = set(db_session.scalars(select(Permission.code)).all())
    assert codes == set(PERMISSIONS)
    assert {r.name for r in _system_roles(db_session)} == set(ROLE_GRANTS)


def test_seed_does_not_commit_callers_transaction(db_session: Session) -> None:
    # A seed helper must be composable with a larger unit of work.
    assert db_session.in_transaction() is False
    seed_system_rbac(db_session)
    assert db_session.in_transaction() is True


def test_seed_is_idempotent(db_session: Session) -> None:
    seed_system_rbac(db_session)
    seed_system_rbac(db_session)

    assert db_session.scalar(select(func.count()).select_from(Permission)) == len(PERMISSIONS)
    assert len(_system_roles(db_session)) == len(ROLE_GRANTS)


def test_owner_role_has_every_permission(db_session: Session) -> None:
    seed_system_rbac(db_session)

    owner = _role_by_name(db_session, "owner")
    assert {p.code for p in owner.permissions} == set(PERMISSIONS)


def test_viewer_role_gets_only_read_permissions(db_session: Session) -> None:
    seed_system_rbac(db_session)

    viewer = _role_by_name(db_session, "viewer")
    assert {p.code for p in viewer.permissions} == set(ROLE_GRANTS["viewer"])


def test_seed_reconciles_stale_grants(db_session: Session) -> None:
    seed_system_rbac(db_session)

    viewer = _role_by_name(db_session, "viewer")
    stale = Permission(code="stale:grant")
    db_session.add(stale)
    db_session.flush()
    viewer.permissions.append(stale)
    db_session.commit()

    seed_system_rbac(db_session)

    db_session.refresh(viewer)
    assert {p.code for p in viewer.permissions} == set(ROLE_GRANTS["viewer"])
