"""Tests for the generic repository base classes.

Uses Permission (no ``deleted_at``) for BaseRepository and Organization
(soft-deletable) for SoftDeleteRepository against a real PostgreSQL database.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.identity import Organization, Permission
from app.repositories import BaseRepository, SoftDeleteRepository


class PermissionRepository(BaseRepository[Permission]):
    model = Permission


class OrganizationRepository(SoftDeleteRepository[Organization]):
    model = Organization


def _code(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4().hex[:8]}"


class TestBaseRepository:
    def test_add_get_and_delete(self, db_session: Session) -> None:
        repo = PermissionRepository(db_session)
        permission = repo.add(Permission(code=_code("test")))

        assert repo.get(permission.id) is permission

        repo.delete(permission)
        assert repo.get(permission.id) is None

    def test_get_missing_returns_none(self, db_session: Session) -> None:
        repo = PermissionRepository(db_session)
        assert repo.get(uuid.uuid4()) is None

    def test_list_all_orders_by_id_and_paginates(self, db_session: Session) -> None:
        repo = PermissionRepository(db_session)
        created_ids = {repo.add(Permission(code=_code("page"))).id for _ in range(3)}

        page = repo.list_all(limit=2, offset=0)
        assert len(page) == 2
        first_ids = [row.id for row in page]
        assert first_ids == sorted(first_ids)

        remainder = repo.list_all(limit=2, offset=2)
        assert len(remainder) == 1
        remainder_ids = [row.id for row in remainder]
        assert remainder_ids == sorted(remainder_ids)

        # UUIDv4 keys are random, so only set coverage and disjointness are
        # meaningful — insertion order does not match id order.
        assert set(first_ids) | set(remainder_ids) == created_ids
        assert not set(first_ids) & set(remainder_ids)

    def test_list_all_rejects_invalid_page_values(self, db_session: Session) -> None:
        repo = PermissionRepository(db_session)
        import pytest

        with pytest.raises(ValueError, match="limit"):
            repo.list_all(limit=0)
        with pytest.raises(ValueError, match="offset"):
            repo.list_all(offset=-1)


class TestSoftDeleteRepository:
    def test_soft_delete_hides_from_get_and_list(self, db_session: Session) -> None:
        repo = OrganizationRepository(db_session)
        org = repo.add(Organization(name=f"org-{uuid.uuid4().hex[:8]}"))

        repo.soft_delete(org)

        assert repo.get(org.id) is None
        assert org not in repo.list_all()
        # Still visible when explicitly requested.
        assert repo.get(org.id, include_deleted=True) is org
        assert org in repo.list_all(include_deleted=True)

    def test_soft_delete_is_idempotent(self, db_session: Session) -> None:
        repo = OrganizationRepository(db_session)
        org = repo.add(Organization(name=f"org-{uuid.uuid4().hex[:8]}"))

        repo.soft_delete(org)
        first_stamp = org.deleted_at
        repo.soft_delete(org)

        assert org.deleted_at == first_stamp

    def test_hard_delete_still_available(self, db_session: Session) -> None:
        repo = OrganizationRepository(db_session)
        org = repo.add(Organization(name=f"org-{uuid.uuid4().hex[:8]}"))

        repo.delete(org)

        assert repo.get(org.id, include_deleted=True) is None

    def test_soft_delete_uses_timezone_aware_timestamp(self, db_session: Session) -> None:
        repo = OrganizationRepository(db_session)
        org = repo.add(Organization(name=f"org-{uuid.uuid4().hex[:8]}"))

        repo.soft_delete(org)

        assert org.deleted_at is not None
        assert org.deleted_at.utcoffset() is not None
