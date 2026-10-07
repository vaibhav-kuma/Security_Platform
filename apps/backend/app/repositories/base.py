"""Generic repository abstractions over the Phase 2 domain model.

Repositories are thin, session-scoped data-access helpers. They carry no
business logic, no authorization, and no transaction management beyond what
the caller's session provides; services own those concerns (Phase 3+).

Two base classes are provided:

- :class:`BaseRepository` — models without ``deleted_at`` (observations,
  audit rows, ...): every stored row is visible.
- :class:`SoftDeleteRepository` — models with ``deleted_at``: reads exclude
  soft-deleted rows unless ``include_deleted=True`` is passed explicitly.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.base import Base, SoftDeleteMixin


class BaseRepository[ModelT: Base]:
    """Minimal CRUD helpers for a single model type.

    Subclasses set :attr:`model` to the mapped class they manage. Methods
    flush but never commit — the caller owns the session and transaction.
    """

    model: type[ModelT]

    def __init__(self, session: Session, model: type[ModelT] | None = None) -> None:
        self.session = session
        if model is not None:
            self.model = model

    def add(self, instance: ModelT) -> ModelT:
        """Persist ``instance`` and return it after a flush."""
        self.session.add(instance)
        self.session.flush()
        return instance

    def get(self, entity_id: uuid.UUID) -> ModelT | None:
        """Return the row with ``entity_id`` or ``None``."""
        return self.session.get(self.model, entity_id)

    def list_all(self, *, limit: int = 100, offset: int = 0) -> Sequence[ModelT]:
        """Return a stable-ordered page of rows."""
        _validate_page(limit, offset)
        statement = (
            select(self.model)
            .order_by(self.model.id)  # type: ignore[attr-defined]
            .limit(limit)
            .offset(offset)
        )
        return self.session.scalars(statement).all()

    def delete(self, instance: ModelT) -> None:
        """Hard-delete ``instance``. Prefer soft delete where available."""
        self.session.delete(instance)
        self.session.flush()


class SoftDeleteRepository[SoftModelT: Base](BaseRepository[SoftModelT]):
    """Read helpers that hide soft-deleted rows by default.

    ``soft_delete`` stamps ``deleted_at`` without removing the row; hard
    deletion remains available through :meth:`delete` for the rare cases
    that genuinely need it (e.g. GDPR-style erasure).
    """

    def get(self, entity_id: uuid.UUID, *, include_deleted: bool = False) -> SoftModelT | None:
        instance = self.session.get(self.model, entity_id)
        if instance is None:
            return None
        if not include_deleted and self._is_deleted(instance):
            return None
        return instance

    def list_all(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[SoftModelT]:
        _validate_page(limit, offset)
        statement = select(self.model).order_by(
            self.model.id  # type: ignore[attr-defined]
        )
        if not include_deleted:
            statement = statement.where(self.model.deleted_at.is_(None))  # type: ignore[attr-defined]
        return self.session.scalars(statement.limit(limit).offset(offset)).all()

    def soft_delete(self, instance: SoftModelT) -> None:
        """Stamp ``deleted_at`` on ``instance`` if not already deleted."""
        if isinstance(instance, SoftDeleteMixin) and instance.deleted_at is None:
            from datetime import UTC, datetime

            instance.deleted_at = datetime.now(UTC)
            self.session.flush()

    @staticmethod
    def _is_deleted(instance: SoftModelT) -> bool:
        return isinstance(instance, SoftDeleteMixin) and instance.deleted_at is not None


def _validate_page(limit: int, offset: int) -> None:
    if limit < 1:
        raise ValueError("limit must be greater than zero")
    if offset < 0:
        raise ValueError("offset must not be negative")
