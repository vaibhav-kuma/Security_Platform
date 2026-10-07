"""Pagination, filtering, and sorting utilities for API endpoints."""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Select, func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

T = TypeVar("T")


class PageParams(BaseModel):
    """Query parameters for pagination."""

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")

    @field_validator("page_size")
    @classmethod
    def validate_page_size(cls, v: int) -> int:
        if v > 100:
            raise ValueError("page_size cannot exceed 100")
        return v


class SortParams(BaseModel):
    """Query parameters for sorting."""

    sort_by: str | None = Field(default=None, description="Field to sort by")
    sort_order: str = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")


class FilterParams(BaseModel):
    """Base class for filter parameters. Subclass to define entity-specific filters."""

    pass


class Page(BaseModel, Generic[T]):
    """Paginated response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1


def paginate(
    session: Session,
    statement: Select[tuple[T]],
    page_params: PageParams,
) -> Page[T]:
    """Execute a paginated query and return a Page envelope.

    Args:
        session: Database session
        statement: Base SELECT statement (without LIMIT/OFFSET)
        page_params: Pagination parameters

    Returns:
        Page with items and metadata
    """
    # Count total
    count_stmt = select(func.count()).select_from(statement.subquery())
    total = session.scalar(count_stmt) or 0

    # Apply pagination
    offset = (page_params.page - 1) * page_params.page_size
    items = session.scalars(
        statement.limit(page_params.page_size).offset(offset)
    ).all()

    total_pages = (total + page_params.page_size - 1) // page_params.page_size

    return Page(
        items=list(items),
        total=total,
        page=page_params.page,
        page_size=page_params.page_size,
        total_pages=total_pages,
    )


def apply_sorting(
    statement: Select[tuple[T]],
    sort_params: SortParams,
    allowed_fields: dict[str, InstrumentedAttribute[Any]],
    default_sort: InstrumentedAttribute[Any] | None = None,
) -> Select[tuple[T]]:
    """Apply sorting to a statement based on sort parameters.

    Args:
        statement: Base SELECT statement
        sort_params: Sort parameters from request
        allowed_fields: Mapping of field names to model columns
        default_sort: Default sort column if sort_by not provided or invalid

    Returns:
        Statement with ORDER BY applied
    """
    if sort_params.sort_by and sort_params.sort_by in allowed_fields:
        column = allowed_fields[sort_params.sort_by]
        if sort_params.sort_order == "desc":
            column = column.desc()
        return statement.order_by(column)

    if default_sort is not None:
        return statement.order_by(default_sort)

    return statement


def apply_filters(
    statement: Select[tuple[T]],
    filter_params: FilterParams,
    filter_map: dict[str, InstrumentedAttribute[Any]],
) -> Select[tuple[T]]:
    """Apply filters to a statement based on filter parameters.

    Args:
        statement: Base SELECT statement
        filter_params: Filter parameters from request
        filter_map: Mapping of filter field names to model columns

    Returns:
        Statement with WHERE clauses applied
    """
    for field_name, column in filter_map.items():
        value = getattr(filter_params, field_name, None)
        if value is not None:
            # Handle different filter types
            if isinstance(value, str) and value.startswith("~"):
                # Partial match (ILIKE)
                statement = statement.where(column.ilike(f"%{value[1:]}%"))
            elif isinstance(value, list):
                # IN clause
                statement = statement.where(column.in_(value))
            else:
                # Exact match
                statement = statement.where(column == value)

    return statement


# Common filter params mixins
class NameFilterMixin(FilterParams):
    """Filter by name (exact or partial)."""

    name: str | None = Field(default=None, description="Filter by name (prefix with ~ for partial)")


class DateRangeFilterMixin(FilterParams):
    """Filter by date range."""

    created_after: str | None = Field(default=None, description="Filter created after (ISO 8601)")
    created_before: str | None = Field(default=None, description="Filter created before (ISO 8601)")


class StatusFilterMixin(FilterParams):
    """Filter by status."""

    status: str | None = Field(default=None, description="Filter by status")


class OrganizationFilterMixin(FilterParams):
    """Filter by organization."""

    organization_id: str | None = Field(default=None, description="Filter by organization ID")


class ProjectFilterMixin(FilterParams):
    """Filter by project."""

    project_id: str | None = Field(default=None, description="Filter by project ID")
