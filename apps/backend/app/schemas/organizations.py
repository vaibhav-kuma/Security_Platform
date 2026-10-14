"""Pydantic schemas for Organization API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreate(BaseModel):
    """Create organization request."""

    name: Annotated[str, Field(min_length=1, max_length=255)]
    description: Annotated[str | None, Field(max_length=2000)] = None


class OrganizationUpdate(BaseModel):
    """Update organization request."""

    name: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    description: Annotated[str | None, Field(max_length=2000)] = None


class OrganizationResponse(BaseModel):
    """Organization response."""

    id: UUID
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationListResponse(BaseModel):
    """Paginated organization list."""

    items: list[OrganizationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
