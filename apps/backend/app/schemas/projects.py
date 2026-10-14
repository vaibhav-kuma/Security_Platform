"""Pydantic schemas for Project API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    """Create project request."""

    name: Annotated[str, Field(min_length=1, max_length=255)]
    description: Annotated[str | None, Field(max_length=5000)] = None


class ProjectUpdate(BaseModel):
    """Update project request."""

    name: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    description: Annotated[str | None, Field(max_length=5000)] = None
    status: Annotated[
        str | None,
        Field(pattern="^(draft|active|paused|completed|archived)$"),
    ] = None


class ProjectResponse(BaseModel):
    """Project response."""

    id: UUID
    organization_id: UUID
    name: str
    description: str | None = None
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectDetailResponse(ProjectResponse):
    """Project response with nested relationships."""

    member_count: int = 0
    scope_count: int = 0
    target_count: int = 0


class ProjectListResponse(BaseModel):
    """Paginated project list."""

    items: list[ProjectResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ProjectMemberCreate(BaseModel):
    """Add project member request."""

    user_id: UUID
    # Role assignment will be added in later phases


class ProjectMemberResponse(BaseModel):
    """Project member response."""

    id: UUID
    project_id: UUID
    user_id: UUID
    user_email: str
    user_full_name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectMemberListResponse(BaseModel):
    """Paginated project member list."""

    items: list[ProjectMemberResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
