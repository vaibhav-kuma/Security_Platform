"""Pydantic schemas for Target and Asset API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ScopeRuleTargetType, ScopeStatus


class TargetCreate(BaseModel):
    """Create target request."""

    name: Annotated[str, Field(min_length=1, max_length=512)]
    description: Annotated[str | None, Field(max_length=5000)] = None
    scope_id: UUID | None = None
    target_type: Annotated[
        ScopeRuleTargetType,
        Field(description="Explicit target type for scope matching"),
    ]


class TargetUpdate(BaseModel):
    """Update target request."""

    name: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    description: Annotated[str | None, Field(max_length=5000)] = None
    scope_id: UUID | None = None
    scope_status: Annotated[
        str | None,
        Field(pattern="^(in_scope|out_of_scope|unknown|third_party)$"),
    ] = None


class TargetStatusUpdate(BaseModel):
    """Override target scope status request."""

    status: ScopeStatus


class TargetResponse(BaseModel):
    """Target response."""

    id: UUID
    project_id: UUID
    scope_id: UUID | None = None
    name: str
    description: str | None = None
    scope_status: str
    target_type: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TargetDetailResponse(TargetResponse):
    """Target response with asset count."""

    asset_count: int = 0


class TargetListResponse(BaseModel):
    """Paginated target list."""

    items: list[TargetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Basic asset schemas
class AssetResponse(BaseModel):
    """Basic asset response."""

    id: UUID
    project_id: UUID
    target_id: UUID | None = None
    kind: str
    name: str
    display_name: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetListResponse(BaseModel):
    """Paginated asset list."""

    items: list[AssetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
