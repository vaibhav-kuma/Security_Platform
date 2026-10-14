"""Pydantic schemas for Scan API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Create scan request."""

    name: Annotated[str, Field(min_length=1, max_length=512)]
    scan_type: Annotated[
        str,
        Field(pattern="^(discovery|enumeration|vulnerability|methodology|manual|other)$"),
    ]
    target_id: UUID | None = None
    configuration: dict[str, Annotated[str | int | float | bool | None, Field()]] | None = None


class ScanUpdate(BaseModel):
    """Update scan request."""

    name: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    configuration: dict[str, Annotated[str | int | float | bool | None, Field()]] | None = None


class ScanResponse(BaseModel):
    """Scan response."""

    id: UUID
    project_id: UUID
    target_id: UUID | None = None
    initiated_by: UUID | None = None
    name: str
    scan_type: str
    status: str
    configuration: dict[str, Annotated[str | int | float | bool | None, Field()]]
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    """Scan response with jobs."""

    jobs: list["ScanJobResponse"] = []


class ScanProgressResponse(BaseModel):
    """Scan progress response."""

    scan_id: UUID
    status: str
    progress: int
    total_jobs: int
    completed_jobs: int
    failed_jobs: int
    running_jobs: int
    queued_jobs: int
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScanJobResponse(BaseModel):
    """Scan job response."""

    id: UUID
    scan_id: UUID
    name: str
    status: str
    configuration: dict[str, Annotated[str | int | float | bool | None, Field()]]
    result: dict[str, Annotated[str | int | float | bool | None, Field()]] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    """Paginated scan list."""

    items: list[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

# Update forward references
ScanDetailResponse.model_rebuild()
