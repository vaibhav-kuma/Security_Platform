"""Plugin API schemas."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class PluginPermissionEnum(str, Enum):
    """Plugin permission enumeration for API."""
    NETWORK_REQUEST = "network.request"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    PROCESS_EXECUTE = "process.execute"
    DATABASE_QUERY = "database.query"
    CACHE_ACCESS = "cache.access"
    SECRET_READ = "secret.read"


class PluginCategoryEnum(str, Enum):
    """Plugin category enumeration for API."""
    RECON = "recon"
    WEB = "web"
    API = "api"
    MOBILE = "mobile"
    DNS = "dns"
    TLS = "tls"
    TECHNOLOGY = "technology"
    CONFIGURATION = "configuration"
    VULNERABILITY = "vulnerability"
    REPORTING = "reporting"
    METHODOLOGY = "methodology"
    OTHER = "other"


class ResourceLimitsSchema(BaseModel):
    """Resource limits schema."""
    cpu_percent: int = Field(default=50, ge=1, le=100)
    memory_mb: int = Field(default=256, ge=64, le=4096)
    time_seconds: int = Field(default=300, ge=10, le=3600)
    network_egress_allowlist: list[str] = Field(default_factory=list)


class PluginManifestSchema(BaseModel):
    """Plugin manifest schema for API."""
    name: str
    version: str
    description: str
    author: str
    license: str = "MIT"
    homepage: str | None = None
    repository: str | None = None
    category: PluginCategoryEnum
    tags: list[str] = Field(default_factory=list)
    min_core_version: str
    max_core_version: str | None = None
    python_version: str = ">=3.12"
    capabilities: list[str] = Field(default_factory=list)
    permissions: list[PluginPermissionEnum] = Field(default_factory=list)
    resource_limits: ResourceLimitsSchema = Field(default_factory=ResourceLimitsSchema)
    config_schema: dict[str, Any] = Field(default_factory=dict)
    entry_point: str
    dependencies: list[str] = Field(default_factory=list)
    checksum: str | None = None


# Request/Response schemas

class PluginInstallRequest(BaseModel):
    """Request to install a plugin."""
    manifest: PluginManifestSchema
    # Plugin code would be uploaded as multipart/form-data


class PluginInstallResponse(BaseModel):
    """Response from plugin installation."""
    success: bool
    plugin_id: str | None = None
    errors: list[str] = Field(default_factory=list)


class PluginResponse(BaseModel):
    """Plugin response."""
    id: UUID
    name: str
    version: str
    description: str
    author: str
    license: str
    homepage: str | None = None
    repository: str | None = None
    category: str
    tags: list[str]
    min_core_version: str
    max_core_version: str | None = None
    python_version: str
    capabilities: list[str]
    permissions: list[str]
    resource_limits: dict[str, Any]
    config_schema: dict[str, Any]
    entry_point: str
    dependencies: list[str]
    checksum: str | None = None
    enabled: bool
    installed_at: datetime
    last_executed_at: datetime | None = None
    default_config: dict[str, Any]


class PluginListResponse(BaseModel):
    """Plugin list response."""
    plugins: list[PluginResponse]
    total: int


class PluginUpdateRequest(BaseModel):
    """Request to update plugin config/enable/disable."""
    enabled: bool | None = None
    default_config: dict[str, Any] | None = None


class PluginConfigSchema(BaseModel):
    """Plugin project configuration schema."""
    plugin_id: UUID
    project_id: UUID
    config: dict[str, Any]
    enabled: bool
    overridden_by: UUID | None = None
    created_at: datetime
    updated_at: datetime


class PluginConfigUpdateRequest(BaseModel):
    """Request to update plugin project config."""
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class PluginExecutionRequest(BaseModel):
    """Request to execute a plugin."""
    scan_context: dict[str, Any]
    plugin_config: dict[str, Any] | None = None
    mode: str = "thread"  # "thread" or "process"
    timeout: int | None = None


class PluginExecutionResponse(BaseModel):
    """Plugin execution response."""
    id: UUID
    plugin_id: UUID
    project_id: UUID | None = None
    scan_id: UUID | None = None
    scan_job_id: UUID | None = None
    triggered_by: UUID | None = None
    trigger_type: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    warnings: list[str]
    metrics: dict[str, Any]
    cpu_time_ms: int | None = None
    memory_peak_mb: int | None = None


class PluginExecutionListResponse(BaseModel):
    """Plugin execution list response."""
    executions: list[PluginExecutionResponse]
    total: int


class PluginValidationResponse(BaseModel):
    """Plugin validation response."""
    valid: bool
    errors: list[str]
    warnings: list[str]
    required_permissions: list[str]
    estimated_resources: dict[str, Any]


class PluginManifestSchemaResponse(BaseModel):
    """Plugin manifest JSON schema response."""
    schema: dict[str, Any]


class PluginCategoryListResponse(BaseModel):
    """Plugin categories response."""
    categories: list[str]
