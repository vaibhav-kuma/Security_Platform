"""Pydantic schemas for API Security Assessment API."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ApiDefinitionCreate(BaseModel):
    """Create API definition request."""

    name: Annotated[str, Field(min_length=1, max_length=255)]
    base_url: Annotated[str | None, Field(max_length=2048)] = None
    spec_format: Annotated[str | None, Field(max_length=32)] = None
    spec_version: Annotated[str | None, Field(max_length=32)] = None
    spec: dict[str, Any] | None = None
    asset_id: UUID | None = None


class ApiDefinitionUpdate(BaseModel):
    """Update API definition request."""

    name: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    base_url: Annotated[str | None, Field(max_length=2048)] = None
    spec: dict[str, Any] | None = None


class ApiDefinitionResponse(BaseModel):
    """API definition response."""

    id: UUID
    asset_id: UUID | None = None
    name: str
    base_url: str | None = None
    spec_format: str | None = None
    spec_version: str | None = None
    description: str | None = None
    version: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiEndpointResponse(BaseModel):
    """API endpoint response."""

    id: UUID
    api_definition_id: UUID
    method: str
    path: str
    summary: str | None = None
    operation_id: str | None = None
    deprecated: bool = False
    is_sensitive_business_flow: bool = False
    ssrf_risk: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiSchemaResponse(BaseModel):
    """API schema response."""

    id: UUID
    api_definition_id: UUID
    name: str
    title: str | None = None
    type: str | None = None
    object_identifier_fields: list[str] = []
    sensitive_fields: list[str] = []
    requires_privilege: list[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiAuthSchemeResponse(BaseModel):
    """API authentication scheme response."""

    id: UUID
    api_definition_id: UUID
    name: str
    type: str
    scheme: str | None = None
    bearer_format: str | None = None
    is_weak: bool = False
    detected_issues: list[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiAuthzContextResponse(BaseModel):
    """API authorization context response."""

    id: UUID
    api_definition_id: UUID
    role: str
    privilege: str
    allowed_endpoints: list[str] = []
    denied_endpoints: list[str] = []
    source: str
    confidence: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiRateLimitProfileResponse(BaseModel):
    """API rate limit profile response."""

    id: UUID
    api_definition_id: UUID
    name: str
    algorithm: str
    requests_per_window: int
    window_seconds: int
    burst_allowance: int | None = None
    key_strategy: str
    is_configured: bool
    is_detected: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OpenAPIImportRequest(BaseModel):
    """Import OpenAPI spec request."""

    name: Annotated[str, Field(min_length=1, max_length=255)]
    spec: dict[str, Any]
    asset_id: UUID | None = None


class OpenAPIImportResponse(BaseModel):
    """Import OpenAPI spec response."""

    api_definition: ApiDefinitionResponse
    endpoints_count: int
    schemas_count: int
    auth_schemes_count: int
    authz_contexts_count: int


class APISecurityScanRequest(BaseModel):
    """API security scan request."""

    testing_profile: Annotated[
        str, Field(pattern="^(passive|safe|active)$")
    ] = "passive"
    auth_contexts: list[dict[str, Any]] = []
    target_categories: list[str] = [
        "API1", "API2", "API3", "API4", "API5",
        "API6", "API7", "API8", "API9", "API10"
    ]
    max_requests_per_endpoint: int = 50
    follow_redirects: bool = False
    verify_ssl: bool = True


class APISecurityScanResponse(BaseModel):
    """API security scan response."""

    scan_id: UUID
    status: str
    message: str


class APISecurityObservationResponse(BaseModel):
    """API security observation response."""

    id: UUID
    scan_id: UUID
    endpoint_id: UUID | None = None
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    findings: list[str] = []
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MethodologyCoverageResponse(BaseModel):
    """Methodology coverage response."""

    methodology_version_id: UUID
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    coverage_percentage: float
    by_category: dict[str, dict[str, int]]


# Forward references
ApiDefinitionResponse.model_rebuild()
ApiEndpointResponse.model_rebuild()
ApiSchemaResponse.model_rebuild()
ApiAuthSchemeResponse.model_rebuild()
ApiAuthzContextResponse.model_rebuild()
ApiRateLimitProfileResponse.model_rebuild()
