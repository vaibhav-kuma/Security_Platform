"""API asset models: API definitions, endpoints, parameters, schemas, auth, authz, and rate limits.

An ``ApiDefinition`` is the typed contract of an API asset (OpenAPI/Postman
upload or manual entry); endpoints and parameters hang off it. The
corresponding ``Asset`` row (kind ``api_definition``) is linked one-to-one.

Phase 11 adds: schemas, authentication schemes, authorization contexts,
object identifiers, rate limit profiles, and privilege analysis.
"""

import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    HttpMethod,
    ParameterLocation,
    native_enum,
)


class ApiDefinition(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """API contract (OpenAPI/Swagger/Postman spec)."""

    __tablename__ = "api_definitions"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(2048))
    spec_format: Mapped[str | None] = mapped_column(String(32))  # openapi, swagger, postman
    spec_version: Mapped[str | None] = mapped_column(String(32))
    spec: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Phase 11: API-level metadata
    description: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(64))
    terms_of_service: Mapped[str | None] = mapped_column(Text)
    contact: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    license: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    servers: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    security_schemes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Global rate limit profile (can be overridden per endpoint)
    rate_limit_profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    endpoints: Mapped[list["ApiEndpoint"]] = relationship(back_populates="definition", lazy="selectin")
    schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="definition", lazy="selectin")
    auth_schemes: Mapped[list["ApiAuthScheme"]] = relationship(back_populates="definition", lazy="selectin")
    authz_contexts: Mapped[list["ApiAuthzContext"]] = relationship(back_populates="definition", lazy="selectin")


class ApiSchema(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Reusable schema component (from OpenAPI components/schemas)."""

    __tablename__ = "api_schemas"
    __table_args__ = (
        UniqueConstraint("api_definition_id", "name", name="definition_schema_name"),
    )

    api_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    type: Mapped[str | None] = mapped_column(String(64))  # object, array, string, etc.
    schema_: Mapped[dict[str, Any] | None] = mapped_column("schema", JSONB)
    # Object identifier analysis (for API1:2023 - Broken Object Level Authorization)
    object_identifier_fields: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Property-level authorization analysis (for API3:2023 - Broken Object Property Level Authorization)
    sensitive_fields: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Privilege analysis (for API6:2023 - Unrestricted Access to Sensitive Business Flows)
    requires_privilege: Mapped[list[str]] = mapped_column(JSONB, default=list)

    definition: Mapped[ApiDefinition] = relationship(back_populates="schemas")
    parameters: Mapped[list["ApiParameter"]] = relationship(back_populates="schema_ref", lazy="selectin")


class ApiEndpoint(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """API endpoint (path + method combination)."""

    __tablename__ = "api_endpoints"
    __table_args__ = (
        UniqueConstraint("api_definition_id", "method", "path", name="definition_method_path"),
    )

    api_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[HttpMethod] = mapped_column(native_enum(HttpMethod), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    operation_id: Mapped[str | None] = mapped_column(String(255))
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    # Phase 11: Endpoint-level security
    security_requirements: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    # Override global rate limit
    rate_limit_profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Authorization context for this endpoint
    required_privileges: Mapped[list[str]] = mapped_column(JSONB, default=list)
    required_roles: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Sensitive business flow marker (for API6:2023)
    is_sensitive_business_flow: Mapped[bool] = mapped_column(Boolean, default=False)
    # External API consumption marker (for API10:2023 - Unsafe Consumption of APIs)
    consumes_external_api: Mapped[bool] = mapped_column(Boolean, default=False)
    external_api_references: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # SSRF risk marker (for API7:2023 - Server Side Request Forgery)
    ssrf_risk: Mapped[bool] = mapped_column(Boolean, default=False)
    ssrf_parameters: Mapped[list[str]] = mapped_column(JSONB, default=list)

    definition: Mapped[ApiDefinition] = relationship(back_populates="endpoints")
    parameters: Mapped[list["ApiParameter"]] = relationship(back_populates="endpoint", lazy="selectin")
    responses: Mapped[list["ApiResponse"]] = relationship(back_populates="endpoint", lazy="selectin")


class ApiParameter(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Parameter for an endpoint (query, path, header, cookie, body)."""

    __tablename__ = "api_parameters"
    __table_args__ = (
        UniqueConstraint("api_endpoint_id", "location", "name", name="endpoint_location_name"),
    )

    api_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[ParameterLocation] = mapped_column(
        native_enum(ParameterLocation), nullable=False
    )
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    data_type: Mapped[str | None] = mapped_column(String(64))
    schema_: Mapped[dict[str, Any] | None] = mapped_column("schema", JSONB)
    # Reference to reusable schema component
    schema_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_schemas.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Object identifier analysis (for API1:2023)
    is_object_identifier: Mapped[bool] = mapped_column(Boolean, default=False)
    object_identifier_type: Mapped[str | None] = mapped_column(String(64))  # uuid, integer, slug, etc.
    # Property-level authorization (for API3:2023)
    is_sensitive_property: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitivity_classification: Mapped[str | None] = mapped_column(String(64))  # pii, financial, auth, etc.
    # Rate limiting (for API4:2023 - Unrestricted Resource Consumption)
    rate_limit_key: Mapped[bool] = mapped_column(Boolean, default=False)
    # External API consumption (for API10:2023)
    is_external_api_input: Mapped[bool] = mapped_column(Boolean, default=False)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="parameters")
    schema_ref: Mapped[ApiSchema | None] = relationship(back_populates="parameters")


class ApiResponse(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """API response definition."""

    __tablename__ = "api_responses"
    __table_args__ = (
        UniqueConstraint("api_endpoint_id", "status_code", name="endpoint_status_code"),
    )

    api_endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status_code: Mapped[str] = mapped_column(String(16), nullable=False)  # "200", "4XX", "default"
    description: Mapped[str | None] = mapped_column(Text)
    headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    content: Mapped[dict[str, Any] | None] = mapped_column(JSONB)  # media type -> schema
    # Phase 11: Response analysis
    exposes_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_fields: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Information exposure analysis (for API3:2023, API6:2023)
    information_exposure_risk: Mapped[bool] = mapped_column(Boolean, default=False)

    endpoint: Mapped[ApiEndpoint] = relationship(back_populates="responses")


class ApiAuthScheme(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Authentication scheme defined in the API spec (OpenAPI securitySchemes)."""

    __tablename__ = "api_auth_schemes"
    __table_args__ = (
        UniqueConstraint("api_definition_id", "name", name="definition_auth_scheme_name"),
    )

    api_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g., "BearerAuth", "ApiKeyAuth"
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # http, apiKey, oauth2, openIdConnect, mutualTLS
    scheme: Mapped[str | None] = mapped_column(String(32))  # for http: basic, bearer, etc.
    bearer_format: Mapped[str | None] = mapped_column(String(64))  # JWT, etc.
    in_location: Mapped[str | None] = mapped_column(String(16))  # for apiKey: header, query, cookie
    param_name: Mapped[str | None] = mapped_column(String(64))  # for apiKey
    flows: Mapped[dict[str, Any] | None] = mapped_column(JSONB)  # for oauth2
    openid_connect_url: Mapped[str | None] = mapped_column(Text)  # for openIdConnect
    description: Mapped[str | None] = mapped_column(Text)
    # Phase 11: Auth analysis
    is_weak: Mapped[bool] = mapped_column(Boolean, default=False)  # basic auth, api key in query
    detected_issues: Mapped[list[str]] = mapped_column(JSONB, default=list)

    definition: Mapped[ApiDefinition] = relationship(back_populates="auth_schemes")


class ApiAuthzContext(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Authorization context model for role/privilege analysis."""

    __tablename__ = "api_authz_contexts"
    __table_args__ = (
        UniqueConstraint("api_definition_id", "role", "privilege", name="definition_role_privilege"),
    )

    api_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(128), nullable=False)  # anonymous, user, admin, service_account
    privilege: Mapped[str] = mapped_column(String(128), nullable=False)  # read, write, delete, admin, execute
    # Endpoints accessible with this role/privilege
    allowed_endpoints: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Endpoints explicitly denied
    denied_endpoints: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # Object-level access rules
    object_access_rules: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Property-level access rules
    property_access_rules: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Source of this context (manual, inferred, imported)
    source: Mapped[str] = mapped_column(String(32), default="manual")
    confidence: Mapped[str] = mapped_column(String(16), default="medium")  # low, medium, high

    definition: Mapped[ApiDefinition] = relationship(back_populates="authz_contexts")


class ApiRateLimitProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Rate limit configuration (can be global or per-endpoint)."""

    __tablename__ = "api_rate_limit_profiles"
    __table_args__ = (
        UniqueConstraint("api_definition_id", "name", name="definition_rate_limit_name"),
    )

    api_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("api_definitions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Rate limit algorithm
    algorithm: Mapped[str] = mapped_column(String(32), default="token_bucket")  # token_bucket, sliding_window, fixed_window
    # Limits
    requests_per_window: Mapped[int] = mapped_column(Integer, default=100)
    window_seconds: Mapped[int] = mapped_column(Integer, default=60)
    # Burst allowance
    burst_allowance: Mapped[int | None] = mapped_column(Integer)
    # Key strategy
    key_strategy: Mapped[str] = mapped_column(String(32), default="ip")  # ip, user_id, api_key, endpoint
    # Per-endpoint overrides
    endpoint_overrides: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Phase 11: Detected vs configured
    is_configured: Mapped[bool] = mapped_column(Boolean, default=False)  # explicitly in spec
    is_detected: Mapped[bool] = mapped_column(Boolean, default=False)  # observed during testing
    detection_notes: Mapped[str | None] = mapped_column(Text)
