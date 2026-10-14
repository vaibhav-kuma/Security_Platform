"""Knowledge Base API schemas."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class KnowledgePackTypeEnum(str, Enum):
    """Knowledge pack type enumeration for API."""
    WSTG = "wstg"
    API_SECURITY = "api_security"
    MASTG = "mastg"
    MASVS = "masvs"
    CWE = "cwe"
    CVSS = "cvss"
    DETECTION_RULES = "detection_rules"
    REMEDIATION = "remediation"
    METHODOLOGY = "methodology"
    FINGERPRINTS = "fingerprints"
    CUSTOM = "custom"


class KnowledgePackStatusEnum(str, Enum):
    """Knowledge pack status enumeration for API."""
    PENDING = "pending"
    INSTALLED = "installed"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DependencyTypeEnum(str, Enum):
    """Pack dependency type."""
    REQUIRED = "required"
    OPTIONAL = "optional"
    CONFLICTS = "conflicts"


class KnowledgePackResponse(BaseModel):
    """Knowledge pack response."""
    id: UUID
    name: str
    version: str
    pack_type: str
    description: str
    author: str
    license: str
    homepage: str | None = None
    repository: str
    min_core_version: str
    max_core_version: str | None = None
    schema_version: str
    checksum: str
    signature: str | None = None
    status: str
    is_official: bool
    installed_by: UUID | None = None
    installed_at: datetime | None = None
    activated_at: datetime | None = None
    deprecated_at: datetime | None = None
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class KnowledgePackListResponse(BaseModel):
    """Knowledge pack list response."""
    packs: list[KnowledgePackResponse]
    total: int


class PackContentResponse(BaseModel):
    """Pack content response."""
    id: UUID
    pack_id: UUID
    content_id: str
    content_version: str
    name: str
    methodology: str | None = None
    category: str | None = None
    subcategory: str | None = None
    target_types: list[str]
    platforms: list[str]
    technologies: list[str]
    prerequisites: list[str]
    evidence_requirements: list[str]
    severity_guidance: dict[str, Any]
    confidence_guidance: dict[str, Any]
    references: list[dict[str, str]]
    cwe_ids: list[str]
    capec_ids: list[str]
    detection_behavior: dict[str, Any]
    remediation_guidance: str | None = None
    remediation_complexity: str | None = None
    remediation_references: list[dict[str, str]]
    description: str
    long_description: str | None = None
    examples: list[dict[str, Any]]
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class PackContentListResponse(BaseModel):
    """Pack content list response."""
    contents: list[PackContentResponse]
    total: int


class PackVersionResponse(BaseModel):
    """Pack version response."""
    id: UUID
    pack_id: UUID
    version: str
    changelog: str
    compatibility_notes: str | None = None
    breaking_changes: list[str]
    deprecated_content: list[str]
    new_content: list[str]
    updated_content: list[str]
    released_at: datetime
    released_by: UUID | None = None
    created_at: datetime


class PackDependencyResponse(BaseModel):
    """Pack dependency response."""
    id: UUID
    pack_id: UUID
    depends_on_id: UUID
    dependency_type: str
    min_version: str | None = None
    max_version: str | None = None
    reason: str | None = None
    created_at: datetime


class PackInstallationResponse(BaseModel):
    """Pack installation response."""
    id: UUID
    pack_id: UUID
    installed_by: UUID | None = None
    installed_at: datetime
    source: str
    source_url: str | None = None
    previous_version: str | None = None
    status: str
    error: str | None = None
    rollback_at: datetime | None = None
    rolled_back_by: UUID | None = None


class PackInstallRequest(BaseModel):
    """Request to install a knowledge pack."""
    # Either upload pack file or provide registry reference
    pack_file: str | None = None  # base64 encoded or file reference
    registry_url: str | None = None
    pack_name: str | None = None
    pack_version: str | None = None
    force: bool = False


class PackInstallResponse(BaseModel):
    """Response from pack installation."""
    success: bool
    pack_id: UUID | None = None
    installation_id: UUID | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class PackUpdateRequest(BaseModel):
    """Request to update pack status."""
    activate: bool | None = None
    deprecate: bool | None = None


class PackRollbackRequest(BaseModel):
    """Request to rollback a pack."""
    target_version: str | None = None  # None = previous version
    reason: str | None = None


class PackRollbackResponse(BaseModel):
    """Rollback response."""
    success: bool
    pack_id: UUID
    rolled_back_to_version: str
    rollback_installation_id: UUID
    errors: list[str] = Field(default_factory=list)


class KnowledgeRegistryPack(BaseModel):
    """Knowledge pack from registry."""
    name: str
    version: str
    pack_type: str
    description: str
    author: str
    license: str
    homepage: str | None = None
    repository: str
    min_core_version: str
    max_core_version: str | None = None
    schema_version: str
    checksum: str
    signature: str | None = None
    is_official: bool
    tags: list[str]
    metadata: dict[str, Any]
    released_at: datetime


class KnowledgeRegistryResponse(BaseModel):
    """Registry response."""
    packs: list[KnowledgeRegistryPack]
    total: int


class PackValidationResponse(BaseModel):
    """Pack validation response."""
    valid: bool
    errors: list[str]
    warnings: list[str]
    schema_valid: bool
    integrity_valid: bool
    security_valid: bool
    compatibility_valid: bool


class PackUpdateCheckResponse(BaseModel):
    """Pack update check response."""
    pack_id: UUID
    current_version: str
    latest_version: str | None = None
    update_available: bool
    changelog: str | None = None
    breaking_changes: list[str] = Field(default_factory=list)


class PackAuditLogEntry(BaseModel):
    """Pack audit log entry."""
    id: UUID
    pack_id: UUID
    action: str
    performed_by: UUID | None = None
    performed_at: datetime
    details: dict[str, Any]
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None


class PackAuditLogResponse(BaseModel):
    """Pack audit log response."""
    entries: list[PackAuditLogEntry]
    total: int