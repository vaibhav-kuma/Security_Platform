"""Pydantic schemas for Android Dynamic Analysis."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Emulator Profile Schemas
# =============================================================================

class EmulatorProfileBase(BaseModel):
    """Base emulator profile schema."""
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    avd_name: str = Field(min_length=1, max_length=255)
    api_level: int = Field(ge=1, le=35)
    abi: str = Field(min_length=1, max_length=64)
    ram_mb: int = Field(ge=512, le=16384, default=2048)
    storage_mb: int = Field(ge=1024, le=65536, default=4096)
    proxy_host: str | None = Field(default=None, max_length=255)
    proxy_port: int | None = Field(default=None, ge=1, le=65535)
    gpu_enabled: bool = True
    camera_enabled: bool = False
    gps_enabled: bool = False
    max_cpu_percent: int = Field(ge=10, le=100, default=80)
    max_memory_mb: int = Field(ge=512, le=32768, default=4096)
    max_execution_time_seconds: int = Field(ge=60, le=86400, default=3600)
    network_policy: str = Field(default="proxy_only", max_length=64)


class EmulatorProfileCreate(EmulatorProfileBase):
    """Create emulator profile request."""


class EmulatorProfileUpdate(BaseModel):
    """Update emulator profile request."""
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    ram_mb: int | None = Field(default=None, ge=512, le=16384)
    storage_mb: int | None = Field(default=None, ge=1024, le=65536)
    proxy_host: str | None = Field(default=None, max_length=255)
    proxy_port: int | None = Field(default=None, ge=1, le=65535)
    gpu_enabled: bool | None = None
    camera_enabled: bool | None = None
    gps_enabled: bool | None = None
    max_cpu_percent: int | None = Field(default=None, ge=10, le=100)
    max_memory_mb: int | None = Field(default=None, ge=512, le=32768)
    max_execution_time_seconds: int | None = Field(default=None, ge=60, le=86400)
    network_policy: str | None = Field(default=None, max_length=64)


class EmulatorProfileResponse(EmulatorProfileBase):
    """Emulator profile response."""
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EmulatorProfileListResponse(BaseModel):
    """Paginated emulator profile list."""
    items: list[EmulatorProfileResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Emulator Instance Schemas
# =============================================================================

class EmulatorInstanceResponse(BaseModel):
    """Emulator instance response."""
    id: UUID
    profile_id: UUID
    status: str
    pid: int | None = None
    adb_port: int | None = None
    vnc_port: int | None = None
    cpu_percent: float = 0.0
    memory_mb: int = 0
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EmulatorInstanceListResponse(BaseModel):
    """Paginated emulator instance list."""
    items: list[EmulatorInstanceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class EmulatorActionRequest(BaseModel):
    """Emulator action request."""
    action: str = Field(pattern="^(start|stop|restart|snapshot|restore)$")
    snapshot_name: str | None = None


# =============================================================================
# Dynamic Analysis Run Schemas
# =============================================================================

class DynamicAnalysisRunBase(BaseModel):
    """Base dynamic analysis run schema."""
    test_context: str = Field(default="default", max_length=64)
    network_policy: str = Field(default="proxy_only", max_length=64)
    proxy_configuration: dict[str, Any] = {}
    frida_scripts: list[str] = []
    resource_limits: dict[str, Any] = {}


class DynamicAnalysisRunCreate(DynamicAnalysisRunBase):
    """Create dynamic analysis run request."""
    scan_id: UUID
    emulator_instance_id: UUID | None = None
    apk_file_id: UUID


class DynamicAnalysisRunUpdate(BaseModel):
    """Update dynamic analysis run request."""
    test_context: str | None = Field(default=None, max_length=64)
    network_policy: str | None = Field(default=None, max_length=64)
    proxy_configuration: dict[str, Any] | None = None
    frida_scripts: list[str] | None = None
    resource_limits: dict[str, Any] | None = None


class DynamicAnalysisRunResponse(DynamicAnalysisRunBase):
    """Dynamic analysis run response."""
    id: UUID
    scan_id: UUID
    emulator_instance_id: UUID | None = None
    apk_file_id: UUID
    status: str
    events_captured: int = 0
    network_observations: int = 0
    file_operations: int = 0
    ipc_events: int = 0
    crypto_operations: int = 0
    evidence_artifacts: dict[str, Any] = {}
    correlated_static_findings: int = 0
    correlated_api_findings: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DynamicAnalysisRunDetailResponse(DynamicAnalysisRunResponse):
    """Dynamic analysis run response with details."""
    runtime_events: list["RuntimeEventResponse"] = []
    network_observations: list["NetworkObservationResponse"] = []
    file_observations: list["FileObservationResponse"] = []
    ipc_observations: list["IpcObservationResponse"] = []


class DynamicAnalysisRunListResponse(BaseModel):
    """Paginated dynamic analysis run list."""
    items: list[DynamicAnalysisRunResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Runtime Event Schemas
# =============================================================================

class RuntimeEventBase(BaseModel):
    """Base runtime event schema."""
    event_type: str = Field(max_length=64)
    event_subtype: str | None = Field(default=None, max_length=128)
    source_package: str | None = Field(default=None, max_length=255)
    source_class: str | None = Field(default=None, max_length=512)
    source_method: str | None = Field(default=None, max_length=256)
    description: str
    raw_data: dict[str, Any] = {}
    severity: str = Field(default="info", max_length=16)
    confidence: str = Field(default="medium", max_length=16)
    mastg_references: list[str] = []
    masvs_references: list[str] = []
    evidence_artifacts: dict[str, Any] = {}
    stack_trace: str | None = None


class RuntimeEventCreate(RuntimeEventBase):
    """Create runtime event request."""
    analysis_run_id: UUID
    correlated_static_finding_id: UUID | None = None
    correlated_api_finding_id: UUID | None = None


class RuntimeEventResponse(RuntimeEventBase):
    """Runtime event response."""
    id: UUID
    analysis_run_id: UUID
    correlated_static_finding_id: UUID | None = None
    correlated_api_finding_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RuntimeEventListResponse(BaseModel):
    """Paginated runtime event list."""
    items: list[RuntimeEventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Network Observation Schemas
# =============================================================================

class NetworkObservationBase(BaseModel):
    """Base network observation schema."""
    protocol: str = Field(max_length=16)
    direction: str = Field(max_length=16)
    source_package: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = None
    destination_host: str = Field(max_length=512)
    destination_ip: str | None = Field(default=None, max_length=64)
    destination_port: int | None = None
    http_method: str | None = Field(default=None, max_length=16)
    http_path: str | None = Field(default=None, max_length=2048)
    http_status: int | None = None
    request_headers: dict[str, str] = {}
    response_headers: dict[str, str] = {}
    request_body: str | None = None
    response_body: str | None = None
    tls_version: str | None = Field(default=None, max_length=32)
    cipher_suite: str | None = Field(default=None, max_length=128)
    certificate_pinned: bool = False
    certificate_valid: bool | None = None
    duration_ms: int | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    is_cleartext: bool = False
    is_suspicious: bool = False
    suspicious_reason: str | None = None
    mastg_references: list[str] = []
    masvs_references: list[str] = []
    pcap_file: str | None = Field(default=None, max_length=1024)


class NetworkObservationCreate(NetworkObservationBase):
    """Create network observation request."""
    analysis_run_id: UUID


class NetworkObservationResponse(NetworkObservationBase):
    """Network observation response."""
    id: UUID
    analysis_run_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkObservationListResponse(BaseModel):
    """Paginated network observation list."""
    items: list[NetworkObservationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# File Observation Schemas
# =============================================================================

class FileObservationBase(BaseModel):
    """Base file observation schema."""
    operation: str = Field(max_length=32)
    file_path: str = Field(max_length=2048)
    file_size: int | None = None
    file_hash: str | None = Field(default=None, max_length=64)
    mime_type: str | None = Field(default=None, max_length=128)
    source_package: str | None = Field(default=None, max_length=255)
    source_class: str | None = Field(default=None, max_length=512)
    source_method: str | None = Field(default=None, max_length=256)
    old_permissions: str | None = Field(default=None, max_length=16)
    new_permissions: str | None = Field(default=None, max_length=16)
    contains_sensitive_data: bool = False
    sensitive_patterns: list[str] = []
    mastg_references: list[str] = []
    masvs_references: list[str] = []
    file_snapshot: str | None = Field(default=None, max_length=1024)


class FileObservationCreate(FileObservationBase):
    """Create file observation request."""
    analysis_run_id: UUID


class FileObservationResponse(FileObservationBase):
    """File observation response."""
    id: UUID
    analysis_run_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FileObservationListResponse(BaseModel):
    """Paginated file observation list."""
    items: list[FileObservationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# IPC Observation Schemas
# =============================================================================

class IpcObservationBase(BaseModel):
    """Base IPC observation schema."""
    ipc_type: str = Field(max_length=32)
    source_package: str | None = Field(default=None, max_length=255)
    source_component: str | None = Field(default=None, max_length=512)
    destination_package: str | None = Field(default=None, max_length=255)
    destination_component: str | None = Field(default=None, max_length=512)
    action: str | None = Field(default=None, max_length=256)
    categories: list[str] = []
    data_uri: str | None = Field(default=None, max_length=2048)
    mime_type: str | None = Field(default=None, max_length=128)
    extras: dict[str, Any] = {}
    flags: list[str] = []
    exported: bool | None = None
    permission_required: str | None = Field(default=None, max_length=256)
    mastg_references: list[str] = []
    masvs_references: list[str] = []
    intent_dump: str | None = None


class IpcObservationCreate(IpcObservationBase):
    """Create IPC observation request."""
    analysis_run_id: UUID


class IpcObservationResponse(IpcObservationBase):
    """IPC observation response."""
    id: UUID
    analysis_run_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IpcObservationListResponse(BaseModel):
    """Paginated IPC observation list."""
    items: list[IpcObservationResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# Dynamic Analysis Evidence Schemas
# =============================================================================

class DynamicAnalysisEvidenceBase(BaseModel):
    """Base dynamic analysis evidence schema."""
    evidence_type: str = Field(max_length=64)
    storage: str = Field(default="inline", max_length=16)
    content: str | None = None
    object_key: str | None = Field(default=None, max_length=1024)
    sha256: str | None = Field(default=None, max_length=64)
    description: str | None = None
    tags: list[str] = []


class DynamicAnalysisEvidenceCreate(DynamicAnalysisEvidenceBase):
    """Create dynamic analysis evidence request."""
    analysis_run_id: UUID


class DynamicAnalysisEvidenceResponse(DynamicAnalysisEvidenceBase):
    """Dynamic analysis evidence response."""
    id: UUID
    analysis_run_id: UUID
    redacted: bool = False
    redacted_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Dynamic Analysis Summary & Correlation
# =============================================================================

class DynamicAnalysisSummary(BaseModel):
    """Dynamic analysis run summary."""
    run_id: UUID
    scan_id: UUID
    apk_package_name: str
    test_context: str
    status: str
    duration_seconds: float | None = None
    events_captured: int
    network_observations: int
    file_operations: int
    ipc_events: int
    crypto_operations: int
    findings_by_severity: dict[str, int] = {}
    findings_by_type: dict[str, int] = {}
    mastg_coverage: dict[str, str] = {}
    correlated_static_findings: int
    correlated_api_findings: int
    evidence_artifacts: dict[str, Any] = {}


class CorrelationResult(BaseModel):
    """Correlation between dynamic and static findings."""
    dynamic_event_id: UUID
    static_finding_id: UUID | None = None
    api_finding_id: UUID | None = None
    correlation_type: str  # exact, similar, related
    confidence: float
    evidence: dict[str, Any] = {}


# =============================================================================
# Update forward references
# =============================================================================

DynamicAnalysisRunDetailResponse.model_rebuild()
RuntimeEventResponse.model_rebuild()
NetworkObservationResponse.model_rebuild()
FileObservationResponse.model_rebuild()
IpcObservationResponse.model_rebuild()