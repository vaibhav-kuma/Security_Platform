"""Pydantic schemas for APK static analysis."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# APK File Upload and Analysis Request Schemas
# =============================================================================

class ApkUploadRequest(BaseModel):
    """Request to upload an APK for analysis."""
    project_id: UUID
    asset_id: UUID | None = None
    scan_id: UUID | None = None


class ApkAnalysisRequest(BaseModel):
    """Request to analyze an APK."""
    apk_file_id: UUID
    analysis_types: list[str] = Field(
        default_factory=lambda: [
            "manifest", "permissions", "certificate", "dex", "native_libraries",
            "resources", "urls", "configuration", "exported_components",
            "webview", "storage", "crypto", "network_security"
        ]
    )


# =============================================================================
# APK File Response Schemas
# =============================================================================

class ApkFileBase(BaseModel):
    """Base APK file schema."""
    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    sha256: str
    object_key: str | None = None


class ApkFileCreate(ApkFileBase):
    """Create APK file request."""
    asset_id: UUID


class ApkFileResponse(ApkFileBase):
    """APK file response."""
    id: UUID
    asset_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApkFileDetailResponse(ApkFileResponse):
    """APK file response with components and analysis results."""
    components: list["ApkComponentResponse"] = []
    analysis_results: list["ApkAnalysisResultResponse"] = []


class ApkFileListResponse(BaseModel):
    """Paginated APK file list."""
    items: list[ApkFileResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# =============================================================================
# APK Component Schemas
# =============================================================================

class ApkComponentBase(BaseModel):
    """Base APK component schema."""
    component_type: str
    name: str
    exported: bool = False
    intent_filters: list[dict[str, Any]] = []


class ApkComponentCreate(ApkComponentBase):
    """Create APK component request."""
    apk_file_id: UUID


class ApkComponentResponse(ApkComponentBase):
    """APK component response."""
    id: UUID
    apk_file_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# APK Analysis Result Schemas
# =============================================================================

class ApkAnalysisResultBase(BaseModel):
    """Base APK analysis result schema."""
    analyzer_name: str
    finding_type: str  # observation, info, warning, critical
    title: str
    description: str | None = None
    severity_hint: str | None = None  # info, low, medium, high, critical
    confidence_hint: str | None = None  # very_low, low, medium, high, very_high
    location: str | None = None
    evidence: dict[str, Any] = {}
    mastg_references: list[str] = []
    masvs_references: list[str] = []


class ApkAnalysisResultCreate(ApkAnalysisResultBase):
    """Create APK analysis result request."""
    apk_file_id: UUID
    component_id: UUID | None = None


class ApkAnalysisResultResponse(ApkAnalysisResultBase):
    """APK analysis result response."""
    id: UUID
    apk_file_id: UUID
    component_id: UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Manifest Analysis Schemas
# =============================================================================

class ManifestAnalysisRequest(BaseModel):
    """Manifest analysis request."""
    apk_file_id: UUID


class ManifestAnalysisResult(BaseModel):
    """Manifest analysis result."""
    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    max_sdk: int | None = None
    permissions: list[str] = []
    uses_features: list[str] = []
    application_attributes: dict[str, Any] = {}
    activities: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    receivers: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    libraries: list[str] = []
    metadata: list[dict[str, Any]] = []


# =============================================================================
# Permission Analysis Schemas
# =============================================================================

class PermissionAnalysisResult(BaseModel):
    """Permission analysis result."""
    permission: str
    protection_level: str | None = None  # normal, dangerous, signature, signatureOrSystem
    description: str | None = None
    is_dangerous: bool = False
    is_custom: bool = False
    related_mastg: list[str] = []


class PermissionAnalysisResponse(BaseModel):
    """Permission analysis response."""
    permissions: list[PermissionAnalysisResult]
    dangerous_permissions: list[str]
    custom_permissions: list[str]
    permission_groups: dict[str, list[str]]


# =============================================================================
# Certificate Analysis Schemas
# =============================================================================

class CertificateInfo(BaseModel):
    """Certificate information."""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    sha1_fingerprint: str
    sha256_fingerprint: str
    is_self_signed: bool
    is_expired: bool
    days_until_expiry: int


class CertificateAnalysisResult(BaseModel):
    """Certificate analysis result."""
    certificates: list[CertificateInfo]
    warnings: list[str] = []


# =============================================================================
# DEX Analysis Schemas
# =============================================================================

class DexClassInfo(BaseModel):
    """DEX class information."""
    name: str
    superclass: str | None = None
    interfaces: list[str] = []
    methods: list[dict[str, Any]] = []
    fields: list[dict[str, Any]] = []
    annotations: list[str] = []


class DexAnalysisResult(BaseModel):
    """DEX analysis result."""
    classes: list[DexClassInfo] = []
    total_classes: int = 0
    total_methods: int = 0
    suspicious_patterns: list[dict[str, Any]] = []
    api_calls: list[dict[str, Any]] = []
    crypto_usage: list[dict[str, Any]] = []


# =============================================================================
# Native Library Analysis Schemas
# =============================================================================

class NativeLibraryInfo(BaseModel):
    """Native library information."""
    name: str
    path: str
    architecture: str  # arm64-v8a, armeabi-v7a, x86, x86_64
    size: int
    exported_functions: list[str] = []
    imported_functions: list[str] = []
    suspicious_strings: list[str] = []


class NativeLibraryAnalysisResult(BaseModel):
    """Native library analysis result."""
    libraries: list[NativeLibraryInfo] = []
    jni_methods: list[dict[str, Any]] = []


# =============================================================================
# Resource Analysis Schemas
# =============================================================================

class ResourceAnalysisResult(BaseModel):
    """Resource analysis result."""
    strings: dict[str, str] = {}
    layouts: list[str] = []
    drawables: list[str] = []
    xml_files: dict[str, str] = {}
    raw_files: list[str] = []
    hardcoded_secrets: list[dict[str, Any]] = []
    embedded_urls: list[str] = []


# =============================================================================
# URL/Endpoint Extraction Schemas
# =============================================================================

class ExtractedUrl(BaseModel):
    """Extracted URL from APK."""
    url: str
    source: str  # string, xml, code, config
    context: str | None = None
    is_backend_reference: bool = False
    category: str | None = None  # api, websocket, firebase, deep_link, etc.


class UrlAnalysisResult(BaseModel):
    """URL analysis result."""
    urls: list[ExtractedUrl] = []
    api_endpoints: list[str] = []
    websocket_urls: list[str] = []
    firebase_urls: list[str] = []
    deep_links: list[str] = []
    webview_urls: list[str] = []


# =============================================================================
# Configuration Analysis Schemas
# =============================================================================

class NetworkSecurityConfig(BaseModel):
    """Network security configuration."""
    has_config: bool = False
    cleartext_traffic_permitted: bool = True
    domain_configs: list[dict[str, Any]] = []
    certificate_pinning: list[dict[str, Any]] = []
    debug_overrides: list[dict[str, Any]] = []


class ConfigurationAnalysisResult(BaseModel):
    """Configuration analysis result."""
    network_security: NetworkSecurityConfig
    application_flags: dict[str, Any] = {}
    backup_allowed: bool = True
    debuggable: bool = False
    allow_cleartext_traffic: bool = True
    uses_cleartext_traffic: bool = True


# =============================================================================
# Exported Component Analysis Schemas
# =============================================================================

class ExportedComponentInfo(BaseModel):
    """Exported component information."""
    component_type: str  # activity, service, receiver, provider
    name: str
    exported: bool = False
    explicit_export: bool = False
    intent_filters: list[dict[str, Any]] = []
    permissions: list[str] = []
    is_vulnerable: bool = False
    risk_level: str | None = None


class ExportedComponentAnalysisResult(BaseModel):
    """Exported component analysis result."""
    components: list[ExportedComponentInfo] = []
    exported_activities: list[ExportedComponentInfo] = []
    exported_services: list[ExportedComponentInfo] = []
    exported_receivers: list[ExportedComponentInfo] = []
    exported_providers: list[ExportedComponentInfo] = []


# =============================================================================
# WebView Analysis Schemas
# =============================================================================

class WebViewConfig(BaseModel):
    """WebView configuration."""
    allows_universal_access: bool = False
    allows_file_access: bool = False
    allows_content_access: bool = False
    javascript_enabled: bool = False
    dom_storage_enabled: bool = False
    database_enabled: bool = False
    mixed_content_mode: str | None = None
    safe_browsing_enabled: bool = False


class WebViewAnalysisResult(BaseModel):
    """WebView analysis result."""
    webviews: list[dict[str, Any]] = []
    configurations: list[WebViewConfig] = []
    javascript_interfaces: list[dict[str, Any]] = []
    url_loading_patterns: list[str] = []


# =============================================================================
# Storage Analysis Schemas
# =============================================================================

class StorageAnalysisResult(BaseModel):
    """Storage analysis result."""
    shared_preferences: list[dict[str, Any]] = []
    sqlite_databases: list[dict[str, Any]] = []
    internal_files: list[str] = []
    external_files: list[str] = []
    sensitive_data_patterns: list[dict[str, Any]] = []
    world_readable_files: list[str] = []
    world_writable_files: list[str] = []


# =============================================================================
# Crypto Analysis Schemas
# =============================================================================

class CryptoFinding(BaseModel):
    """Cryptographic finding."""
    algorithm: str
    mode: str | None = None
    padding: str | None = None
    key_size: int | None = None
    location: str
    issue: str
    severity: str  # info, low, medium, high, critical
    recommendation: str


class CryptoAnalysisResult(BaseModel):
    """Crypto analysis result."""
    findings: list[CryptoFinding] = []
    used_algorithms: dict[str, int] = {}
    hardcoded_keys: list[dict[str, Any]] = []
    weak_random: list[dict[str, Any]] = []


# =============================================================================
# Network Security Analysis Schemas
# =============================================================================

class NetworkSecurityAnalysisResult(BaseModel):
    """Network security analysis result."""
    network_security_config: NetworkSecurityConfig
    ssl_pinning: list[dict[str, Any]] = []
    hostname_verification: list[dict[str, Any]] = []
    trust_managers: list[dict[str, Any]] = []
    cleartext_endpoints: list[str] = []


# =============================================================================
# MASTG/MASVS Methodology Schemas
# =============================================================================

class MastgTestCaseResponse(BaseModel):
    """MASTG test case response."""
    id: UUID
    methodology_version_id: UUID
    identifier: str
    name: str
    description: str | None = None
    category: str | None = None
    order: int
    supported_target_types: list[str] = []
    prerequisites: list[str] = []
    passive_mode: bool = True
    active_mode: bool = False
    safe_mode_compatible: bool = True
    evidence_requirements: list[str] = []
    detection_rules: list[str] = []
    references: list[str] = []

    model_config = ConfigDict(from_attributes=True)


class MastgCoverageResponse(BaseModel):
    """MASTG coverage response."""
    total: int
    tested: int
    not_tested: int
    needs_review: int
    not_applicable: int
    coverage_percent: float
    by_category: dict[str, dict[str, int]] = {}


# =============================================================================
# APK Analysis Summary
# =============================================================================

class ApkAnalysisSummary(BaseModel):
    """APK analysis summary."""
    apk_file_id: UUID
    package_name: str
    analysis_timestamp: datetime
    total_findings: int
    findings_by_severity: dict[str, int] = {}
    findings_by_type: dict[str, int] = {}
    mastg_coverage: dict[str, str] = {}
    analyzers_run: list[str] = []


# =============================================================================
# Update forward references
# =============================================================================

ApkFileDetailResponse.model_rebuild()
ApkComponentResponse.model_rebuild()
ApkAnalysisResultResponse.model_rebuild()