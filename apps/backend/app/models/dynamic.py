"""Android Dynamic Analysis models: emulators, dynamic analysis runs, and runtime events."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import native_enum

if TYPE_CHECKING:
    from app.models.scans import Scan


class EmulatorStatus(StrEnum):
    """Emulator lifecycle status."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class EmulatorProfile(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Pre-configured emulator profile for dynamic analysis."""

    __tablename__ = "emulator_profiles"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Emulator configuration
    avd_name: Mapped[str] = mapped_column(String(255), nullable=False)
    api_level: Mapped[int] = mapped_column(nullable=False)
    abi: Mapped[str] = mapped_column(String(64), nullable=False)  # arm64-v8a, x86_64, etc.
    ram_mb: Mapped[int] = mapped_column(default=2048)
    storage_mb: Mapped[int] = mapped_column(default=4096)
    # Network configuration
    proxy_host: Mapped[str | None] = mapped_column(String(255))
    proxy_port: Mapped[int | None] = mapped_column()
    # Feature flags
    gpu_enabled: Mapped[bool] = mapped_column(default=True)
    camera_enabled: Mapped[bool] = mapped_column(default=False)
    gps_enabled: Mapped[bool] = mapped_column(default=False)
    # Resource limits
    max_cpu_percent: Mapped[int] = mapped_column(default=80)
    max_memory_mb: Mapped[int] = mapped_column(default=4096)
    max_execution_time_seconds: Mapped[int] = mapped_column(default=3600)
    # Default network policy
    network_policy: Mapped[str] = mapped_column(String(64), default="proxy_only")
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    emulator_instances: Mapped[list["EmulatorInstance"]] = relationship(back_populates="profile")


class EmulatorInstance(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Running emulator instance."""

    __tablename__ = "emulator_instances"

    profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("emulator_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Runtime state
    status: Mapped[EmulatorStatus] = mapped_column(
        native_enum(EmulatorStatus), nullable=False, default=EmulatorStatus.STOPPED
    )
    pid: Mapped[int | None] = mapped_column()
    adb_port: Mapped[int | None] = mapped_column()
    vnc_port: Mapped[int | None] = mapped_column()
    # Resource usage
    cpu_percent: Mapped[float] = mapped_column(default=0.0)
    memory_mb: Mapped[int] = mapped_column(default=0)
    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Error tracking
    last_error: Mapped[str | None] = mapped_column(Text)
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    profile: Mapped["EmulatorProfile"] = relationship(back_populates="emulator_instances")
    dynamic_analysis_runs: Mapped[list["DynamicAnalysisRun"]] = relationship(back_populates="emulator_instance")


class DynamicAnalysisRun(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A single dynamic analysis execution within a scan."""

    __tablename__ = "dynamic_analysis_runs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    emulator_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("emulator_instances.id", ondelete="SET NULL"), index=True
    )
    apk_file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("apk_files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Configuration
    test_context: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default"
    )  # default, mitm, frida, full
    network_policy: Mapped[str] = mapped_column(String(64), nullable=False)
    proxy_configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    frida_scripts: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    resource_limits: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    # Runtime state
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )  # pending, preparing, running, completed, failed, cancelled
    # Results summary
    events_captured: Mapped[int] = mapped_column(default=0)
    network_observations: Mapped[int] = mapped_column(default=0)
    file_operations: Mapped[int] = mapped_column(default=0)
    ipc_events: Mapped[int] = mapped_column(default=0)
    crypto_operations: Mapped[int] = mapped_column(default=0)
    # Evidence artifacts
    evidence_artifacts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )  # pcap, logs, screenshots, frida output
    # Correlation
    correlated_static_findings: Mapped[int] = mapped_column(default=0)
    correlated_api_findings: Mapped[int] = mapped_column(default=0)
    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Error tracking
    error: Mapped[str | None] = mapped_column(Text)
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    scan: Mapped["Scan"] = relationship()
    emulator_instance: Mapped["EmulatorInstance"] = relationship(back_populates="dynamic_analysis_runs")
    runtime_events: Mapped[list["RuntimeEvent"]] = relationship(back_populates="analysis_run")
    network_observations: Mapped[list["NetworkObservation"]] = relationship(back_populates="analysis_run")
    file_observations: Mapped[list["FileObservation"]] = relationship(back_populates="analysis_run")
    ipc_observations: Mapped[list["IpcObservation"]] = relationship(back_populates="analysis_run")


class RuntimeEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Normalized runtime event captured during dynamic analysis."""

    __tablename__ = "runtime_events"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Event classification
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # lifecycle, network, file, ipc, crypto, ui, sensor, permission
    event_subtype: Mapped[str | None] = mapped_column(String(128), index=True)
    # Source information
    source_package: Mapped[str | None] = mapped_column(String(255), index=True)
    source_class: Mapped[str | None] = mapped_column(String(512))
    source_method: Mapped[str | None] = mapped_column(String(256))
    # Event data
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Severity and confidence
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="info"
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium"
    )
    # Correlation
    mastg_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    masvs_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    correlated_static_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    correlated_api_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    # Evidence
    evidence_artifacts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )  # screenshots, stack traces, logs
    # Stack trace
    stack_trace: Mapped[str | None] = mapped_column(Text)
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    analysis_run: Mapped["DynamicAnalysisRun"] = relationship(back_populates="runtime_events")


class NetworkObservation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Network traffic observation from dynamic analysis."""

    __tablename__ = "network_observations"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Connection details
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # http, https, ws, wss, tcp, udp
    direction: Mapped[str] = mapped_column(String(16), nullable=False)  # inbound, outbound
    # Source
    source_package: Mapped[str | None] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    source_port: Mapped[int | None] = mapped_column()
    # Destination
    destination_host: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64))
    destination_port: Mapped[int | None] = mapped_column()
    # HTTP details
    http_method: Mapped[str | None] = mapped_column(String(16))
    http_path: Mapped[str | None] = mapped_column(String(2048))
    http_status: Mapped[int | None] = mapped_column()
    request_headers: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    response_headers: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text)
    response_body: Mapped[str | None] = mapped_column(Text)
    # TLS/SSL
    tls_version: Mapped[str | None] = mapped_column(String(32))
    cipher_suite: Mapped[str | None] = mapped_column(String(128))
    certificate_pinned: Mapped[bool] = mapped_column(default=False)
    certificate_valid: Mapped[bool | None] = mapped_column()
    # Timing
    duration_ms: Mapped[int | None] = mapped_column()
    bytes_sent: Mapped[int | None] = mapped_column()
    bytes_received: Mapped[int | None] = mapped_column()
    # Security findings
    is_cleartext: Mapped[bool] = mapped_column(default=False)
    is_suspicious: Mapped[bool] = mapped_column(default=False)
    suspicious_reason: Mapped[str | None] = mapped_column(Text)
    # Correlation
    mastg_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    masvs_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Evidence
    pcap_file: Mapped[str | None] = mapped_column(String(1024))
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    analysis_run: Mapped["DynamicAnalysisRun"] = relationship(back_populates="network_observations")


class FileObservation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """File system operation observation."""

    __tablename__ = "file_observations"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Operation details
    operation: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # read, write, create, delete, modify, permission_change
    # File details
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    file_size: Mapped[int | None] = mapped_column()
    file_hash: Mapped[str | None] = mapped_column(String(64))
    mime_type: Mapped[str | None] = mapped_column(String(128))
    # Source
    source_package: Mapped[str | None] = mapped_column(String(255), index=True)
    source_class: Mapped[str | None] = mapped_column(String(512))
    source_method: Mapped[str | None] = mapped_column(String(256))
    # Permissions
    old_permissions: Mapped[str | None] = mapped_column(String(16))
    new_permissions: Mapped[str | None] = mapped_column(String(16))
    # Content analysis
    contains_sensitive_data: Mapped[bool] = mapped_column(default=False)
    sensitive_patterns: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Correlation
    mastg_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    masvs_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Evidence
    file_snapshot: Mapped[str | None] = mapped_column(String(1024))
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    analysis_run: Mapped["DynamicAnalysisRun"] = relationship(back_populates="file_observations")


class IpcObservation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Inter-Process Communication observation."""

    __tablename__ = "ipc_observations"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # IPC type
    ipc_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # intent, binder, content_provider, broadcast, service, messenger
    # Source
    source_package: Mapped[str | None] = mapped_column(String(255), index=True)
    source_component: Mapped[str | None] = mapped_column(String(512))
    # Destination
    destination_package: Mapped[str | None] = mapped_column(String(255), index=True)
    destination_component: Mapped[str | None] = mapped_column(String(512))
    # Intent details
    action: Mapped[str | None] = mapped_column(String(256))
    categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    data_uri: Mapped[str | None] = mapped_column(String(2048))
    mime_type: Mapped[str | None] = mapped_column(String(128))
    extras: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    flags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Security
    exported: Mapped[bool | None] = mapped_column()
    permission_required: Mapped[str | None] = mapped_column(String(256))
    # Correlation
    mastg_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    masvs_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Evidence
    intent_dump: Mapped[str | None] = mapped_column(Text)
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    # Relationships
    analysis_run: Mapped["DynamicAnalysisRun"] = relationship(back_populates="ipc_observations")


class DynamicAnalysisEvidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Evidence artifacts from dynamic analysis (pcap, screenshots, logs, etc.)."""

    __tablename__ = "dynamic_analysis_evidence"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Evidence details
    evidence_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # pcap, screenshot, logcat, frida_output, heap_dump, trace
    # Storage
    storage: Mapped[str] = mapped_column(String(16), nullable=False, default="inline")  # inline, object
    content: Mapped[str | None] = mapped_column(Text)
    object_key: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    # Redaction
    redacted: Mapped[bool] = mapped_column(default=False)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Context
    description: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Metadata
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )