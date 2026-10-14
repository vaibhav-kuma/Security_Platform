"""Asset Graph models for relationship mapping across the security assessment environment."""

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)

if TYPE_CHECKING:
    from app.models.assets import Asset
    from app.models.detection import Finding, Observation
    from app.models.projects import Project
    from app.models.scans import Scan
    from app.models.scans import ScanJob


class AssetNodeType(str, Enum):
    """Types of nodes in the asset graph."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    URL = "url"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    API_SPECIFICATION = "api_specification"
    TECHNOLOGY = "technology"
    APK = "apk"
    CERTIFICATE = "certificate"
    FINDING = "finding"
    OBSERVATION = "observation"
    TEST_CASE = "test_case"
    METHODOLOGY = "methodology"
    PROJECT = "project"
    SCAN = "scan"
    SCAN_JOB = "scan_job"


class RelationshipType(str, Enum):
    """Types of relationships in the asset graph."""
    # Network relationships
    RESOLVES_TO = "resolves_to"           # domain -> IP
    HOSTS = "hosts"                       # IP -> domain
    SUBDOMAIN_OF = "subdomain_of"         # subdomain -> domain
    SAME_CIDR = "same_cidr"               # IP -> CIDR
    
    # Application relationships
    HOSTS_APPLICATION = "hosts_application"  # IP/domain -> web_application
    BELONGS_TO = "belongs_to"             # API endpoint -> web_application
    COMMUNICATES_WITH = "communicates_with"  # APK -> API endpoint
    EXPOSES = "exposes"                   # web_application -> API endpoint
    
    # Technology relationships
    USES_TECHNOLOGY = "uses_technology"   # asset -> technology
    DETECTED_TECHNOLOGY = "detected_technology"  # asset -> technology (from fingerprint)
    
    # Certificate relationships
    HAS_CERTIFICATE = "has_certificate"   # domain -> certificate
    CERTIFICATE_FOR = "certificate_for"   # certificate -> domain
    SIGNED_BY = "signed_by"               # certificate -> certificate (CA)
    
    # Finding/Observation relationships
    HAS_FINDING = "has_finding"           # asset -> finding
    FINDING_ON = "finding_on"             # finding -> asset
    HAS_OBSERVATION = "has_observation"   # asset -> observation
    OBSERVATION_ON = "observation_on"     # observation -> asset
    DERIVED_FROM = "derived_from"         # finding/observation -> test_case/methodology
    
    # Finding relationships
    DUPLICATE_OF = "duplicate_of"         # finding -> finding
    RELATED_TO = "related_to"             # finding -> finding
    VARIANT_OF = "variant_of"             # finding -> finding
    PREREQUISITE_FOR = "prerequisite_for" # finding -> finding
    CHAINS_TO = "chains_to"               # finding -> finding
    SAME_ROOT_CAUSE = "same_root_cause"   # finding -> finding
    
    # Project/Scan relationships
    PART_OF_PROJECT = "part_of_project"   # asset -> project
    PART_OF_SCAN = "part_of_scan"         # asset -> scan
    EXECUTED_BY = "executed_by"           # scan_job -> asset
    
    # Inferred vs Explicit
    INFERRED = "inferred"                 # inferred relationship
    EXPLICIT = "explicit"                 # explicitly created


class RelationshipConfidence(str, Enum):
    """Confidence levels for relationships."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"  # Manually verified


class AssetNode(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Base node representing any asset in the graph."""

    __tablename__ = "asset_nodes"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    node_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    observation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("observations.id", ondelete="SET NULL"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), index=True
    )
    
    # Identification
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    
    # Scope and authorization
    scope_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")  # unknown, in_scope, out_of_scope
    is_authorized: Mapped[bool] = mapped_column(nullable=False, default=False)
    
    # Timing
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Properties
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # e.g., {"port": 443, "protocol": "https", "fingerprint": "nginx"}
    
    # Visualization
    layout_x: Mapped[float | None] = mapped_column()
    layout_y: Mapped[float | None] = mapped_column()
    color: Mapped[str | None] = mapped_column(String(20))
    size: Mapped[float | None] = mapped_column()
    icon: Mapped[str | None] = mapped_column(String(100))
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    node_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Relationships
    outgoing_edges: Mapped[list["AssetEdge"]] = relationship(
        back_populates="source", foreign_keys="AssetEdge.source_id", lazy="dynamic"
    )
    incoming_edges: Mapped[list["AssetEdge"]] = relationship(
        back_populates="target", foreign_keys="AssetEdge.target_id", lazy="dynamic"
    )
    
    __table_args__ = (
        Index("ix_asset_nodes_project_type", "project_id", "node_type"),
        Index("ix_asset_nodes_asset_id", "asset_id"),
        Index("ix_asset_nodes_finding_id", "finding_id"),
        Index("ix_asset_nodes_scope", "scope_status"),
    )


class AssetEdge(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Relationship between two asset nodes."""

    __tablename__ = "asset_edges"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default=RelationshipConfidence.MEDIUM)
    is_inferred: Mapped[bool] = mapped_column(nullable=False, default=False)
    
    # Evidence
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    # e.g., [{"type": "dns", "record": "A", "value": "1.2.3.4"}, {"type": "http", "header": "Server"}]
    
    # Timing
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    
    # Properties
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # e.g., {"protocol": "https", "port": 443, "method": "GET"}
    
    # Source
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # manual, recon, scanner, inferred
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    edge_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Relationships
    source: Mapped["AssetNode"] = relationship(back_populates="outgoing_edges", foreign_keys=[source_id])
    target: Mapped["AssetNode"] = relationship(back_populates="incoming_edges", foreign_keys=[target_id])
    
    __table_args__ = (
        Index("ix_asset_edges_project_type", "project_id", "relationship_type"),
        Index("ix_asset_edges_source_target", "source_id", "target_id"),
        Index("ix_asset_edges_confidence", "confidence"),
        UniqueConstraint("source_id", "target_id", "relationship_type", name="uq_asset_edge"),
    )


class GraphSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Point-in-time snapshot of the graph for historical analysis."""

    __tablename__ = "graph_snapshots"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    
    # Serialized graph
    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    
    # Statistics
    node_count: Mapped[int] = mapped_column(nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(nullable=False, default=0)
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    snapshot_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class GraphQuery(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Saved graph queries for reuse."""

    __tablename__ = "graph_queries"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    
    # Query definition
    query_type: Mapped[str] = mapped_column(String(50), nullable=False)  # traverse, path, subgraph, centrality
    query_params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Results cache
    cached_results: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    cached_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    
    # Metadata
    is_public: Mapped[bool] = mapped_column(nullable=False, default=False)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)


# Export enums for external use
__all__ = [
    "AssetNodeType",
    "RelationshipType",
    "RelationshipConfidence",
    "AssetNode",
    "AssetEdge",
    "GraphSnapshot",
    "GraphQuery",
]