"""Finding Graph models for vulnerability relationship mapping."""

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
    from app.models.detection import Finding
    from app.models.assets import Asset
    from app.models.projects import Project


class FindingRelationshipType(str, Enum):
    """Types of relationships between findings."""
    DUPLICATE_OF = "duplicate_of"
    RELATED_TO = "related_to"
    VARIANT_OF = "variant_of"
    PREREQUISITE_FOR = "prerequisite_for"
    CHAINS_TO = "chains_to"
    SAME_ROOT_CAUSE = "same_root_cause"
    EXPLOITS = "exploits"
    ENABLES = "enables"
    MITIGATES = "mitigates"
    INFERRED = "inferred"


class AttackPathStepType(str, Enum):
    """Types of steps in an attack path."""
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class FindingGraphNode(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Node representing a finding in the finding graph."""

    __tablename__ = "finding_graph_nodes"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    
    # Node identification
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    
    # CVSS
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_score: Mapped[float | None] = mapped_column()
    
    # Location
    location: Mapped[str | None] = mapped_column(String(1024))  # URL, parameter, file path, etc.
    asset_name: Mapped[str | None] = mapped_column(String(512))
    asset_type: Mapped[str | None] = mapped_column(String(50))
    
    # Visualization
    layout_x: Mapped[float | None] = mapped_column()
    layout_y: Mapped[float | None] = mapped_column()
    color: Mapped[str | None] = mapped_column(String(20))
    size: Mapped[float | None] = mapped_column()
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    node_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Relationships
    outgoing_edges: Mapped[list["FindingGraphEdge"]] = relationship(
        back_populates="source", foreign_keys="FindingGraphEdge.source_id", lazy="dynamic"
    )
    incoming_edges: Mapped[list["FindingGraphEdge"]] = relationship(
        back_populates="target", foreign_keys="FindingGraphEdge.target_id", lazy="dynamic"
    )
    
    __table_args__ = (
        Index("ix_finding_graph_nodes_project_severity", "project_id", "severity"),
        Index("ix_finding_graph_nodes_project_type", "project_id", "vulnerability_type"),
        Index("ix_finding_graph_nodes_project_status", "project_id", "status"),
    )


class FindingGraphEdge(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Relationship between two findings in the finding graph."""

    __tablename__ = "finding_graph_edges"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    is_inferred: Mapped[bool] = mapped_column(nullable=False, default=False)
    
    # Evidence
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    
    # Description
    description: Mapped[str | None] = mapped_column(Text)
    
    # Properties
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # e.g., {"exploit_chain": true, "shared_parameter": "user_id"}
    
    # Source
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # manual, correlation, scanner, inferred
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    edge_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    # Relationships
    source: Mapped["FindingGraphNode"] = relationship(back_populates="outgoing_edges", foreign_keys=[source_id])
    target: Mapped["FindingGraphNode"] = relationship(back_populates="incoming_edges", foreign_keys=[target_id])
    
    __table_args__ = (
        Index("ix_finding_graph_edges_project_type", "project_id", "relationship_type"),
        Index("ix_finding_graph_edges_source_target", "source_id", "target_id"),
        UniqueConstraint("source_id", "target_id", "relationship_type", name="uq_finding_graph_edge"),
    )


class FindingCluster(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Cluster of related findings."""

    __tablename__ = "finding_clusters"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    
    # Cluster properties
    primary_finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding_graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    member_finding_ids: Mapped[list[uuid.UUID]] = mapped_column(JSONB, nullable=False, default=list)
    
    # Aggregated metrics
    total_findings: Mapped[int] = mapped_column(nullable=False, default=0)
    max_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    max_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    unique_vulnerability_types: Mapped[int] = mapped_column(nullable=False, default=0)
    unique_assets: Mapped[int] = mapped_column(nullable=False, default=0)
    
    # Classification
    cluster_type: Mapped[str] = mapped_column(String(50), nullable=False)  # attack_chain, same_root_cause, technology, component
    cluster_confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    cluster_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AttackPath(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Attack path representing a chain of findings."""

    __tablename__ = "attack_paths"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    
    # Path definition
    step_finding_ids: Mapped[list[uuid.UUID]] = mapped_column(JSONB, nullable=False, default=list)
    step_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    
    # Metrics
    total_steps: Mapped[int] = mapped_column(nullable=False, default=0)
    max_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    path_confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    estimated_impact: Mapped[str] = mapped_column(String(32), nullable=False)  # low, medium, high, critical
    
    # Entry and exit
    entry_point: Mapped[str | None] = mapped_column(String(512))
    target_asset: Mapped[str | None] = mapped_column(String(512))
    
    # Status
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="theoretical")  # theoretical, validated, mitigated
    validated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    cluster_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    
    __table_args__ = (
        Index("ix_attack_paths_project_status", "project_id", "status"),
    )


class FindingGraphSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Snapshot of finding graph for historical analysis."""

    __tablename__ = "finding_graph_snapshots"

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
    clusters: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    attack_paths: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    
    # Statistics
    node_count: Mapped[int] = mapped_column(nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(nullable=False, default=0)
    cluster_count: Mapped[int] = mapped_column(nullable=False, default=0)
    attack_path_count: Mapped[int] = mapped_column(nullable=False, default=0)
    
    # Metadata
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    cluster_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


# Export enums
__all__ = [
    "FindingRelationshipType",
    "AttackPathStepType",
    "FindingGraphNode",
    "FindingGraphEdge",
    "FindingCluster",
    "AttackPath",
    "FindingGraphSnapshot",
]