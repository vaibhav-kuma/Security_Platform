"""Graph Service for managing asset and finding graphs."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.relationship_engine import RelationshipEngine, get_relationship_engine
from app.db.session import get_engine, make_session_factory
from app.models.graph import (
    AssetNode,
    AssetEdge,
    GraphSnapshot,
    GraphQuery,
    AssetNodeType,
    RelationshipType,
    RelationshipConfidence,
)
from app.models.finding_graph import (
    FindingGraphNode,
    FindingGraphEdge,
    FindingCluster,
    AttackPath,
    FindingGraphSnapshot,
    FindingRelationshipType,
)
from app.models.assets import Asset
from app.models.detection import Finding, Observation
from app.models.projects import Project
from app.models.enums import ScopeStatus


def get_db_session() -> Session:
    """Get a new database session."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


class AssetGraphService:
    """Service for managing the asset graph."""

    def __init__(self, db: Session | None = None):
        self.db = db or get_db_session()
        self.relationship_engine = get_relationship_engine(self.db)

    # Node CRUD
    def create_node(
        self,
        project_id: UUID,
        node_type: AssetNodeType,
        name: str,
        display_name: str | None = None,
        description: str | None = None,
        asset_id: UUID | None = None,
        finding_id: UUID | None = None,
        observation_id: UUID | None = None,
        scan_id: UUID | None = None,
        scan_job_id: UUID | None = None,
        scope_status: str = "unknown",
        is_authorized: bool = False,
        properties: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AssetNode:
        """Create a new asset node."""
        now = datetime.now(UTC)
        node = AssetNode(
            project_id=project_id,
            node_type=node_type.value,
            name=name,
            display_name=display_name,
            description=description,
            asset_id=asset_id,
            finding_id=finding_id,
            observation_id=observation_id,
            scan_id=scan_id,
            scan_job_id=scan_job_id,
            scope_status=scope_status,
            is_authorized=is_authorized,
            properties=properties or {},
            tags=tags or [],
            metadata=metadata or {},
            first_seen_at=now,
            last_seen_at=now,
        )
        self.db.add(node)
        self.db.flush()
        return node

    def get_node(self, node_id: UUID) -> AssetNode | None:
        """Get node by ID."""
        return self.db.get(AssetNode, node_id)

    def update_node(
        self,
        node_id: UUID,
        display_name: str | None = None,
        description: str | None = None,
        scope_status: str | None = None,
        is_authorized: bool | None = None,
        properties: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        layout_x: float | None = None,
        layout_y: float | None = None,
    ) -> AssetNode | None:
        """Update node properties."""
        node = self.db.get(AssetNode, node_id)
        if not node:
            return None
        
        if display_name is not None:
            node.display_name = display_name
        if description is not None:
            node.description = description
        if scope_status is not None:
            node.scope_status = scope_status
        if is_authorized is not None:
            node.is_authorized = is_authorized
        if properties is not None:
            node.properties = {**node.properties, **properties}
        if tags is not None:
            node.tags = tags
        if metadata is not None:
            node.metadata = {**node.metadata, **metadata}
        if layout_x is not None:
            node.layout_x = layout_x
        if layout_y is not None:
            node.layout_y = layout_y
        
        node.last_seen_at = datetime.now(UTC)
        self.db.flush()
        return node

    def delete_node(self, node_id: UUID) -> bool:
        """Soft delete a node."""
        node = self.db.get(AssetNode, node_id)
        if not node:
            return False
        node.deleted_at = datetime.now(UTC)
        self.db.flush()
        return True

    def list_nodes(
        self,
        project_id: UUID,
        node_type: AssetNodeType | None = None,
        scope_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AssetNode], int]:
        """List nodes with filters."""
        query = select(AssetNode).where(
            AssetNode.project_id == project_id,
            AssetNode.deleted_at.is_(None)
        )
        
        if node_type:
            query = query.where(AssetNode.node_type == node_type.value)
        if scope_status:
            query = query.where(AssetNode.scope_status == scope_status)
        
        total = self.db.scalar(
            select(AssetNode.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(AssetNode.last_seen_at.desc()).limit(limit).offset(offset)
        nodes = self.db.scalars(query).all()
        
        return list(nodes), total

    # Edge CRUD
    def create_edge(
        self,
        project_id: UUID,
        source_id: UUID,
        target_id: UUID,
        relationship_type: RelationshipType,
        confidence: RelationshipConfidence = RelationshipConfidence.MEDIUM,
        is_inferred: bool = False,
        source: str = "manual",
        evidence: list[dict[str, Any]] | None = None,
        properties: dict[str, Any] | None = None,
        created_by: UUID | None = None,
    ) -> AssetEdge:
        """Create a new asset edge."""
        # Check for existing
        existing = self.db.scalar(
            select(AssetEdge).where(
                AssetEdge.source_id == source_id,
                AssetEdge.target_id == target_id,
                AssetEdge.relationship_type == relationship_type.value
            )
        )
        if existing:
            return existing
        
        now = datetime.now(UTC)
        edge = AssetEdge(
            project_id=project_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type.value,
            confidence=confidence.value,
            is_inferred=is_inferred,
            source=source,
            evidence=evidence or [],
            properties=properties or {},
            created_by=created_by,
            first_seen_at=now,
            last_seen_at=now,
        )
        self.db.add(edge)
        self.db.flush()
        return edge

    def get_edge(self, edge_id: UUID) -> AssetEdge | None:
        """Get edge by ID."""
        return self.db.get(AssetEdge, edge_id)

    def update_edge(
        self,
        edge_id: UUID,
        confidence: RelationshipConfidence | None = None,
        evidence: list[dict[str, Any]] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> AssetEdge | None:
        """Update edge properties."""
        edge = self.db.get(AssetEdge, edge_id)
        if not edge:
            return None
        
        if confidence is not None:
            edge.confidence = confidence.value
        if evidence is not None:
            edge.evidence = evidence
        if properties is not None:
            edge.properties = {**edge.properties, **properties}
        
        edge.last_seen_at = datetime.now(UTC)
        self.db.flush()
        return edge

    def delete_edge(self, edge_id: UUID) -> bool:
        """Delete an edge."""
        edge = self.db.get(AssetEdge, edge_id)
        if not edge:
            return False
        self.db.delete(edge)
        self.db.flush()
        return True

    def list_edges(
        self,
        project_id: UUID,
        relationship_type: RelationshipType | None = None,
        source_id: UUID | None = None,
        target_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AssetEdge], int]:
        """List edges with filters."""
        query = select(AssetEdge).where(AssetEdge.project_id == project_id)
        
        if relationship_type:
            query = query.where(AssetEdge.relationship_type == relationship_type.value)
        if source_id:
            query = query.where(AssetEdge.source_id == source_id)
        if target_id:
            query = query.where(AssetEdge.target_id == target_id)
        
        total = self.db.scalar(
            select(AssetEdge.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(AssetEdge.last_seen_at.desc()).limit(limit).offset(offset)
        edges = self.db.scalars(query).all()
        
        return list(edges), total

    # Graph Operations
    def infer_relationships(self, project_id: UUID, dry_run: bool = True) -> list[dict[str, Any]]:
        """Infer relationships for a project."""
        return self.relationship_engine.infer_relationships(project_id, dry_run=dry_run)

    def get_related_nodes(
        self,
        node_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
        direction: str = "both",
        max_depth: int = 1,
    ) -> list[dict[str, Any]]:
        """Get nodes related to a given node."""
        return self.relationship_engine.get_related_nodes(
            node_id=node_id,
            relationship_types=relationship_types,
            direction=direction,
            max_depth=max_depth,
        )

    def find_path(
        self,
        source_id: UUID,
        target_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
        max_depth: int = 10,
    ) -> list[dict[str, Any]] | None:
        """Find shortest path between two nodes."""
        return self.relationship_engine.find_path(
            source_id=source_id,
            target_id=target_id,
            relationship_types=relationship_types,
            max_depth=max_depth,
        )

    def get_subgraph(
        self,
        project_id: UUID,
        center_node_id: UUID,
        max_depth: int = 2,
        relationship_types: list[RelationshipType] | None = None,
    ) -> dict[str, Any]:
        """Extract subgraph around a center node."""
        return self.relationship_engine.get_subgraph(
            project_id=project_id,
            center_node_id=center_node_id,
            max_depth=max_depth,
            relationship_types=relationship_types,
        )

    def calculate_centrality(
        self,
        project_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
    ) -> dict[str, float]:
        """Calculate degree centrality for all nodes."""
        return self.relationship_engine.calculate_centrality(project_id)

    def update_scope_status(self, project_id: UUID) -> dict[str, int]:
        """Update scope status for all nodes."""
        return self.relationship_engine.update_scope_status(project_id)

    # Graph Snapshots
    def create_snapshot(
        self,
        project_id: UUID,
        name: str,
        description: str | None = None,
        scan_id: UUID | None = None,
        tags: list[str] | None = None,
    ) -> GraphSnapshot:
        """Create a graph snapshot."""
        # Get all nodes and edges
        nodes = self.db.scalars(
            select(AssetNode).where(
                AssetNode.project_id == project_id,
                AssetNode.deleted_at.is_(None)
            )
        ).all()
        
        edges = self.db.scalars(
            select(AssetEdge).where(AssetEdge.project_id == project_id)
        ).all()
        
        snapshot = GraphSnapshot(
            project_id=project_id,
            scan_id=scan_id,
            name=name,
            description=description,
            nodes=[{
                "id": str(n.id),
                "node_type": n.node_type,
                "name": n.name,
                "display_name": n.display_name,
                "scope_status": n.scope_status,
                "is_authorized": n.is_authorized,
                "properties": n.properties,
                "first_seen_at": n.first_seen_at.isoformat() if n.first_seen_at else None,
                "last_seen_at": n.last_seen_at.isoformat() if n.last_seen_at else None,
            } for n in nodes],
            edges=[{
                "id": str(e.id),
                "source_id": str(e.source_id),
                "target_id": str(e.target_id),
                "relationship_type": e.relationship_type,
                "confidence": e.confidence,
                "is_inferred": e.is_inferred,
            } for e in self.db.scalars(
                select(AssetEdge).where(AssetEdge.project_id == project_id)
            ).all()],
            node_count=len(nodes),
            edge_count=0,  # Will be updated
            tags=tags or [],
        )
        self.db.add(snapshot)
        self.db.flush()
        return snapshot

    def list_snapshots(
        self,
        project_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[GraphSnapshot], int]:
        """List graph snapshots."""
        query = select(GraphSnapshot).where(GraphSnapshot.project_id == project_id)
        total = self.db.scalar(
            select(GraphSnapshot.id).select_from(query.subquery()).count()
        )
        query = query.order_by(GraphSnapshot.created_at.desc()).limit(limit).offset(offset)
        snapshots = self.db.scalars(query).all()
        return list(snapshots), total


class FindingGraphService:
    """Service for managing the finding graph."""

    def __init__(self, db: Session | None = None):
        self.db = db or get_db_session()

    # Finding Graph Node CRUD
    def create_finding_node(
        self,
        project_id: UUID,
        finding_id: UUID,
        asset_id: UUID | None = None,
        title: str = "",
        vulnerability_type: str = "",
        severity: str = "low",
        confidence: str = "medium",
        status: str = "open",
        cvss_vector: str | None = None,
        cvss_score: float | None = None,
        location: str | None = None,
        asset_name: str | None = None,
        asset_type: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FindingGraphNode:
        """Create a finding graph node."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")
        
        node = FindingGraphNode(
            project_id=project_id,
            finding_id=finding_id,
            asset_id=asset_id,
            title=finding.title or title,
            vulnerability_type=finding.vulnerability_type or vulnerability_type,
            severity=finding.severity.value if finding.severity else severity,
            confidence=finding.confidence.value if finding.confidence else confidence,
            status=finding.status.value if finding.status else status,
            cvss_vector=finding.cvss_vector or cvss_vector,
            cvss_score=finding.cvss_score or cvss_score,
            location=finding.location or location,
            asset_name=asset_name,
            asset_type=asset_type,
            tags=tags or [],
            metadata=metadata or {},
        )
        self.db.add(node)
        self.db.flush()
        return node

    def get_finding_node(self, node_id: UUID) -> FindingGraphNode | None:
        return self.db.get(FindingGraphNode, node_id)

    def get_finding_node_by_finding(self, finding_id: UUID) -> FindingGraphNode | None:
        return self.db.scalar(
            select(FindingGraphNode).where(FindingGraphNode.finding_id == finding_id)
        )

    def update_finding_node(
        self,
        node_id: UUID,
        title: str | None = None,
        vulnerability_type: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        status: str | None = None,
        cvss_vector: str | None = None,
        cvss_score: float | None = None,
        layout_x: float | None = None,
        layout_y: float | None = None,
    ) -> FindingGraphNode | None:
        node = self.db.get(FindingGraphNode, node_id)
        if not node:
            return None
        
        if title is not None:
            node.title = title
        if vulnerability_type is not None:
            node.vulnerability_type = vulnerability_type
        if severity is not None:
            node.severity = severity
        if confidence is not None:
            node.confidence = confidence
        if status is not None:
            node.status = status
        if cvss_vector is not None:
            node.cvss_vector = cvss_vector
        if cvss_score is not None:
            node.cvss_score = cvss_score
        if layout_x is not None:
            node.layout_x = layout_x
        if layout_y is not None:
            node.layout_y = layout_y
        
        self.db.flush()
        return node

    def delete_finding_node(self, node_id: UUID) -> bool:
        node = self.db.get(FindingGraphNode, node_id)
        if not node:
            return False
        node.deleted_at = datetime.now(UTC)
        self.db.flush()
        return True

    def list_finding_nodes(
        self,
        project_id: UUID,
        severity: str | None = None,
        status: str | None = None,
        vulnerability_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[FindingGraphNode], int]:
        query = select(FindingGraphNode).where(
            FindingGraphNode.project_id == project_id,
            FindingGraphNode.deleted_at.is_(None)
        )
        
        if severity:
            query = query.where(FindingGraphNode.severity == severity)
        if status:
            query = query.where(FindingGraphNode.status == status)
        if vulnerability_type:
            query = query.where(FindingGraphNode.vulnerability_type == vulnerability_type)
        
        total = self.db.scalar(
            select(FindingGraphNode.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(FindingGraphNode.created_at.desc()).limit(limit).offset(offset)
        nodes = self.db.scalars(query).all()
        
        return list(nodes), total

    # Finding Graph Edge CRUD
    def create_finding_edge(
        self,
        project_id: UUID,
        source_id: UUID,
        target_id: UUID,
        relationship_type: FindingRelationshipType,
        confidence: str = "medium",
        is_inferred: bool = False,
        source: str = "manual",
        evidence: list[dict[str, Any]] | None = None,
        description: str | None = None,
        properties: dict[str, Any] | None = None,
        created_by: UUID | None = None,
    ) -> FindingGraphEdge:
        """Create a finding graph edge."""
        existing = self.db.scalar(
            select(FindingGraphEdge).where(
                FindingGraphEdge.source_id == source_id,
                FindingGraphEdge.target_id == target_id,
                FindingGraphEdge.relationship_type == relationship_type.value
            )
        )
        if existing:
            return existing
        
        edge = FindingGraphEdge(
            project_id=project_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type.value,
            confidence=confidence,
            is_inferred=is_inferred,
            source=source,
            evidence=evidence or [],
            description=description,
            properties=properties or {},
            created_by=created_by,
        )
        self.db.add(edge)
        self.db.flush()
        return edge

    def get_finding_edge(self, edge_id: UUID) -> FindingGraphEdge | None:
        return self.db.get(FindingGraphEdge, edge_id)

    def list_finding_edges(
        self,
        project_id: UUID,
        relationship_type: FindingRelationshipType | None = None,
        source_id: UUID | None = None,
        target_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[FindingGraphEdge], int]:
        query = select(FindingGraphEdge).where(FindingGraphEdge.project_id == project_id)
        
        if relationship_type:
            query = query.where(FindingGraphEdge.relationship_type == relationship_type.value)
        if source_id:
            query = query.where(FindingGraphEdge.source_id == source_id)
        if target_id:
            query = query.where(FindingGraphEdge.target_id == target_id)
        
        total = self.db.scalar(
            select(FindingGraphEdge.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(FindingGraphEdge.created_at.desc()).limit(limit).offset(offset)
        edges = self.db.scalars(query).all()
        
        return list(edges), total

    # Finding Clusters
    def create_cluster(
        self,
        project_id: UUID,
        name: str,
        primary_finding_id: UUID,
        member_finding_ids: list[UUID],
        description: str | None = None,
        cluster_type: str = "related",
        cluster_confidence: str = "medium",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FindingCluster:
        """Create a finding cluster."""
        # Get member nodes
        member_nodes = self.db.scalars(
            select(FindingGraphNode).where(FindingGraphNode.finding_id.in_(member_finding_ids))
        ).all()
        
        max_severity = "info"
        max_confidence = "low"
        vuln_types = set()
        assets = set()
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        confidence_order = {"confirmed": 3, "high": 2, "medium": 1, "low": 0}
        
        for node in member_nodes:
            if severity_order.get(node.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = node.severity
            if confidence_order.get(node.confidence, 0) > confidence_order.get(max_confidence, 0):
                max_confidence = node.confidence
            vuln_types.add(node.vulnerability_type)
            if node.asset_id:
                assets.add(str(node.asset_id))
        
        cluster = FindingCluster(
            project_id=project_id,
            name=name,
            description=description,
            primary_finding_id=member_finding_ids[0],
            member_finding_ids=member_finding_ids,
            total_findings=len(member_finding_ids),
            max_severity=max_severity,
            max_confidence=max_confidence,
            unique_vulnerability_types=len(vuln_types),
            unique_assets=len(assets),
            cluster_type=cluster_type,
            cluster_confidence=cluster_confidence,
            tags=tags or [],
            metadata=metadata or {},
        )
        self.db.add(cluster)
        self.db.flush()
        return cluster

    def get_cluster(self, cluster_id: UUID) -> FindingCluster | None:
        return self.db.get(FindingCluster, cluster_id)

    def list_clusters(
        self,
        project_id: UUID,
        cluster_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FindingCluster], int]:
        query = select(FindingCluster).where(FindingCluster.project_id == project_id)
        
        if cluster_type:
            query = query.where(FindingCluster.cluster_type == cluster_type)
        
        total = self.db.scalar(
            select(FindingCluster.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(FindingCluster.created_at.desc()).limit(limit).offset(offset)
        clusters = self.db.scalars(query).all()
        
        return list(clusters), total

    # Attack Paths
    def create_attack_path(
        self,
        project_id: UUID,
        name: str,
        step_finding_ids: list[UUID],
        step_types: list[str],
        description: str | None = None,
        entry_point: str | None = None,
        target_asset: str | None = None,
        tags: list[str] | None = None,
    ) -> AttackPath:
        """Create an attack path."""
        finding_nodes = self.db.scalars(
            select(FindingGraphNode).where(FindingGraphNode.finding_id.in_(step_finding_ids))
        ).all()
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = "info"
        for node in finding_nodes:
            if severity_order.get(node.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = node.severity
        
        path = AttackPath(
            project_id=project_id,
            name=name,
            description=description,
            step_finding_ids=step_finding_ids,
            step_types=step_types,
            total_steps=len(step_finding_ids),
            max_severity=max_severity,
            path_confidence="medium",
            estimated_impact="medium",
            entry_point=entry_point,
            target_asset=target_asset,
            tags=tags or [],
        )
        self.db.add(path)
        self.db.flush()
        return path

    def get_attack_path(self, path_id: UUID) -> AttackPath | None:
        return self.db.get(AttackPath, path_id)

    def list_attack_paths(
        self,
        project_id: UUID,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AttackPath], int]:
        query = select(AttackPath).where(AttackPath.project_id == project_id)
        
        if status:
            query = query.where(AttackPath.status == status)
        
        total = self.db.scalar(
            select(AttackPath.id).select_from(query.subquery()).count()
        )
        
        query = query.order_by(AttackPath.created_at.desc()).limit(limit).offset(offset)
        paths = self.db.scalars(query).all()
        
        return list(paths), total

    # Finding Graph Snapshots
    def create_snapshot(
        self,
        project_id: UUID,
        name: str,
        description: str | None = None,
        scan_id: UUID | None = None,
        tags: list[str] | None = None,
    ) -> FindingGraphSnapshot:
        """Create a finding graph snapshot."""
        nodes = self.db.scalars(
            select(FindingGraphNode).where(
                FindingGraphNode.project_id == project_id,
                FindingGraphNode.deleted_at.is_(None)
            )
        ).all()
        
        edges = self.db.scalars(
            select(FindingGraphEdge).where(FindingGraphEdge.project_id == project_id)
        ).all()
        
        clusters = self.db.scalars(
            select(FindingCluster).where(FindingCluster.project_id == project_id)
        ).all()
        
        attack_paths = self.db.scalars(
            select(AttackPath).where(AttackPath.project_id == project_id)
        ).all()
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = "info"
        for node in nodes:
            if severity_order.get(node.severity, 0) > severity_order.get(max_severity, 0):
                max_severity = node.severity
        
        snapshot = FindingGraphSnapshot(
            project_id=project_id,
            scan_id=scan_id,
            name=name,
            description=description,
            nodes=[{
                "id": str(n.id),
                "finding_id": str(n.finding_id),
                "title": n.title,
                "vulnerability_type": n.vulnerability_type,
                "severity": n.severity,
                "confidence": n.confidence,
                "status": n.status,
            } for n in nodes],
            edges=[{
                "id": str(e.id),
                "source_id": str(e.source_id),
                "target_id": str(e.target_id),
                "relationship_type": e.relationship_type,
                "confidence": e.confidence,
                "is_inferred": e.is_inferred,
            } for e in self.db.scalars(
                select(FindingGraphEdge).where(FindingGraphEdge.project_id == project_id)
            ).all()],
            clusters=[{
                "id": str(c.id),
                "name": c.name,
                "primary_finding_id": str(c.primary_finding_id),
                "member_finding_ids": [str(f) for f in c.member_finding_ids],
            } for c in clusters],
            attack_paths=[{
                "id": str(p.id),
                "name": p.name,
                "step_finding_ids": [str(f) for f in p.step_finding_ids],
            } for p in attack_paths],
            node_count=len(nodes),
            edge_count=0,
            cluster_count=len(clusters),
            attack_path_count=0,
            tags=tags or [],
        )
        self.db.add(snapshot)
        self.db.flush()
        return snapshot


class GraphService:
    """Unified graph service combining asset and finding graphs."""

    def __init__(self, db: Session | None = None):
        self.db = db or get_db_session()
        self.asset_graph = AssetGraphService(db)
        self.finding_graph = FindingGraphService(db)
        self.relationship_engine = get_relationship_engine(db)

    def sync_from_assets(self, project_id: UUID) -> dict[str, int]:
        """
        Sync asset graph from existing assets.
        
        Creates nodes for all assets and infers relationships.
        """
        # Get all assets for project
        assets = self.db.scalars(
            select(Asset).where(Asset.project_id == project_id)
        ).all()
        
        created_nodes = 0
        created_edges = 0
        
        for asset in assets:
            # Check if node already exists
            existing = self.db.scalar(
                select(AssetNode).where(
                    AssetNode.project_id == project_id,
                    AssetNode.asset_id == asset.id
                )
            )
            
            if not existing:
                # Map asset kind to node type
                type_map = {
                    "domain": AssetNodeType.DOMAIN,
                    "subdomain": AssetNodeType.SUBDOMAIN,
                    "ip_address": AssetNodeType.IP_ADDRESS,
                    "cidr": AssetNodeType.CIDR,
                    "url": AssetNodeType.URL,
                    "endpoint": AssetNodeType.API_ENDPOINT,
                    "apk": AssetNodeType.APK,
                }
                node_type = type_map.get(asset.kind.value, AssetNodeType.DOMAIN)
                
                node = AssetNode(
                    project_id=project_id,
                    node_type=node_type.value,
                    name=asset.value,
                    display_name=asset.name or asset.value,
                    asset_id=asset.id,
                    scope_status=asset.scope_status.value if asset.scope_status else "unknown",
                    is_authorized=asset.scope_status == ScopeStatus.IN_SCOPE if asset.scope_status else False,
                    properties=asset.attributes or {},
                    first_seen_at=asset.created_at,
                    last_seen_at=asset.updated_at,
                )
                self.db.add(node)
                created_nodes += 1
        
        self.db.flush()
        
        # Infer relationships
        inferred = self.relationship_engine.infer_relationships(project_id, dry_run=False)
        
        return {"created_nodes": created_nodes, "inferred_edges": len(inferred)}

    def sync_from_findings(self, project_id: UUID) -> dict[str, int]:
        """
        Sync finding graph from existing findings.
        """
        findings = self.db.scalars(
            select(Finding).where(Finding.project_id == project_id)
        ).all()
        
        created_nodes = 0
        
        for finding in findings:
            existing = self.db.scalar(
                select(FindingGraphNode).where(
                    FindingGraphNode.finding_id == finding.id
                )
            )
            
            if not existing:
                asset = self.db.get(Asset, finding.asset_id) if finding.asset_id else None
                
                node = FindingGraphNode(
                    project_id=project_id,
                    finding_id=finding.id,
                    asset_id=finding.asset_id,
                    title=finding.title,
                    vulnerability_type=finding.vulnerability_type or "unknown",
                    severity=finding.severity.value if finding.severity else "info",
                    confidence=finding.confidence.value if finding.confidence else "medium",
                    status=finding.status.value if finding.status else "open",
                    cvss_vector=finding.cvss_vector,
                    cvss_score=finding.cvss_score,
                    location=finding.location,
                    asset_name=asset.value if asset else None,
                    asset_type=asset.kind.value if asset else None,
                )
                self.db.add(node)
                created_nodes += 1
        
        self.db.flush()
        
        # Create edges based on correlation
        # This would use the correlation engine
        
        return {"created_nodes": created_nodes, "created_edges": 0}

    def export_graph(
        self,
        project_id: UUID,
        format: str = "json",  # json, graphml, cypher
        include_finding_graph: bool = True,
    ) -> str | dict[str, Any]:
        """
        Export graph in various formats.
        """
        # Get asset graph
        asset_nodes = self.db.scalars(
            select(AssetNode).where(
                AssetNode.project_id == project_id,
                AssetNode.deleted_at.is_(None)
            )
        ).all()
        
        asset_edges = self.db.scalars(
            select(AssetEdge).where(AssetEdge.project_id == project_id)
        ).all()
        
        result = {
            "project_id": str(project_id),
            "exported_at": datetime.now(UTC).isoformat(),
            "asset_graph": {
                "nodes": [{
                    "id": str(n.id),
                    "node_type": n.node_type,
                    "name": n.name,
                    "display_name": n.display_name,
                    "scope_status": n.scope_status,
                    "is_authorized": n.is_authorized,
                    "properties": n.properties,
                } for n in asset_nodes],
                "edges": [{
                    "id": str(e.id),
                    "source_id": str(e.source_id),
                    "target_id": str(e.target_id),
                    "relationship_type": e.relationship_type,
                    "confidence": e.confidence,
                    "is_inferred": e.is_inferred,
                } for e in self.db.scalars(
                    select(AssetEdge).where(AssetEdge.project_id == project_id)
                ).all()],
            },
        }
        
        if include_finding_graph:
            finding_nodes = self.db.scalars(
                select(FindingGraphNode).where(
                    FindingGraphNode.project_id == project_id,
                    FindingGraphNode.deleted_at.is_(None)
                )
            ).all()
            
            finding_edges = self.db.scalars(
                select(FindingGraphEdge).where(FindingGraphEdge.project_id == project_id)
            ).all()
            
            result["finding_graph"] = {
                "nodes": [{
                    "id": str(n.id),
                    "finding_id": str(n.finding_id),
                    "title": n.title,
                    "vulnerability_type": n.vulnerability_type,
                    "severity": n.severity,
                    "confidence": n.confidence,
                    "status": n.status,
                } for n in finding_nodes],
                "edges": [{
                    "id": str(e.id),
                    "source_id": str(e.source_id),
                    "target_id": str(e.target_id),
                    "relationship_type": e.relationship_type,
                    "confidence": e.confidence,
                    "is_inferred": e.is_inferred,
                } for e in self.db.scalars(
                    select(FindingGraphEdge).where(FindingGraphEdge.project_id == project_id)
                ).all()],
            }
        
        if format == "json":
            return result
        elif format == "graphml":
            return self._to_graphml(result)
        elif format == "cypher":
            return self._to_cypher(result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _to_graphml(self, data: dict[str, Any]) -> str:
        """Convert to GraphML format."""
        # Simplified GraphML output
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                 '  <key id="name" for="node" attr.name="name" attr.type="string"/>',
                 '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
                 '  <key id="relationship" for="edge" attr.name="relationship" attr.type="string"/>',
                 '  <graph id="G" edgedefault="directed">']
        
        for node in data["asset_graph"]["nodes"]:
            lines.append(f'    <node id="{node["id"]}">')
            lines.append(f'      <data key="name">{node["name"]}</data>')
            lines.append(f'      <data key="type">{node["node_type"]}</data>')
            lines.append(f'    </node>')
        
        for edge in data["asset_graph"]["edges"]:
            lines.append(f'    <edge id="{edge["id"]}" source="{edge["source_id"]}" target="{edge["target_id"]}">')
            lines.append(f'      <data key="relationship">{edge["relationship_type"]}</data>')
            lines.append(f'    </edge>')
        
        lines.append('  </graph>')
        lines.append('</graphml>')
        
        return "\n".join(lines)

    def _to_cypher(self, data: dict[str, Any]) -> str:
        """Convert to Cypher format for Neo4j."""
        lines = []
        
        for node in data["asset_graph"]["nodes"]:
            props = {
                "name": node["name"],
                "node_type": node["node_type"],
                "scope_status": node.get("scope_status", "unknown"),
                "is_authorized": node.get("is_authorized", False),
            }
            prop_str = ", ".join(f'{k}: "{v}"' for k, v in props.items())
            lines.append(f'CREATE (n:{node["node_type"]} {{{prop_str}}})')
        
        for edge in data["asset_graph"]["edges"]:
            lines.append(
                f'MATCH (a {{id: "{edge["source_id"]}"}}), (b {{id: "{edge["target_id"]}"}}) '
                f'CREATE (a)-[:{edge["relationship_type"].upper()}]->(b)'
            )
        
        return "\n".join(lines)


# Celery tasks
@celery_app.task(bind=True, name="app.graph.tasks.sync_project_graph")
def sync_project_graph(self, project_id: str) -> dict[str, Any]:
    """Sync graph for a project."""
    from uuid import UUID
    service = GraphService()
    result = service.sync_from_assets(UUID(project_id))
    return result


@celery_app.task(bind=True, name="app.graph.tasks.sync_findings_graph")
def sync_findings_graph(self, project_id: str) -> dict[str, Any]:
    """Sync finding graph for a project."""
    from uuid import UUID
    service = GraphService()
    result = service.sync_from_findings(UUID(project_id))
    return result


@celery_app.task(bind=True, name="app.graph.tasks.infer_relationships")
def infer_relationships_task(self, project_id: str, dry_run: bool = False) -> dict[str, Any]:
    """Infer relationships for a project."""
    from uuid import UUID
    service = AssetGraphService()
    inferred = service.infer_relationships(UUID(project_id), dry_run=dry_run)
    return {"inferred": len(inferred), "dry_run": dry_run}


@celery_app.task(bind=True, name="app.graph.tasks.create_graph_snapshot")
def create_graph_snapshot(self, project_id: str, name: str, description: str | None = None) -> dict[str, Any]:
    """Create a graph snapshot."""
    from uuid import UUID
    service = AssetGraphService()
    snapshot = service.create_snapshot(UUID(project_id), name, description)
    return {"snapshot_id": str(snapshot.id)}


@celery_app.task(bind=True, name="app.graph.tasks.update_all_scope_status")
def update_all_scope_status(self, project_id: str) -> dict[str, Any]:
    """Update scope status for all nodes in a project."""
    from uuid import UUID
    service = AssetGraphService()
    result = service.update_scope_status(UUID(project_id))
    return result


def get_asset_graph_service(db: Session | None = None) -> AssetGraphService:
    return AssetGraphService(db)


def get_finding_graph_service(db: Session | None = None) -> FindingGraphService:
    return FindingGraphService(db)


def get_graph_service(db: Session | None = None) -> GraphService:
    return GraphService(db)