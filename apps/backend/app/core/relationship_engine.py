"""Relationship Engine for inferring and managing asset relationships."""

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_engine, make_session_factory
from app.models.graph import (
    AssetNode,
    AssetEdge,
    AssetNodeType,
    RelationshipType,
    RelationshipConfidence,
)
from app.models.finding_graph import (
    FindingGraphNode,
    FindingGraphEdge,
    FindingRelationshipType,
)
from app.models.assets import Asset
from app.models.detection import Finding, Observation
from app.models.projects import Target, Scope
from app.core.scope_engine import create_scope_engine, ScopeRuleEffect, ScopeRuleTargetType


def get_db_session() -> Session:
    """Get a new database session."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


class RelationshipInferenceRule:
    """Rule for inferring relationships from asset properties."""
    
    def __init__(
        self,
        name: str,
        source_type: AssetNodeType,
        target_type: AssetNodeType,
        relationship_type: RelationshipType,
        condition: callable,
        confidence: RelationshipConfidence = RelationshipConfidence.MEDIUM,
        is_inferred: bool = True,
    ):
        self.name = name
        self.source_type = source_type
        self.target_type = target_type
        self.relationship_type = relationship_type
        self.condition = condition
        self.confidence = confidence
        self.is_inferred = is_inferred


class RelationshipEngine:
    """Engine for managing and inferring asset relationships."""
    
    def __init__(self, db: Session | None = None):
        self.db = db or get_db_session()
        self._rules: list[RelationshipInferenceRule] = []
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default inference rules."""
        
        # DNS resolution: domain -> IP
        self._rules.append(RelationshipInferenceRule(
            name="dns_resolution",
            source_type=AssetNodeType.DOMAIN,
            target_type=AssetNodeType.IP_ADDRESS,
            relationship_type=RelationshipType.RESOLVES_TO,
            condition=self._check_dns_resolution,
            confidence=RelationshipConfidence.HIGH,
        ))
        
        # Subdomain relationship
        self._rules.append(RelationshipInferenceRule(
            name="subdomain_of",
            source_type=AssetNodeType.SUBDOMAIN,
            target_type=AssetNodeType.DOMAIN,
            relationship_type=RelationshipType.SUBDOMAIN_OF,
            condition=self._check_subdomain,
            confidence=RelationshipConfidence.HIGH,
        ))
        
        # IP in CIDR
        self._rules.append(RelationshipInferenceRule(
            name="ip_in_cidr",
            source_type=AssetNodeType.IP_ADDRESS,
            target_type=AssetNodeType.CIDR,
            relationship_type=RelationshipType.SAME_CIDR,
            condition=self._check_ip_in_cidr,
            confidence=RelationshipConfidence.HIGH,
        ))
        
        # Domain hosts web application
        self._rules.append(RelationshipInferenceRule(
            name="domain_hosts_app",
            source_type=AssetNodeType.DOMAIN,
            target_type=AssetNodeType.WEB_APPLICATION,
            relationship_type=RelationshipType.HOSTS_APPLICATION,
            condition=self._check_domain_hosts_app,
            confidence=RelationshipConfidence.MEDIUM,
        ))
        
        # IP hosts web application
        self._rules.append(RelationshipInferenceRule(
            name="ip_hosts_app",
            source_type=AssetNodeType.IP_ADDRESS,
            target_type=AssetNodeType.WEB_APPLICATION,
            relationship_type=RelationshipType.HOSTS_APPLICATION,
            condition=self._check_ip_hosts_app,
            confidence=RelationshipConfidence.MEDIUM,
        ))
        
        # Web application exposes API endpoint
        self._rules.append(RelationshipInferenceRule(
            name="app_exposes_api",
            source_type=AssetNodeType.WEB_APPLICATION,
            target_type=AssetNodeType.API_ENDPOINT,
            relationship_type=RelationshipType.EXPOSES,
            condition=self._check_app_exposes_api,
            confidence=RelationshipConfidence.MEDIUM,
        ))
        
        # API endpoint belongs to web application
        self._rules.append(RelationshipInferenceRule(
            name="api_belongs_to_app",
            source_type=AssetNodeType.API_ENDPOINT,
            target_type=AssetNodeType.WEB_APPLICATION,
            relationship_type=RelationshipType.BELONGS_TO,
            condition=self._check_api_belongs_to_app,
            confidence=RelationshipConfidence.HIGH,
        ))
        
        # APK communicates with API
        self._rules.append(RelationshipInferenceRule(
            name="apk_communicates_api",
            source_type=AssetNodeType.APK,
            target_type=AssetNodeType.API_ENDPOINT,
            relationship_type=RelationshipType.COMMUNICATES_WITH,
            condition=self._check_apk_communicates_api,
            confidence=RelationshipConfidence.MEDIUM,
        ))
        
        # Asset uses technology
        self._rules.append(RelationshipInferenceRule(
            name="asset_uses_technology",
            source_type=AssetNodeType.DOMAIN,
            target_type=AssetNodeType.TECHNOLOGY,
            relationship_type=RelationshipType.USES_TECHNOLOGY,
            condition=self._check_asset_uses_technology,
            confidence=RelationshipConfidence.MEDIUM,
        ))
        
        # Domain has certificate
        self._rules.append(RelationshipInferenceRule(
            name="domain_has_certificate",
            source_type=AssetNodeType.DOMAIN,
            target_type=AssetNodeType.CERTIFICATE,
            relationship_type=RelationshipType.HAS_CERTIFICATE,
            condition=self._check_domain_has_certificate,
            confidence=RelationshipConfidence.HIGH,
        ))
        
        # Finding on asset
        self._rules.append(RelationshipInferenceRule(
            name="finding_on_asset",
            source_type=AssetNodeType.FINDING,
            target_type=AssetNodeType.DOMAIN,  # Can be any asset type
            relationship_type=RelationshipType.HAS_FINDING,
            condition=self._check_finding_on_asset,
            confidence=RelationshipConfidence.CONFIRMED,
        ))
        
        # Observation on asset
        self._rules.append(RelationshipInferenceRule(
            name="observation_on_asset",
            source_type=AssetNodeType.OBSERVATION,
            target_type=AssetNodeType.DOMAIN,
            relationship_type=RelationshipType.HAS_OBSERVATION,
            condition=self._check_observation_on_asset,
            confidence=RelationshipConfidence.CONFIRMED,
        ))
    
    # Condition functions
    def _check_dns_resolution(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if domain resolves to IP."""
        if source.node_type == AssetNodeType.DOMAIN and target.node_type == AssetNodeType.IP_ADDRESS:
            return target.properties.get("resolves_to") == source.name or \
                   source.properties.get("resolves_to") == target.name
        return False
    
    def _check_subdomain(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if subdomain is under domain."""
        if source.node_type == AssetNodeType.SUBDOMAIN and target.node_type == AssetNodeType.DOMAIN:
            return source.name.endswith("." + target.name) or source.name == target.name
        return False
    
    def _check_ip_in_cidr(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if IP is in CIDR."""
        if source.node_type == AssetNodeType.IP_ADDRESS and target.node_type == AssetNodeType.CIDR:
            import ipaddress
            try:
                ip = ipaddress.ip_address(source.name)
                network = ipaddress.ip_network(target.name, strict=False)
                return ip in network
            except ValueError:
                return False
        return False
    
    def _check_domain_hosts_app(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if domain hosts web application."""
        if source.node_type == AssetNodeType.DOMAIN and target.node_type == AssetNodeType.WEB_APPLICATION:
            return target.properties.get("host") == source.name
        return False
    
    def _check_ip_hosts_app(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if IP hosts web application."""
        if source.node_type == AssetNodeType.IP_ADDRESS and target.node_type == AssetNodeType.WEB_APPLICATION:
            return target.properties.get("host_ip") == source.name
        return False
    
    def _check_app_exposes_api(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if web application exposes API endpoint."""
        if source.node_type == AssetNodeType.WEB_APPLICATION and target.node_type == AssetNodeType.API_ENDPOINT:
            return target.properties.get("base_url", "").startswith(source.properties.get("base_url", ""))
        return False
    
    def _check_api_belongs_to_app(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if API endpoint belongs to web application."""
        if source.node_type == AssetNodeType.API_ENDPOINT and target.node_type == AssetNodeType.WEB_APPLICATION:
            return source.properties.get("application_id") == str(target.asset_id)
        return False
    
    def _check_apk_communicates_api(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if APK communicates with API endpoint."""
        if source.node_type == AssetNodeType.APK and target.node_type == AssetNodeType.API_ENDPOINT:
            apk_endpoints = source.properties.get("api_endpoints", [])
            return target.name in apk_endpoints or target.properties.get("url") in apk_endpoints
        return False
    
    def _check_asset_uses_technology(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if asset uses technology."""
        if target.node_type == AssetNodeType.TECHNOLOGY:
            tech_list = source.properties.get("technologies", [])
            return target.name in tech_list or target.name in source.properties.get("fingerprints", [])
        return False
    
    def _check_domain_has_certificate(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if domain has certificate."""
        if source.node_type == AssetNodeType.DOMAIN and target.node_type == AssetNodeType.CERTIFICATE:
            cert_domains = target.properties.get("domains", [])
            return source.name in cert_domains or target.properties.get("subject_cn") == source.name
        return False
    
    def _check_finding_on_asset(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if finding is on asset."""
        if source.node_type == AssetNodeType.FINDING and source.asset_id:
            return str(source.asset_id) == str(target.asset_id)
        return False
    
    def _check_observation_on_asset(self, source: AssetNode, target: AssetNode) -> bool:
        """Check if observation is on asset."""
        if source.node_type == AssetNodeType.OBSERVATION and source.asset_id:
            return str(source.asset_id) == str(target.asset_id)
        return False
    
    def add_rule(self, rule: RelationshipInferenceRule):
        """Add a custom inference rule."""
        self._rules.append(rule)
    
    def infer_relationships(
        self,
        project_id: UUID,
        source_nodes: list[AssetNode] | None = None,
        target_nodes: list[AssetNode] | None = None,
        dry_run: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Infer relationships between nodes.
        
        Args:
            project_id: Project to scope the inference
            source_nodes: Optional specific source nodes
            target_nodes: Optional specific target nodes
            dry_run: If True, don't persist relationships
            
        Returns:
            List of inferred relationships
        """
        if source_nodes is None:
            source_nodes = self.db.scalars(
                select(AssetNode).where(
                    AssetNode.project_id == project_id,
                    AssetNode.deleted_at.is_(None)
                )
            ).all()
        
        if target_nodes is None:
            target_nodes = source_nodes
        
        inferred = []
        
        for source in source_nodes:
            for target in target_nodes:
                if source.id == target.id:
                    continue
                
                for rule in self._rules:
                    if source.node_type != rule.source_type:
                        continue
                    if target.node_type != rule.target_type:
                        continue
                    
                    if rule.condition(source, target):
                        # Check if edge already exists
                        existing = self.db.scalar(
                            select(AssetEdge).where(
                                AssetEdge.source_id == source.id,
                                AssetEdge.target_id == target.id,
                                AssetEdge.relationship_type == rule.relationship_type.value
                            )
                        )
                        
                        if not existing:
                            inferred.append({
                                "source_id": source.id,
                                "target_id": target.id,
                                "relationship_type": rule.relationship_type.value,
                                "confidence": rule.confidence.value,
                                "is_inferred": rule.is_inferred,
                                "source": "inferred",
                                "first_seen_at": datetime.now(UTC),
                                "last_seen_at": datetime.now(UTC),
                                "properties": {"rule": rule.name},
                                "evidence": [{"type": "inference", "rule": rule.name}],
                            })
                            
                            if not dry_run:
                                self._create_edge(
                                    project_id=project_id,
                                    source_id=source.id,
                                    target_id=target.id,
                                    relationship_type=rule.relationship_type,
                                    confidence=rule.confidence,
                                    is_inferred=rule.is_inferred,
                                    source="inferred",
                                    properties={"rule": rule.name},
                                    evidence=[{"type": "inference", "rule": rule.name}],
                                )
        
        return inferred
    
    def _create_edge(
        self,
        project_id: UUID,
        source_id: UUID,
        target_id: UUID,
        relationship_type: RelationshipType,
        confidence: RelationshipConfidence,
        is_inferred: bool,
        source: str,
        properties: dict[str, Any] | None = None,
        evidence: list[dict[str, Any]] | None = None,
    ) -> AssetEdge:
        """Create a new asset edge."""
        now = datetime.now(UTC)
        edge = AssetEdge(
            project_id=project_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type.value,
            confidence=confidence.value,
            is_inferred=is_inferred,
            source=source,
            properties=properties or {},
            evidence=evidence or [],
            first_seen_at=now,
            last_seen_at=now,
        )
        self.db.add(edge)
        self.db.flush()
        return edge
    
    def create_explicit_relationship(
        self,
        project_id: UUID,
        source_id: UUID,
        target_id: UUID,
        relationship_type: RelationshipType,
        confidence: RelationshipConfidence = RelationshipConfidence.HIGH,
        evidence: list[dict[str, Any]] | None = None,
        properties: dict[str, Any] | None = None,
        created_by: UUID | None = None,
    ) -> AssetEdge:
        """Create an explicit (non-inferred) relationship."""
        return self._create_edge(
            project_id=project_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            confidence=confidence,
            is_inferred=False,
            source="manual",
            properties=properties,
            evidence=evidence,
        )
    
    def get_related_nodes(
        self,
        node_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
        direction: str = "both",  # outgoing, incoming, both
        max_depth: int = 1,
    ) -> list[dict[str, Any]]:
        """
        Get nodes related to a given node.
        
        Args:
            node_id: Starting node
            relationship_types: Filter by relationship types
            direction: outgoing, incoming, or both
            max_depth: Maximum traversal depth
            
        Returns:
            List of related nodes with path information
        """
        results = []
        visited = set()
        
        def traverse(current_id: UUID, depth: int, path: list[dict]):
            if depth > max_depth or current_id in visited:
                return
            visited.add(current_id)
            
            # Get outgoing edges
            if direction in ("outgoing", "both"):
                edges_query = select(AssetEdge).where(
                    AssetEdge.source_id == current_id
                )
                if relationship_types:
                    edges_query = edges_query.where(
                        AssetEdge.relationship_type.in_([rt.value for rt in relationship_types])
                    )
                
                for edge in self.db.scalars(edges_query).all():
                    if edge.target_id not in visited:
                        new_path = path + [{
                            "edge_id": edge.id,
                            "relationship_type": edge.relationship_type,
                            "confidence": edge.confidence,
                            "is_inferred": edge.is_inferred,
                        }]
                        results.append({
                            "node_id": edge.target_id,
                            "path": new_path,
                            "depth": depth + 1,
                        })
                        traverse(edge.target_id, depth + 1, new_path)
            
            # Get incoming edges
            if direction in ("incoming", "both"):
                edges_query = select(AssetEdge).where(
                    AssetEdge.target_id == current_id
                )
                if relationship_types:
                    edges_query = edges_query.where(
                        AssetEdge.relationship_type.in_([rt.value for rt in relationship_types])
                    )
                
                for edge in self.db.scalars(edges_query).all():
                    if edge.source_id not in visited:
                        new_path = path + [{
                            "edge_id": edge.id,
                            "relationship_type": edge.relationship_type,
                            "confidence": edge.confidence,
                            "is_inferred": edge.is_inferred,
                            "direction": "incoming",
                        }]
                        results.append({
                            "node_id": edge.source_id,
                            "path": new_path,
                            "depth": depth + 1,
                        })
                        traverse(edge.source_id, depth + 1, new_path)
        
        traverse(node_id, 0, [])
        return results
    
    def find_path(
        self,
        source_id: UUID,
        target_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
        max_depth: int = 10,
    ) -> list[dict[str, Any]] | None:
        """
        Find shortest path between two nodes using BFS.
        
        Returns:
            List of steps (node_id, edge_id, relationship_type) or None if no path
        """
        from collections import deque
        
        queue = deque([(source_id, [])])
        visited = {source_id: None}  # node_id -> (parent_id, edge_id, relationship_type)
        
        while queue:
            current_id, path = queue.popleft()
            
            if current_id == target_id:
                # Reconstruct path
                full_path = []
                for step in reversed(path):
                    full_path.append(step)
                return full_path
            
            if len(path) >= max_depth:
                continue
            
            # Get outgoing edges
            edges_query = select(AssetEdge).where(AssetEdge.source_id == current_id)
            if relationship_types:
                edges_query = edges_query.where(
                    AssetEdge.relationship_type.in_([rt.value for rt in relationship_types])
                )
            
            for edge in self.db.scalars(edges_query).all():
                if edge.target_id not in visited:
                    visited[edge.target_id] = (current_id, edge.id, edge.relationship_type)
                    queue.append((
                        edge.target_id,
                        path + [{
                            "edge_id": edge.id,
                            "source_id": current_id,
                            "target_id": edge.target_id,
                            "relationship_type": edge.relationship_type,
                            "confidence": edge.confidence,
                            "is_inferred": edge.is_inferred,
                        }]
                    ))
        
        return None
    
    def get_subgraph(
        self,
        project_id: UUID,
        center_node_id: UUID,
        max_depth: int = 2,
        relationship_types: list[RelationshipType] | None = None,
    ) -> dict[str, Any]:
        """
        Extract subgraph around a center node.
        
        Returns:
            Dict with nodes and edges
        """
        nodes = {center_id: True}
        edges = []
        
        # BFS to find nodes within depth
        current_level = {center_node_id}
        for depth in range(max_depth):
            next_level = set()
            for node_id in current_level:
                edges_query = select(AssetEdge).where(
                    (AssetEdge.source_id == node_id) | (AssetEdge.target_id == node_id)
                )
                if relationship_types:
                    edges_query = edges_query.where(
                        AssetEdge.relationship_type.in_([rt.value for rt in relationship_types])
                    )
                
                for edge in self.db.scalars(edges_query).all():
                    edges.append({
                        "id": str(edge.id),
                        "source_id": str(edge.source_id),
                        "target_id": str(edge.target_id),
                        "relationship_type": edge.relationship_type,
                        "confidence": edge.confidence,
                        "is_inferred": edge.is_inferred,
                    })
                    
                    if edge.source_id not in nodes:
                        nodes[edge.source_id] = True
                        next_level.add(edge.source_id)
                    if edge.target_id not in nodes:
                        nodes[edge.target_id] = True
                        next_level.add(edge.target_id)
            
            current_level = next_level
            if not current_level:
                break
        
        # Get node details
        node_ids = list(nodes.keys())
        if node_ids:
            nodes_query = select(AssetNode).where(AssetNode.id.in_(node_ids))
            node_details = {}
            for node in self.db.scalars(nodes_query).all():
                node_details[str(node.id)] = {
                    "id": str(node.id),
                    "node_type": node.node_type,
                    "name": node.name,
                    "display_name": node.display_name,
                    "scope_status": node.scope_status,
                    "is_authorized": node.is_authorized,
                    "properties": node.properties,
                    "first_seen_at": node.first_seen_at.isoformat() if node.first_seen_at else None,
                    "last_seen_at": node.last_seen_at.isoformat() if node.last_seen_at else None,
                }
        else:
            node_details = {}
        
        return {
            "nodes": node_details,
            "edges": edges,
            "center_node": str(center_node_id),
            "max_depth": max_depth,
        }
    
    def calculate_centrality(
        self,
        project_id: UUID,
        relationship_types: list[RelationshipType] | None = None,
    ) -> dict[str, float]:
        """
        Calculate degree centrality for all nodes in project.
        
        Returns:
            Dict of node_id -> centrality score
        """
        edges_query = select(AssetEdge).where(AssetEdge.project_id == project_id)
        if relationship_types:
            edges_query = edges_query.where(
                AssetEdge.relationship_type.in_([rt.value for rt in relationship_types])
            )
        
        degree_counts = defaultdict(int)
        total_edges = 0
        
        for edge in self.db.scalars(edges_query).all():
            degree_counts[str(edge.source_id)] += 1
            degree_counts[str(edge.target_id)] += 1
            total_edges += 1
        
        # Normalize by max degree
        max_degree = max(degree_counts.values()) if degree_counts else 1
        centrality = {node_id: count / max_degree for node_id, count in degree_counts.items()}
        
        return centrality
    
    def update_scope_status(self, project_id: UUID) -> dict[str, int]:
        """
        Update scope status for all nodes based on ScopeEngine.
        
        Returns:
            Stats of updated nodes
        """
        from app.models.projects import Scope, ScopeRule
        from app.models.enums import ScopeStatus
        
        scope_engine = create_scope_engine()
        
        # Get all active scopes for project
        scopes = self.db.scalars(
            select(Scope).where(Scope.project_id == project_id)
        ).all()
        
        if not scopes:
            return {"updated": 0, "errors": 0}
        
        # Build rules per scope
        scope_rules = {}
        for scope in scopes:
            rules = self.db.scalars(
                select(ScopeRule).where(ScopeRule.scope_id == scope.id)
            ).all()
            scope_rules[scope.id] = rules
        
        # Update all nodes in project
        nodes = self.db.scalars(
            select(AssetNode).where(
                AssetNode.project_id == project_id,
                AssetNode.deleted_at.is_(None)
            )
        ).all()
        
        updated = 0
        errors = 0
        
        for node in nodes:
            # Find matching scope
            node_scope_id = None
            if node.asset_id:
                asset = self.db.get(Asset, node.asset_id)
                if asset and asset.scope_id:
                    node_scope_id = asset.scope_id
            
            if node_scope_id and node_scope_id in scope_rules:
                rules = scope_rules[node_scope_id]
                # Convert to scope engine format
                rule_objects = []
                for rule in rules:
                    class RuleProxy:
                        def __init__(self, r):
                            self.effect = r.effect
                            self.target_type = r.target_type
                            self.pattern = r.pattern
                    rule_objects.append(RuleProxy(rule))
                
                # Map node type to target type
                target_type_map = {
                    AssetNodeType.DOMAIN: ScopeRuleTargetType.DOMAIN,
                    AssetNodeType.SUBDOMAIN: ScopeRuleTargetType.SUBDOMAIN_PATTERN,
                    AssetNodeType.IP_ADDRESS: ScopeRuleTargetType.IP,
                    AssetNodeType.CIDR: ScopeRuleTargetType.CIDR,
                    AssetNodeType.URL: ScopeRuleTargetType.URL,
                    AssetNodeType.API_ENDPOINT: ScopeRuleTargetType.API,
                    AssetNodeType.APK: ScopeRuleTargetType.APK,
                }
                target_type = target_type_map.get(node.node_type, ScopeRuleTargetType.DOMAIN)
                
                try:
                    scope_status = scope_engine.evaluate_target(
                        target_value=node.name,
                        target_type=target_type,
                        rules=rule_objects,
                    )
                    
                    new_status = scope_status.value
                    new_authorized = scope_status == ScopeStatus.IN_SCOPE
                    
                    if node.scope_status != new_status or node.is_authorized != new_authorized:
                        node.scope_status = new_status
                        node.is_authorized = new_authorized
                        updated += 1
                except Exception:
                    errors += 1
        
        return {"updated": updated, "errors": errors}


def get_relationship_engine(db: Session | None = None) -> RelationshipEngine:
    """Get relationship engine instance."""
    return RelationshipEngine(db)