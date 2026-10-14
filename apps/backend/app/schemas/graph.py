"""Graph API schemas."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from enum import Enum


class AssetNodeTypeEnum(str, Enum):
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


class RelationshipTypeEnum(str, Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    SUBDOMAIN_OF = "subdomain_of"
    SAME_CIDR = "same_cidr"
    HOSTS_APPLICATION = "hosts_application"
    BELONGS_TO = "belongs_to"
    COMMUNICATES_WITH = "communicates_with"
    EXPOSES = "exposes"
    USES_TECHNOLOGY = "uses_technology"
    DETECTED_TECHNOLOGY = "detected_technology"
    HAS_CERTIFICATE = "has_certificate"
    CERTIFICATE_FOR = "certificate_for"
    SIGNED_BY = "signed_by"
    HAS_FINDING = "has_finding"
    FINDING_ON = "finding_on"
    HAS_OBSERVATION = "has_observation"
    OBSERVATION_ON = "observation_on"
    DERIVED_FROM = "derived_from"
    DUPLICATE_OF = "duplicate_of"
    RELATED_TO = "related_to"
    VARIANT_OF = "variant_of"
    PREREQUISITE_FOR = "prerequisite_for"
    CHAINS_TO = "chains_to"
    SAME_ROOT_CAUSE = "same_root_cause"
    PART_OF_PROJECT = "part_of_project"
    PART_OF_SCAN = "part_of_scan"
    EXECUTED_BY = "executed_by"
    INFERRED = "inferred"
    EXPLICIT = "explicit"


class RelationshipConfidenceEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class AssetNodeResponse(BaseModel):
    id: UUID
    project_id: UUID
    node_type: str
    asset_id: UUID | None = None
    finding_id: UUID | None = None
    observation_id: UUID | None = None
    scan_id: UUID | None = None
    scan_job_id: UUID | None = None
    name: str
    display_name: str | None = None
    description: str | None = None
    scope_status: str
    is_authorized: bool
    properties: dict[str, Any]
    tags: list[str]
    metadata: dict[str, Any]
    layout_x: float | None = None
    layout_y: float | None = None
    color: str | None = None
    size: float | None = None
    icon: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class AssetNodeListResponse(BaseModel):
    nodes: list[AssetNodeResponse]
    total: int


class AssetNodeCreateRequest(BaseModel):
    node_type: AssetNodeTypeEnum
    name: str
    display_name: str | None = None
    description: str | None = None
    asset_id: UUID | None = None
    finding_id: UUID | None = None
    observation_id: UUID | None = None
    scan_id: UUID | None = None
    scan_job_id: UUID | None = None
    scope_status: str = "unknown"
    is_authorized: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetNodeUpdateRequest(BaseModel):
    display_name: str | None = None
    description: str | None = None
    scope_status: str | None = None
    is_authorized: bool | None = None
    properties: dict[str, Any] | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None
    layout_x: float | None = None
    layout_y: float | None = None


class AssetEdgeResponse(BaseModel):
    id: UUID
    project_id: UUID
    source_id: UUID
    target_id: UUID
    relationship_type: str
    confidence: str
    is_inferred: bool
    source: str
    evidence: list[dict[str, Any]]
    properties: dict[str, Any]
    created_by: UUID | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime


class AssetEdgeListResponse(BaseModel):
    edges: list[AssetEdgeResponse]
    total: int


class AssetEdgeCreateRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    relationship_type: RelationshipTypeEnum
    confidence: RelationshipConfidenceEnum = RelationshipConfidenceEnum.MEDIUM
    is_inferred: bool = False
    source: str = "manual"
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class AssetEdgeUpdateRequest(BaseModel):
    confidence: RelationshipConfidenceEnum | None = None
    evidence: list[dict[str, Any]] | None = None
    properties: dict[str, Any] | None = None


class RelatedNodeResponse(BaseModel):
    node_id: UUID
    path: list[dict[str, Any]]
    depth: int


class RelatedNodesResponse(BaseModel):
    nodes: list[RelatedNodeResponse]


class PathResponse(BaseModel):
    source_id: UUID
    target_id: UUID
    path: list[dict[str, Any]]
    found: bool


class SubgraphResponse(BaseModel):
    nodes: dict[str, dict[str, Any]]
    edges: list[dict[str, Any]]
    center_node: str
    max_depth: int


class CentralityResponse(BaseModel):
    centrality: dict[str, float]


class ScopeUpdateResponse(BaseModel):
    updated: int
    errors: int


class GraphSnapshotResponse(BaseModel):
    id: UUID
    project_id: UUID
    scan_id: UUID | None = None
    name: str
    description: str | None = None
    node_count: int
    edge_count: int
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class GraphSnapshotListResponse(BaseModel):
    snapshots: list[GraphSnapshotResponse]
    total: int


class GraphSnapshotCreateRequest(BaseModel):
    name: str
    description: str | None = None
    scan_id: UUID | None = None
    tags: list[str] = Field(default_factory=list)


# Asset Graph aliases (for API compatibility)
AssetNodeResponse = AssetNodeResponse
AssetNodeListResponse = AssetNodeListResponse
AssetNodeCreateRequest = AssetNodeCreateRequest
AssetNodeUpdateRequest = AssetNodeUpdateRequest
AssetGraphNodeResponse = AssetNodeResponse
AssetGraphNodeListResponse = AssetNodeListResponse
AssetGraphNodeCreateRequest = AssetNodeCreateRequest
AssetGraphNodeUpdateRequest = AssetNodeUpdateRequest

class AssetClusterResponse(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    primary_node_id: UUID
    member_node_ids: list[UUID]
    total_nodes: int
    cluster_type: str
    cluster_confidence: str
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class AssetClusterListResponse(BaseModel):
    clusters: list[AssetClusterResponse]
    total: int


class AssetPathResponse(BaseModel):
    source_id: UUID
    target_id: UUID
    path: list[dict[str, Any]]
    found: bool


class AssetRelatedNodesResponse(BaseModel):
    nodes: list[RelatedNodesResponse]


class AssetSubgraphResponse(BaseModel):
    nodes: dict[str, dict[str, Any]]
    edges: list[dict[str, Any]]
    center_node: str
    max_depth: int


class AssetGraphSnapshotResponse(BaseModel):
    id: UUID
    project_id: UUID
    scan_id: UUID | None = None
    name: str
    description: str | None = None
    node_count: int
    edge_count: int
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class AssetGraphSnapshotListResponse(BaseModel):
    snapshots: list[AssetGraphSnapshotResponse]
    total: int


class AssetGraphSnapshotCreateRequest(BaseModel):
    name: str
    description: str | None = None
    scan_id: UUID | None = None
    tags: list[str] = Field(default_factory=list)


# Finding Graph Schemas

class FindingRelationshipTypeEnum(str, Enum):
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


class FindingGraphNodeResponse(BaseModel):
    id: UUID
    project_id: UUID
    finding_id: UUID
    asset_id: UUID | None = None
    title: str
    vulnerability_type: str
    severity: str
    confidence: str
    status: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    location: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    layout_x: float | None = None
    layout_y: float | None = None
    color: str | None = None
    size: float | None = None
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class FindingGraphNodeListResponse(BaseModel):
    nodes: list[FindingGraphNodeResponse]
    total: int


class FindingGraphNodeCreateRequest(BaseModel):
    finding_id: UUID
    asset_id: UUID | None = None
    title: str
    vulnerability_type: str
    severity: str
    confidence: str
    status: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    location: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingGraphNodeUpdateRequest(BaseModel):
    title: str | None = None
    vulnerability_type: str | None = None
    severity: str | None = None
    confidence: str | None = None
    status: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    layout_x: float | None = None
    layout_y: float | None = None


class FindingGraphEdgeResponse(BaseModel):
    id: UUID
    project_id: UUID
    source_id: UUID
    target_id: UUID
    relationship_type: str
    confidence: str
    is_inferred: bool
    source: str
    evidence: list[dict[str, Any]]
    description: str | None = None
    properties: dict[str, Any]
    created_by: UUID | None = None
    created_at: datetime


class FindingGraphEdgeListResponse(BaseModel):
    edges: list[FindingGraphEdgeResponse]
    total: int


class FindingGraphEdgeCreateRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    relationship_type: FindingRelationshipTypeEnum
    confidence: str = "medium"
    is_inferred: bool = False
    source: str = "manual"
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    description: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class FindingClusterResponse(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    primary_finding_id: UUID
    member_finding_ids: list[UUID]
    total_findings: int
    max_severity: str
    max_confidence: str
    unique_vulnerability_types: int
    unique_assets: int
    cluster_type: str
    cluster_confidence: str
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class FindingClusterListResponse(BaseModel):
    clusters: list[FindingClusterResponse]
    total: int


class FindingClusterCreateRequest(BaseModel):
    name: str
    primary_finding_id: UUID
    member_finding_ids: list[UUID]
    description: str | None = None
    cluster_type: str = "related"
    cluster_confidence: str = "medium"
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPathStepTypeEnum(str, Enum):
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


class AttackPathResponse(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    step_finding_ids: list[UUID]
    step_types: list[str]
    total_steps: int
    max_severity: str
    path_confidence: str
    estimated_impact: str
    entry_point: str | None = None
    target_asset: str | None = None
    status: str
    validated_by: UUID | None = None
    validated_at: datetime | None = None
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class AttackPathListResponse(BaseModel):
    paths: list[AttackPathResponse]
    total: int


class AttackPathCreateRequest(BaseModel):
    name: str
    step_finding_ids: list[UUID]
    step_types: list[str]
    description: str | None = None
    entry_point: str | None = None
    target_asset: str | None = None
    tags: list[str] = Field(default_factory=list)


class FindingGraphSnapshotResponse(BaseModel):
    id: UUID
    project_id: UUID
    scan_id: UUID | None = None
    name: str
    description: str | None = None
    node_count: int
    edge_count: int
    cluster_count: int
    attack_path_count: int
    tags: list[str]
    metadata: dict[str, Any]
    created_at: datetime


class FindingGraphSnapshotCreateRequest(BaseModel):
    name: str
    description: str | None = None
    scan_id: UUID | None = None
    tags: list[str] = Field(default_factory=list)


class FindingGraphSnapshotListResponse(BaseModel):
    snapshots: list[FindingGraphSnapshotResponse]
    total: int


# Graph Operations Schemas

class GraphSyncResponse(BaseModel):
    created_nodes: int
    inferred_edges: int


class FindingGraphSyncResponse(BaseModel):
    created_nodes: int
    created_edges: int


class GraphExportResponse(BaseModel):
    project_id: UUID
    exported_at: str
    asset_graph: dict[str, Any]
    finding_graph: dict[str, Any] | None = None


# Alias for API compatibility
ExportGraphResponse = GraphExportResponse


class GraphExportRequest(BaseModel):
    format: str = "json"  # json, graphml, cypher
    include_finding_graph: bool = True


class InferRelationshipsRequest(BaseModel):
    dry_run: bool = True


class InferRelationshipsResponse(BaseModel):
    inferred: int
    dry_run: bool


class RelatedNodesRequest(BaseModel):
    relationship_types: list[str] | None = None
    direction: str = "both"
    max_depth: int = 1


class PathRequest(BaseModel):
    relationship_types: list[str] | None = None
    max_depth: int = 10


class SubgraphRequest(BaseModel):
    max_depth: int = 2
    relationship_types: list[str] | None = None


class CentralityRequest(BaseModel):
    relationship_types: list[str] | None = None


class ScopeUpdateRequest(BaseModel):
    pass


class ExportGraphRequest(BaseModel):
    format: str = "json"
    include_finding_graph: bool = True