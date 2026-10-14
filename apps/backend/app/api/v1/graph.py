"""Graph API endpoints."""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.session import get_db
from app.models.identity import User
from app.schemas.graph import (
    AssetClusterListResponse,
    AssetEdgeCreateRequest,
    AssetEdgeListResponse,
    AssetEdgeResponse,
    AssetEdgeUpdateRequest,
    AssetGraphNodeCreateRequest,
    AssetGraphNodeListResponse,
    AssetGraphNodeResponse,
    AssetGraphNodeUpdateRequest,
    AssetGraphSnapshotCreateRequest,
    AssetGraphSnapshotListResponse,
    AssetGraphSnapshotResponse,
    AssetNodeResponse,
    AssetNodeListResponse,
    AssetNodeCreateRequest,
    AssetNodeUpdateRequest,
    AssetPathResponse,
    AssetRelatedNodesResponse,
    AssetSubgraphResponse,
    CentralityRequest,
    CentralityResponse,
    ExportGraphRequest,
    ExportGraphResponse,
    FindingClusterCreateRequest,
    FindingClusterListResponse,
    FindingClusterResponse,
    FindingGraphEdgeCreateRequest,
    FindingGraphEdgeListResponse,
    FindingGraphEdgeResponse,
    FindingGraphNodeCreateRequest,
    FindingGraphNodeListResponse,
    FindingGraphNodeResponse,
    FindingGraphNodeUpdateRequest,
    FindingGraphSnapshotCreateRequest,
    FindingGraphSnapshotListResponse,
    FindingGraphSnapshotResponse,
    FindingGraphSyncResponse,
    GraphExportRequest,
    GraphExportResponse,
    GraphSyncResponse,
    InferRelationshipsRequest,
    InferRelationshipsResponse,
    PathRequest,
    PathResponse,
    RelatedNodesRequest,
    RelatedNodesResponse,
    ScopeUpdateResponse,
    SubgraphRequest,
    SubgraphResponse,
)
from app.services.graph import (
    AssetGraphService,
    FindingGraphService,
    GraphService,
    get_asset_graph_service,
    get_finding_graph_service,
    get_graph_service,
)

router = APIRouter(prefix="/graph", tags=["graph"])


def get_asset_graph_service_dep() -> AssetGraphService:
    return get_asset_graph_service()


def get_finding_graph_service_dep() -> FindingGraphService:
    return get_finding_graph_service()


def get_graph_service_dep() -> GraphService:
    return get_graph_service()


# Asset Graph Node Endpoints

@router.post("/nodes", response_model=AssetGraphNodeResponse, status_code=status.HTTP_201_CREATED)
async def create_asset_node(
    request: AssetGraphNodeCreateRequest,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphNodeResponse:
    """Create a new asset node."""
    node = service.create_node(
        project_id=current_user.default_project_id,  # This would need to come from context
        node_type=request.node_type,
        name=request.name,
        display_name=request.display_name,
        description=request.description,
        asset_id=request.asset_id,
        finding_id=request.finding_id,
        observation_id=request.observation_id,
        scan_id=request.scan_id,
        scan_job_id=request.scan_job_id,
        scope_status=request.scope_status,
        is_authorized=request.is_authorized,
        properties=request.properties,
        tags=request.tags,
        metadata=request.metadata,
    )
    return AssetGraphNodeResponse.model_validate(node)


@router.get("/nodes", response_model=AssetGraphNodeListResponse)
async def list_asset_nodes(
    project_id: UUID = Query(...),
    node_type: str | None = Query(None),
    scope_status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphNodeListResponse:
    """List asset nodes."""
    node_type = None
    if node_type:
        from app.models.graph import AssetNodeType
        try:
            node_type = AssetNodeType(node_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid node type: {node_type}")
    
    nodes, total = service.list_nodes(
        project_id=project_id,
        node_type=node_type,
        scope_status=scope_status,
        limit=limit,
        offset=offset,
    )
    
    return AssetGraphNodeListResponse(
        nodes=[AssetGraphNodeResponse.model_validate(n) for n in nodes],
        total=total,
    )


@router.get("/nodes/{node_id}", response_model=AssetGraphNodeResponse)
async def get_asset_node(
    node_id: UUID,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphNodeResponse:
    """Get asset node by ID."""
    node = service.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return AssetGraphNodeResponse.model_validate(node)


@router.patch("/nodes/{node_id}", response_model=AssetGraphNodeResponse)
async def update_asset_node(
    node_id: UUID,
    request: AssetGraphNodeUpdateRequest,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphNodeResponse:
    """Update asset node."""
    node = service.update_node(
        node_id=node_id,
        display_name=request.display_name,
        description=request.description,
        scope_status=request.scope_status,
        is_authorized=request.is_authorized,
        properties=request.properties,
        tags=request.tags,
        metadata=request.metadata,
        layout_x=request.layout_x,
        layout_y=request.layout_y,
    )
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return AssetGraphNodeResponse.model_validate(node)


@router.delete("/nodes/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset_node(
    node_id: UUID,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete asset node."""
    success = service.delete_node(node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Node not found")


# Asset Graph Edge Endpoints

@router.post("/edges", response_model=AssetEdgeResponse, status_code=status.HTTP_201_CREATED)
async def create_asset_edge(
    request: AssetEdgeCreateRequest,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetEdgeResponse:
    """Create a new asset edge."""
    edge = service.create_edge(
        project_id=current_user.default_project_id,
        source_id=request.source_id,
        target_id=request.target_id,
        relationship_type=request.relationship_type,
        confidence=request.confidence,
        is_inferred=request.is_inferred,
        source=request.source,
        evidence=request.evidence,
        properties=request.properties,
        created_by=current_user.id,
    )
    return AssetEdgeResponse.model_validate(edge)


@router.get("/edges", response_model=AssetEdgeListResponse)
async def list_asset_edges(
    project_id: UUID = Query(...),
    relationship_type: str | None = Query(None),
    source_id: UUID | None = Query(None),
    target_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetEdgeListResponse:
    """List asset edges."""
    relationship_type = None
    if relationship_type:
        from app.models.graph import RelationshipType
        try:
            relationship_type = RelationshipType(relationship_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid relationship type: {relationship_type}")
    
    edges, total = service.list_edges(
        project_id=project_id,
        relationship_type=relationship_type,
        source_id=source_id,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )
    
    return AssetEdgeListResponse(
        edges=[AssetEdgeResponse.model_validate(e) for e in edges],
        total=total,
    )


@router.get("/edges/{edge_id}", response_model=AssetEdgeResponse)
async def get_asset_edge(
    edge_id: UUID,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetEdgeResponse:
    """Get asset edge by ID."""
    edge = service.get_edge(edge_id)
    if not edge:
        raise HTTPException(status_code=404, detail="Edge not found")
    return AssetEdgeResponse.model_validate(edge)


@router.patch("/edges/{edge_id}", response_model=AssetEdgeResponse)
async def update_asset_edge(
    edge_id: UUID,
    request: AssetEdgeUpdateRequest,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetEdgeResponse:
    """Update asset edge."""
    edge = service.update_edge(
        edge_id=edge_id,
        confidence=request.confidence,
        evidence=request.evidence,
        properties=request.properties,
    )
    if not edge:
        raise HTTPException(status_code=404, detail="Edge not found")
    return AssetEdgeResponse.model_validate(edge)


@router.delete("/edges/{edge_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset_edge(
    edge_id: UUID,
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete asset edge."""
    success = service.delete_edge(edge_id)
    if not success:
        raise HTTPException(status_code=404, detail="Edge not found")


# Graph Operations Endpoints

@router.post("/infer-relationships", response_model=InferRelationshipsResponse)
async def infer_relationships(
    project_id: UUID = Query(...),
    request: InferRelationshipsRequest = InferRelationshipsRequest(),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> InferRelationshipsResponse:
    """Infer relationships for a project."""
    inferred = service.infer_relationships(project_id, dry_run=request.dry_run)
    return InferRelationshipsResponse(inferred=len(inferred), dry_run=request.dry_run)


@router.get("/nodes/{node_id}/related", response_model=RelatedNodesResponse)
async def get_related_nodes(
    node_id: UUID,
    relationship_types: list[str] | None = Query(None),
    direction: str = Query("both"),
    max_depth: int = Query(1, ge=1, le=5),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> RelatedNodesResponse:
    """Get nodes related to a given node."""
    from app.models.graph import RelationshipType
    
    relationship_types = None
    if relationship_types:
        try:
            relationship_types = [RelationshipType(rt) for rt in relationship_types]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid relationship type: {e}")
    
    related = service.get_related_nodes(
        node_id=node_id,
        relationship_types=relationship_types,
        direction=direction,
        max_depth=max_depth,
    )
    
    return RelatedNodesResponse(
        nodes=[
            RelatedNodesResponse(
                node_id=r["node_id"],
                path=r["path"],
                depth=r["depth"],
            ) for r in related
        ]
    )


@router.get("/path", response_model=PathResponse)
async def find_path(
    source_id: UUID = Query(...),
    target_id: UUID = Query(...),
    relationship_types: list[str] | None = Query(None),
    max_depth: int = Query(10, ge=1, le=20),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> PathResponse:
    """Find shortest path between two nodes."""
    from app.models.graph import RelationshipType
    
    relationship_types = None
    if relationship_types:
        try:
            relationship_types = [RelationshipType(rt) for rt in relationship_types]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid relationship type: {e}")
    
    path = service.find_path(
        source_id=source_id,
        target_id=target_id,
        relationship_types=relationship_types,
        max_depth=max_depth,
    )
    
    return PathResponse(
        source_id=source_id,
        target_id=target_id,
        path=path or [],
        found=path is not None,
    )


@router.get("/subgraph", response_model=SubgraphResponse)
async def get_subgraph(
    project_id: UUID = Query(...),
    center_node_id: UUID = Query(...),
    max_depth: int = Query(2, ge=1, le=5),
    relationship_types: list[str] | None = Query(None),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> SubgraphResponse:
    """Extract subgraph around a center node."""
    from app.models.graph import RelationshipType
    
    relationship_types = None
    if relationship_types:
        try:
            relationship_types = [RelationshipType(rt) for rt in relationship_types]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid relationship type: {e}")
    
    subgraph = service.get_subgraph(
        project_id=project_id,
        center_node_id=center_node_id,
        max_depth=max_depth,
        relationship_types=relationship_types,
    )
    
    return SubgraphResponse(**subgraph)


@router.get("/centrality", response_model=CentralityResponse)
async def calculate_centrality(
    project_id: UUID = Query(...),
    relationship_types: list[str] | None = Query(None),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> CentralityResponse:
    """Calculate degree centrality for all nodes."""
    from app.models.graph import RelationshipType
    
    relationship_types = None
    if relationship_types:
        try:
            relationship_types = [RelationshipType(rt) for rt in relationship_types]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid relationship type: {e}")
    
    centrality = service.calculate_centrality(
        project_id=project_id,
        relationship_types=relationship_types,
    )
    
    return CentralityResponse(centrality=centrality)


@router.post("/scope/update", response_model=ScopeUpdateResponse)
async def update_scope_status(
    project_id: UUID = Query(...),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> ScopeUpdateResponse:
    """Update scope status for all nodes."""
    result = service.update_scope_status(project_id)
    return ScopeUpdateResponse(**result)


@router.post("/infer-relationships", response_model=InferRelationshipsResponse)
async def infer_relationships(
    project_id: UUID = Query(...),
    request: InferRelationshipsRequest = InferRelationshipsRequest(),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> InferRelationshipsResponse:
    """Infer relationships for a project."""
    inferred = service.infer_relationships(project_id, dry_run=request.dry_run)
    return InferRelationshipsResponse(inferred=len(inferred), dry_run=request.dry_run)


# Graph Snapshot Endpoints

@router.post("/snapshots", response_model=AssetGraphSnapshotResponse, status_code=status.HTTP_201_CREATED)
async def create_graph_snapshot(
    project_id: UUID = Query(...),
    request: AssetGraphSnapshotCreateRequest = Body(...),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphSnapshotResponse:
    """Create a graph snapshot."""
    snapshot = service.create_snapshot(
        project_id=project_id,
        name=request.name,
        description=request.description,
        scan_id=request.scan_id,
        tags=request.tags,
    )
    return AssetGraphSnapshotResponse.model_validate(snapshot)


@router.get("/snapshots", response_model=AssetGraphSnapshotListResponse)
async def list_graph_snapshots(
    project_id: UUID = Query(...),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    service: AssetGraphService = Depends(get_asset_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> AssetGraphSnapshotListResponse:
    """List graph snapshots."""
    snapshots, total = service.list_snapshots(
        project_id=project_id,
        limit=limit,
        offset=offset,
    )
    
    return AssetGraphSnapshotListResponse(
        snapshots=[AssetGraphSnapshotResponse.model_validate(s) for s in snapshots],
        total=total,
    )


# Graph Sync Endpoints

@router.post("/sync", response_model=GraphSyncResponse)
async def sync_graph(
    project_id: UUID = Query(...),
    service: GraphService = Depends(get_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> GraphSyncResponse:
    """Sync asset graph from existing assets."""
    result = service.sync_from_assets(project_id)
    return GraphSyncResponse(**result)


@router.post("/sync/findings", response_model=FindingGraphSyncResponse)
async def sync_findings_graph(
    project_id: UUID = Query(...),
    service: GraphService = Depends(get_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> FindingGraphSyncResponse:
    """Sync finding graph from existing findings."""
    result = service.sync_from_findings(project_id)
    return FindingGraphSyncResponse(**result)


@router.post("/export", response_model=GraphExportResponse)
async def export_graph(
    project_id: UUID = Query(...),
    request: GraphExportRequest = GraphExportRequest(),
    service: GraphService = Depends(get_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> GraphExportResponse:
    """Export graph in various formats."""
    result = service.export_graph(
        project_id=project_id,
        format=request.format,
        include_finding_graph=request.include_finding_graph,
    )
    
    if request.format == "json":
        return GraphExportResponse(**result)
    else:
        # For graphml/cypher, return as text
        return GraphExportResponse(
            project_id=project_id,
            exported_at=datetime.now().isoformat(),
            asset_graph={"data": result} if isinstance(result, str) else result.get("asset_graph", {}),
        )


# Finding Graph Endpoints (simplified - similar structure to asset graph)

@router.post("/findings/nodes", response_model=FindingGraphNodeResponse, status_code=status.HTTP_201_CREATED)
async def create_finding_node(
    project_id: UUID = Query(...),
    request: FindingGraphNodeCreateRequest = Body(...),
    service: FindingGraphService = Depends(get_finding_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> FindingGraphNodeResponse:
    """Create a finding graph node."""
    node = service.create_finding_node(
        project_id=project_id,
        finding_id=request.finding_id,
        asset_id=request.asset_id,
        title=request.title,
        vulnerability_type=request.vulnerability_type,
        severity=request.severity,
        confidence=request.confidence,
        status=request.status,
        cvss_vector=request.cvss_vector,
        cvss_score=request.cvss_score,
        location=request.location,
        asset_name=request.asset_name,
        asset_type=request.asset_type,
        tags=request.tags,
        metadata=request.metadata,
    )
    return FindingGraphNodeResponse.model_validate(node)


@router.get("/findings/nodes", response_model=FindingGraphNodeListResponse)
async def list_finding_nodes(
    project_id: UUID = Query(...),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    vulnerability_type: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: FindingGraphService = Depends(get_finding_graph_service_dep),
    current_user: User = Depends(get_current_user),
) -> FindingGraphNodeListResponse:
    """List finding graph nodes."""
    nodes, total = service.list_finding_nodes(
        project_id=project_id,
        severity=severity,
        status=status,
        vulnerability_type=vulnerability_type,
        limit=limit,
        offset=offset,
    )
    
    return FindingGraphNodeListResponse(
        nodes=[FindingGraphNodeResponse.model_validate(n) for n in nodes],
        total=total,
    )


# Add remaining finding graph endpoints...
# (Clusters, Attack Paths, Snapshots, Edges)


# Celery Task Endpoints

@router.post("/tasks/sync", response_model=dict)
async def trigger_sync(
    project_id: UUID = Query(...),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger graph sync task."""
    from app.graph.tasks import sync_project_graph
    task = sync_project_graph.delay(str(project_id))
    return {"task_id": task.id, "status": "queued"}


@router.post("/tasks/sync-findings", response_model=dict)
async def trigger_findings_sync(
    project_id: UUID = Query(...),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger finding graph sync task."""
    from app.graph.tasks import sync_findings_graph
    task = sync_findings_graph.delay(str(project_id))
    return {"task_id": task.id, "status": "queued"}


@router.post("/tasks/infer-relationships", response_model=dict)
async def trigger_infer_relationships(
    project_id: UUID = Query(...),
    dry_run: bool = Query(False),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger relationship inference task."""
    from app.graph.tasks import infer_relationships_task
    task = infer_relationships_task.delay(str(project_id), dry_run)
    return {"task_id": task.id, "status": "queued"}


@router.post("/tasks/snapshot", response_model=dict)
async def trigger_snapshot(
    project_id: UUID = Query(...),
    name: str = Query(...),
    description: str | None = Query(None),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger graph snapshot task."""
    from app.graph.tasks import create_graph_snapshot
    task = create_graph_snapshot.delay(str(project_id), name, description)
    return {"task_id": task.id, "status": "queued"}


@router.post("/tasks/update-scope", response_model=dict)
async def trigger_scope_update(
    project_id: UUID = Query(...),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger scope status update task."""
    from app.graph.tasks import update_all_scope_status
    task = update_all_scope_status.delay(str(project_id))
    return {"task_id": task.id, "status": "queued"}