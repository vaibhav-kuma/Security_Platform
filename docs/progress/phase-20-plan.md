# Phase 20 Implementation Plan

## Objective
Build an advanced AssetGraph, RelationshipEngine, and FindingGraph that model relationships across the authorized security-assessment environment. Represent connections between domains, subdomains, IPs, certificates, web applications, URLs, API endpoints, API specifications, technologies, APKs, runtime observations, scanner results, methodology test cases, and findings, while retaining explicit scope and authorization state for every entity.

## Architecture Changes

### 1. Asset Graph Models (`app/models/graph.py`)
- **AssetNode**: Base node representing any asset (domain, IP, URL, API, APK, etc.)
- **AssetEdge**: Relationship between assets with type, confidence, evidence
- **GraphSnapshot**: Point-in-time graph state for historical analysis
- **GraphQuery**: Saved graph queries for reuse

### 2. Relationship Engine (`app/core/relationship_engine.py`)
- **RelationshipEngine**: Core engine for managing and querying relationships
- **Relationship Types**: 
  - `resolves_to` (domain -> IP)
  - `hosts` (IP -> domain)
  - `belongs_to` (API endpoint -> application)
  - `communicates_with` (APK -> API)
  - `uses_technology` (asset -> technology)
  - `has_certificate` (domain -> certificate)
  - `has_finding` (asset -> finding)
  - `has_observation` (asset -> observation)
  - `derived_from` (asset -> methodology test case)
  - `related_finding` (finding -> finding)
- **Confidence Scoring**: Explicit vs inferred relationships
- **Scope Awareness**: All relationships respect scope boundaries

### 3. Finding Graph (`app/models/finding_graph.py`)
- **FindingNode**: Finding with severity, confidence, status
- **FindingEdge**: Relationship between findings (duplicate, chain, prerequisite, same_root_cause)
- **FindingCluster**: Group of related findings
- **AttackPath**: Sequence of findings forming attack chain

### 4. Graph Service (`app/services/graph.py`)
- **AssetGraphService**: CRUD for nodes/edges, graph traversal
- **RelationshipEngine**: Inference rules, confidence calculation
- **GraphQueryService**: Path finding, subgraph extraction, centrality
- **Export/Import**: GraphML, JSON, Cypher formats

### 5. Graph API (`app/api/v1/graph.py`)
- `GET /graph/nodes` - List nodes with filters
- `GET /graph/nodes/{node_id}` - Get node with relationships
- `POST /graph/nodes` - Create node
- `PATCH /graph/nodes/{node_id}` - Update node
- `DELETE /graph/nodes/{node_id}` - Delete node
- `GET /graph/edges` - List edges
- `POST /graph/edges` - Create edge
- `DELETE /graph/edges/{edge_id}` - Delete edge
- `GET /graph/traverse` - Traverse from node (BFS/DFS)
- `GET /graph/path` - Find path between nodes
- `GET /graph/subgraph` - Extract subgraph
- `GET /graph/centrality` - Node centrality metrics
- `GET /graph/attack-surface` - Attack surface for project
- `GET /graph/finding-graph` - Finding relationship graph
- `GET /graph/export` - Export graph (GraphML, JSON, Cypher)

### 6. Graph Visualization Data (`app/schemas/graph.py`)
- Node/Edge schemas with visualization properties
- Layout hints for frontend
- Filtering and pagination

### 7. Database Migration
- Alembic migration for graph tables

### 8. Integration Points
- Connect existing Asset, Finding, Observation, APK, API models to graph
- ScopeEngine integration for authorization checks
- Recon engine integration for automatic relationship creation

## Files to Create
- `app/models/graph.py`
- `app/models/finding_graph.py`
- `app/core/relationship_engine.py`
- `app/services/graph.py`
- `app/schemas/graph.py`
- `app/api/v1/graph.py`
- `tests/test_graph.py`
- Database migration

## Files to Modify
- `app/models/__init__.py`
- `app/schemas/__init__.py`
- `app/services/__init__.py`
- `app/api/v1/__init__.py`
- `app/models/assets.py` (add graph integration)
- `app/models/detection.py` (add finding graph integration)
- `app/recon/engine.py` (auto-create relationships)

## Security Controls
- All graph operations require authentication/authorization
- ScopeEngine validation on every graph query
- Relationship confidence never implies authorization
- Explicit vs inferred relationship differentiation
- Audit logging for graph modifications

## Tests
- Unit tests for relationship engine
- Integration tests for graph queries
- Security tests for scope enforcement
- Performance tests for large graphs

## Documentation
- Graph data model documentation
- Relationship type reference
- API usage guide