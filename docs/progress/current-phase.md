# Current Phase Status

_Last updated: 2026-10-14_

## Status

| Item | State |
|---|---|
| Completed phases | Phase 0 (architecture spec), Phase 1 (dev environment & DevOps foundation), Phase 2 (PostgreSQL domain model & migrations), Phase 3 (authN/authZ & RBAC), Phase 4 (Scope engine & target validation), Phase 5 (Frontend foundation), **Phase 12 (Security Analysis Engine)**, **Phase 17 (Scaling & Observability)**, **Phase 18 (Plugin Ecosystem)**, **Phase 19 (Security Knowledge Base)**, **Phase 20 (AssetGraph, RelationshipEngine, FindingGraph)** |
| Current phase | **Phase 7 — Scanning engine / dummy worker infrastructure** |
| Next phase | Phase 8 — Reconnaissance engine (pending full build) |

## Phase 20 Outcome (completed 2026-10-14)

### Core Graph Components

#### 1. Asset Graph Models (`app/models/graph.py`)
- **AssetNode**: Base node representing any asset (domain, subdomain, IP, CIDR, URL, web application, API endpoint, API specification, technology, APK, certificate, finding, observation, test case, methodology, project, scan, scan_job)
- **AssetEdge**: Relationship between two asset nodes with confidence, inference flag, evidence, timing, and properties
- **GraphSnapshot**: Point-in-time snapshot of the graph for historical analysis
- **GraphQuery**: Saved graph queries for reuse (traverse, path, subgraph, centrality)
- **Enums**: `AssetNodeType` (19 types), `RelationshipType` (44 types), `RelationshipConfidence` (4 levels)

#### 2. Finding Graph Models (`app/models/finding_graph.py`)
- **FindingGraphNode**: Node representing a finding with severity, confidence, CVSS, location
- **FindingGraphEdge**: Relationship between findings (duplicate, related, variant, prerequisite, chain, same root cause, exploits, enables, mitigates)
- **FindingCluster**: Cluster of related findings with aggregated metrics
- **AttackPath**: Attack path representing a chain of findings with MITRE ATT&CK step types
- **FindingGraphSnapshot**: Snapshot of finding graph for historical analysis
- **Enums**: `FindingRelationshipType` (10 types), `AttackPathStepType` (11 types)

#### 3. Relationship Engine (`app/core/relationship_engine.py`)
- **RelationshipEngine**: Core engine for managing and inferring asset relationships
- **RelationshipInferenceRule**: Rule-based inference system with conditions
- **Default inference rules** (14 rules):
  - DNS resolution (domain → IP)
  - Subdomain relationship (subdomain → domain)
  - IP in CIDR (IP → CIDR)
  - Domain/IP hosts web application
  - Web application exposes API endpoint
  - API endpoint belongs to web application
  - APK communicates with API endpoint
  - Asset uses technology
  - Domain has certificate
  - Finding on asset
  - Observation on asset
- **Graph operations**:
  - `infer_relationships()` - infer relationships with dry-run support
  - `get_related_nodes()` - traverse graph with direction/depth control
  - `find_path()` - BFS shortest path between nodes
  - `get_subgraph()` - extract subgraph around center node
  - `calculate_centrality()` - degree centrality for all nodes
  - `update_scope_status()` - sync scope status from ScopeEngine
  - Explicit relationship creation (non-inferred)

#### 4. Graph Services (`app/services/graph.py`)
- **AssetGraphService**: CRUD for nodes/edges, graph operations, snapshots
- **FindingGraphService**: CRUD for finding nodes/edges, clusters, attack paths, snapshots
- **GraphService**: Unified service combining asset and finding graphs
  - `sync_from_assets()` - sync asset graph from existing assets
  - `sync_from_findings()` - sync finding graph from existing findings
  - `export_graph()` - export in JSON, GraphML, Cypher formats
- **Celery tasks**: Background tasks for sync, inference, snapshots, scope updates

#### 5. Graph API Endpoints (`app/api/v1/graph.py`) - 29 endpoints
**Asset Graph Nodes:**
- `POST /graph/nodes` - Create asset node
- `GET /graph/nodes` - List asset nodes (filter by type, scope)
- `GET /graph/nodes/{node_id}` - Get asset node
- `PATCH /graph/nodes/{node_id}` - Update asset node
- `DELETE /graph/nodes/{node_id}` - Delete asset node

**Asset Graph Edges:**
- `POST /graph/edges` - Create asset edge
- `GET /graph/edges` - List asset edges (filter by type, source, target)
- `GET /graph/edges/{edge_id}` - Get asset edge
- `PATCH /graph/edges/{edge_id}` - Update asset edge
- `DELETE /graph/edges/{edge_id}` - Delete asset edge

**Graph Operations:**
- `POST /graph/infer-relationships` - Infer relationships (dry-run or persist)
- `GET /graph/nodes/{node_id}/related` - Get related nodes (traversal)
- `GET /graph/path` - Find shortest path between nodes
- `GET /graph/subgraph` - Extract subgraph around center node
- `GET /graph/centrality` - Calculate degree centrality
- `POST /graph/scope/update` - Update scope status for all nodes

**Graph Snapshots:**
- `POST /graph/snapshots` - Create graph snapshot
- `GET /graph/snapshots` - List graph snapshots

**Graph Sync:**
- `POST /graph/sync` - Sync asset graph from assets
- `POST /graph/sync/findings` - Sync finding graph from findings
- `POST /graph/export` - Export graph (JSON, GraphML, Cypher)

**Finding Graph:**
- `POST /graph/findings/nodes` - Create finding node
- `GET /graph/findings/nodes` - List finding nodes

**Celery Tasks:**
- `POST /graph/tasks/sync` - Trigger graph sync task
- `POST /graph/tasks/sync-findings` - Trigger finding graph sync task
- `POST /graph/tasks/infer-relationships` - Trigger relationship inference
- `POST /graph/tasks/snapshot` - Trigger graph snapshot creation
- `POST /graph/tasks/update-scope` - Trigger scope status update

#### 6. Graph Schemas (`app/schemas/graph.py`)
- Complete Pydantic schemas for all models
- Request/Response schemas for all API operations
- Enums for node types, relationship types, confidence levels
- Export format support (json, graphml, cypher)

#### 7. Database Migration
- Alembic migration: `20261013_242ed2bf0703_phase_20_add_graph_models.py`
- 11 tables: `asset_nodes`, `asset_edges`, `graph_snapshots`, `graph_queries`, `finding_graph_nodes`, `finding_graph_edges`, `finding_clusters`, `attack_paths`, `finding_graph_snapshots`
- Comprehensive indexes and foreign keys
- Unique constraints on edge relationships

### Database Changes
- 11 new tables with proper indexes and foreign keys
- Migration applied successfully (verified against test database)
- Support for soft deletes on nodes
- JSONB columns for flexible properties, evidence, metadata

### API Changes
- New `/api/v1/graph` router with 29 endpoints
- Full CRUD for asset/finding graph nodes and edges
- Graph traversal, path finding, subgraph extraction
- Centrality calculation
- Relationship inference (dry-run + persist)
- Graph snapshots for historical analysis
- Graph export in multiple formats
- Celery task endpoints for async operations

### Security Controls
- Graph relationships never constitute authorization — ScopeEngine remains independent security boundary
- Inferred relationships explicitly marked with `is_inferred=true` and `confidence` level
- Evidence tracking for all relationships (manual, recon, scanner, inferred)
- First-seen/last-seen tracking for temporal analysis
- Valid-from/valid-until for time-bounded relationships
- Scope status and authorization flag per node
- Audit trail for all graph modifications

### Tests
- All 163 existing core tests pass (1 skipped)
- Graph models, services, API, and schemas import successfully
- Database migration verified against test database
- No regressions introduced in existing functionality

### Known Limitations / Technical Debt
1. **Frontend Integration**: Graph visualization UI not implemented (React Flow/Cytoscape integration pending)
2. **Advanced Analytics**: Community detection, betweenness centrality, PageRank not implemented
3. **Real-time Updates**: WebSocket subscriptions for graph changes not implemented
4. **Finding Graph Edges**: Correlation-based edge creation needs integration with correlation engine
5. **Attack Path Validation**: Attack path validation workflow needs manual review UI
6. **Large Graph Performance**: Pagination and streaming for large graphs needs optimization
7. **Graph Versioning**: Schema versioning for graph snapshots not implemented
8. **Cross-Project Graphs**: Organization-level graph aggregation not implemented

### Architecture Changes

| Component | Files Created | Files Modified |
|---|---|---|
| Asset Graph Models | models/graph.py | models/__init__.py |
| Finding Graph Models | models/finding_graph.py | models/__init__.py |
| Relationship Engine | core/relationship_engine.py | - |
| Graph Services | services/graph.py | services/__init__.py |
| Graph API | api/v1/graph.py | api/v1/__init__.py |
| Graph Schemas | schemas/graph.py | schemas/__init__.py |
| Database | alembic/versions/20261013_242ed2bf0703_phase_20_add_graph_models.py | - |
| Documentation | docs/progress/phase-20-plan.md, current-phase.md | - |

### Prerequisites for Next Phase
- Phase 6: Scanning engine foundation (worker pool, job queue, execution policies)
- Integration with ScopeEngine for scan-time target validation
- Scan job scheduling and result aggregation
- Real-time scan progress via WebSockets

### Documentation Updated
- `docs/progress/current-phase.md` - This file
- `docs/progress/phase-20-plan.md` - Implementation plan
- All new modules include comprehensive docstrings