# Current Phase Status

_Last updated: 2026-10-04_

## Status

| Item | State |
|---|---|
| Completed phases | Phase 0 (architecture spec), Phase 1 (dev environment & DevOps foundation), Phase 2 (PostgreSQL domain model & migrations), Phase 3 (authN/authZ & RBAC), Phase 4 (Scope engine & target validation), Phase 5 (Frontend foundation), **Phase 12 (Security Analysis Engine)** |
| Current phase | **Phase 12 — Complete** |
| Next phase | Phase 6 — Scanning engine foundation (or next sequential phase per project plan) |

## Phase 12 Outcome (completed 2026-10-04)

### Core Security Analysis Engine Components

#### 1. Evidence Sanitization Pipeline (`app/core/evidence_sanitizer.py`)
- **SecretRedactor**: Detects and redacts API keys, tokens, secrets (AWS, GitHub, GitLab, Slack, Stripe, JWT, private keys, database URLs, SSH keys, cloud credentials)
- **PIIRedactor**: Detects and redacts personally identifiable information (emails, phone numbers, SSN, credit cards, private IPs, MAC addresses, UUIDs)
- **CredentialDetector**: Specialized detector for authentication credentials (basic auth in URLs, auth headers, session cookies, form passwords, OAuth tokens, API key headers, DB connection strings, env vars)
- **EvidenceSanitizer**: Main pipeline combining all redactors with proper ordering (credentials → secrets → PII)
- **Recursive dict sanitization** for JSON evidence structures

#### 2. CVSS v3.1 Scoring (`app/core/cvss.py`)
- Full CVSS v3.1 calculator per FIRST specification
- Vector string parsing and serialization (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Default vectors for 30+ vulnerability categories (SQLi, XSS, SSRF, BOLA, IDOR, etc.)
- Severity ratings: NONE (0.0), LOW (0.1-3.9), MEDIUM (4.0-6.9), HIGH (7.0-8.9), CRITICAL (9.0-10.0)

#### 3. Finding Correlation Engine (`app/core/finding_correlation.py`)
- **NormalizedFindingKey**: Deduplication key based on asset, vuln type, location, parameter, rule identity, HTTP method
- **FindingCorrelationEngine**: Correlation with configurable similarity threshold (default 0.85)
- **Correlation types**: DUPLICATE, RELATED, VARIANT, PREREQUISITE, CHAIN, SAME_ROOT_CAUSE
- **FindingCluster**: Groups findings into clusters (primary + duplicates + related + variants)
- Vulnerability type normalization mapping (100+ variants to canonical types)
- Asset value normalization per type (domain, IP, URL, endpoint, APK)

#### 4. Manual Review Queue (`app/core/manual_review.py`)
- **ManualReviewQueue**: Service for managing review items
- **ReviewPolicy**: Configurable policies (confidence thresholds, severity auto-review, observation types, heuristic-only, unknown scope)
- **Auto-review logic**: Determines when observations need human review
- **Review states**: PENDING, IN_PROGRESS, NEEDS_MORE_INFO, PROMOTED_TO_FINDING, DISMISSED, ESCALATED
- **Review reasons**: LOW_CONFIDENCE, INSUFFICIENT_EVIDENCE, AMBIGUOUS_SEVERITY, HEURISTIC_ONLY, NO_DETECTION_RULE, CONFLICTING_SIGNALS, NEW_VULNERABILITY_TYPE, SCOPE_UNCLEAR, POLICY_REQUIRES_REVIEW, CUSTOM

#### 5. Analysis Engine Orchestrator (`app/core/analysis_engine.py`)
- **AnalysisEngine**: Central pipeline orchestrating ingest → sanitize → observe → correlate → triage → review
- **IngestionContext**: Rich context for observation ingestion (project, scan, asset, source, scanner info, scope status)
- **Pipeline steps**:
  1. Sanitize payload and evidence
  2. Create Observation record
  3. Check for duplicate observations
  4. Save observation
  5. Attach sanitized evidence
  6. Auto-promote to Finding if high confidence + sufficient evidence + detection rule
  7. Otherwise queue for manual review
  8. Correlate with existing findings
- **Batch ingestion** support for multiple observations

### Database Models Extended (`app/models/detection.py`)
- **Finding**: Added `cvss_vector` field for storing CVSS vector string
- **CWE**: New model for Common Weakness Enumeration reference data (cwe_id, name, description, related weaknesses, consequences, mitigations)
- **ManualReviewQueue**: New model for persisting review queue items (observation_id, project_id, scan_id, asset_id, title, description, observation_type, severity_hint, confidence_hint, payload, review_reason, priority, status, assigned_to, reviewer_notes, reviewed_at, resolved_at, promoted_finding_id, metadata)

### Enums Added (`app/models/enums.py`)
- **SecurityEventType**: Added finding/observation/evidence/review events (FINDING_CREATE, FINDING_UPDATE, FINDING_DELETE, FINDING_PROMOTE, FINDING_STATUS_CHANGE, OBSERVATION_CREATE, OBSERVATION_DISMISS, EVIDENCE_ADD, REVIEW_QUEUE_ENQUEUE, REVIEW_QUEUE_DECIDE)
- **ReviewPriority**: LOW, MEDIUM, HIGH, CRITICAL
- **ReviewStatus**: PENDING, IN_PROGRESS, NEEDS_MORE_INFO, PROMOTED_TO_FINDING, DISMISSED, ESCALATED
- **ReviewReason**: LOW_CONFIDENCE, INSUFFICIENT_EVIDENCE, AMBIGUOUS_SEVERITY, HEURISTIC_ONLY, NO_DETECTION_RULE, CONFLICTING_SIGNALS, NEW_VULNERABILITY_TYPE, SCOPE_UNCLEAR, POLICY_REQUIRES_REVIEW, CUSTOM

### Database Migration
- **Alembic migration**: `20261004_e797863fe107_phase_12_add_findings_evidence_review_.py`
  - Creates `cwes` table with unique index on `cwe_id`
  - Creates `manual_review_queue` table with FKs to observations, projects, scans, assets, users, findings
  - Adds `cvss_vector` column to `findings` table
  - All indexes for query performance

### Schemas (`app/schemas/findings.py`)
- **Observation**: Create, Update, Response, Detail, List (with evidence)
- **Evidence**: Create, Update, Response, List (with type, storage, content, object_key, sha256, redaction markers)
- **Finding**: Create, Update, Promote, Response, Detail, List (with evidence, comments, relationships)
- **FindingComment**: Create, Response
- **FindingRelationship**: Create, Response
- **ManualReviewItem**: Response, List, Stats
- **ManualReviewDecision**: Request, Response
- **Correlation**: Result, Cluster, Analysis Request/Response
- **CVSS**: Vector Request, Score Response
- **CWE**: Entry Response
- **Batch**: Observation Ingest Request/Response

### Services (`app/services/findings.py`)
- **FindingService**: CRUD, status updates, evidence, comments, relationships, statistics
- **ObservationService**: CRUD, ingestion (single + batch), promotion, dismissal
- **EvidenceService**: Sanitize-and-store, listing, download, re-redaction
- **CorrelationService**: Single finding correlation, all-findings clustering, duplicate marking
- **ManualReviewService**: Enqueue, list, assign, resolve, promote, dismiss, stats
- **CVSSService**: Calculate, parse vectors, default vectors by category

### API Endpoints (`app/api/v1/findings.py`)

#### Findings (`/projects/{project_id}/findings`)
- POST `/` - Create finding
- GET `/` - List findings (paginated, filtered by status/severity/confidence/asset)
- GET `/stats` - Finding statistics (by status, severity, confidence)
- GET `/{finding_id}` - Get finding with evidence, comments, relationships
- PATCH `/{finding_id}` - Update finding
- PATCH `/{finding_id}/status` - Update status with audit trail
- DELETE `/{finding_id}` - Soft delete finding
- POST `/{finding_id}/evidence` - Add evidence
- GET `/{finding_id}/evidence` - List evidence
- GET `/{finding_id}/evidence/{evidence_id}` - Get evidence
- POST `/{finding_id}/comments` - Add comment
- GET `/{finding_id}/comments` - List comments
- POST `/{finding_id}/relationships` - Add relationship
- GET `/{finding_id}/relationships` - List relationships

#### Observations (`/projects/{project_id}/observations`)
- POST `/` - Create observation
- POST `/ingest` - Ingest through analysis engine (sanitization, correlation, auto-promotion)
- POST `/ingest/batch` - Batch ingest observations
- GET `/` - List observations (paginated, filtered)
- GET `/{observation_id}` - Get observation with evidence
- PATCH `/{observation_id}` - Update observation
- POST `/{observation_id}/promote` - Promote to finding
- POST `/{observation_id}/dismiss` - Dismiss observation

#### Correlation (`/projects/{project_id}/correlation`)
- POST `/analyze` - Analyze correlations for a finding
- GET `/clusters` - Get all finding clusters
- POST `/{finding_id}/mark-duplicate` - Mark finding as duplicate

#### Manual Review (`/projects/{project_id}/review`)
- GET `/` - List review queue (paginated, filtered)
- GET `/stats` - Queue statistics
- GET `/{item_id}` - Get review item
- POST `/{item_id}/assign` - Assign to current user
- POST `/{item_id}/decide` - Make decision (promote/dismiss/needs_more_info/escalate)

#### CVSS (`/cvss`)
- POST `/calculate` - Calculate CVSS from vector
- GET `/default/{category}` - Get default CVSS for category

### Tests
- **31 new unit tests** (`tests/test_phase12_analysis_engine.py`):
  - SecretRedactor: 5 tests (AWS, GitHub, JWT, private key, no false positive)
  - PIIRedactor: 4 tests (email, phone, SSN, private IP)
  - CredentialDetector: 3 tests (basic auth URL, auth header, form password)
  - EvidenceSanitizer: 2 tests (combined, dict)
  - CVSS: 6 tests (critical, high, medium, low, roundtrip, default vectors)
  - FindingCorrelation: 5 tests (normalize vuln type, normalize asset, compute key, exact duplicate, similarity)
  - ManualReview: 4 tests (low confidence, high severity, heuristic only, high confidence no queue)
  - AnalysisEngineIntegration: 2 tests (context creation, result enum)
- **All 123 total tests pass** (92 existing + 31 new)

### Security Invariants Enforced
1. **Observation ≠ Finding**: Never auto-promote observation to confirmed finding without sufficient evidence
2. **Severity ⊥ Confidence**: Independent enums, never derived from each other
3. **Evidence Redaction**: All evidence passes through sanitizer before storage/display
4. **Scope Validation**: Findings only created for in-scope assets (via ScopeEngine integration)
5. **Audit Trail**: All finding status changes, promotions, reviews audited

### Architecture Changes
| Component | Files Created | Files Modified |
|---|---|---|
| Core Engine | analysis_engine.py, evidence_sanitizer.py, cvss.py, finding_correlation.py, manual_review.py | - |
| Models | - | detection.py (CWE, ManualReviewQueue, cvss_vector), enums.py (Review enums, SecurityEventType) |
| Schemas | findings.py | - |
| Services | findings.py | - |
| API | findings.py (router + obs_router + corr_router + review_router + cvss_router) | api/v1/__init__.py |
| Database | alembic/versions/20261004_e797863fe107_phase_12_add_findings_evidence_review_.py | - |
| Tests | test_phase12_analysis_engine.py | - |

### Test Results
- **123 tests pass** (92 existing + 31 Phase 12)
- **1 skipped** (FK constraint test)
- **0 failures**

### Known Limitations / Technical Debt
1. **ManualReviewQueue persistence**: Service currently returns in-memory items; full DB persistence needs integration with API endpoints
2. **CWE data seeding**: CWE table created but not populated with reference data (needs seed script)
3. **Object storage for evidence**: Evidence model supports `object_key` for MinIO/S3 but storage integration not implemented
4. **Real-time review queue**: No WebSocket notifications for review queue updates
5. **Finding correlation UI**: Frontend integration for correlation clusters not yet implemented

### Prerequisites for Next Phase
- Phase 6: Scanning engine foundation (worker pool, job queue, execution policies)
- Integration with ScopeEngine for scan-time target validation
- Scan job scheduling and result aggregation
- Real-time scan progress via WebSockets

### Documentation Updated
- `docs/progress/current-phase.md` - This file
- `docs/progress/phase-12-plan.md` - Implementation plan (created)