# Phase 12 Implementation Plan: Security Analysis Engine

## Objective
Implement the central security-analysis engine that transforms scanner output into trustworthy observations and findings with evidence collection, redaction, correlation, and manual review workflows.

## Architecture Changes

### New Core Components
1. **AnalysisEngine** (`app/core/analysis_engine.py`) - Central orchestrator for transforming scanner output
2. **EvidenceSanitizer** (`app/core/evidence_sanitizer.py`) - Base sanitization with SecretRedactor, PIIRedactor, CredentialDetector
3. **FindingCorrelationEngine** (`app/core/finding_correlation.py`) - Deduplication and cross-scanner correlation
4. **CVSSCalculator** (`app/core/cvss.py`) - CVSS v3.1 scoring integration
5. **ManualReviewQueue** (`app/core/manual_review.py`) - Queue for ambiguous observations

### New Models (extend `app/models/detection.py`)
- Models already exist: DetectionRule, Observation, Finding, Evidence, FindingComment, FindingRelationship
- Need to add: CWE mapping table, CVSS vector storage, ManualReviewQueue table

### New Schemas (`app/schemas/findings.py`)
- Observation schemas (create, read, list)
- Finding schemas (create, read, update, list, promote)
- Evidence schemas (create, read, download)
- Finding correlation schemas
- ManualReviewQueue schemas
- CVSS/CWE mapping schemas

### New Services (`app/services/findings.py`, `app/services/evidence.py`, `app/services/correlation.py`)
- FindingService: CRUD, promotion, status transitions
- EvidenceService: Collection, sanitization, storage
- CorrelationService: Deduplication, cross-reference
- ManualReviewService: Queue management

### New API Endpoints (`app/api/v1/findings.py`, `app/api/v1/observations.py`, `app/api/v1/evidence.py`)
- Observations: POST (ingest), GET, LIST
- Findings: POST (promote), GET, LIST, PATCH (status), POST (correlate)
- Evidence: POST (attach), GET, LIST, GET (download)
- ManualReviewQueue: GET, PATCH (triage)
- Correlation: POST (analyze), GET (relationships)

### Database Migration
- Add CWE reference table
- Add CVSS vector fields to findings
- Add ManualReviewQueue table
- Add finding correlation indexes

## Implementation Steps

### 1. Core Engine & Sanitization (Week 1)
- [ ] Create AnalysisEngine with observation ingestion pipeline
- [ ] Implement EvidenceSanitizer with SecretRedactor, PIIRedactor, CredentialDetector
- [ ] Add redaction patterns for API keys, JWTs, passwords, PII, etc.
- [ ] Write unit tests for sanitization

### 2. Finding Correlation Engine (Week 1)
- [ ] Implement FindingCorrelationEngine with normalization
- [ ] Deduplication logic: normalized asset, vuln type, location, parameter, rule identity
- [ ] Cross-scanner correlation
- [ ] Write unit tests for correlation

### 3. CVSS & CWE Integration (Week 1)
- [ ] Add CWE reference data (top 50+ CWEs)
- [ ] Implement CVSS v3.1 calculator
- [ ] Map detection rules to CWE/CVSS
- [ ] Write unit tests

### 4. Models & Migration (Week 1)
- [ ] Add CWE table, ManualReviewQueue table
- [ ] Add CVSS vector storage to Finding
- [ ] Create Alembic migration
- [ ] Run migration, verify

### 5. Schemas (Week 1)
- [ ] Create `app/schemas/findings.py` with all Pydantic models
- [ ] Add validation for evidence types, finding promotion
- [ ] Type-safe API contracts

### 6. Services (Week 2)
- [ ] FindingService: CRUD, promotion, status workflow
- [ ] EvidenceService: Ingest, sanitize, store (inline + object storage ready)
- [ ] CorrelationService: Auto-correlation on finding creation
- [ ] ManualReviewService: Queue, assign, resolve

### 7. API Endpoints (Week 2)
- [ ] Observations API (ingest from scanners)
- [ ] Findings API (triage, promote, correlate)
- [ ] Evidence API (attach, retrieve)
- [ ] ManualReviewQueue API
- [ ] Correlation API

### 8. Integration & Tests (Week 2)
- [ ] Integration tests for full pipeline
- [ ] Security regression tests (no auto-promotion to confirmed critical)
- [ ] Evidence sanitization negative tests
- [ ] Correlation accuracy tests
- [ ] API contract tests

### 9. Documentation & Phase Report
- [ ] Update docs/progress/current-phase.md
- [ ] Document architecture decisions
- [ ] Phase completion report

## Key Security Invariants
1. **Observation ≠ Finding**: Never auto-promote observation to confirmed finding
2. **Severity ⊥ Confidence**: Independent enums, never derive one from another
3. **Evidence Redaction**: All evidence passes through sanitizer before storage/display
4. **Scope Validation**: Findings only created for in-scope assets
5. **Audit Trail**: All finding status changes audited

## Dependencies
- Phase 4: ScopeEngine (for finding scope validation)
- Phase 6: Scan execution (source of observations)
- Phase 11: API security models (CWE mappings, detection rules)

## Test Strategy
- Unit tests: Sanitization, correlation, CVSS calculation (target: 30+ tests)
- Integration tests: Full observation→finding pipeline (target: 15+ tests)
- Security regression: No auto-promotion, redaction effectiveness (target: 10+ tests)
- API tests: All CRUD + workflow endpoints