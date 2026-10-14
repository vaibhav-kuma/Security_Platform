# Phase 19 Implementation Plan

## Objective
Implement a versioned Security Knowledge Base that allows the platform to evolve independently from its core application logic. Model and manage versioned OWASP WSTG definitions, OWASP API Security definitions, MASTG and MASVS mappings, CWE metadata, CVSS metadata, detection rules, remediation content, methodology test cases, and technology fingerprints as separately versioned rule or knowledge packs.

## Architecture Changes

### 1. Knowledge Pack Models (`app/models/knowledge.py`)
- **KnowledgePack**: Main pack container (name, version, type, description, author, checksum, status)
- **PackContent**: Individual rules/content within a pack (identity, version, name, methodology, category, target_types, prerequisites, evidence_requirements, severity_guidance, confidence_guidance, references, detection_behavior)
- **PackVersion**: Version history with changelog, compatibility info
- **PackDependency**: Dependencies between packs
- **PackInstallation**: Installation record with activation state, installed_by, installed_at

### 2. Knowledge Pack Schemas (`app/schemas/knowledge.py`)
- Pack metadata schemas
- Content schemas for each type (WSTG, API Security, MASTG, MASVS, CWE, CVSS, Detection Rules, Remediation, Methodology, Fingerprints)
- Installation/activation schemas
- Validation schemas

### 3. Knowledge Pack Service (`app/services/knowledge.py`)
- **Download**: Fetch packs from remote repository with auth
- **Integrity Verification**: SHA256 checksum, GPG signature verification
- **Schema Validation**: Validate against pack content schema
- **Security Validation**: Sandbox validation, no executable code, safe patterns only
- **Installation**: Atomic install with rollback on failure
- **Activation/Deactivation**: Toggle pack versions
- **Rollback**: Revert to previous version
- **Audit Logging**: All operations logged

### 4. Knowledge Pack Update Pipeline (`app/services/knowledge_pipeline.py`)
- Scheduled checks for updates
- Staged download and validation
- Admin approval workflow
- Automated installation with health checks
- Rollback on validation failure

### 5. API Endpoints (`app/api/v1/knowledge.py`)
- `GET /knowledge/packs` - List installed packs
- `GET /knowledge/packs/{pack_id}` - Get pack details
- `GET /knowledge/packs/{pack_id}/content` - List pack content
- `GET /knowledge/packs/{pack_id}/content/{content_id}` - Get specific rule/content
- `POST /knowledge/packs` - Install pack (upload or from registry)
- `PATCH /knowledge/packs/{pack_id}` - Activate/deactivate pack
- `POST /knowledge/packs/{pack_id}/rollback` - Rollback to previous version
- `DELETE /knowledge/packs/{pack_id}` - Uninstall pack
- `GET /knowledge/registry` - List available packs from registry
- `POST /knowledge/check-updates` - Check for pack updates
- `GET /knowledge/packs/{pack_id}/audit` - Pack audit log

### 6. Knowledge Pack Types
- **OWASP WSTG**: Web Security Testing Guide test cases
- **OWASP API Security**: API Security Top 10 test cases
- **MASTG**: Mobile Application Security Testing Guide
- **MASVS**: Mobile Application Security Verification Standard
- **CWE**: Common Weakness Enumeration metadata
- **CVSS**: CVSS metadata and scoring guidance
- **Detection Rules**: Vulnerability detection rules
- **Remediation**: Remediation guidance content
- **Methodology**: Testing methodology definitions
- **Fingerprints**: Technology fingerprint definitions

### 6. Database Migration
- Alembic migration for knowledge pack tables

### 7. CLI Tool (`scripts/knowledge_cli.py`)
- List installed packs
- Install/activate/deactivate packs
- Check updates
- Rollback packs

### 8. Documentation
- Knowledge pack authoring guide
- Update pipeline documentation
- Security validation rules

## Files to Create
- `app/models/knowledge.py`
- `app/schemas/knowledge.py`
- `app/services/knowledge.py`
- `app/services/knowledge_pipeline.py`
- `app/api/v1/knowledge.py`
- `scripts/knowledge_cli.py`
- `tests/test_knowledge.py`
- `docs/knowledge/pack-authoring-guide.md`

## Files to Modify
- `app/models/__init__.py`
- `app/schemas/__init__.py`
- `app/services/__init__.py`
- `app/api/v1/__init__.py`
- `app/config.py`
- Database migration

## Security Controls
- Packs treated as untrusted input
- Schema validation before processing
- No executable code in packs
- Signature verification for official packs
- Sandboxed validation
- Audit trail for all operations
- Rollback capability

## Tests
- Unit tests for models, schemas, service
- Integration tests for installation pipeline
- Security tests for validation
- Negative tests (malformed packs, invalid signatures)

## Documentation
- Pack authoring guide
- Update pipeline documentation
- Admin CLI reference