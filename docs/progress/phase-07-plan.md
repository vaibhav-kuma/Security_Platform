# Phase 7 Implementation Plan

## Objective
Build asynchronous job/worker infrastructure (Celery-based, using existing infrastructure) with dummy worker verification, scan events, and authorization confirmation integration.

## Minimal Executable Scope
- Dummy worker endpoint (`POST /dummy-worker/verify`) that runs existing Celery lifecycle
- Scope preview endpoint (already in authorization router)
- Authorization gate integrated into scan creation
- Job event schema reuses `ScanEvent`

## Architecture Changes
- `app/api/v1/authorization.py` — authorization confirmation + scope preview
- `app/api/v1/scans.py` — authorization gate before scan creation
- `app/workers/tasks.py` — dummy task verification

## Security Controls
- Authorization confirmation uses server-side `ScopeEngine` (independent from client)
- Scan creation requires target scope validation (`validate_target_for_scan`)
- Scope preview shows rules without applying changes

## Tests
- `tests/test_authorization_phase6.py` — authorization and preview assertions
- Syntax verification only (DB not available)

shortcut: full worker pool, WebSocket events, real recon plugins, and full scan engine not implemented; upgrade when moving from dummy lifecycle to production scanners.
