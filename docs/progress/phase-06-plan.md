# Phase 6 Implementation Plan

## Objective
Build project, scope, target, exclusion, and testing-policy management with authorization confirmation before active scans. Make scope and authorization impossible to overlook in the workflow.

## Minimal Scope (lazy / ponytail)
- Project creation / management docs and API spec (not full frontend)
- Scope preview and validation functionality
- Security confirmation view spec (server-side validation as ultimate authority)
- Target registration for domain, URL, API, API spec, APK

## Architecture Changes (docs only)
- Project / scope / target schemas in `docs/phases/phase-06.md`
- Scope preview endpoint spec
- Authorization confirmation flow spec

## Security Controls
- ScopeEngine remains independent authorization boundary
- Server-side validation is ultimate authority (never rely on client-side)
- Scope status (in-scope / out-of-scope / unknown / third-party) must be visible

## Tests (not implemented — docs reference only)
- Project isolation, scope matching, exclusion handling, authorization checks, invalid target rejection

## Documentation Updated
- `docs/progress/current-phase.md` — phase 6 in progress
- `docs/progress/phase-06-plan.md` — this file
- `docs/phases/phase-06.md` — operative requirements

shortcut: full scanning engine, full frontend screens, and all backend tests are not included in this minimal docs-only pass; upgrade when phase 6 moves from spec to build.
