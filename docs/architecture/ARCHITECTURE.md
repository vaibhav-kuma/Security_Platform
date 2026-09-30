# Architecture — Authorized Security Assessment Platform

> Status: Phase 0 specification (architecture only — no implementation exists yet).
> Source of truth: `docs/phases/phase-00.md` … `phase-20.md` and `CLAUDE.md`.
> **Known gap:** CLAUDE.md names `docs/PROJECT_MASTER_PROMPT.md` as the master requirements source, but that file does not exist. The phase files are the operative requirements until it is restored. See `PHASE_DEPENDENCIES.md` § Ambiguity Register.

## 1. Product Vision

An open-source platform for **authorized** penetration testing and bug-bounty security assessment. Every test executes only inside explicitly authorized project scope. The platform supports six target classes:

| Target type | Methodology mapping |
|---|---|
| Domain | Recon / attack-surface mapping (feeds WSTG) |
| URL / Web Application | OWASP WSTG |
| REST API / GraphQL | OWASP API Security |
| OpenAPI / Swagger specification | OWASP API Security (spec-driven inventory) |
| Android APK | OWASP MASTG / MASVS |
| (Cross-target) | CWE + CVSS mappings for findings |

Design principles: security-first, modular, extensible, testable, open-source friendly, **secure-by-default**.

## 2. Personas

- **Penetration testers** — structured engagements with scope, methodology coverage, and deliverable reports.
- **Bug-bounty hunters** — program-scoped research workspace: recon → testing → validation → finding → report draft.
- **Security teams** — org/project management, RBAC, audit trails, continuous assessment.
- **Plugin developers** — third-party scanner/methodology extensions via the ScannerPlugin SDK (Phase 18).
- **Administrators** — knowledge-pack management, plugin lifecycle, deployment.

## 3. Core Workflow (mandated, phase-00)

```
Target → Authorization → Scope Validation → Classification → Discovery →
Attack-Surface Mapping → Methodology Selection → Test Planning →
Controlled Testing → Observation → Evidence → Correlation →
Manual Validation → Finding → Risk → Remediation → Reporting
```

Hard rules embedded in every stage:

- Relationship or discovery **never** constitutes authorization.
- An **Observation** (something suspicious detected) is never auto-promoted to a confirmed **Finding** without sufficient evidence.
- **Severity** and **confidence** are separate axes; "not detected" ≠ "secure".

## 4. High-Level System Architecture

```
                ┌────────────────────────────┐
                │  Next.js / React frontend  │  (shadcn/ui, React Query, WebSocket client)
                └─────────────┬──────────────┘
                              │ REST /api/v1 + WebSocket events
                ┌─────────────▼──────────────┐
                │        FastAPI core        │  routers → services → domain → repositories
                │  AuthN/AuthZ · ScopeEngine │  Pydantic schemas · structured errors · audit
                └──┬───────────┬──────────┬──┘
                   │           │          │
          ┌────────▼───┐  ┌────▼─────┐ ┌──▼─────────────┐
          │ PostgreSQL │  │  Redis   │ │     MinIO      │
          │ (system of │  │ queues + │ │ artifacts:     │
          │  record)   │  │ rate-lim │ │ evidence, APKs,│
          └────────────┘  └────┬─────┘ │ screenshots,   │
                               │       │ reports        │
                     ┌─────────▼──────┐└────────────────┘
                     │  Worker pool   │
                     │ Scan→ScanJob→  │
                     │ ScanEvent      │
                     └─────────┬──────┘
                               │ plugin interfaces (ReconPlugin / ScannerPlugin SDK)
              ┌────────────────┼─────────────────────────┐
              ▼                ▼                         ▼
        Recon plugins    Web/API/APK engines      Third-party plugins
        (Phase 8)        (Phases 9, 11, 13–14)    (Phase 18)

Observability: Prometheus + Grafana + OpenTelemetry (placeholders Phase 1, wired Phase 17).
Deployment: Docker Compose (dev/test/prod profiles), GitHub Actions CI.
```

### Execution pipeline (Phase 7 invariant)

```
API → Scan → ScanJob → Queue → Worker → Plugin → Observation
```

Every job carries: project context, **scope snapshot** (immutable), execution policy, testing profile, rate limits, security metadata.

## 5. Monorepo Layout (Phase 1)

```
apps/          # frontend (Next.js) and backend (FastAPI) applications
workers/       # scanner/worker processes and job executors
packages/      # shared libraries (schemas, SDK, security kernels)
rules/         # methodology + detection-rule + knowledge-pack sources
infrastructure/# Docker, Compose, CI, observability config
docs/          # this documentation tree
scripts/       # dev, seed, migration, tooling scripts
tests/         # unit / integration / e2e / security regression suites
```

## 6. Layered Backend Architecture (Phase 3)

Clean architecture with dependency inversion:

1. **API routers** — versioned REST (`/api/v1`), OpenAPI auto-docs, pagination/filter/sort.
2. **Application services** — orchestration, transactions, audit emission.
3. **Domain logic** — ScopeEngine, finding lifecycle, correlation rules (framework-free).
4. **Repositories** — explicit interfaces over SQLAlchemy persistence.
5. **Persistence models** — SQLAlchemy/Alembic, UUID PKs (Phase 2 schema).

Structured error taxonomy, e.g. `TARGET_OUT_OF_SCOPE`, `FORBIDDEN_RESOURCE_ACCESS`.

## 7. Entity Lifecycle Spine

```
Organization → Project → Scope → Target → Asset → Scan → Observation → Finding → Evidence
```

Asset families hang off Asset with relationships: Domain ↔ Subdomain ↔ IP ↔ Port ↔ URL/Endpoint ↔ Technology ↔ Certificate; API → endpoints → methods → parameters → schemas; APK → components. Phase 20 layers AssetGraph/RelationshipEngine/FindingGraph over all of it, keeping scope/authorization state per entity.

## 8. MVP / V1 / V2 / Future Classification (phase-00 requirement)

| Tier | Components |
|---|---|
| **MVP** | Monorepo+CI (P1), data model (P2), core API (P3), auth/RBAC/audit (P4), frontend foundation (P5), project/scope/target workflows (P6), job/worker infra + dummy worker (P7), recon engine (P8), web mapping (P9), methodology layer (P10), analysis engine (P12) |
| **V1** | API security engine (P11), APK static analysis (P13), reporting + bug-bounty workspace (P15), security hardening audit (P16) |
| **V2** | Scaling + observability (P17), plugin SDK/ecosystem (P18), versioned knowledge base (P19) |
| **Future** | APK dynamic analysis (P14 — optional, disabled by default), AssetGraph/FindingGraph (P20), OAuth/OIDC, external submission (explicitly human-controlled, never automated) |

## 9. Related Documents

- Components & interfaces: `COMPONENTS.md`
- Runtime data flows: `DATA_FLOW.md`
- Trust boundaries & invariants: `TRUST_BOUNDARIES.md`
- Technology decisions: `TECHNOLOGY_DECISIONS.md`
- Phase dependency graph, migration hazards, ambiguity register, roadmap: `PHASE_DEPENDENCIES.md`