# Phase Dependency Graph, Migration Hazards, Ambiguity Register & Roadmap

## 1. Dependency Graph (Phases 0–20)

```
P0 (architecture docs — this set)
└─ P1 (dev infra, monorepo, Docker, CI)
   └─ P2 (PostgreSQL domain model, Alembic, repositories)
      └─ P3 (FastAPI core, CRUD for org/project/scope/target/asset)
         ├─ P4 (AuthN, RBAC, audit, security middleware)  ◄── GATE: must precede any scanning worker
         │   ├─ P5 (frontend foundation, design system)
         │   │   └─ P6 (project/scope/target workflows + confirmation views + scope preview)
         │   └─ P7 (job/worker infra, dummy worker, WebSocket events)
         │       ├─ P8 (recon engine: ReconPlugin, ScopeEngine, RateLimiter, TargetNormalizer, ExecutionPolicy)
         │       │   └─ P9 (web mapping: crawler, application model, SSRF protections)
         │       │       └─ P10 (methodology layer: TestPlanner, CoverageEngine, versioned rule packs)
         │       │           └─ P11 (API security engine + API methodology)
         │       ├─ P12 (analysis engine: Observation/Finding/Evidence, redaction, correlation)  ◄── consumes P8–P11 output
         │       │   ├─ P13 (APK static analysis → shared analysis engines)
         │       │   │   └─ P14 (APK dynamic analysis — optional, isolated, off by default)
         │       │   └─ P15 (reporting + bug-bounty workspace)
         │       └─ (P17 scaling needs P7+ runtime under load)
         ├─ P16 (security audit & hardening) ◄── after main capabilities functional (P15-complete baseline)
         ├─ P17 (scaling + observability)
         ├─ P18 (plugin SDK/ecosystem) ◄── generalizes P8's plugin interface + P7 isolation
         ├─ P19 (versioned knowledge base) ◄── externalizes P10/P11/P13 methodology + detection rules
         └─ P20 (AssetGraph / RelationshipEngine / FindingGraph) ◄── consumes all entity families
```

### Edge table (condensed rationale)

| Edge | Why |
|---|---|
| 0→1 | Architecture specs govern the scaffold |
| 1→2 | Migrations/tests need the monorepo, Docker services, CI |
| 2→3 | Repositories/models precede services/API |
| 3→4 | RBAC attaches to existing services/resources; audit needs the API surface |
| 4→7 | Phase 4 explicitly: security boundaries must exist **before** the platform controls security-testing workers |
| 3,4→6 | Workflows need CRUD APIs + authorization; P5 shell hosts the screens |
| 2,3,4→7 | Jobs carry project context, scope snapshot, policy; auth gates scan creation |
| 7→8,9,11,13,14 | Every scanner executes through the job pipeline |
| 8→9 | Web mapping consumes recon's asset inventory + shared ScopeEngine/RateLimiter/Normalizer |
| 9→10 | TestPlanner selects on application model + discovered tech |
| 10→11 | API engine integrates the WSTG framework + versioned methodology layer |
| 8,9,11→12 | Analysis engine consumes scanner output; evidence model must pre-exist findings |
| 12→13 | APK results integrate with shared Observation/Finding/Evidence/Correlation engines |
| 13→14 | Dynamic analysis correlates with static results; authorization model comes first |
| 12→15 | Reports render findings/evidence/coverage |
| ≤15→16 | Audit tests the functional platform end-to-end |
| 7+→17 | Scaling tunes an existing queue/worker system |
| 7,8→18 | SDK stabilizes the existing plugin interface + isolation mechanisms |
| 10,11,13→19 | Knowledge base externalizes already-versioned methodology/detection data |
| all→20 | Graph consumes every entity family with scope state |

### Parallelizable tracks
After P4: **frontend track** (P5→P6) can run alongside **worker track** (P7→P8→P9→P10→P11). After P12: P13/P15 in parallel. P17–P19 largely independent once their anchors exist. Critical path: 1→2→3→4→7→8→9→10→12.

## 2. Migration Hazards

| Hazard | Phases | Mitigation |
|---|---|---|
| Schema accretion across many phases on one Alembic chain | 2→3→4→7→8→10→12→13→15→19→20 | Every phase adds migrations only (never rewrites history); migration tests from fresh DB each phase (P2 requirement kept as standing practice) |
| Evidence model stability | 12 onward | Evidence/redaction schema must be designed extensible in P12 — retrofitting redaction onto stored evidence is the highest-risk later change |
| Methodology data embedded → externalized | 10→19 | P10 must store methodology as versioned data/rule packs from day one (requirement), so P19 is a packaging change, not a data migration |
| Scope snapshot immutability vs schema evolution | 7 onward | Snapshot stored as versioned serialized payload; add a schema-version field from P7 |
| Observation/Finding separation retrofit | any | Separation is designed in P2 schema (distinct tables) and enforced in P12; merging them later breaks correlation keys |
| Plugin interface churn | 8→18 | ReconPlugin (P8) is the internal prototype; SDK (P18) must keep backward-compatible `validate/scan/normalize` semantics |
| Seed data vs knowledge packs | 2, 10, 19 | Keep seed data minimal; methodology content belongs to packs from P10 on |

## 3. Ambiguity & Requirements-Gap Register

| # | Item | Impact | Suggested resolution |
|---|---|---|---|
| A1 | **`docs/PROJECT_MASTER_PROMPT.md` is missing** although CLAUDE.md declares it the master source of truth | Requirement conflicts can't be escalated | Restore the file; until then phase files are operative |
| A2 | Queue library Celery vs Dramatiq undecided | Blocks P7 design freeze | Decide at P7 kickoff against the lifecycle contract |
| A3 | OAuth/OIDC "optional integration points" (P4) | Scope of auth surface unclear | Deliver integration *interfaces* in P4, providers post-MVP |
| A4 | WSTG/API-Security/MASTG version pins unspecified | Methodology reproducibility | Pin at P10/P11/P13; record as methodology versions |
| A5 | Multi-role API testing contexts (P11) need credentials but plaintext storage is forbidden | Credential handling design | Encrypted vault-style storage keyed per project; design at P11 |
| A6 | Tenancy model (multi-org isolation granularity) implied but not explicit | RBAC + query scoping | Assume org-level isolation enforced everywhere (P3/P4) |
| A7 | Emulator choice for P14 unspecified | Dynamic analysis feasibility | Decide at P14; keep subsystem disabled by default regardless |
| A8 | PDF tooling for reports unspecified | P15 delivery | Decide at P15; HTML/MD/JSON first |
| A9 | Plugin distribution/integrity key model unspecified (P18) | Supply-chain risk | Define signing/verification scheme in P18 design |

## 4. Implementation Roadmap

**Execute next: Phase 0 → then Phase 1.** This document set completes Phase 0's documentation deliverable. No code exists, so Phase 1 (monorepo + Docker + CI) is the first implementation phase.

Strict order for the spine: **P1 → P2 → P3 → P4 → P7** (P4 gates all scanning). Frontend P5–P6 may overlap P7. Scanner sequence **P8 → P9 → P10 → P11** must not start before P7's dummy worker proves cancellation + resource limits. **P12 before P13/P15.** P16 after the platform is functional; P17–P20 as specified.

Per-phase prerequisites (condensed):

| Phase | Prerequisites |
|---|---|
| P1 | Docker/Compose available; CI host; this doc set reviewed |
| P2 | P1 services (PostgreSQL) running; migration conventions |
| P3 | P2 models + repository interfaces |
| P4 | P3 services to attach RBAC/audit to |
| P5 | P3 API contract (typed clients) |
| P6 | P3 + P4 + P5 |
| P7 | P2 (Scan/ScanJob/ScanEvent tables) + P4 gate |
| P8 | P7 pipeline; ScopeEngine/RateLimiter/Policy/Normalizer built here; controlled test domains |
| P9 | P7 + P8 components; local vulnerable test apps |
| P10 | P9 application model; WSTG version pin (A4) |
| P11 | P10 framework; credential-context design (A5) |
| P12 | P8–P11 output contracts |
| P13 | P12 engines; MinIO artifact storage |
| P14 | P13 + isolated environment + explicit authorization model |
| P15 | P12 (+ P10 coverage data) |
| P16 | P15-complete functional platform |
| P17 | Working queue/worker runtime under test |
| P18 | P7 isolation + P8 plugin interface stable |
| P19 | P10/P11/P13 versioned methodology data in place |
| P20 | All entity families populated |

**Guardrail for the current phase:** do not implement scanners or application code yet — Phase 0 is exclusively architecture and engineering specifications.