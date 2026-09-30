# Technology Decisions

## 1. Mandated Stack (from CLAUDE.md / phase-01)

| Technology | Role | Introduced | Rationale (per requirements) |
|---|---|---|---|
| Python 3.12+ | Backend language | P1 | Modern typing, async, ecosystem for security tooling |
| FastAPI | API framework | P1, P3 | Versioned REST, OpenAPI auto-docs, DI, Pydantic integration |
| Pydantic | Validation/schemas | P3 | Server-side validation, typed API contracts |
| SQLAlchemy | ORM/persistence | P2 | Repository abstractions over PostgreSQL |
| Alembic | Migrations | P2 | Fresh-DB-from-zero requirement; migration tests |
| PostgreSQL | System of record | P1–P2 | Integrity rules, UUID PKs, indexes, soft deletion |
| Redis | Queues, rate limiting, pub/sub | P1, P7 | Job queue backbone + real-time event fan-out |
| Next.js / React / TypeScript | Frontend | P1, P5 | Typed UI, route protection, React Query integration |
| Tailwind CSS + shadcn/ui | Design system | P5 | Consistent security-oriented UI components |
| Docker / Docker Compose | Dev/test/prod runtime | P1 | Reproducible env; one-command local startup |
| MinIO | Object storage | P1 | Evidence, APKs, screenshots, reports |
| GitHub Actions | CI | P1 | Lint, format, typing, unit/integration tests, dependency checks, build validation |
| Ruff / MyPy | Python lint + typing | P1 | Enforced in CI |
| Pytest | Python tests | P1+ | Unit/integration/API/DB/migration/security tests |
| ESLint / Prettier / pre-commit | Frontend quality + hooks | P1 | Enforced in CI |
| Argon2 | Password hashing | P4 | Mandated by phase-04 |
| Prometheus / Grafana / OpenTelemetry | Observability | P1 placeholders → P17 wired | Metrics, traces, dashboards |
| UUID primary keys | DB identity | P2 | Guessed-identifier resistance, distributed safety |

## 2. Decisions to Resolve During Implementation

| Decision | Phase | Criteria / constraints |
|---|---|---|
| Queue library: **Celery vs Dramatiq** | P7 | Reliable worker model, retries, cancellation, pause, timeout, concurrency control, recovery; whichever satisfies the Phase 7 lifecycle contract with least complexity. Phase 7 explicitly allows either. |
| WSTG version pin | P10 | Versioned methodology data; must evolve without rewriting scanner code; pick a current WSTG release and record it as methodology version 1 |
| OWASP API Security version | P11 | Same versioning discipline |
| MASTG/MASVS version | P13 | Same versioning discipline |
| CVSS variant (3.1 vs 4.x) | P12 | Needs CWE/OWASP mapping compatibility; record in knowledge-base metadata (P19) |
| Emulator / test environment for dynamic analysis | P14 | Isolation guarantees, ADB integration, resource limits; subsystem stays disabled by default |
| PDF generation approach | P15 | Must sanitize secrets; HTML/MD/JSON are primary, PDF derivative |
| WebSocket gateway placement (FastAPI-native vs separate service) | P7 | Event contract is fixed; deployment choice is open |

## 3. Rejected / Out-of-Scope by Requirements

- Automatic submission of reports to third-party bounty programs (human-controlled only — P15).
- Hard-coding methodology logic inside scanners (must be versioned data/rule packs — P10).
- Treating heuristic observations as confirmed vulnerabilities (P12).
- Testing third-party/out-of-scope targets under any configuration (standing rule).