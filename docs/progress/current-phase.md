# Current Phase Status

_Last updated: 2026-09-30_

## Status

| Item | State |
|---|---|
| Completed phases | Phase 0 (architecture spec), Phase 1 (dev environment & DevOps foundation) |
| Current phase | **Phase 2 — PostgreSQL domain model & migrations** |
| Next phase | Phase 3 — authN/authZ & RBAC |

## Phase 1 Outcome (completed 2026-09-30)

- Monorepo skeleton: `apps/` (backend, frontend), `infrastructure/`, `scripts/`, `docs/`.
- Backend: FastAPI app factory (`app/main.py`), health endpoints, Pydantic settings
  (`app/config.py`), SQLAlchemy engine/session scaffolding (`app/db/session.py`),
  Alembic skeleton (no migrations yet), Makefile, `pyproject.toml` with ruff/mypy/pytest config.
- Frontend: Next.js 15 + React 19 + TypeScript + Tailwind + shadcn/ui scaffolding.
- Docker Compose: postgres, redis, minio, backend, worker placeholder, frontend,
  prometheus/grafana under `observability` profile. Healthchecks on core services.
- CI (`.github/workflows/ci.yml`): backend lint/format/typecheck/tests/audit,
  frontend lint/typecheck/format/build/audit.
- Tooling: `.pre-commit-config.yaml`, `.env.example` (root + backend), `scripts/dev-up.sh`.
- Verified: `pytest` 5/5 pass, `ruff check` + `ruff format --check` clean, `mypy app` clean,
  `docker compose` validated with Compose v5.5.1.
- Docs: `docs/LOCAL_DEV.md`.

## Phase 2 Scope (in progress)

Per `docs/phases/phase-02.md`:

- SQLAlchemy domain model covering identity/RBAC, projects/scopes, asset graph
  (domain/subdomain/IP/port/URL/endpoint/technology/certificate), scans/jobs/events,
  methodology engine, detection rules, observations/findings/evidence (Observation and
  Finding remain separate tables; severity and confidence remain separate fields),
  API assets, APK assets, reports, audit logs, security events.
- UUID PKs, FKs, indexes, unique constraints, timestamps, soft delete, native PG enums.
- Alembic migration(s) generated from metadata; fresh-DB-from-zero verification.
- Repository abstractions + database tests; seed data for permissions/system roles.

## Phase 2 Invariants (from architecture docs)

- Observation ≠ Finding (distinct tables, promotion link only).
- Severity ⟂ confidence (independent enums).
- Scope status enum: `in_scope | out_of_scope | unknown | third_party`.
- Finding status enum: `open | needs_review | confirmed | false_positive | duplicate | accepted_risk | resolved`.
- Evidence storage must be extensible for the redaction pipeline (Phase 9+).
- Scope snapshots stored as versioned payloads.

## Decision Log

Record decisions in `docs/decisions/` as they are made.