# Security Platform (SASP)

Open-source authorized penetration-testing / bug-bounty platform. FastAPI + Next.js + PostgreSQL + Redis + Celery + MinIO. Phases documented in docs/phases/; completed phases per docs/progress/current-phase.md: 0,1,2,3,4,5,12,17,18,19,20 (11 complete); 6-11,13-16 not complete. Phase 20 is complete; next is 6.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate  # Python 3.12+
# OR use uv (preferred): uv sync --extra dev
```

One-command stack (Docker required): `./scripts/dev-up.sh` (core) or `--observability` (+Prometheus/Grafana). Waits for postgres/redis/minio health before reporting URLs: backend http://localhost:8000/api/docs, frontend http://localhost:3000, MinIO console http://localhost:9001.

Requirements: Docker Compose v2 plugin, Python 3.12+, Node.js 20+, `uv` installed.

## Build & test

Backend (`apps/backend`):
- `make install` → `uv sync --extra dev`
- `make lint` → `ruff check .` + `ruff format --check .`
- `make format` → format + fix
- `make typecheck` → `mypy app`
- `make test` → `pytest -v`

Frontend (`apps/frontend`):
- `npm ci`
- `npm run lint` (ESLint)
- `npm run typecheck` (`tsc --noEmit`)
- `npm run format:check` (Prettier)
- `npm run build`

CI (`.github/workflows/ci.yml`): same commands, plus `uvx pip-audit` and `npm audit --audit-level=high` (continue-on-error).

## Conventions (observed, not assumed)

- Monorepo: `apps/backend`, `apps/frontend`, `packages/` (empty), `workers/`, `scripts/`, `tests/` (load tests under `tests/load/`), `infrastructure/`.
- Commit style from git log: `feat: Add ...`, `feat: Phase N ...`, `feat: ...` (conventional commits, short subject).
- Python: FastAPI routers in `app/api/`, services `app/services/`, models `app/models/`, schemas `app/schemas/`, repositories `app/repositories/`. Pydantic v2, SQLAlchemy 2.0, Alembic migrations in `alembic/versions/`. Ruff target py312, line length 100, excludes `alembic/versions`.
- Type strict: `mypy` strict=true, `warn_unreachable=true`. Tests ignore untyped decorators (`tests/**` override).
- Security rules hard: never bypass auth, RBAC, ScopeEngine, rate limits, worker isolation, sandbox boundaries. ScopeEngine is independent from graph relationships (Phase 20 note).
- Naming: snake_case Python, kebab/camel in frontend. UUID PKs in DB. Soft deletes supported. JSONB for flexible properties.

## Pitfalls

- `.env` is gitignored but `scripts/dev-up.sh` creates it from `.env.example` if missing (same for `apps/backend/.env`). Never commit secrets.
- `docker-compose.yml` uses `docker compose` v2 plugin (`docker compose version` must work). Old `docker-compose` binary fails.
- Backend tests require a running PostgreSQL on `POSTGRES_HOST:POSTGRES_PORT` (see `.env` / CI env vars); `APP_ENV=test` selects test behavior.
- `pre-commit` installed but not required; hooks run `ruff check --fix` locally in `apps/backend`. Run manually: `pre-commit run --all-files`.
- Alembic migrations must not be hand-edited to match lint; `ruff` excludes `alembic/versions` for this reason.
- Phase 20 graph tables (11 tables) added by migration `20261013_242ed2bf0703_...`; if migrating from scratch, run `alembic upgrade head`.
- Observability profile (`--observability`) adds Prometheus (9090), Grafana (3001), otel-collector (4317/4318/8888/13133). Default profile excludes these.
- `packages/` is empty; future plugin SDK goes there but is not implemented yet.

## Files to read first

- `docs/progress/current-phase.md` (phase status)
- `docs/phases/MASTER_RULE.md` (engineering rules for phases)
- `CLAUDE.md` (security rules, scope discipline)
- `docs/LOCAL_DEV.md` (local dev details)

Ponytail note: skipped deep architecture review of graph models and plugin SDK; focused on verifiable commands and actual phase status. Risk — if user expects detailed plugin interface spec, that's in future phases (18/20) but SDK not yet built.
