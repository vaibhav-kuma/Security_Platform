# Local Development

## Prerequisites

- Docker Engine with the `docker compose` v2 plugin
- Python 3.12+ and [uv](https://docs.astral.sh/uv/)
- Node.js 20+ and npm

## One-command startup

```bash
./scripts/dev-up.sh                 # core stack
./scripts/dev-up.sh --observability # + Prometheus/Grafana (Phase 1 placeholders)
```

The script copies `.env.example` → `.env` (root and `apps/backend`) when missing,
builds images, starts services, and waits for health checks.

| Service | URL |
|---|---|
| Backend API (FastAPI) | http://localhost:8000/api/docs |
| Frontend (Next.js) | http://localhost:3000 |
| MinIO console | http://localhost:9001 |
| Prometheus (observability profile) | http://localhost:9090 |
| Grafana (observability profile) | http://localhost:3001 |

## Environment handling

- `.env.example` (root) feeds `docker-compose.yml`; `apps/backend/.env.example` feeds the app.
- All defaults are explicit development placeholders — never real secrets.
- Never commit `.env` files (gitignored).
- `APP_ENV` selects `development | test | production` behavior.

## Backend dev loop (without Docker)

```bash
cd apps/backend
make install     # uv sync --extra dev
make lint        # ruff check + format check
make typecheck   # mypy
make test        # pytest (needs PostgreSQL on POSTGRES_HOST:POSTGRES_PORT)
```

## Frontend dev loop

```bash
cd apps/frontend
npm install
npm run dev      # http://localhost:3000
npm run lint && npm run typecheck
```

## Teardown

```bash
docker compose down          # keep volumes
docker compose down -v       # destroy data too
```

## Conventions

- Migrations: append-only Alembic revisions; never rewrite history. Fresh DB must be
  creatable from zero via `alembic upgrade head` (tested every phase).
- Commits: small, reviewable; conventional-commit-style prefixes (`feat:`, `fix:`, `docs:`).
- Branching: `main` is protected in spirit — work on feature branches, review diffs.
- Naming: snake_case Python, camelCase TS, kebab-case files/docs.
- Logging: structured, request-scoped; never log secrets or credentials.