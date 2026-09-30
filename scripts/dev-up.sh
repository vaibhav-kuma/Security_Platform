#!/usr/bin/env bash
# One-command local startup for the development stack.
# Usage: ./scripts/dev-up.sh [--observability]
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE_ARGS=()
if [[ "${1:-}" == "--observability" ]]; then
  PROFILE_ARGS=(--profile observability)
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: 'docker compose' plugin not found. Install docker-compose-v2." >&2
  exit 1
fi

# Create .env files from templates if missing (never overwrite real values).
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi
if [[ ! -f apps/backend/.env ]]; then
  cp apps/backend/.env.example apps/backend/.env
  echo "Created apps/backend/.env from template"
fi

docker compose up -d --build "${PROFILE_ARGS[@]}"

echo
echo "Waiting for services to become healthy..."
for svc in postgres redis minio backend; do
  for _ in $(seq 1 60); do
    state=$(docker compose ps --format json "$svc" 2>/dev/null | grep -o '"Health":"healthy"' || true)
    if [[ -n "$state" ]]; then break; fi
    sleep 2
  done
done

docker compose ps
echo
echo "Backend:   http://localhost:8000/api/docs"
echo "Frontend:  http://localhost:3000"
echo "MinIO:     http://localhost:9001 (console)"
if [[ "${1:-}" == "--observability" ]]; then
  echo "Prometheus: http://localhost:9090"
  echo "Grafana:    http://localhost:3001"
fi