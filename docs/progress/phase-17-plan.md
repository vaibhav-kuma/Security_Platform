# Phase 17 Implementation Plan

## Objective
Scale the platform from a functional security-assessment application into a robust multi-worker system capable of handling larger authorized projects.

## Architecture Changes

### 1. Enhanced Celery Configuration (`app/core/celery_app.py`)
- Queue prioritization (priority, scans, maintenance)
- Worker concurrency controls
- Retry behavior with exponential backoff
- Job recovery from worker termination
- Idempotency keys for tasks
- Backpressure mechanisms
- Per-project and per-target limits

### 2. Database Connection Pooling (`app/db/session.py`)
- Configure SQLAlchemy pool settings
- Pool size, max overflow, pool timeout
- Connection recycling

### 3. Prometheus Metrics (`app/core/metrics.py` - NEW)
- Queue depth metrics
- Scan duration metrics
- Asset discovery metrics
- Finding creation metrics
- Scanner error metrics
- Blocked request metrics
- Worker utilization metrics
- HTTP request metrics

### 4. OpenTelemetry Tracing (`app/core/tracing.py` - NEW)
- Trace spans for scan operations
- Context propagation
- Integration with Celery tasks
- Export to OTEL collector

### 5. Structured Logging (`app/core/logging.py` - enhance)
- Correlation IDs
- JSON formatting
- Log levels per component

### 6. Worker Health Monitoring (`app/workers/health.py` - NEW)
- Heartbeat emission
- Health check endpoint
- Resource utilization tracking
- Automatic offline detection

### 7. Scan Resource Controls (`app/recon/policy.py` - enhance)
- Per-project concurrent scan limits
- Per-target rate limits
- Memory/CPU limits
- Timeout enforcement

### 8. Job Idempotency (`app/workers/tasks.py` - enhance)
- Idempotency keys
- Deduplication
- Recovery from partial execution

### 9. Artifact Lifecycle Management (`app/services/artifacts.py` - NEW)
- Retention policies
- Cleanup jobs
- Storage tiering

### 10. Grafana Dashboards (`infrastructure/grafana/provisioning/dashboards/`)
- Worker utilization dashboard
- Queue depth dashboard
- Scan performance dashboard
- Resource utilization dashboard

### 11. Docker Compose Updates (`docker-compose.yml`)
- Enable Prometheus, Grafana, OTEL collector by default
- Resource limits for workers

### 12. Load Testing (`tests/load/`)
- Locust or k6 scripts
- Controlled load test scenarios
- Bottleneck identification

## Files to Create
- `app/core/metrics.py`
- `app/core/tracing.py`
- `app/workers/health.py`
- `app/services/artifacts.py`
- `infrastructure/grafana/provisioning/dashboards/*.json`
- `tests/load/locustfile.py`

## Files to Modify
- `app/core/celery_app.py`
- `app/db/session.py`
- `app/core/logging.py`
- `app/recon/policy.py`
- `app/workers/tasks.py`
- `app/config.py`
- `docker-compose.yml`
- `infrastructure/prometheus/prometheus.yml`
- `infrastructure/otel/otel-collector-config.yaml`

## Security Controls
- All new endpoints protected by auth/RBAC
- Metrics endpoints require appropriate permissions
- Worker isolation maintained
- Resource limits enforced

## Tests
- Unit tests for metrics, tracing, health monitoring
- Integration tests for worker scaling
- Load test scenarios
- Security regression tests

## Documentation
- Update `docs/progress/current-phase.md`
- Document observability stack
- Document scaling procedures