"""Prometheus metrics instrumentation for the security assessment platform.

Provides metrics for:
- Queue depth and worker utilization
- Scan duration and performance
- Asset discovery rates
- Finding creation rates
- Scanner error rates
- Blocked request rates
- HTTP request metrics
"""

import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Summary,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Create a custom registry to avoid conflicts with other prometheus_client uses
registry = CollectorRegistry()

# =============================================================================
# Queue Metrics
# =============================================================================

queue_depth = Gauge(
    "sasp_queue_depth",
    "Number of jobs waiting in queue",
    ["queue_name"],
    registry=registry,
)

jobs_enqueued_total = Counter(
    "sasp_jobs_enqueued_total",
    "Total number of jobs enqueued",
    ["queue_name", "job_type"],
    registry=registry,
)

jobs_dequeued_total = Counter(
    "sasp_jobs_dequeued_total",
    "Total number of jobs dequeued for processing",
    ["queue_name", "job_type"],
    registry=registry,
)

jobs_completed_total = Counter(
    "sasp_jobs_completed_total",
    "Total number of jobs completed successfully",
    ["queue_name", "job_type"],
    registry=registry,
)

jobs_failed_total = Counter(
    "sasp_jobs_failed_total",
    "Total number of jobs that failed",
    ["queue_name", "job_type", "error_type"],
    registry=registry,
)

jobs_retried_total = Counter(
    "sasp_jobs_retried_total",
    "Total number of job retries",
    ["queue_name", "job_type", "retry_count"],
    registry=registry,
)

job_processing_duration_seconds = Histogram(
    "sasp_job_processing_duration_seconds",
    "Time spent processing jobs",
    ["queue_name", "job_type"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
    registry=registry,
)

# =============================================================================
# Worker Metrics
# =============================================================================

worker_count = Gauge(
    "sasp_worker_count",
    "Number of registered workers",
    ["status"],  # idle, busy, offline
    registry=registry,
)

worker_utilization = Gauge(
    "sasp_worker_utilization",
    "Worker utilization percentage (0-100)",
    ["worker_id"],
    registry=registry,
)

worker_cpu_percent = Gauge(
    "sasp_worker_cpu_percent",
    "Worker CPU utilization percentage",
    ["worker_id"],
    registry=registry,
)

worker_memory_mb = Gauge(
    "sasp_worker_memory_mb",
    "Worker memory usage in MB",
    ["worker_id"],
    registry=registry,
)

worker_disk_mb = Gauge(
    "sasp_worker_disk_mb",
    "Worker disk usage in MB",
    ["worker_id"],
    registry=registry,
)

worker_heartbeat_lag_seconds = Gauge(
    "sasp_worker_heartbeat_lag_seconds",
    "Seconds since last worker heartbeat",
    ["worker_id"],
    registry=registry,
)

# =============================================================================
# Scan Metrics
# =============================================================================

scan_duration_seconds = Histogram(
    "sasp_scan_duration_seconds",
    "Total scan duration in seconds",
    ["scan_type", "project_id"],
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 14400],
    registry=registry,
)

scan_job_duration_seconds = Histogram(
    "sasp_scan_job_duration_seconds",
    "Individual scan job duration in seconds",
    ["scan_type", "job_type"],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
    registry=registry,
)

scans_started_total = Counter(
    "sasp_scans_started_total",
    "Total number of scans started",
    ["scan_type", "project_id"],
    registry=registry,
)

scans_completed_total = Counter(
    "sasp_scans_completed_total",
    "Total number of scans completed successfully",
    ["scan_type", "project_id"],
    registry=registry,
)

scans_failed_total = Counter(
    "sasp_scans_failed_total",
    "Total number of scans that failed",
    ["scan_type", "project_id", "failure_reason"],
    registry=registry,
)

scans_active = Gauge(
    "sasp_scans_active",
    "Number of currently active scans",
    ["project_id"],
    registry=registry,
)

# =============================================================================
# Asset Discovery Metrics
# =============================================================================

assets_discovered_total = Counter(
    "sasp_assets_discovered_total",
    "Total number of assets discovered",
    ["project_id", "asset_kind", "scope_status"],
    registry=registry,
)

asset_discovery_rate = Summary(
    "sasp_asset_discovery_rate",
    "Rate of asset discovery per scan",
    ["project_id", "asset_kind"],
    registry=registry,
)

# =============================================================================
# Finding Metrics
# =============================================================================

findings_created_total = Counter(
    "sasp_findings_created_total",
    "Total number of findings created",
    ["project_id", "severity", "confidence", "vulnerability_type"],
    registry=registry,
)

findings_promoted_total = Counter(
    "sasp_findings_promoted_total",
    "Total number of observations promoted to findings",
    ["project_id", "severity"],
    registry=registry,
)

observations_created_total = Counter(
    "sasp_observations_created_total",
    "Total number of observations created",
    ["project_id", "observation_type"],
    registry=registry,
)

# =============================================================================
# Scanner Error Metrics
# =============================================================================

scanner_errors_total = Counter(
    "sasp_scanner_errors_total",
    "Total number of scanner errors",
    ["scanner_name", "error_type", "project_id"],
    registry=registry,
)

plugin_errors_total = Counter(
    "sasp_plugin_errors_total",
    "Total number of recon plugin errors",
    ["plugin_name", "error_type", "project_id"],
    registry=registry,
)

plugin_rate_limited_total = Counter(
    "sasp_plugin_rate_limited_total",
    "Total number of times plugins were rate limited",
    ["plugin_name", "project_id"],
    registry=registry,
)

# =============================================================================
# Blocked Request Metrics
# =============================================================================

blocked_requests_total = Counter(
    "sasp_blocked_requests_total",
    "Total number of blocked requests (scope, rate limit, auth)",
    ["block_reason", "project_id", "target_type"],
    registry=registry,
)

# block_reason: scope_violation, rate_limit_exceeded, unauthorized, forbidden, out_of_scope

# =============================================================================
# HTTP Request Metrics
# =============================================================================

http_requests_total = Counter(
    "sasp_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
    registry=registry,
)

http_request_duration_seconds = Histogram(
    "sasp_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=registry,
)

http_request_size_bytes = Histogram(
    "sasp_http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "endpoint"],
    buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000],
    registry=registry,
)

http_response_size_bytes = Histogram(
    "sasp_http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint"],
    buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000],
    registry=registry,
)

# =============================================================================
# Database Metrics
# =============================================================================

db_pool_size = Gauge(
    "sasp_db_pool_size",
    "Database connection pool size",
    registry=registry,
)

db_pool_checked_out = Gauge(
    "sasp_db_pool_checked_out",
    "Database connections checked out",
    registry=registry,
)

db_pool_overflow = Gauge(
    "sasp_db_pool_overflow",
    "Database pool overflow connections",
    registry=registry,
)

db_query_duration_seconds = Histogram(
    "sasp_db_query_duration_seconds",
    "Database query duration in seconds",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=registry,
)

# =============================================================================
# Cache Metrics
# =============================================================================

cache_hits_total = Counter(
    "sasp_cache_hits_total",
    "Total cache hits",
    ["cache_name"],
    registry=registry,
)

cache_misses_total = Counter(
    "sasp_cache_misses_total",
    "Total cache misses",
    ["cache_name"],
    registry=registry,
)

# =============================================================================
# Helper Functions
# =============================================================================

def record_job_enqueued(queue_name: str, job_type: str) -> None:
    """Record a job being enqueued."""
    jobs_enqueued_total.labels(queue_name=queue_name, job_type=job_type).inc()
    queue_depth.labels(queue_name=queue_name).inc()


def record_job_dequeued(queue_name: str, job_type: str) -> None:
    """Record a job being dequeued."""
    jobs_dequeued_total.labels(queue_name=queue_name, job_type=job_type).inc()
    queue_depth.labels(queue_name=queue_name).dec()


def record_job_completed(queue_name: str, job_type: str, duration: float) -> None:
    """Record a job completed successfully."""
    jobs_completed_total.labels(queue_name=queue_name, job_type=job_type).inc()
    job_processing_duration_seconds.labels(queue_name=queue_name, job_type=job_type).observe(duration)


def record_job_failed(queue_name: str, job_type: str, error_type: str) -> None:
    """Record a job failure."""
    jobs_failed_total.labels(queue_name=queue_name, job_type=job_type, error_type=error_type).inc()


def record_job_retried(queue_name: str, job_type: str, retry_count: int) -> None:
    """Record a job retry."""
    jobs_retried_total.labels(queue_name=queue_name, job_type=job_type, retry_count=str(retry_count)).inc()


def record_scan_started(scan_type: str, project_id: str) -> None:
    """Record a scan started."""
    scans_started_total.labels(scan_type=scan_type, project_id=project_id).inc()
    scans_active.labels(project_id=project_id).inc()


def record_scan_completed(scan_type: str, project_id: str, duration: float) -> None:
    """Record a scan completed."""
    scans_completed_total.labels(scan_type=scan_type, project_id=project_id).inc()
    scans_active.labels(project_id=project_id).dec()
    scan_duration_seconds.labels(scan_type=scan_type, project_id=project_id).observe(duration)


def record_scan_failed(scan_type: str, project_id: str, failure_reason: str) -> None:
    """Record a scan failure."""
    scans_failed_total.labels(scan_type=scan_type, project_id=project_id, failure_reason=failure_reason).inc()
    scans_active.labels(project_id=project_id).dec()


def record_asset_discovered(project_id: str, asset_kind: str, scope_status: str) -> None:
    """Record an asset discovery."""
    assets_discovered_total.labels(
        project_id=project_id,
        asset_kind=asset_kind,
        scope_status=scope_status
    ).inc()


def record_finding_created(project_id: str, severity: str, confidence: str, vuln_type: str) -> None:
    """Record a finding creation."""
    findings_created_total.labels(
        project_id=project_id,
        severity=severity,
        confidence=confidence,
        vulnerability_type=vuln_type
    ).inc()


def record_finding_promoted(project_id: str, severity: str) -> None:
    """Record an observation promoted to finding."""
    findings_promoted_total.labels(project_id=project_id, severity=severity).inc()


def record_observation_created(project_id: str, observation_type: str) -> None:
    """Record an observation creation."""
    observations_created_total.labels(project_id=project_id, observation_type=observation_type).inc()


def record_scanner_error(scanner_name: str, error_type: str, project_id: str) -> None:
    """Record a scanner error."""
    scanner_errors_total.labels(
        scanner_name=scanner_name,
        error_type=error_type,
        project_id=project_id
    ).inc()


def record_plugin_error(plugin_name: str, error_type: str, project_id: str) -> None:
    """Record a plugin error."""
    plugin_errors_total.labels(
        plugin_name=plugin_name,
        error_type=error_type,
        project_id=project_id
    ).inc()


def record_plugin_rate_limited(plugin_name: str, project_id: str) -> None:
    """Record a plugin being rate limited."""
    plugin_rate_limited_total.labels(plugin_name=plugin_name, project_id=project_id).inc()


def record_blocked_request(block_reason: str, project_id: str, target_type: str) -> None:
    """Record a blocked request."""
    blocked_requests_total.labels(
        block_reason=block_reason,
        project_id=project_id,
        target_type=target_type
    ).inc()


def update_worker_count(status: str, count: int) -> None:
    """Update worker count by status."""
    worker_count.labels(status=status).set(count)


def update_worker_utilization(worker_id: str, utilization: float) -> None:
    """Update worker utilization percentage."""
    worker_utilization.labels(worker_id=worker_id).set(utilization)


def update_worker_resources(worker_id: str, cpu_percent: float, memory_mb: float, disk_mb: float) -> None:
    """Update worker resource usage."""
    worker_cpu_percent.labels(worker_id=worker_id).set(cpu_percent)
    worker_memory_mb.labels(worker_id=worker_id).set(memory_mb)
    worker_disk_mb.labels(worker_id=worker_id).set(disk_mb)


def update_worker_heartbeat_lag(worker_id: str, lag_seconds: float) -> None:
    """Update worker heartbeat lag."""
    worker_heartbeat_lag_seconds.labels(worker_id=worker_id).set(lag_seconds)


def update_db_pool_stats(pool_size: int, checked_out: int, overflow: int) -> None:
    """Update database pool statistics."""
    db_pool_size.set(pool_size)
    db_pool_checked_out.set(checked_out)
    db_pool_overflow.set(overflow)


def record_db_query(operation: str, duration: float) -> None:
    """Record database query duration."""
    db_query_duration_seconds.labels(operation=operation).observe(duration)


def record_cache_hit(cache_name: str) -> None:
    """Record a cache hit."""
    cache_hits_total.labels(cache_name=cache_name).inc()


def record_cache_miss(cache_name: str) -> None:
    """Record a cache miss."""
    cache_misses_total.labels(cache_name=cache_name).inc()


# =============================================================================
# Middleware for HTTP Metrics
# =============================================================================

class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP request metrics."""

    def __init__(self, app, exclude_paths: list[str] | None = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/favicon.ico"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        start_time = time.time()

        # Get request size
        request_size = 0
        if request.headers.get("content-length"):
            try:
                request_size = int(request.headers["content-length"])
            except ValueError:
                pass

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Get response size
        response_size = 0
        if hasattr(response, "headers") and response.headers.get("content-length"):
            try:
                response_size = int(response.headers["content-length"])
            except ValueError:
                pass

        # Normalize endpoint path (replace path parameters with placeholders)
        endpoint = self._normalize_endpoint(request.url.path)

        # Record metrics
        http_requests_total.labels(
            method=request.method,
            endpoint=endpoint,
            status_code=response.status_code
        ).inc()

        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint
        ).observe(duration)

        http_request_size_bytes.labels(
            method=request.method,
            endpoint=endpoint
        ).observe(request_size)

        http_response_size_bytes.labels(
            method=request.method,
            endpoint=endpoint
        ).observe(response_size)

        return response

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path by replacing UUIDs and IDs with placeholders."""
        import re
        # Replace UUIDs
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{id}',
            path
        )
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        return path


# =============================================================================
# Metrics Endpoint
# =============================================================================

def metrics_endpoint() -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST,
    )


# =============================================================================
# Decorator for timing functions
# =============================================================================

def time_it(metric: Histogram, labels: dict[str, str] | None = None):
    """Decorator to time a function and record to a histogram."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.time() - start
                if labels:
                    metric.labels(**labels).observe(duration)
                else:
                    metric.observe(duration)
        return wrapper
    return decorator


def time_it_async(metric: Histogram, labels: dict[str, str] | None = None):
    """Async decorator to time a function and record to a histogram."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.time()
            try:
                return await func(*args, **kwargs)
            finally:
                duration = time.time() - start
                if labels:
                    metric.labels(**labels).observe(duration)
                else:
                    metric.observe(duration)
        return wrapper
    return decorator
