"""Celery application for distributed scan workers."""

from celery import Celery
from celery.signals import (
    task_failure,
    task_postrun,
    task_prerun,
    task_retry,
    worker_init,
    worker_shutdown,
)
from kombu import Queue

from app.config import get_settings

settings = get_settings()

# Create Celery app
celery_app = Celery(
    "sasp_worker",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.workers.tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "app.workers.tasks.execute_scan_job": {"queue": "scans"},
        "app.workers.tasks.cleanup_stale_jobs": {"queue": "maintenance"},
        "app.workers.tasks.priority_scan_job": {"queue": "priority"},
    },
    # Queue definitions
    task_queues=(
        Queue("priority", routing_key="priority.#"),
        Queue("scans", routing_key="scan.#"),
        Queue("maintenance", routing_key="maintenance.#"),
    ),
    # Worker configuration
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    worker_max_memory_per_child=500000,  # 500MB
    # Task execution
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_acks_on_failure_or_timeout=True,
    # Task revocation for cancellation support
    task_revoke_by_id=True,
    # Result backend
    result_expires=86400,  # 24 hours
    result_compression="gzip",
    result_extended=True,
    # Retry configuration
    task_autoretry_for=(Exception,),
    task_retry_backoff=True,
    task_retry_backoff_max=600,  # 10 minutes max backoff
    task_retry_jitter=True,
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    # Beat schedule (for maintenance tasks)
    beat_schedule={
        "cleanup-stale-jobs": {
            "task": "app.workers.tasks.cleanup_stale_jobs",
            "schedule": 300.0,  # Every 5 minutes
        },
        "worker-health-check": {
            "task": "app.workers.tasks.worker_health_check",
            "schedule": 60.0,  # Every minute
        },
    },
    # Task time limits
    task_soft_time_limit=3600,  # 1 hour soft limit
    task_time_limit=3900,  # 1 hour 5 minutes hard limit
    # Idempotency
    task_idempotency_key_length=64,
    # Broker connection
    broker_connection_retry=True,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    # Consumer configuration
    worker_cancel_long_running_tasks_on_connection_loss=True,
)

# Track active tasks per worker for backpressure
_worker_active_tasks: dict[str, int] = {}
_worker_max_concurrent: dict[str, int] = {}


@worker_init.connect
def init_worker(**kwargs):
    """Initialize worker: set up database connections, etc."""
    from app.db.session import get_engine

    # Force new engine creation for this worker process
    get_engine.cache_clear() if hasattr(get_engine, 'cache_clear') else None

    # Initialize worker metrics
    import socket
    hostname = socket.gethostname()
    _worker_active_tasks[hostname] = 0
    _worker_max_concurrent[hostname] = settings.worker_max_concurrent_jobs if hasattr(settings, 'worker_max_concurrent_jobs') else 4


@worker_shutdown.connect
def shutdown_worker(**kwargs):
    """Clean up on worker shutdown."""
    from app.db.session import get_engine

    engine = get_engine()
    if engine:
        engine.dispose()


@task_prerun.connect
def task_prerun_handler(task_id, task, *args, **kwargs):
    """Track task start for backpressure."""
    import socket
    hostname = socket.gethostname()
    _worker_active_tasks[hostname] = _worker_active_tasks.get(hostname, 0) + 1

    # Set trace context for logging
    from opentelemetry import trace

    from app.core.logging import set_trace_context
    span = trace.get_current_span()
    if span and span.is_recording():
        ctx = span.get_span_context()
        set_trace_context(
            trace_id=format(ctx.trace_id, "032x"),
            span_id=format(ctx.span_id, "016x")
        )


@task_postrun.connect
def task_postrun_handler(task_id, task, *args, **kwargs):
    """Track task completion for backpressure."""
    import socket
    hostname = socket.gethostname()
    _worker_active_tasks[hostname] = max(0, _worker_active_tasks.get(hostname, 1) - 1)


@task_retry.connect
def task_retry_handler(request, reason, *args, **kwargs):
    """Log task retry."""
    from app.core.logging import get_structured_logger
    logger = get_structured_logger("celery.task")
    logger.warning(
        "Task retry",
        task_id=request.id,
        task_name=request.task,
        retry_count=request.retries,
        reason=str(reason),
    )


@task_failure.connect
def task_failure_handler(request, exception, *args, **kwargs):
    """Log task failure."""
    from app.core.logging import get_structured_logger
    logger = get_structured_logger("celery.task")
    logger.error(
        "Task failed",
        task_id=request.id,
        task_name=request.task,
        error=str(exception),
        traceback=__import__('traceback').format_exc(),
    )


def get_celery_app() -> Celery:
    """Get the Celery application instance."""
    return celery_app


def get_worker_load(hostname: str | None = None) -> dict:
    """Get current worker load for backpressure decisions."""
    import socket
    if hostname is None:
        hostname = socket.gethostname()
    return {
        "active_tasks": _worker_active_tasks.get(hostname, 0),
        "max_concurrent": _worker_max_concurrent.get(hostname, 4),
        "utilization": _worker_active_tasks.get(hostname, 0) / _worker_max_concurrent.get(hostname, 4) * 100,
    }


def can_accept_task(hostname: str | None = None) -> bool:
    """Check if worker can accept more tasks."""
    load = get_worker_load(hostname)
    return load["active_tasks"] < load["max_concurrent"]
