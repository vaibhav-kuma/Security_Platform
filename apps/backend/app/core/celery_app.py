"""Celery application for distributed scan workers."""

from celery import Celery
from celery.signals import worker_init, worker_shutdown
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
    },
    # Queue definitions
    task_queues=(
        Queue("scans", routing_key="scan.#"),
        Queue("maintenance", routing_key="maintenance.#"),
        Queue("priority", routing_key="priority.#"),
    ),
    # Worker configuration
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    # Task execution
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Task revocation for cancellation support
    task_revoke_by_id=True,
    # Result backend
    result_expires=86400,  # 24 hours
    result_compression="gzip",
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    # Beat schedule (for maintenance tasks)
    beat_schedule={
        "cleanup-stale-jobs": {
            "task": "app.workers.tasks.cleanup_stale_jobs",
            "schedule": 300.0,  # Every 5 minutes
        },
    },
)


@worker_init.connect
def init_worker(**kwargs):
    """Initialize worker: set up database connections, etc."""
    from app.db.session import get_engine

    # Force new engine creation for this worker process
    get_engine.cache_clear() if hasattr(get_engine, 'cache_clear') else None


@worker_shutdown.connect
def shutdown_worker(**kwargs):
    """Clean up on worker shutdown."""
    from app.db.session import get_engine

    engine = get_engine()
    if engine:
        engine.dispose()


def get_celery_app() -> Celery:
    """Get the Celery application instance."""
    return celery_app
