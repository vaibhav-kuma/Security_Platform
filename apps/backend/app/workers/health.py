"""Worker health monitoring and heartbeat system."""

import socket
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psutil
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app, get_worker_load
from app.db.session import get_engine, make_session_factory
from app.models.enums import ScanJobStatus
from app.models.scans import Scan, ScanEvent, ScanJob
from app.models.workers import Worker, WorkerHeartbeat


def get_db_session() -> Session:
    """Get a new database session for the worker."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


def _emit_event(
    db: Session,
    scan_id: str,
    job_id: str | None,
    event_type: str,
    level: str,
    message: str,
    payload: dict[str, Any],
) -> None:
    """Emit a scan event."""
    event = ScanEvent(
        scan_id=UUID(scan_id),
        scan_job_id=UUID(job_id) if job_id else None,
        event_type=event_type,
        level=level,
        message=message,
        payload=payload,
    )
    db.add(event)


@shared_task(bind=True, name="app.workers.tasks.worker_health_check")
def worker_health_check(self) -> dict[str, Any]:
    """
    Periodic health check task that runs on each worker.
    
    Updates worker heartbeat with resource utilization metrics.
    Detects and handles stale jobs.
    """
    hostname = socket.gethostname()

    db = get_db_session()
    try:
        # Collect system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_mb = memory.used // (1024 * 1024)
        disk = psutil.disk_usage('/')
        disk_mb = disk.used // (1024 * 1024)

        # Get worker load
        load = get_worker_load(hostname)

        # Find or create worker record
        worker = db.scalars(
            select(Worker).where(Worker.hostname == hostname)
        ).first()

        if not worker:
            worker = Worker(
                name=f"worker-{hostname}",
                hostname=hostname,
                status="idle",
                capabilities={},
                started_at=datetime.now(UTC),
            )
            db.add(worker)
            db.flush()

        # Update worker status
        worker.pid = psutil.Process().pid
        worker.last_heartbeat = datetime.now(UTC)
        worker.last_seen_at = datetime.now(UTC)
        worker.status = "busy" if load["active_tasks"] > 0 else "idle"
        worker.capabilities = {
            **worker.capabilities,
            "max_concurrent_jobs": load["max_concurrent"],
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "disk_mb": disk_mb,
        }

        # Record heartbeat
        heartbeat = WorkerHeartbeat(
            worker_id=worker.id,
            status=worker.status,
            current_job_id=None,  # Could be enhanced to track current job
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            heartbeat_metadata={
                "active_tasks": load["active_tasks"],
                "utilization": load["utilization"],
            },
        )
        db.add(heartbeat)

        # Update worker metrics
        from app.core.metrics import (
            update_worker_count,
            update_worker_heartbeat_lag,
            update_worker_resources,
            update_worker_utilization,
        )

        # Count workers by status
        idle_count = db.scalars(
            select(Worker).where(Worker.status == "idle")
        ).all()
        busy_count = db.scalars(
            select(Worker).where(Worker.status == "busy")
        ).all()
        offline_count = db.scalars(
            select(Worker).where(Worker.status == "offline")
        ).all()

        update_worker_count("idle", len(idle_count))
        update_worker_count("busy", len(busy_count))
        update_worker_count("offline", len(offline_count))

        update_worker_utilization(str(worker.id), load["utilization"])
        update_worker_resources(str(worker.id), cpu_percent, memory_mb, disk_mb)
        update_worker_heartbeat_lag(str(worker.id), 0)

        db.commit()

        return {
            "success": True,
            "worker_id": str(worker.id),
            "hostname": hostname,
            "status": worker.status,
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "disk_mb": disk_mb,
            "active_tasks": load["active_tasks"],
            "utilization": load["utilization"],
        }

    except Exception as exc:
        db.rollback()
        from app.core.logging import get_structured_logger
        logger = get_structured_logger("worker.health")
        logger.error("Worker health check failed", error=str(exc))
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.detect_offline_workers")
def detect_offline_workers(self, timeout_seconds: int = 120) -> dict[str, Any]:
    """
    Detect workers that haven't sent a heartbeat within the timeout period.
    
    Marks them as offline and requeues their running jobs.
    """
    db = get_db_session()
    try:
        cutoff = datetime.now(UTC).timestamp() - timeout_seconds

        # Find workers with stale heartbeats
        stale_workers = db.scalars(
            select(Worker).where(
                Worker.status.in_(["idle", "busy"]),
                Worker.last_heartbeat.isnot(None),
            )
        ).all()

        offline_count = 0
        requeued_jobs = 0

        for worker in stale_workers:
            if worker.last_heartbeat and worker.last_heartbeat.timestamp() < cutoff:
                # Mark worker as offline
                worker.status = "offline"

                # Requeue running jobs
                from sqlalchemy import select
                running_jobs = db.scalars(
                    select(ScanJob).where(
                        ScanJob.worker_id == worker.id,
                        ScanJob.status.in_([ScanJobStatus.QUEUED, ScanJobStatus.RUNNING]),
                    )
                ).all()

                for job in running_jobs:
                    job.status = ScanJobStatus.QUEUED
                    job.worker_id = None
                    job.started_at = None
                    requeued_jobs += 1

                    _emit_event(
                        db,
                        str(job.scan_id),
                        str(job.id),
                        "job.requeued",
                        "warning",
                        f"Job requeued due to worker {worker.hostname} going offline",
                        {"original_worker": worker.hostname},
                    )

                # Check scans that might need status update
                for job in running_jobs:
                    scan = db.get(Scan, job.scan_id)
                    if scan:
                        running = db.scalars(
                            select(ScanJob).where(
                                ScanJob.scan_id == scan.id,
                                ScanJob.status.in_([ScanJobStatus.QUEUED, ScanJobStatus.RUNNING]),
                            )
                        ).all()
                        if not running:
                            # All jobs are done/failed, scan will be updated by cleanup task
                            pass

                offline_count += 1

                from app.core.logging import get_structured_logger
                logger = get_structured_logger("worker.offline")
                logger.warning(
                    "Worker marked offline",
                    worker_id=str(worker.id),
                    hostname=worker.hostname,
                    last_heartbeat=worker.last_heartbeat.isoformat() if worker.last_heartbeat else None,
                    requeued_jobs=len(running_jobs),
                )

        db.commit()

        return {
            "success": True,
            "offline_workers": offline_count,
            "requeued_jobs": requeued_jobs,
        }

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.recover_abandoned_jobs")
def recover_abandoned_jobs(self, max_age_minutes: int = 60) -> dict[str, Any]:
    """
    Recover jobs that were running on workers that no longer exist.
    
    Finds jobs in RUNNING state with no associated worker or worker offline.
    """
    from datetime import timedelta

    db = get_db_session()
    try:
        cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)

        # Find abandoned jobs (running but worker is offline or missing)
        abandoned_jobs = db.scalars(
            select(ScanJob).where(
                ScanJob.status == ScanJobStatus.RUNNING,
                ScanJob.started_at < cutoff,
            )
        ).all()

        recovered = 0
        for job in abandoned_jobs:
            worker = db.get(Worker, job.worker_id) if job.worker_id else None

            should_recover = False
            if worker is None:
                should_recover = True
                reason = "Worker no longer exists"
            elif worker.status == "offline":
                should_recover = True
                reason = f"Worker {worker.hostname} is offline"
            elif worker.last_heartbeat and (datetime.now(UTC) - worker.last_heartbeat).total_seconds() > 300:
                should_recover = True
                reason = f"Worker {worker.hostname} heartbeat stale"

            if should_recover:
                job.status = ScanJobStatus.QUEUED
                job.worker_id = None
                job.started_at = None
                job.error = None

                _emit_event(
                    db,
                    str(job.scan_id),
                    str(job.id),
                    "job.recovered",
                    "info",
                    f"Abandoned job recovered: {reason}",
                    {"reason": reason, "original_worker": worker.hostname if worker else None},
                )

                recovered += 1

                from app.core.logging import get_structured_logger
                logger = get_structured_logger("job.recovery")
                logger.info(
                    "Abandoned job recovered",
                    job_id=str(job.id),
                    scan_id=str(job.scan_id),
                    reason=reason,
                )

        db.commit()

        return {
            "success": True,
            "recovered_jobs": recovered,
        }

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.cleanup_old_heartbeats")
def cleanup_old_heartbeats(self, retention_days: int = 7) -> dict[str, Any]:
    """Clean up old worker heartbeat records."""
    from datetime import timedelta

    db = get_db_session()
    try:
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        from sqlalchemy import delete
        result = db.execute(
            delete(WorkerHeartbeat).where(WorkerHeartbeat.created_at < cutoff)
        )

        db.commit()

        return {
            "success": True,
            "deleted_count": result.rowcount,
        }

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def register_worker(
    name: str,
    hostname: str,
    capabilities: dict[str, Any] | None = None,
    max_concurrent_jobs: int = 4,
) -> Worker:
    """Register a new worker or update existing one."""
    db = get_db_session()
    try:
        worker = db.scalars(
            select(Worker).where(Worker.hostname == hostname)
        ).first()

        if not worker:
            worker = Worker(
                name=name,
                hostname=hostname,
                capabilities=capabilities or {},
            )
            db.add(worker)
        else:
            worker.name = name
            worker.capabilities = capabilities or worker.capabilities
            worker.status = "idle"

        worker.started_at = datetime.now(UTC)
        worker.last_seen_at = datetime.now(UTC)
        worker.last_heartbeat = datetime.now(UTC)

        # Store max concurrent jobs in capabilities
        worker.capabilities["max_concurrent_jobs"] = max_concurrent_jobs

        db.commit()
        db.refresh(worker)

        return worker

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_worker_stats() -> dict[str, Any]:
    """Get aggregate worker statistics."""
    db = get_db_session()
    try:
        workers = db.scalars(select(Worker)).all()

        total = len(workers)
        idle = sum(1 for w in workers if w.status == "idle")
        busy = sum(1 for w in workers if w.status == "busy")
        offline = sum(1 for w in workers if w.status == "offline")

        total_capacity = sum(w.capabilities.get("max_concurrent_jobs", 4) for w in workers)
        active_jobs = db.scalars(
            select(ScanJob).where(ScanJob.status == ScanJobStatus.RUNNING)
        ).all()

        return {
            "total_workers": total,
            "idle_workers": idle,
            "busy_workers": busy,
            "offline_workers": offline,
            "total_capacity": total_capacity,
            "active_jobs": len(active_jobs),
            "utilization": (len(active_jobs) / total_capacity * 100) if total_capacity > 0 else 0,
            "workers": [
                {
                    "id": str(w.id),
                    "name": w.name,
                    "hostname": w.hostname,
                    "status": w.status,
                    "last_heartbeat": w.last_heartbeat.isoformat() if w.last_heartbeat else None,
                    "capabilities": w.capabilities,
                }
                for w in workers
            ],
        }
    finally:
        db.close()


# Register tasks
celery_app.task(worker_health_check)
celery_app.task(detect_offline_workers)
celery_app.task(recover_abandoned_jobs)
celery_app.task(cleanup_old_heartbeats)
