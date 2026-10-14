"""Worker tasks for scan execution with idempotency and enhanced reliability."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import can_accept_task, celery_app
from app.core.metrics import (
    record_asset_discovered,
    record_job_completed,
    record_job_dequeued,
    record_job_failed,
    record_scan_completed,
    record_scan_failed,
    record_scan_started,
)
from app.db.session import get_engine, make_session_factory
from app.models.enums import ScanJobStatus, ScanStatus
from app.models.scans import Scan, ScanEvent, ScanJob
from app.recon.engine import ReconEngineFactory


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


def _check_scan_completion(db: Session, scan: Scan) -> None:
    """Check if all jobs in a scan are complete and update scan status."""
    running_jobs = [
        j for j in scan.jobs
        if j.status in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)
    ]

    if not running_jobs:
        # All jobs done - check if any failed
        failed_jobs = [j for j in scan.jobs if j.status == ScanJobStatus.FAILED]

        if failed_jobs:
            scan.status = ScanStatus.FAILED
            _emit_event(db, str(scan.id), None, "scan.failed", "error",
                       f"Scan failed: {len(failed_jobs)} job(s) failed",
                       {"failed_jobs": len(failed_jobs)})
            record_scan_failed(scan.scan_type.value, str(scan.project_id), "jobs_failed")
        else:
            scan.status = ScanStatus.COMPLETED
            _emit_event(db, str(scan.id), None, "scan.completed", "info",
                       "Scan completed successfully",
                       {"total_jobs": len(scan.jobs)})
            record_scan_completed(scan.scan_type.value, str(scan.project_id), 0)  # Duration would be calculated

        scan.finished_at = datetime.now(UTC)


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    name="app.workers.tasks.execute_scan_job"
)
def execute_scan_job(self, job_id: str, scan_id: str, idempotency_key: str | None = None) -> dict[str, Any]:
    """
    Execute a scan job with idempotency support.
    
    Args:
        job_id: UUID of the scan job
        scan_id: UUID of the parent scan
        idempotency_key: Optional key to prevent duplicate execution
    
    Returns:
        Dict with success status and result
    """
    # Check idempotency
    if idempotency_key:
        from app.core.celery_app import get_celery_app
        celery = get_celery_app()
        # Check if result already exists in backend
        existing_result = celery.backend.get(idempotency_key)
        if existing_result:
            return {"success": True, "result": existing_result, "idempotent": True}

    # Backpressure check
    if not can_accept_task():
        # Requeue with delay
        raise self.retry(countdown=30, max_retries=5)

    db = get_db_session()
    start_time = datetime.now(UTC)

    try:
        job_uuid = UUID(job_id)
        scan_uuid = UUID(scan_id)

        job = db.get(ScanJob, job_uuid)
        scan = db.get(Scan, scan_uuid)

        if not job or not scan:
            return {"success": False, "error": "Job or scan not found"}

        if job.status not in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING):
            return {"success": False, "error": f"Job not in runnable state: {job.status.value}"}

        # Update job status to running
        job.status = ScanJobStatus.RUNNING
        job.started_at = datetime.now(UTC)
        db.commit()

        # Record metrics
        record_job_dequeued("scans", job.name)
        record_scan_started(scan.scan_type.value, str(scan.project_id))

        # Emit scan.started event
        _emit_event(db, scan_id, job_id, "scan.started", "info", f"Scan job {job.name} started", {})

        # Execute recon using the recon engine
        result = _execute_recon(db, scan, job)

        # Update job with result
        job.result = result
        job.status = ScanJobStatus.SUCCEEDED
        job.finished_at = datetime.now(UTC)

        # Calculate duration
        duration = (job.finished_at - start_time).total_seconds()

        # Emit scan.completed event
        _emit_event(
            db, scan_id, job_id, "scan.completed", "info",
            f"Scan job {job.name} completed", result
        )

        # Record metrics
        record_job_completed("scans", job.name, duration)
        record_scan_job_duration = duration

        # Record asset discoveries
        for asset in result.get("recon_results", []):
            record_asset_discovered(
                str(scan.project_id),
                asset.get("asset_kind", "unknown"),
                asset.get("scope_status", "unknown")
            )

        # Check if all jobs in scan are done
        _check_scan_completion(db, scan)

        db.commit()

        # Store idempotency result
        if idempotency_key:
            celery = get_celery_app()
            celery.backend.set(idempotency_key, {"success": True, "result": result})

        return {"success": True, "result": result, "duration_seconds": duration}

    except Exception as exc:
        db.rollback()
        job = db.get(ScanJob, UUID(job_id))
        if job:
            job.status = ScanJobStatus.FAILED
            job.error = str(exc)
            job.finished_at = datetime.now(UTC)
            duration = (job.finished_at - start_time).total_seconds()

            _emit_event(
                db, scan_id, job_id, "scan.failed", "error",
                f"Scan job failed: {exc}", {"error": str(exc), "duration_seconds": duration}
            )

            record_job_failed("scans", job.name, type(exc).__name__)
            record_scan_failed(scan.scan_type.value if scan else "unknown", str(scan.project_id) if scan else "unknown", type(exc).__name__)

            db.commit()

        # Retry on failure (handled by autoretry)
        from app.core.logging import get_structured_logger
        logger = get_structured_logger("worker.task")
        logger.error(
            "Scan job failed",
            job_id=job_id,
            scan_id=scan_id,
            error=str(exc),
            retry_count=self.request.retries,
        )
        raise

    finally:
        db.close()


def _execute_recon(db: Session, scan: Scan, job: ScanJob) -> dict[str, Any]:
    """
    Execute reconnaissance using the recon engine.
    
    This replaces the dummy simulation with real plugin execution.
    """
    # Get target
    from app.models.projects import Target
    target = db.get(Target, scan.target_id) if scan.target_id else None
    if not target:
        return {"success": False, "error": "No target associated with scan"}

    # Get scope rules for this project
    from app.models.projects import Scope, ScopeRule
    scope_rules = []
    if target.scope_id:
        scope = db.get(Scope, target.scope_id)
        if scope:
            rules = db.query(ScopeRule).filter(ScopeRule.scope_id == scope.id).all()
            scope_rules = [
                {
                    "effect": rule.effect.value,
                    "target_type": rule.target_type.value,
                    "pattern": rule.pattern,
                    "note": rule.note,
                }
                for rule in rules
            ]

    # Create recon engine with Redis-backed rate limiter for production
    from app.config import get_settings
    from app.recon.rate_limiter import ReconRateLimiter

    settings = get_settings()
    rate_limiter = ReconRateLimiter(redis_url=settings.redis_url)

    engine = ReconEngineFactory.create(
        db_session=db,
        rate_limiter=rate_limiter,
    )

    # Determine target type for recon
    target_type = target.target_type or "domain"

    # Run recon
    recon_results = engine.run_recon(
        scan=scan,
        job=job,
        target_value=target.name,
        target_type=target_type,
        scope_rules=scope_rules,
    )

    return {
        "scan_type": scan.scan_type.value,
        "target": target.name,
        "target_type": target_type,
        "duration_seconds": 0,  # Could add timing
        "assets_discovered": len(recon_results),
        "recon_results": [
            {
                "asset_kind": r.asset_kind,
                "value": r.value,
                "scope_status": r.scope_status,
                "confidence": r.confidence,
                "source": r.source,
            }
            for r in recon_results
        ],
        "completed_at": datetime.now(UTC).isoformat(),
    }


@shared_task(
    bind=True,
    name="app.workers.tasks.priority_scan_job"
)
def priority_scan_job(self, job_id: str, scan_id: str, idempotency_key: str | None = None) -> dict[str, Any]:
    """
    Execute a priority scan job (bypasses normal queue).
    
    Used for urgent scans that need immediate execution.
    """
    # Priority jobs still respect backpressure but with higher priority
    if not can_accept_task():
        raise self.retry(countdown=10, max_retries=3)

    return execute_scan_job(job_id, scan_id, idempotency_key)


@shared_task(
    bind=True,
    name="app.workers.tasks.cleanup_stale_jobs"
)
def cleanup_stale_jobs(self) -> dict[str, Any]:
    """
    Clean up stale scan jobs that have been running too long.
    
    This maintenance task finds jobs stuck in RUNNING state for more than
    the configured timeout and marks them as failed.
    """
    from app.config import get_settings

    settings = get_settings()
    db = get_db_session()

    try:
        timeout_minutes = getattr(settings, "scan_job_timeout_minutes", 60)
        from datetime import timedelta

        cutoff = datetime.now(UTC) - timedelta(minutes=timeout_minutes)

        stale_jobs = db.scalars(
            select(ScanJob).where(
                ScanJob.status == ScanJobStatus.RUNNING,
                ScanJob.started_at < cutoff,
            )
        ).all()

        count = 0
        for job in stale_jobs:
            job.status = ScanJobStatus.FAILED
            job.error = f"Job timed out after {timeout_minutes} minutes"
            job.finished_at = datetime.now(UTC)

            _emit_event(
                db,
                str(job.scan_id),
                str(job.id),
                "scan.failed",
                "error",
                f"Job timed out: {job.error}",
                {"timeout_minutes": timeout_minutes},
            )

            record_job_failed("scans", job.name, "timeout")

            # Check if scan should be marked failed
            scan = db.get(Scan, job.scan_id)
            if scan:
                running_jobs = [
                    j for j in scan.jobs
                    if j.status in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)
                ]
                if not running_jobs:
                    scan.status = ScanStatus.FAILED
                    scan.finished_at = datetime.now(UTC)
                    _emit_event(
                        db,
                        str(scan.id),
                        None,
                        "scan.failed",
                        "error",
                        "Scan failed due to job timeout",
                        {"scan_id": str(scan.id)},
                    )
                    record_scan_failed(scan.scan_type.value, str(scan.project_id), "job_timeout")

            count += 1

        db.commit()
        return {"success": True, "cleaned_up": count}

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(
    bind=True,
    name="app.workers.tasks.cancel_scan_job"
)
def cancel_scan_job(self, job_id: str, reason: str = "Cancelled by user") -> dict[str, Any]:
    """Cancel a queued or running scan job."""
    db = get_db_session()

    try:
        job_uuid = UUID(job_id)
        job = db.get(ScanJob, job_uuid)

        if not job:
            return {"success": False, "error": "Job not found"}

        if job.status in (ScanJobStatus.SUCCEEDED, ScanJobStatus.FAILED, ScanJobStatus.CANCELLED):
            return {"success": False, "error": f"Job already in terminal state: {job.status.value}"}

        job.status = ScanJobStatus.CANCELLED
        job.error = reason
        job.finished_at = datetime.now(UTC)

        _emit_event(
            db,
            str(job.scan_id),
            job_id,
            "job.cancelled",
            "info",
            f"Job cancelled: {reason}",
            {"reason": reason},
        )

        record_job_failed("scans", job.name, "cancelled")

        # Check scan completion
        scan = db.get(Scan, job.scan_id)
        if scan:
            _check_scan_completion(db, scan)

        db.commit()

        return {"success": True}

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(
    bind=True,
    name="app.workers.tasks.retry_failed_job"
)
def retry_failed_job(self, job_id: str) -> dict[str, Any]:
    """Retry a failed scan job."""
    db = get_db_session()

    try:
        job_uuid = UUID(job_id)
        job = db.get(ScanJob, job_uuid)

        if not job:
            return {"success": False, "error": "Job not found"}

        if job.status != ScanJobStatus.FAILED:
            return {"success": False, "error": f"Job not in failed state: {job.status.value}"}

        # Reset job for retry
        job.status = ScanJobStatus.QUEUED
        job.error = None
        job.started_at = None
        job.finished_at = None
        job.result = None

        _emit_event(
            db,
            str(job.scan_id),
            job_id,
            "job.retry",
            "info",
            "Job queued for retry",
            {},
        )

        db.commit()

        # Re-enqueue the task
        execute_scan_job.delay(str(job.id), str(job.scan_id))

        return {"success": True}

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


# Register tasks explicitly
celery_app.task(execute_scan_job)
celery_app.task(priority_scan_job)
celery_app.task(cleanup_stale_jobs)
celery_app.task(cancel_scan_job)
celery_app.task(retry_failed_job)
