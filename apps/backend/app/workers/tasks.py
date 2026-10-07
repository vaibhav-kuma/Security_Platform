"""Worker tasks for scan execution."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
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
        else:
            scan.status = ScanStatus.COMPLETED
            _emit_event(db, str(scan.id), None, "scan.completed", "info",
                       "Scan completed successfully",
                       {"total_jobs": len(scan.jobs)})

        scan.finished_at = datetime.now(UTC)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_scan_job(self, job_id: str, scan_id: str) -> dict[str, Any]:
    """
    Execute a scan job.

    This task runs the recon engine to perform reconnaissance on the target.
    """
    db = get_db_session()
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

        # Emit scan.started event
        _emit_event(db, scan_id, job_id, "scan.started", "info", f"Scan job {job.name} started", {})

        # Execute recon using the recon engine
        result = _execute_recon(db, scan, job)

        # Update job with result
        job.result = result
        job.status = ScanJobStatus.SUCCEEDED
        job.finished_at = datetime.now(UTC)

        # Emit scan.completed event
        _emit_event(
            db, scan_id, job_id, "scan.completed", "info",
            f"Scan job {job.name} completed", result
        )

        # Check if all jobs in scan are done
        _check_scan_completion(db, scan)

        db.commit()
        return {"success": True, "result": result}

    except Exception as exc:
        db.rollback()
        job = db.get(ScanJob, UUID(job_id))
        if job:
            job.status = ScanJobStatus.FAILED
            job.error = str(exc)
            job.finished_at = datetime.now(UTC)
            _emit_event(
                db, scan_id, job_id, "scan.failed", "error",
                f"Scan job failed: {exc}", {"error": str(exc)}
            )
            db.commit()

        # Retry on failure
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {"success": False, "error": f"Max retries exceeded: {exc}"}

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

    # Create recon engine
    engine = ReconEngineFactory.create(db)

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


@shared_task
def cleanup_stale_jobs() -> dict[str, Any]:
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

            count += 1

        db.commit()
        return {"success": True, "cleaned_up": count}

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}

    finally:
        db.close()


# Register tasks with celery app
celery_app.task(execute_scan_job)
celery_app.task(cleanup_stale_jobs)
