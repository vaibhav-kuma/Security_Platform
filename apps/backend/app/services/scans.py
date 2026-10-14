"""Worker service for managing scan execution."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.scope_engine import ScopeEngine
from app.models.enums import ScanJobStatus, ScanStatus, ScanType
from app.models.projects import Project, Scope
from app.models.scans import Scan, ScanJob
from app.recon.policy import ExecutionPolicy
from app.services.target_validation import validate_target_for_scan


class ScanExecutionService:
    """Service for managing scan execution lifecycle."""

    def __init__(self, db: Session):
        self.db = db
        self.scope_engine = ScopeEngine()

    def create_scan_jobs(self, scan: Scan) -> list[ScanJob]:
        """
        Create scan jobs for a scan based on its type and configuration.

        In Phase 7, this creates a single job per scan. In future phases,
        this will create multiple jobs for different scanner plugins.
        """
        job = ScanJob(
            scan_id=scan.id,
            name=f"{scan.scan_type.value} scan",
            status=ScanJobStatus.QUEUED,
            configuration=scan.configuration or {},
        )
        self.db.add(job)
        self.db.flush()
        return [job]

    def validate_scan_preconditions(self, scan: Scan) -> tuple[bool, str | None]:
        """
        Validate that a scan can be started.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check scan status
        if scan.status != ScanStatus.PENDING:
            return False, f"Scan is not in PENDING status: {scan.status.value}"

        # Check target exists
        if scan.target_id:
            from app.models.projects import Target

            target = self.db.get(Target, scan.target_id)
            if not target:
                return False, "Target not found"
            if target.project_id != scan.project_id:
                return False, "Target does not belong to this project"

            # Validate target against scope
            is_valid, error = validate_target_for_scan(self.db, scan.project_id, scan.target_id)
            if not is_valid:
                return False, f"Target validation failed: {error}"

        # Check project exists and is active
        project = self.db.get(Project, scan.project_id)
        if not project:
            return False, "Project not found"
        if project.status.value != "active":
            return False, f"Project is not active: {project.status.value}"

        # Check active scope exists
        active_scope = self.db.scalar(
            select(Scope).where(Scope.project_id == scan.project_id, Scope.is_active)
        )
        if not active_scope:
            return False, "No active scope found for project"

        return True, None

    def start_scan(self, scan: Scan) -> Scan:
        """Start a scan by creating jobs and queueing them."""
        # Validate preconditions
        is_valid, error = self.validate_scan_preconditions(scan)
        if not is_valid:
            raise ValueError(error)

        # Update scan status
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)

        # Create and queue jobs
        jobs = self.create_scan_jobs(scan)
        for job in jobs:
            # Add execution policy to job configuration
            policy = ExecutionPolicy.default_passive()
            job.configuration = {
                **job.configuration,
                "execution_policy": {
                    "testing_mode": policy.testing_mode.value,
                    "safe_mode": policy.safe_mode,
                    "rate_limits": {
                        k: {
                            "requests_per_minute": v.requests_per_minute,
                            "requests_per_hour": v.requests_per_hour,
                            "scope": v.scope.value,
                        }
                        for k, v in policy.rate_limits.items()
                    },
                },
            }

            # Queue the job via Celery
            celery_app.send_task(
                "app.workers.tasks.execute_scan_job",
                args=[str(job.id), str(scan.id)],
                queue="scans",
                routing_key="scan.execute",
            )

        self.db.commit()
        return scan

    def cancel_scan(self, scan: Scan) -> Scan:
        """Cancel a running or pending scan with true Celery task revocation."""
        if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
            raise ValueError(f"Cannot cancel scan with status: {scan.status.value}")

        scan.status = ScanStatus.CANCELLED
        scan.finished_at = datetime.now(UTC)

        # Cancel any running/pending jobs
        for job in scan.jobs:
            if job.status in (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING):
                job.status = ScanJobStatus.CANCELLED
                job.finished_at = datetime.now(UTC)
                # Revoke the Celery task if it's running
                celery_app.control.revoke(str(job.id), terminate=True, signal="SIGTERM")

        self.db.commit()
        return scan

    def pause_scan(self, scan: Scan) -> Scan:
        """Pause a running scan by revoking queued jobs and signaling running jobs."""
        if scan.status != ScanStatus.RUNNING:
            raise ValueError(f"Cannot pause scan with status: {scan.status.value}")

        scan.status = ScanStatus.PAUSED

        # Revoke queued jobs (they won't be picked up)
        for job in scan.jobs:
            if job.status == ScanJobStatus.QUEUED:
                celery_app.control.revoke(str(job.id), terminate=False)
                # Job stays QUEUED but won't be picked up due to pause signal

            elif job.status == ScanJobStatus.RUNNING:
                # Signal the worker to pause - the task will check pause flag periodically
                # We set a pause flag in the job configuration
                job.configuration = {**job.configuration, "_paused": True}
                # The worker will check this flag and pause execution

        self.db.commit()
        return scan

    def resume_scan(self, scan: Scan) -> Scan:
        """Resume a paused scan."""
        if scan.status not in (ScanStatus.PENDING, ScanStatus.PAUSED):
            raise ValueError(f"Cannot resume scan with status: {scan.status.value}")

        scan.status = ScanStatus.RUNNING

        # Remove pause flag and re-queue any pending jobs
        for job in scan.jobs:
            if job.status == ScanJobStatus.QUEUED:
                # Remove pause flag
                if "_paused" in job.configuration:
                    config = {k: v for k, v in job.configuration.items() if k != "_paused"}
                    job.configuration = config

                celery_app.send_task(
                    "app.workers.tasks.execute_scan_job",
                    args=[str(job.id), str(scan.id)],
                    queue="scans",
                    routing_key="scan.execute",
                )

        self.db.commit()
        return scan

    def get_scan_progress(self, scan: Scan) -> dict[str, Any]:
        """Get real-time progress of a scan."""
        total_jobs = len(scan.jobs)
        completed_jobs = sum(1 for j in scan.jobs if j.status == ScanJobStatus.SUCCEEDED)
        failed_jobs = sum(1 for j in scan.jobs if j.status == ScanJobStatus.FAILED)
        running_jobs = sum(1 for j in scan.jobs if j.status == ScanJobStatus.RUNNING)
        queued_jobs = sum(1 for j in scan.jobs if j.status == ScanJobStatus.QUEUED)

        progress = 0
        if total_jobs > 0:
            progress = int((completed_jobs / total_jobs) * 100)

        return {
            "scan_id": str(scan.id),
            "status": scan.status.value,
            "progress": progress,
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "running_jobs": running_jobs,
            "queued_jobs": queued_jobs,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        }


def create_scan_with_validation(
    db: Session,
    project_id: UUID,
    name: str,
    scan_type: ScanType,
    target_id: UUID | None = None,
    configuration: dict[str, Any] | None = None,
    initiated_by: UUID | None = None,
) -> Scan:
    """Create a new scan with full validation.

    This is the main entry point for scan creation that ensures
    all security preconditions are met.
    """
    from app.models.projects import Target
    from app.services.target_validation import validate_target_for_scan

    # Validate project
    project = db.get(Project, project_id)
    if not project:
        raise ValueError("Project not found")

    # Validate target if provided
    if target_id:
        target = db.get(Target, target_id)
        if not target:
            raise ValueError("Target not found")
        if target.project_id != project_id:
            raise ValueError("Target does not belong to this project")

        # Validate target scope using shared validation function
        is_valid, error = validate_target_for_scan(db, project_id, target_id)
        if not is_valid:
            raise ValueError(f"Target not authorized for scanning: {error}")

    # Create scan
    scan = Scan(
        project_id=project_id,
        target_id=target_id,
        initiated_by=initiated_by,
        name=name,
        scan_type=scan_type,
        status=ScanStatus.PENDING,
        configuration=configuration or {},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan
