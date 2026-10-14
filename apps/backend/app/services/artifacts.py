"""Artifact lifecycle management for scan evidence, reports, and other stored objects."""

from datetime import UTC, datetime, timedelta
from typing import Any

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.db.session import get_engine, make_session_factory
from app.models.detection import Evidence
from app.models.scans import Scan, ScanEvent, ScanJob


def get_db_session() -> Session:
    """Get a new database session."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


def get_minio_client():
    """Get MinIO client for object storage."""
    from minio import Minio

    from app.config import get_settings

    settings = get_settings()
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


@shared_task(bind=True, name="app.workers.tasks.cleanup_expired_artifacts")
def cleanup_expired_artifacts(self, retention_days: int | None = None) -> dict[str, Any]:
    """
    Clean up expired artifacts based on retention policy.
    
    Removes:
    - Evidence files older than retention period
    - Scan events older than retention period
    - Temporary scan job results
    """
    from app.config import get_settings

    settings = get_settings()
    retention = retention_days or settings.artifact_retention_days
    cutoff = datetime.now(UTC) - timedelta(days=retention)

    db = get_db_session()
    minio_client = get_minio_client()

    try:
        deleted_objects = 0
        deleted_db_records = 0
        freed_bytes = 0

        # Clean up evidence objects
        old_evidence = db.scalars(
            select(Evidence).where(
                Evidence.created_at < cutoff,
                Evidence.object_key.isnot(None),
            )
        ).all()

        for evidence in old_evidence:
            try:
                # Delete from MinIO
                if evidence.object_key:
                    try:
                        stat = minio_client.stat_object("evidence", evidence.object_key)
                        freed_bytes += stat.size
                        minio_client.remove_object("evidence", evidence.object_key)
                        deleted_objects += 1
                    except Exception:
                        pass  # Object may not exist

                # Clear object key but keep metadata for audit
                evidence.object_key = None
                evidence.storage = "deleted"
                deleted_db_records += 1

            except Exception as e:
                from app.core.logging import get_structured_logger
                logger = get_structured_logger("artifact.cleanup")
                logger.warning(
                    "Failed to delete evidence object",
                    evidence_id=str(evidence.id),
                    error=str(e),
                )

        # Clean up old scan events (keep only last N per scan)
        max_events_per_scan = 1000
        from sqlalchemy import func

        # Find scans with too many events
        event_counts = db.execute(
            select(ScanEvent.scan_id, func.count(ScanEvent.id))
            .group_by(ScanEvent.scan_id)
            .having(func.count(ScanEvent.id) > max_events_per_scan)
        ).all()

        for scan_id, count in event_counts:
            excess = count - max_events_per_scan
            # Delete oldest events beyond the limit
            oldest_events = db.scalars(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan_id)
                .order_by(ScanEvent.occurred_at.asc())
                .limit(excess)
            ).all()

            for event in oldest_events:
                db.delete(event)
                deleted_db_records += 1

        # Clean up completed/failed scan job results older than retention
        old_jobs = db.scalars(
            select(ScanJob).where(
                ScanJob.status.in_(["succeeded", "failed", "cancelled"]),
                ScanJob.finished_at < cutoff,
                ScanJob.result.isnot(None),
            )
        ).all()

        for job in old_jobs:
            job.result = None  # Clear large result payloads
            deleted_db_records += 1

        db.commit()

        return {
            "success": True,
            "retention_days": retention,
            "deleted_objects": deleted_objects,
            "deleted_db_records": deleted_db_records,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2),
        }

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.cleanup_orphaned_objects")
def cleanup_orphaned_objects(self, bucket: str = "evidence") -> dict[str, Any]:
    """
    Clean up orphaned objects in MinIO that have no database reference.
    
    This handles objects that were uploaded but the DB transaction failed,
    or objects whose DB records were deleted but objects weren't cleaned up.
    """
    minio_client = get_minio_client()
    db = get_db_session()

    try:
        # Get all object keys from database
        db_keys = set()
        evidence_keys = db.scalars(
            select(Evidence.object_key).where(Evidence.object_key.isnot(None))
        ).all()
        db_keys.update(k for k in evidence_keys if k)

        # List all objects in bucket
        orphaned = 0
        freed_bytes = 0

        objects = minio_client.list_objects(bucket, recursive=True)
        for obj in objects:
            if obj.object_name not in db_keys:
                try:
                    # Double-check object is old enough (avoid race conditions)
                    if obj.last_modified:
                        obj_age = datetime.now(UTC) - obj.last_modified.replace(tzinfo=UTC)
                        if obj_age > timedelta(hours=1):  # At least 1 hour old
                            freed_bytes += obj.size
                            minio_client.remove_object(bucket, obj.object_name)
                            orphaned += 1
                except Exception as e:
                    from app.core.logging import get_structured_logger
                    logger = get_structured_logger("artifact.cleanup")
                    logger.warning(
                        "Failed to delete orphaned object",
                        object_name=obj.object_name,
                        error=str(e),
                    )

        return {
            "success": True,
            "bucket": bucket,
            "orphaned_deleted": orphaned,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2),
        }

    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.archive_old_scans")
def archive_old_scans(self, archive_after_days: int = 90) -> dict[str, Any]:
    """
    Archive old completed scans to cold storage.
    
    Moves scan data to archive bucket and marks as archived.
    """
    from app.config import get_settings

    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(days=archive_after_days)

    db = get_db_session()
    minio_client = get_minio_client()

    try:
        # Find scans to archive
        scans_to_archive = db.scalars(
            select(Scan).where(
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED]),
                Scan.finished_at < cutoff,
                Scan.configuration.op("->>")("archived") != "true",
            )
        ).all()

        archived = 0
        for scan in scans_to_archive:
            # Create archive package
            archive_data = {
                "scan_id": str(scan.id),
                "project_id": str(scan.project_id),
                "target_id": str(scan.target_id) if scan.target_id else None,
                "name": scan.name,
                "scan_type": scan.scan_type.value,
                "status": scan.status.value,
                "configuration": scan.configuration,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "jobs": [],
            }

            # Include job summaries
            for job in scan.jobs:
                archive_data["jobs"].append({
                    "id": str(job.id),
                    "name": job.name,
                    "status": job.status.value,
                    "started_at": job.started_at.isoformat() if job.started_at else None,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                    "error": job.error,
                    # Don't include full result - too large
                })

            # Upload to archive bucket
            import json
            archive_key = f"scans/{scan.project_id}/{scan.id}/archive.json"
            archive_bytes = json.dumps(archive_data, indent=2).encode()

            try:
                minio_client.put_object(
                    "archives",
                    archive_key,
                    data=__import__('io').BytesIO(archive_bytes),
                    length=len(archive_bytes),
                    content_type="application/json",
                )

                # Mark scan as archived
                scan.configuration = {**scan.configuration, "archived": True, "archive_key": archive_key}
                archived += 1

            except Exception as e:
                from app.core.logging import get_structured_logger
                logger = get_structured_logger("artifact.archive")
                logger.error(
                    "Failed to archive scan",
                    scan_id=str(scan.id),
                    error=str(e),
                )

        db.commit()

        return {
            "success": True,
            "archive_after_days": archive_after_days,
            "archived_scans": archived,
        }

    except Exception as exc:
        db.rollback()
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


@shared_task(bind=True, name="app.workers.tasks.verify_artifact_integrity")
def verify_artifact_integrity(self, sample_size: int = 100) -> dict[str, Any]:
    """
    Verify integrity of stored artifacts by checking checksums.
    
    Samples a subset of artifacts and verifies their SHA256 matches.
    """
    minio_client = get_minio_client()
    db = get_db_session()

    try:
        # Sample evidence with object keys
        evidence_sample = db.scalars(
            select(Evidence)
            .where(Evidence.object_key.isnot(None), Evidence.sha256.isnot(None))
            .order_by(Evidence.created_at.desc())
            .limit(sample_size)
        ).all()

        verified = 0
        corrupted = 0
        missing = 0

        for evidence in evidence_sample:
            try:
                # Download and verify
                response = minio_client.get_object("evidence", evidence.object_key)
                content = response.read()
                response.close()
                response.release_conn()

                import hashlib
                actual_sha256 = hashlib.sha256(content).hexdigest()

                if actual_sha256 == evidence.sha256:
                    verified += 1
                else:
                    corrupted += 1
                    from app.core.logging import get_structured_logger
                    logger = get_structured_logger("artifact.integrity")
                    logger.error(
                        "Artifact checksum mismatch",
                        evidence_id=str(evidence.id),
                        expected=evidence.sha256,
                        actual=actual_sha256,
                    )

            except Exception as e:
                missing += 1
                from app.core.logging import get_structured_logger
                logger = get_structured_logger("artifact.integrity")
                logger.warning(
                    "Artifact not found in storage",
                    evidence_id=str(evidence.id),
                    object_key=evidence.object_key,
                    error=str(e),
                )

        return {
            "success": True,
            "sample_size": sample_size,
            "verified": verified,
            "corrupted": corrupted,
            "missing": missing,
        }

    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def get_storage_stats() -> dict[str, Any]:
    """Get storage usage statistics."""
    minio_client = get_minio_client()
    db = get_db_session()

    try:
        stats = {
            "buckets": {},
            "database": {},
        }

        # Bucket stats
        for bucket_name in ["evidence", "archives", "reports", "apk"]:
            try:
                total_size = 0
                object_count = 0
                objects = minio_client.list_objects(bucket_name, recursive=True)
                for obj in objects:
                    total_size += obj.size
                    object_count += 1

                stats["buckets"][bucket_name] = {
                    "object_count": object_count,
                    "total_bytes": total_size,
                    "total_mb": round(total_size / (1024 * 1024), 2),
                    "total_gb": round(total_size / (1024 * 1024 * 1024), 3),
                }
            except Exception:
                stats["buckets"][bucket_name] = {"error": "Bucket not found or inaccessible"}

        # Database stats
        evidence_count = db.scalar(select(Evidence).where(Evidence.object_key.isnot(None)).count())
        evidence_with_files = db.scalar(select(Evidence).where(Evidence.object_key.isnot(None)).count())

        stats["database"] = {
            "evidence_records": evidence_count,
            "evidence_with_files": evidence_with_files,
        }

        return stats

    finally:
        db.close()


def set_retention_policy(
    artifact_type: str,
    retention_days: int,
    description: str = "",
) -> dict[str, Any]:
    """Set retention policy for an artifact type (stored in config)."""
    # This would typically be stored in a config table or Consul/etcd
    # For now, return the policy
    return {
        "artifact_type": artifact_type,
        "retention_days": retention_days,
        "description": description,
        "created_at": datetime.now(UTC).isoformat(),
    }


# Register tasks
celery_app.task(cleanup_expired_artifacts)
celery_app.task(cleanup_orphaned_objects)
celery_app.task(archive_old_scans)
celery_app.task(verify_artifact_integrity)
