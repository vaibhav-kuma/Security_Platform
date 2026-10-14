"""Dynamic Analysis Service - orchestrates dynamic analysis workflows."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.dynamic_pipeline import DynamicAnalysisPipeline, DynamicAnalysisPipelineFactory
from app.core.emulator import EmulatorManager
from app.models.dynamic import (
    DynamicAnalysisRun,
    DynamicAnalysisEvidence,
    EmulatorProfile,
    EmulatorInstance,
    EmulatorStatus,
    RuntimeEvent,
    NetworkObservation,
    FileObservation,
    IpcObservation,
)
from app.models.scans import Scan, ScanJob
from app.models.enums import (
    ScanJobStatus,
    ScanStatus,
    SecurityEventType,
)
from app.models.apk import ApkFile
from app.models.audit import AuditLog


class EmulatorProfileService:
    """Service for managing emulator profiles."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_profile(
        self,
        name: str,
        avd_name: str,
        api_level: int,
        abi: str,
        description: str | None = None,
        ram_mb: int = 2048,
        storage_mb: int = 4096,
        proxy_host: str | None = None,
        proxy_port: int | None = None,
        gpu_enabled: bool = True,
        camera_enabled: bool = False,
        gps_enabled: bool = False,
        max_cpu_percent: int = 80,
        max_memory_mb: int = 4096,
        max_execution_time_seconds: int = 3600,
        network_policy: str = "proxy_only",
    ) -> EmulatorProfile:
        """Create an emulator profile."""
        profile = EmulatorProfile(
            name=name,
            avd_name=avd_name,
            api_level=api_level,
            abi=abi,
            description=description,
            ram_mb=ram_mb,
            storage_mb=storage_mb,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            gpu_enabled=gpu_enabled,
            camera_enabled=camera_enabled,
            gps_enabled=gps_enabled,
            max_cpu_percent=max_cpu_percent,
            max_memory_mb=max_memory_mb,
            max_execution_time_seconds=max_execution_time_seconds,
            network_policy=network_policy,
        )
        self.db.add(profile)
        self.db.flush()
        return profile

    def get_profile(self, profile_id: UUID) -> EmulatorProfile | None:
        """Get emulator profile by ID."""
        return self.db.get(EmulatorProfile, profile_id)

    def list_profiles(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[EmulatorProfile], int]:
        """List emulator profiles."""
        stmt = select(EmulatorProfile).where(EmulatorProfile.deleted_at.is_(None))

        total_stmt = select(func.count(EmulatorProfile.id)).where(
            EmulatorProfile.deleted_at.is_(None)
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(EmulatorProfile.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        profiles = list(self.db.scalars(stmt).all())

        return profiles, total

    def update_profile(
        self,
        profile_id: UUID,
        data: dict[str, Any],
    ) -> EmulatorProfile | None:
        """Update emulator profile."""
        profile = self.db.get(EmulatorProfile, profile_id)
        if not profile:
            return None

        for key, value in data.items():
            if hasattr(profile, key) and key not in ("id", "created_at"):
                setattr(profile, key, value)

        profile.updated_at = datetime.now(UTC)
        self.db.flush()
        return profile

    def delete_profile(self, profile_id: UUID) -> bool:
        """Soft delete emulator profile."""
        from app.repositories.base import SoftDeleteRepository
        repo = SoftDeleteRepository(self.db, EmulatorProfile)
        profile = self.db.get(EmulatorProfile, profile_id)
        if not profile:
            return False
        repo.soft_delete(profile)
        return True


class EmulatorInstanceService:
    """Service for managing emulator instances."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.emulator_manager = EmulatorManager(db)

    def get_instance(self, instance_id: UUID) -> EmulatorInstance | None:
        """Get emulator instance by ID."""
        return self.db.get(EmulatorInstance, instance_id)

    def list_instances(
        self,
        profile_id: UUID | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[EmulatorInstance], int]:
        """List emulator instances."""
        stmt = select(EmulatorInstance)

        if profile_id:
            stmt = stmt.where(EmulatorInstance.profile_id == profile_id)
        if status:
            stmt = stmt.where(EmulatorInstance.status == status)

        total_stmt = select(func.count(EmulatorInstance.id))
        if profile_id:
            total_stmt = total_stmt.where(EmulatorInstance.profile_id == profile_id)
        if status:
            total_stmt = total_stmt.where(EmulatorInstance.status == status)
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(EmulatorInstance.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        instances = list(self.db.scalars(stmt).all())

        return instances, total

    async def start_instance(self, instance_id: UUID) -> bool:
        """Start an emulator instance."""
        instance = self.db.get(EmulatorInstance, instance_id)
        if not instance:
            return False

        return await self.emulator_manager.start_instance(instance)

    async def stop_instance(self, instance_id: UUID) -> bool:
        """Stop an emulator instance."""
        instance = self.db.get(EmulatorInstance, instance_id)
        if not instance:
            return False

        return await self.emulator_manager.stop_instance(instance)

    async def restart_instance(self, instance_id: UUID) -> bool:
        """Restart an emulator instance."""
        instance = self.db.get(EmulatorInstance, instance_id)
        if not instance:
            return False

        return await self.emulator_manager.restart_instance(instance)

    async def snapshot_instance(self, instance_id: UUID, snapshot_name: str) -> bool:
        """Create a snapshot of the emulator."""
        instance = self.db.get(EmulatorInstance, instance_id)
        if not instance:
            return False

        return await self.emulator_manager.snapshot_instance(instance, snapshot_name)

    async def restore_snapshot(self, instance_id: UUID, snapshot_name: str) -> bool:
        """Restore emulator to a snapshot."""
        instance = self.db.get(EmulatorInstance, instance_id)
        if not instance:
            return False

        return await self.emulator_manager.restore_snapshot(instance, snapshot_name)


class DynamicAnalysisService:
    """Service for managing dynamic analysis runs."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.pipeline = DynamicAnalysisPipelineFactory.create(db)

    def get_run(self, run_id: UUID) -> DynamicAnalysisRun | None:
        """Get dynamic analysis run by ID."""
        return self.db.get(DynamicAnalysisRun, run_id)

    def get_run_detail(self, run_id: UUID) -> DynamicAnalysisRun | None:
        """Get dynamic analysis run with all observations."""
        run = self.db.get(DynamicAnalysisRun, run_id)
        if run:
            # Access relationships to load them
            _ = run.runtime_events
            _ = run.network_observations
            _ = run.file_observations
            _ = run.ipc_observations
        return run

    def list_runs(
        self,
        scan_id: UUID,
        page: int = 1,
        page_size: int = 20,
        status_filter: str | None = None,
    ) -> tuple[list[DynamicAnalysisRun], int]:
        """List dynamic analysis runs for a scan."""
        stmt = select(DynamicAnalysisRun).where(
            DynamicAnalysisRun.scan_id == scan_id,
            DynamicAnalysisRun.deleted_at.is_(None),
        )

        if status_filter:
            stmt = stmt.where(DynamicAnalysisRun.status == status_filter)

        total_stmt = select(func.count(DynamicAnalysisRun.id)).where(
            DynamicAnalysisRun.scan_id == scan_id,
            DynamicAnalysisRun.deleted_at.is_(None),
        )
        if status_filter:
            total_stmt = total_stmt.where(DynamicAnalysisRun.status == status_filter)
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(DynamicAnalysisRun.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        runs = list(self.db.scalars(stmt).all())

        return runs, total

    async def start_analysis(
        self,
        scan_id: UUID,
        scan_job_id: UUID,
        profile_id: UUID,
        apk_file_id: UUID,
        test_context: str = "default",
        network_policy: str = "proxy_only",
        frida_scripts: list[str] | None = None,
        resource_limits: dict[str, Any] | None = None,
        current_user_id: UUID | None = None,
    ) -> DynamicAnalysisRun:
        """Start a dynamic analysis run."""
        # Get required objects
        scan = self.db.get(Scan, scan_id)
        scan_job = self.db.get(ScanJob, scan_job_id)
        apk_file = self.db.get(ApkFile, apk_file_id)

        if not scan or not scan_job or not apk_file:
            raise ValueError("Required objects not found")

        # Get emulator profile
        from app.core.emulator import EmulatorProfile as CoreEmulatorProfile
        # Note: This is a simplified version - in production, we'd load the profile from DB
        # and create a core profile object

        # Create dynamic run record
        dynamic_run = DynamicAnalysisRun(
            scan_id=scan_id,
            emulator_instance_id=None,  # Will be set by pipeline
            apk_file_id=apk_file_id,
            test_context="default",
            network_policy="proxy_only",
            proxy_configuration={},
            frida_scripts=[],
            resource_limits={},
            status="pending",
        )
        self.db.add(dynamic_run)
        self.db.flush()

        # Audit log
        if current_user_id:
            audit = AuditLog(
                actor_id=current_user_id,
                action=SecurityEventType.SCAN_START.value,
                entity_type="dynamic_analysis_run",
                entity_id=dynamic_run.id,
                details={"scan_id": str(scan_id), "apk_file_id": str(apk_file_id)},
            )
            self.db.add(audit)
            self.db.commit()

        return dynamic_run

    def update_run_status(
        self,
        run_id: UUID,
        status: str,
        error: str | None = None,
    ) -> DynamicAnalysisRun | None:
        """Update dynamic analysis run status."""
        run = self.db.get(DynamicAnalysisRun, run_id)
        if not run:
            return None

        run.status = status
        if error:
            run.error = error
        if status in ("completed", "failed", "cancelled"):
            run.finished_at = datetime.now(UTC)
        run.updated_at = datetime.now(UTC)

        self.db.flush()
        return run

    def get_runtime_events(
        self,
        run_id: UUID,
        page: int = 1,
        page_size: int = 50,
        event_type: str | None = None,
    ) -> tuple[list[RuntimeEvent], int]:
        """Get runtime events for a dynamic analysis run."""
        stmt = select(RuntimeEvent).where(RuntimeEvent.analysis_run_id == run_id)

        if event_type:
            stmt = stmt.where(RuntimeEvent.event_type == event_type)

        total_stmt = select(func.count(RuntimeEvent.id)).where(
            RuntimeEvent.analysis_run_id == run_id
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(RuntimeEvent.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        events = list(self.db.scalars(stmt).all())

        return events, total

    def get_network_observations(
        self,
        run_id: UUID,
        page: int = 1,
        page_size: int = 50,
        protocol: str | None = None,
    ) -> tuple[list[NetworkObservation], int]:
        """Get network observations for a dynamic analysis run."""
        stmt = select(NetworkObservation).where(NetworkObservation.analysis_run_id == run_id)

        if protocol:
            stmt = stmt.where(NetworkObservation.protocol == protocol)

        total_stmt = select(func.count(NetworkObservation.id)).where(
            NetworkObservation.analysis_run_id == run_id
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(NetworkObservation.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        observations = list(self.db.scalars(stmt).all())

        return observations, total

    def get_file_observations(
        self,
        run_id: UUID,
        page: int = 1,
        page_size: int = 50,
        operation: str | None = None,
    ) -> tuple[list[FileObservation], int]:
        """Get file observations for a dynamic analysis run."""
        stmt = select(FileObservation).where(FileObservation.analysis_run_id == run_id)

        if operation:
            stmt = stmt.where(FileObservation.operation == operation)

        total_stmt = select(func.count(FileObservation.id)).where(
            FileObservation.analysis_run_id == run_id
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(FileObservation.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        observations = list(self.db.scalars(stmt).all())

        return observations, total

    def get_ipc_observations(
        self,
        run_id: UUID,
        page: int = 1,
        page_size: int = 50,
        ipc_type: str | None = None,
    ) -> tuple[list[IpcObservation], int]:
        """Get IPC observations for a dynamic analysis run."""
        stmt = select(IpcObservation).where(IpcObservation.analysis_run_id == run_id)

        if ipc_type:
            stmt = stmt.where(IpcObservation.ipc_type == ipc_type)

        total_stmt = select(func.count(IpcObservation.id)).where(
            IpcObservation.analysis_run_id == run_id
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(IpcObservation.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        observations = list(self.db.scalars(stmt).all())

        return observations, total

    def get_evidence(
        self,
        run_id: UUID,
    ) -> list[DynamicAnalysisEvidence]:
        """Get evidence artifacts for a dynamic analysis run."""
        stmt = select(DynamicAnalysisEvidence).where(
            DynamicAnalysisEvidence.analysis_run_id == run_id
        )
        return list(self.db.scalars(stmt).all())

    def get_run_summary(self, run_id: UUID) -> dict[str, Any] | None:
        """Get dynamic analysis run summary."""
        run = self.db.get(DynamicAnalysisRun, run_id)
        if not run:
            return None

        # Get scan info
        scan = self.db.get(Scan, run.scan_id)
        apk_file = self.db.get(ApkFile, run.apk_file_id) if run.apk_file_id else None

        return {
            "run_id": run.id,
            "scan_id": run.scan_id,
            "apk_package_name": apk_file.package_name if apk_file else "unknown",
            "test_context": run.test_context,
            "status": run.status,
            "duration_seconds": (
                (run.finished_at - run.started_at).total_seconds()
                if run.started_at and run.finished_at else None
            ),
            "events_captured": run.events_captured,
            "network_observations": run.network_observations,
            "file_operations": run.file_operations,
            "ipc_events": run.ipc_events,
            "crypto_operations": run.crypto_operations,
            "findings_by_severity": {},
            "findings_by_type": {},
            "mastg_coverage": {},
            "correlated_static_findings": run.correlated_static_findings,
            "correlated_api_findings": run.correlated_api_findings,
            "evidence_artifacts": run.evidence_artifacts,
        }