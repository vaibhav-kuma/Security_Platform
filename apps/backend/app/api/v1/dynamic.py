"""Dynamic Analysis API router (v1)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.dynamic import DynamicAnalysisRun, EmulatorInstance, EmulatorProfile
from app.models.enums import SecurityEventType
from app.models.identity import User
from app.schemas.dynamic import (
    DynamicAnalysisRunCreate,
    DynamicAnalysisRunDetailResponse,
    DynamicAnalysisRunListResponse,
    DynamicAnalysisRunResponse,
    DynamicAnalysisRunUpdate,
    EmulatorInstanceResponse,
    EmulatorInstanceListResponse,
    EmulatorProfileCreate,
    EmulatorProfileListResponse,
    EmulatorProfileResponse,
    EmulatorProfileUpdate,
    FileObservationListResponse,
    FileObservationResponse,
    IpcObservationListResponse,
    IpcObservationResponse,
    NetworkObservationListResponse,
    NetworkObservationResponse,
    RuntimeEventListResponse,
    RuntimeEventResponse,
)
from app.services.dynamic_analysis import (
    DynamicAnalysisService,
    EmulatorInstanceService,
    EmulatorProfileService,
)

router = APIRouter(prefix="/projects/{project_id}/dynamic", tags=["dynamic-analysis"])


# =============================================================================
# Emulator Profile Endpoints
# =============================================================================

@router.post(
    "/emulator-profiles",
    response_model=EmulatorProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create emulator profile",
)
@strict_rate_limit()
def create_emulator_profile(
    project_id: UUID,
    data: EmulatorProfileCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> EmulatorProfileResponse:
    """Create an emulator profile for dynamic analysis."""
    service = EmulatorProfileService(db)
    profile = service.create_profile(
        name=data.name,
        avd_name=data.avd_name,
        api_level=data.api_level,
        abi=data.abi,
        description=data.description,
        ram_mb=data.ram_mb,
        storage_mb=data.storage_mb,
        proxy_host=data.proxy_host,
        proxy_port=data.proxy_port,
        gpu_enabled=data.gpu_enabled,
        camera_enabled=data.camera_enabled,
        gps_enabled=data.gps_enabled,
        max_cpu_percent=data.max_cpu_percent,
        max_memory_mb=data.max_memory_mb,
        max_execution_time_seconds=data.max_execution_time_seconds,
        network_policy=data.network_policy,
    )

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,
        entity_type="emulator_profile",
        entity_id=profile.id,
        details={"name": profile.name, "avd_name": profile.avd_name, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(profile)

    return EmulatorProfileResponse.model_validate(profile)


@router.get(
    "/emulator-profiles",
    response_model=EmulatorProfileListResponse,
    summary="List emulator profiles",
)
def list_emulator_profiles(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> EmulatorProfileListResponse:
    """List emulator profiles."""
    service = EmulatorProfileService(db)
    profiles, total = service.list_profiles(page, page_size)

    return EmulatorProfileListResponse(
        items=[EmulatorProfileResponse.model_validate(p) for p in profiles],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/emulator-profiles/{profile_id}",
    response_model=EmulatorProfileResponse,
    summary="Get emulator profile",
)
def get_emulator_profile(
    project_id: UUID,
    profile_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> EmulatorProfileResponse:
    """Get emulator profile by ID."""
    service = EmulatorProfileService(db)
    profile = service.get_profile(profile_id)
    if not profile:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Emulator Profile", str(profile_id))

    return EmulatorProfileResponse.model_validate(profile)


@router.patch(
    "/emulator-profiles/{profile_id}",
    response_model=EmulatorProfileResponse,
    summary="Update emulator profile",
)
@strict_rate_limit()
def update_emulator_profile(
    project_id: UUID,
    profile_id: UUID,
    data: EmulatorProfileUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> EmulatorProfileResponse:
    """Update emulator profile."""
    service = EmulatorProfileService(db)
    update_data = data.model_dump(exclude_unset=True)
    profile = service.update_profile(profile_id, update_data)
    if not profile:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Emulator Profile", str(profile_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="emulator_profile",
        entity_id=profile.id,
        details={"updated_fields": list(update_data.keys())},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(profile)

    return EmulatorProfileResponse.model_validate(profile)


@router.delete(
    "/emulator-profiles/{profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete emulator profile",
)
@strict_rate_limit()
def delete_emulator_profile(
    project_id: UUID,
    profile_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete emulator profile."""
    service = EmulatorProfileService(db)
    if not service.delete_profile(profile_id):
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Emulator Profile", str(profile_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_DELETE.value,
        entity_type="emulator_profile",
        entity_id=profile_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()


# =============================================================================
# Emulator Instance Endpoints
# =============================================================================

@router.get(
    "/emulator-instances",
    response_model=EmulatorInstanceListResponse,
    summary="List emulator instances",
)
def list_emulator_instances(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    profile_id: UUID | None = None,
    status: str | None = None,
) -> EmulatorInstanceListResponse:
    """List emulator instances."""
    service = EmulatorInstanceService(db)
    instances, total = service.list_instances(profile_id, status, page, page_size)

    return EmulatorInstanceListResponse(
        items=[EmulatorInstanceResponse.model_validate(i) for i in instances],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/emulator-instances/{instance_id}",
    response_model=EmulatorInstanceResponse,
    summary="Get emulator instance",
)
def get_emulator_instance(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> EmulatorInstanceResponse:
    """Get emulator instance by ID."""
    service = EmulatorInstanceService(db)
    instance = service.get_instance(instance_id)
    if not instance:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Emulator Instance", str(instance_id))

    return EmulatorInstanceResponse.model_validate(instance)


@router.post(
    "/emulator-instances/{instance_id}/start",
    response_model=dict,
    summary="Start emulator instance",
)
@strict_rate_limit()
async def start_emulator_instance(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Start an emulator instance."""
    service = EmulatorInstanceService(db)
    success = await service.start_instance(instance_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_START.value,
        entity_type="emulator_instance",
        entity_id=instance_id,
        details={"action": "start"},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return {"success": success, "instance_id": str(instance_id)}


@router.post(
    "/emulator-instances/{instance_id}/stop",
    response_model=dict,
    summary="Stop emulator instance",
)
@strict_rate_limit()
async def stop_emulator_instance(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Stop an emulator instance."""
    service = EmulatorInstanceService(db)
    success = await service.stop_instance(instance_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_CANCEL.value,
        entity_type="emulator_instance",
        entity_id=instance_id,
        details={"action": "stop"},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return {"success": success, "instance_id": str(instance_id)}


@router.post(
    "/emulator-instances/{instance_id}/restart",
    response_model=dict,
    summary="Restart emulator instance",
)
@strict_rate_limit()
async def restart_emulator_instance(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Restart an emulator instance."""
    service = EmulatorInstanceService(db)
    success = await service.restart_instance(instance_id)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="emulator_instance",
        entity_id=instance_id,
        details={"action": "restart"},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return {"success": success, "instance_id": str(instance_id)}


@router.post(
    "/emulator-instances/{instance_id}/snapshot",
    response_model=dict,
    summary="Create emulator snapshot",
)
@strict_rate_limit()
async def snapshot_emulator_instance(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    snapshot_name: str = Form(...),
) -> dict:
    """Create a snapshot of the emulator."""
    service = EmulatorInstanceService(db)
    success = await service.snapshot_instance(instance_id, snapshot_name)

    return {"success": success, "instance_id": str(instance_id), "snapshot_name": snapshot_name}


@router.post(
    "/emulator-instances/{instance_id}/restore",
    response_model=dict,
    summary="Restore emulator snapshot",
)
@strict_rate_limit()
async def restore_emulator_snapshot(
    project_id: UUID,
    instance_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    snapshot_name: str = Form(...),
) -> dict:
    """Restore emulator to a snapshot."""
    service = EmulatorInstanceService(db)
    success = await service.restore_snapshot(instance_id, snapshot_name)

    return {"success": success, "instance_id": str(instance_id), "snapshot_name": snapshot_name}


# =============================================================================
# Dynamic Analysis Run Endpoints
# =============================================================================

@router.post(
    "/runs",
    response_model=DynamicAnalysisRunResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start dynamic analysis run",
)
@strict_rate_limit()
async def start_dynamic_analysis(
    project_id: UUID,
    data: DynamicAnalysisRunCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> DynamicAnalysisRunResponse:
    """Start a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    run = await service.start_analysis(
        scan_id=data.scan_id,
        scan_job_id=data.scan_job_id,
        profile_id=data.profile_id,
        apk_file_id=data.apk_file_id,
        test_context=data.test_context,
        network_policy=data.network_policy,
        frida_scripts=data.frida_scripts,
        resource_limits=data.resource_limits,
        current_user_id=current_user.id,
    )

    return DynamicAnalysisRunResponse.model_validate(run)


@router.get(
    "/runs",
    response_model=DynamicAnalysisRunListResponse,
    summary="List dynamic analysis runs",
)
def list_dynamic_analysis_runs(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    scan_id: UUID = Query(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
) -> DynamicAnalysisRunListResponse:
    """List dynamic analysis runs for a scan."""
    service = DynamicAnalysisService(db)
    runs, total = service.list_runs(scan_id, page, page_size, status)

    return DynamicAnalysisRunListResponse(
        items=[DynamicAnalysisRunResponse.model_validate(r) for r in runs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/runs/{run_id}",
    response_model=DynamicAnalysisRunDetailResponse,
    summary="Get dynamic analysis run",
)
def get_dynamic_analysis_run(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> DynamicAnalysisRunDetailResponse:
    """Get dynamic analysis run by ID with all observations."""
    service = DynamicAnalysisService(db)
    run = service.get_run_detail(run_id)
    if not run:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Dynamic Analysis Run", str(run_id))

    # Convert to detail response
    detail = DynamicAnalysisRunDetailResponse.model_validate(run)
    detail.runtime_events = [RuntimeEventResponse.model_validate(e) for e in run.runtime_events]
    detail.network_observations = [NetworkObservationResponse.model_validate(n) for n in run.network_observations]
    detail.file_observations = [FileObservationResponse.model_validate(f) for f in run.file_observations]
    detail.ipc_observations = [IpcObservationResponse.model_validate(i) for i in run.ipc_observations]

    return detail


@router.patch(
    "/runs/{run_id}",
    response_model=DynamicAnalysisRunResponse,
    summary="Update dynamic analysis run",
)
@strict_rate_limit()
def update_dynamic_analysis_run(
    project_id: UUID,
    run_id: UUID,
    data: DynamicAnalysisRunUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> DynamicAnalysisRunResponse:
    """Update dynamic analysis run."""
    service = DynamicAnalysisService(db)
    update_data = data.model_dump(exclude_unset=True)

    run = service.get_run(run_id)
    if not run:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Dynamic Analysis Run", str(run_id))

    for key, value in update_data.items():
        if hasattr(run, key) and key not in ("id", "scan_id", "created_at"):
            setattr(run, key, value)

    run.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(run)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_UPDATE.value,
        entity_type="dynamic_analysis_run",
        entity_id=run_id,
        details={"updated_fields": list(update_data.keys())},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(run)

    return DynamicAnalysisRunResponse.model_validate(run)


@router.post(
    "/runs/{run_id}/cancel",
    response_model=dict,
    summary="Cancel dynamic analysis run",
)
@strict_rate_limit()
def cancel_dynamic_analysis_run(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Cancel a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    run = service.update_run_status(run_id, "cancelled")
    if not run:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Dynamic Analysis Run", str(run_id))

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_CANCEL.value,
        entity_type="dynamic_analysis_run",
        entity_id=run_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return {"success": True, "run_id": str(run_id), "status": "cancelled"}


# =============================================================================
# Runtime Event Endpoints
# =============================================================================

@router.get(
    "/runs/{run_id}/events",
    response_model=RuntimeEventListResponse,
    summary="List runtime events",
)
def list_runtime_events(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: str | None = None,
) -> RuntimeEventListResponse:
    """List runtime events for a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    events, total = service.get_runtime_events(run_id, page, page_size, event_type)

    return RuntimeEventListResponse(
        items=[RuntimeEventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/runs/{run_id}/events/{event_id}",
    response_model=RuntimeEventResponse,
    summary="Get runtime event",
)
def get_runtime_event(
    project_id: UUID,
    run_id: UUID,
    event_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> RuntimeEventResponse:
    """Get runtime event by ID."""
    from app.models.dynamic import RuntimeEvent
    event = db.get(RuntimeEvent, event_id)
    if not event or event.analysis_run_id != run_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Runtime Event", str(event_id))

    return RuntimeEventResponse.model_validate(event)


# =============================================================================
# Network Observation Endpoints
# =============================================================================

@router.get(
    "/runs/{run_id}/network",
    response_model=NetworkObservationListResponse,
    summary="List network observations",
)
def list_network_observations(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    protocol: str | None = None,
) -> NetworkObservationListResponse:
    """List network observations for a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    observations, total = service.get_network_observations(run_id, page, page_size, protocol)

    return NetworkObservationListResponse(
        items=[NetworkObservationResponse.model_validate(o) for o in observations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/runs/{run_id}/network/{observation_id}",
    response_model=NetworkObservationResponse,
    summary="Get network observation",
)
def get_network_observation(
    project_id: UUID,
    run_id: UUID,
    observation_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> NetworkObservationResponse:
    """Get network observation by ID."""
    from app.models.dynamic import NetworkObservation
    obs = db.get(NetworkObservation, observation_id)
    if not obs or obs.analysis_run_id != run_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Network Observation", str(observation_id))

    return NetworkObservationResponse.model_validate(obs)


# =============================================================================
# File Observation Endpoints
# =============================================================================

@router.get(
    "/runs/{run_id}/files",
    response_model=FileObservationListResponse,
    summary="List file observations",
)
def list_file_observations(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    operation: str | None = None,
) -> FileObservationListResponse:
    """List file observations for a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    observations, total = service.get_file_observations(run_id, page, page_size, operation)

    return FileObservationListResponse(
        items=[FileObservationResponse.model_validate(o) for o in observations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/runs/{run_id}/files/{observation_id}",
    response_model=FileObservationResponse,
    summary="Get file observation",
)
def get_file_observation(
    project_id: UUID,
    run_id: UUID,
    observation_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> FileObservationResponse:
    """Get file observation by ID."""
    from app.models.dynamic import FileObservation
    obs = db.get(FileObservation, observation_id)
    if not obs or obs.analysis_run_id != run_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("File Observation", str(observation_id))

    return FileObservationResponse.model_validate(obs)


# =============================================================================
# IPC Observation Endpoints
# =============================================================================

@router.get(
    "/runs/{run_id}/ipc",
    response_model=IpcObservationListResponse,
    summary="List IPC observations",
)
def list_ipc_observations(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ipc_type: str | None = None,
) -> IpcObservationListResponse:
    """List IPC observations for a dynamic analysis run."""
    service = DynamicAnalysisService(db)
    observations, total = service.get_ipc_observations(run_id, page, page_size, ipc_type)

    return IpcObservationListResponse(
        items=[IpcObservationResponse.model_validate(o) for o in observations],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/runs/{run_id}/ipc/{observation_id}",
    response_model=IpcObservationResponse,
    summary="Get IPC observation",
)
def get_ipc_observation(
    project_id: UUID,
    run_id: UUID,
    observation_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> IpcObservationResponse:
    """Get IPC observation by ID."""
    from app.models.dynamic import IpcObservation
    obs = db.get(IpcObservation, observation_id)
    if not obs or obs.analysis_run_id != run_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("IPC Observation", str(observation_id))

    return IpcObservationResponse.model_validate(obs)


# =============================================================================
# Dynamic Analysis Evidence Endpoints
# =============================================================================

@router.get(
    "/runs/{run_id}/evidence",
    response_model=list[dict],
    summary="List dynamic analysis evidence",
)
def list_dynamic_evidence(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[dict]:
    """List evidence artifacts for a dynamic analysis run."""
    from app.models.dynamic import DynamicAnalysisEvidence
    from sqlalchemy import select

    stmt = select(DynamicAnalysisEvidence).where(
        DynamicAnalysisEvidence.analysis_run_id == run_id
    )
    evidence = list(db.scalars(stmt).all())

    return [
        {
            "id": str(e.id),
            "evidence_type": e.evidence_type,
            "storage": e.storage,
            "object_key": e.object_key,
            "sha256": e.sha256,
            "description": e.description,
            "tags": e.tags,
            "redacted": e.redacted,
            "redacted_at": e.redacted_at.isoformat() if e.redacted_at else None,
            "created_at": e.created_at.isoformat(),
            "updated_at": e.updated_at.isoformat(),
        }
        for e in evidence
    ]


# =============================================================================
# Summary Endpoint
# =============================================================================

@router.get(
    "/runs/{run_id}/summary",
    response_model=dict,
    summary="Get dynamic analysis run summary",
)
def get_dynamic_analysis_summary(
    project_id: UUID,
    run_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    """Get dynamic analysis run summary with statistics."""
    service = DynamicAnalysisService(db)
    summary = service.get_run_summary(run_id)
    if not summary:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Dynamic Analysis Run", str(run_id))

    return summary


# Import datetime for the update endpoint
from datetime import UTC, datetime