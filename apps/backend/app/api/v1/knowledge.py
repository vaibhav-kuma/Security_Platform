"""Knowledge Base API endpoints."""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.session import get_db
from app.models.identity import User
from app.models.knowledge import KnowledgePack, PackContent, PackVersion, PackDependency, PackInstallation, KnowledgePackStatus
from app.schemas.knowledge import (
    KnowledgePackResponse,
    KnowledgePackListResponse,
    PackContentResponse,
    PackContentListResponse,
    PackVersionResponse,
    PackDependencyResponse,
    PackInstallationResponse,
    PackInstallRequest,
    PackInstallResponse,
    PackUpdateRequest,
    PackRollbackRequest,
    PackRollbackResponse,
    KnowledgeRegistryResponse,
    PackValidationResponse,
    PackUpdateCheckResponse,
    PackAuditLogEntry,
    PackAuditLogResponse,
    KnowledgePackTypeEnum,
    KnowledgePackStatusEnum,
)
from app.services.knowledge import KnowledgePackService

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


def get_knowledge_service() -> KnowledgePackService:
    """Get knowledge pack service instance."""
    return KnowledgePackService()


# Knowledge Pack Management Endpoints

@router.get("/packs", response_model=KnowledgePackListResponse)
async def list_packs(
    pack_type: str | None = None,
    status: str | None = None,
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> KnowledgePackListResponse:
    """List installed knowledge packs."""
    packs, total = service.list_packs(
        pack_type=pack_type,
        status=status,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )

    return KnowledgePackListResponse(
        packs=[
            KnowledgePackResponse(
                id=p.id,
                name=p.name,
                version=p.version,
                pack_type=p.pack_type,
                description=p.description,
                author=p.author,
                license=p.license,
                homepage=p.homepage,
                repository=p.repository,
                min_core_version=p.min_core_version,
                max_core_version=p.max_core_version,
                schema_version=p.schema_version,
                checksum=p.checksum,
                signature=p.signature,
                status=p.status,
                is_official=p.is_official,
                installed_by=p.installed_by,
                installed_at=p.installed_at,
                activated_at=p.activated_at,
                deprecated_at=p.deprecated_at,
                tags=p.tags,
                metadata=p.metadata,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in packs
        ],
        total=total,
    )


@router.post("/packs", response_model=PackInstallResponse, status_code=status.HTTP_201_CREATED)
async def install_pack(
    manifest_json: str = Form(...),
    pack_file: UploadFile = File(...),
    force: bool = Form(False),
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackInstallResponse:
    """
    Install a knowledge pack from uploaded ZIP file.

    The pack should be a ZIP containing:
    - manifest.json
    - content/*.json (content files)
    - versions.json (optional, version history)
    - dependencies.json (optional, pack dependencies)
    - signature.asc (optional, GPG signature)
    """
    import json

    # Parse manifest
    try:
        manifest = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid manifest JSON: {e}",
        )

    # Read uploaded file
    pack_data = await pack_file.read()

    # Install pack
    success, errors, warnings, pack = service.install_pack(
        pack_data=pack_data,
        source="upload",
        installed_by=current_user.id,
        force=force,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors, "warnings": warnings},
        )

    return PackInstallResponse(
        success=True,
        pack_id=pack.id,
        installation_id=None,  # Would need to query
        errors=[],
        warnings=warnings,
    )


@router.get("/packs/{pack_id}", response_model=KnowledgePackResponse)
async def get_pack(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> KnowledgePackResponse:
    """Get knowledge pack details."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    return KnowledgePackResponse(
        id=pack.id,
        name=pack.name,
        version=pack.version,
        pack_type=pack.pack_type,
        description=pack.description,
        author=pack.author,
        license=pack.license,
        homepage=pack.homepage,
        repository=pack.repository,
        min_core_version=pack.min_core_version,
        max_core_version=pack.max_core_version,
        schema_version=pack.schema_version,
        checksum=pack.checksum,
        signature=pack.signature,
        status=pack.status,
        is_official=pack.is_official,
        installed_by=pack.installed_by,
        installed_at=pack.installed_at,
        activated_at=pack.activated_at,
        deprecated_at=pack.deprecated_at,
        tags=pack.tags,
        metadata=pack.metadata,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
    )


@router.patch("/packs/{pack_id}", response_model=KnowledgePackResponse)
async def update_pack_status(
    pack_id: UUID,
    request: PackUpdateRequest,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> KnowledgePackResponse:
    """Activate, deactivate, or deprecate a knowledge pack."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    if request.activate is not None:
        if request.activate:
            success, errors = service.activate_pack(pack_id, current_user.id)
        else:
            success, errors = service.deactivate_pack(pack_id, current_user.id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors},
            )

    if request.deprecate:
        success, errors = service.deprecate_pack(pack_id, current_user.id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors},
            )

    # Return updated pack
    pack = service.get_pack(pack_id)
    return KnowledgePackResponse(
        id=pack.id,
        name=pack.name,
        version=pack.version,
        pack_type=pack.pack_type,
        description=pack.description,
        author=pack.author,
        license=pack.license,
        homepage=pack.homepage,
        repository=pack.repository,
        min_core_version=pack.min_core_version,
        max_core_version=pack.max_core_version,
        schema_version=pack.schema_version,
        checksum=pack.checksum,
        signature=pack.signature,
        status=pack.status,
        is_official=pack.is_official,
        installed_by=pack.installed_by,
        installed_at=pack.installed_at,
        activated_at=pack.activated_at,
        deprecated_at=pack.deprecated_at,
        tags=pack.tags,
        metadata=pack.metadata,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
    )


@router.post("/packs/{pack_id}/rollback", response_model=PackRollbackResponse)
async def rollback_pack(
    pack_id: UUID,
    request: PackRollbackRequest,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackRollbackResponse:
    """Rollback a knowledge pack to a previous version."""
    success, errors, rolled_back_pack = service.rollback_pack(
        pack_id=pack_id,
        target_version=request.target_version,
        rolled_back_by=current_user.id,
        reason=request.reason,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )

    return PackRollbackResponse(
        success=True,
        pack_id=rolled_back_pack.id,
        rolled_back_to_version=rolled_back_pack.version,
        rollback_installation_id=rolled_back_pack.id,  # Would need proper installation ID
        errors=[],
    )


@router.delete("/packs/{pack_id}", status_code=status.HTTP_204_NO_CONTENT)
async def uninstall_pack(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> None:
    """Uninstall a knowledge pack."""
    success, errors = service.uninstall_pack(pack_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )


# Pack Content Endpoints

@router.get("/packs/{pack_id}/content", response_model=PackContentListResponse)
async def get_pack_content(
    pack_id: UUID,
    content_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackContentListResponse:
    """Get knowledge pack content."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    contents, total = service.get_pack_content(
        pack_id=pack_id,
        content_id=content_id,
        limit=limit,
        offset=offset,
    )

    return PackContentListResponse(
        contents=[
            PackContentResponse(
                id=c.id,
                pack_id=c.pack_id,
                content_id=c.content_id,
                content_version=c.content_version,
                name=c.name,
                methodology=c.methodology,
                category=c.category,
                subcategory=c.subcategory,
                target_types=c.target_types,
                platforms=c.platforms,
                technologies=c.technologies,
                prerequisites=c.prerequisites,
                evidence_requirements=c.evidence_requirements,
                severity_guidance=c.severity_guidance,
                confidence_guidance=c.confidence_guidance,
                references=c.references,
                cwe_ids=c.cwe_ids,
                capec_ids=c.capec_ids,
                detection_behavior=c.detection_behavior,
                remediation_guidance=c.remediation_guidance,
                remediation_complexity=c.remediation_complexity,
                remediation_references=c.remediation_references,
                description=c.description,
                long_description=c.long_description,
                examples=c.examples,
                tags=c.tags,
                metadata=c.metadata,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in contents
        ],
        total=total,
    )


@router.get("/packs/{pack_id}/content/{content_id}", response_model=PackContentResponse)
async def get_content_item(
    pack_id: UUID,
    content_id: str,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackContentResponse:
    """Get a specific content item from a pack."""
    contents, _ = service.get_pack_content(pack_id=pack_id, content_id=content_id, limit=1)
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Content not found",
        )

    c = contents[0]
    return PackContentResponse(
        id=c.id,
        pack_id=c.pack_id,
        content_id=c.content_id,
        content_version=c.content_version,
        name=c.name,
        methodology=c.methodology,
        category=c.category,
        subcategory=c.subcategory,
        target_types=c.target_types,
        platforms=c.platforms,
        technologies=c.technologies,
        prerequisites=c.prerequisites,
        evidence_requirements=c.evidence_requirements,
        severity_guidance=c.severity_guidance,
        confidence_guidance=c.confidence_guidance,
        references=c.references,
        cwe_ids=c.cwe_ids,
        capec_ids=c.capec_ids,
        detection_behavior=c.detection_behavior,
        remediation_guidance=c.remediation_guidance,
        remediation_complexity=c.remediation_complexity,
        remediation_references=c.remediation_references,
        description=c.description,
        long_description=c.long_description,
        examples=c.examples,
        tags=c.tags,
        metadata=c.metadata,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


# Pack Version Endpoints

@router.get("/packs/{pack_id}/versions", response_model=list[PackVersionResponse])
async def get_pack_versions(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> list[PackVersionResponse]:
    """Get pack version history."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    versions = service.get_pack_versions(pack_id)
    return [
        PackVersionResponse(
            id=v.id,
            pack_id=v.pack_id,
            version=v.version,
            changelog=v.changelog,
            compatibility_notes=v.compatibility_notes,
            breaking_changes=v.breaking_changes,
            deprecated_content=v.deprecated_content,
            new_content=v.new_content,
            updated_content=v.updated_content,
            released_at=v.released_at,
            released_by=v.released_by,
            created_at=v.created_at,
        )
        for v in versions
    ]


# Pack Dependencies Endpoints

@router.get("/packs/{pack_id}/dependencies", response_model=list[PackDependencyResponse])
async def get_pack_dependencies(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> list[PackDependencyResponse]:
    """Get pack dependencies."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    dependencies = service.get_pack_dependencies(pack_id)
    return [
        PackDependencyResponse(
            id=d.id,
            pack_id=d.pack_id,
            depends_on_id=d.depends_on_id,
            dependency_type=d.dependency_type,
            min_version=d.min_version,
            max_version=d.max_version,
            reason=d.reason,
            created_at=d.created_at,
        )
        for d in dependencies
    ]


# Pack Installation History Endpoints

@router.get("/packs/{pack_id}/installations", response_model=list[PackInstallationResponse])
async def get_pack_installations(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> list[PackInstallationResponse]:
    """Get pack installation history."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    installations = service.get_pack_installations(pack_id)
    return [
        PackInstallationResponse(
            id=i.id,
            pack_id=i.pack_id,
            installed_by=i.installed_by,
            installed_at=i.installed_at,
            source=i.source,
            source_url=i.source_url,
            previous_version=i.previous_version,
            status=i.status,
            error=i.error,
            rollback_at=i.rollback_at,
            rolled_back_by=i.rolled_back_by,
        )
        for i in installations
    ]


# Registry Endpoints

@router.get("/registry", response_model=KnowledgeRegistryResponse)
async def list_registry_packs(
    pack_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
) -> KnowledgeRegistryResponse:
    """List available packs from registry."""
    # In production, this would query a remote registry
    # Placeholder implementation
    return KnowledgeRegistryResponse(packs=[], total=0)


@router.post("/packs/check-updates", response_model=list[PackUpdateCheckResponse])
async def check_pack_updates(
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> list[PackUpdateCheckResponse]:
    """Check all installed packs for updates."""
    from app.knowledge.tasks import check_all_updates
    result = check_all_updates.delay()
    # In production, would return task ID and poll for results
    # For now, run synchronously
    result = check_all_updates()
    return result.get("results", [])


@router.post("/packs/{pack_id}/check-update", response_model=PackUpdateCheckResponse)
async def check_pack_update(
    pack_id: UUID,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackUpdateCheckResponse:
    """Check a specific pack for updates."""
    update_info = service.check_updates(pack_id)
    if "error" in update_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=update_info["error"],
        )
    return PackUpdateCheckResponse(**update_info)


# Audit Log Endpoints

@router.get("/packs/{pack_id}/audit", response_model=PackAuditLogResponse)
async def get_pack_audit_log(
    pack_id: UUID,
    limit: int = 100,
    service: KnowledgePackService = Depends(get_knowledge_service),
    current_user: User = Depends(get_current_user),
) -> PackAuditLogResponse:
    """Get audit log for a knowledge pack."""
    pack = service.get_pack(pack_id)
    if not pack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pack not found",
        )

    entries = service.get_pack_audit_log(pack_id, limit)
    return PackAuditLogResponse(
        entries=[
            PackAuditLogEntry(**e) for e in entries
        ],
        total=len(entries),
    )


# Utility Endpoints

@router.get("/types", response_model=list[str])
async def list_pack_types(
    current_user: User = Depends(get_current_user),
) -> list[str]:
    """List available knowledge pack types."""
    return [t.value for t in KnowledgePackTypeEnum]


@router.get("/statuses", response_model=list[str])
async def list_pack_statuses(
    current_user: User = Depends(get_current_user),
) -> list[str]:
    """List available knowledge pack statuses."""
    return [s.value for s in KnowledgePackStatusEnum]