"""APK Analysis API router (v1)."""

from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.apk import ApkComponent, ApkFile
from app.models.assets import Asset
from app.models.enums import (
    AssetKind,
    SecurityEventType,
)
from app.models.identity import User
from app.schemas.apk import (
    ApkAnalysisRequest,
    ApkAnalysisResultResponse,
    ApkFileDetailResponse,
    ApkFileListResponse,
    ApkFileResponse,
    ApkUploadRequest,
    MastgCoverageResponse,
    MastgTestCaseResponse,
)
from app.services.apk_analysis import ApkAnalysisService
from app.services.mastg_methodology import seed_mastg_methodology

router = APIRouter(prefix="/projects/{project_id}/apk", tags=["apk-analysis"])


# =============================================================================
# APK File Upload and Management
# =============================================================================

@router.post(
    "/upload",
    response_model=ApkFileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload APK for analysis",
)
@strict_rate_limit()
async def upload_apk(
    project_id: UUID,
    file: UploadFile = File(...),
    current_user: Annotated[User, Depends(require_project_member)] = None,
    db: Annotated[Session, Depends(get_db)] = None,
    request: Request = None,
    asset_id: UUID | None = Form(None),
    scan_id: UUID | None = Form(None),
) -> ApkFileResponse:
    """Upload an APK file for static analysis."""
    import hashlib
    import tempfile

    # Validate file type
    if not file.filename or not file.filename.endswith(".apk"):
        from app.core.exceptions import ValidationError
        raise ValidationError("File must be an APK (.apk extension)")

    # Read file content and calculate hash
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()

    # Check for duplicate
    existing = db.query(ApkFile).filter(
        ApkFile.sha256 == sha256,
        ApkFile.deleted_at.is_(None),
    ).first()
    if existing:
        from app.core.exceptions import ConflictError
        raise ConflictError(f"APK with SHA256 {sha256} already exists")

    # Save to temporary location (in production, upload to MinIO)
    import os
    upload_dir = Path("/uploads")
    upload_dir.mkdir(exist_ok=True)
    file_path = upload_dir / f"{sha256}.apk"
    with open(file_path, "wb") as f:
        f.write(content)

    # Extract package name from APK (quick extraction)
    package_name = _extract_package_name(content)

    # Create or use existing asset
    if asset_id:
        asset = db.get(Asset, asset_id)
        if not asset or asset.project_id != project_id:
            from app.core.exceptions import NotFoundError
            raise NotFoundError("Asset", str(asset_id))
    else:
        # Create new asset for APK
        asset = Asset(
            project_id=project_id,
            target_id=None,  # Would be set if associated with a target
            kind=AssetKind.APK,
            value=package_name,
            attributes={"source": "upload", "filename": file.filename},
        )
        db.add(asset)
        db.flush()

    # Create APK file record
    service = ApkAnalysisService(db)
    apk_file = service.create_apk_file_record(
        project_id=project_id,
        asset_id=asset.id,
        package_name=package_name,
        version_name=None,  # Would be extracted from manifest
        version_code=None,
        sha256=sha256,
        object_key=str(file_path),
    )

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.TARGET_CREATE.value,
        entity_type="apk_file",
        entity_id=apk_file.id,
        details={
            "package_name": package_name,
            "sha256": sha256,
            "filename": file.filename,
            "project_id": str(project_id),
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(apk_file)

    return ApkFileResponse.model_validate(apk_file)


@router.get(
    "",
    response_model=ApkFileListResponse,
    summary="List APK files",
)
def list_apk_files(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> ApkFileListResponse:
    """List APK files in a project."""
    service = ApkAnalysisService(db)
    apk_files, total = service.list_apk_files(project_id, page, page_size)

    return ApkFileListResponse(
        items=[ApkFileResponse.model_validate(f) for f in apk_files],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get(
    "/{apk_file_id}",
    response_model=ApkFileDetailResponse,
    summary="Get APK file details",
)
def get_apk_file(
    project_id: UUID,
    apk_file_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ApkFileDetailResponse:
    """Get APK file by ID with components and analysis results."""
    service = ApkAnalysisService(db)
    apk_file = service.get_apk_file(apk_file_id)
    if not apk_file:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    # Verify project access via asset
    asset = db.get(Asset, apk_file.asset_id)
    if not asset or asset.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    # Load components
    components = service.get_apk_components(apk_file_id)

    # Load analysis results (observations/findings)
    from app.models.detection import Finding, Observation
    from sqlalchemy import select

    findings_stmt = select(Finding).where(Finding.promoted_from_observation_id.isnot(None)).join(Observation).where(
        Observation.asset_id == apk_file.asset_id,
        Finding.deleted_at.is_(None),
    )
    findings = list(db.scalars(findings_stmt).all())

    return ApkFileDetailResponse(
        **ApkFileResponse.model_validate(apk_file).model_dump(),
        components=[{"id": c.id, "component_type": c.component_type.value, "name": c.name, "exported": c.exported} for c in components],
        analysis_results=[{"id": f.id, "title": f.title, "severity": f.severity.value, "status": f.status.value} for f in findings],
    )


@router.post(
    "/{apk_file_id}/analyze",
    response_model=dict,
    summary="Run static analysis on APK",
)
@strict_rate_limit()
def analyze_apk(
    project_id: UUID,
    apk_file_id: UUID,
    data: ApkAnalysisRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Run static analysis on an uploaded APK."""
    service = ApkAnalysisService(db)

    # Verify APK belongs to project
    apk_file = service.get_apk_file(apk_file_id)
    if not apk_file:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    asset = db.get(Asset, apk_file.asset_id)
    if not asset or asset.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    # Run analysis
    result = service.analyze_apk(apk_file_id, data.analysis_types)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,
        entity_type="apk_analysis",
        entity_id=apk_file_id,
        details={
            "package_name": apk_file.package_name,
            "analyzers_run": result.get("analyzers_run", []),
            "findings_count": len(result.get("findings", [])),
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return result


@router.get(
    "/{apk_file_id}/components",
    response_model=list[dict],
    summary="Get APK components",
)
def get_apk_components(
    project_id: UUID,
    apk_file_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[dict]:
    """Get all manifest components for an APK."""
    service = ApkAnalysisService(db)
    apk_file = service.get_apk_file(apk_file_id)
    if not apk_file:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    asset = db.get(Asset, apk_file.asset_id)
    if not asset or asset.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    components = service.get_apk_components(apk_file_id)
    return [
        {
            "id": str(c.id),
            "component_type": c.component_type.value,
            "name": c.name,
            "exported": c.exported,
            "intent_filters": c.intent_filters,
        }
        for c in components
    ]


@router.get(
    "/{apk_file_id}/findings",
    response_model=list[ApkAnalysisResultResponse],
    summary="Get APK analysis findings",
)
def get_apk_findings(
    project_id: UUID,
    apk_file_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> list[ApkAnalysisResultResponse]:
    """Get analysis findings for an APK."""
    service = ApkAnalysisService(db)
    apk_file = service.get_apk_file(apk_file_id)
    if not apk_file:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    asset = db.get(Asset, apk_file.asset_id)
    if not asset or asset.project_id != project_id:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("APK File", str(apk_file_id))

    from app.models.detection import Finding, Observation
    from sqlalchemy import select

    findings_stmt = select(Finding).join(Observation).where(
        Observation.asset_id == apk_file.asset_id,
        Finding.deleted_at.is_(None),
    ).order_by(Finding.created_at.desc()).limit(page_size).offset((page - 1) * page_size)

    findings = list(db.scalars(findings_stmt).all())

    # Convert to response format
    results = []
    for f in findings:
        # Get evidence
        from app.models.detection import Evidence
        evidence_stmt = select(Evidence).where(Evidence.finding_id == f.id)
        evidence_list = list(db.scalars(evidence_stmt).all())

        obs = db.get(Observation, f.promoted_from_observation_id)
        results.append(ApkAnalysisResultResponse(
            id=f.id,
            apk_file_id=apk_file_id,
            component_id=None,
            analyzer_name=obs.payload.get("analyzer", "unknown") if obs else "unknown",
            finding_type="finding",
            title=f.title,
            description=f.recommendation,
            severity_hint=f.severity.value,
            confidence_hint=f.confidence.value,
            location=obs.payload.get("location") if obs else None,
            evidence=obs.payload.get("evidence", {}) if obs else {},
            mastg_references=obs.payload.get("mastg_references", []) if obs else [],
            masvs_references=obs.payload.get("masvs_references", []) if obs else [],
            created_at=f.created_at,
            updated_at=f.updated_at,
        ))

    return results


# =============================================================================
# MASTG/MASVS Methodology Endpoints
# =============================================================================

@router.get(
    "/methodology/test-cases",
    response_model=list[MastgTestCaseResponse],
    summary="Get MASTG test cases",
)
def get_mastg_test_cases(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    category: str | None = None,
) -> list[MastgTestCaseResponse]:
    """Get MASTG test cases, optionally filtered by category."""
    service = ApkAnalysisService(db)
    test_cases = service.get_mastg_test_cases(category)

    return [
        MastgTestCaseResponse(
            id=tc.id,
            methodology_version_id=tc.methodology_version_id,
            identifier=tc.identifier,
            name=tc.name,
            description=tc.description,
            category=tc.category,
            order=tc.order,
            supported_target_types=tc.supported_target_types,
            prerequisites=tc.prerequisites,
            passive_mode=tc.passive_mode,
            active_mode=tc.active_mode,
            safe_mode_compatible=tc.safe_mode_compatible,
            evidence_requirements=tc.evidence_requirements,
            detection_rules=tc.detection_rules,
            references=tc.references,
        )
        for tc in test_cases
    ]


@router.get(
    "/methodology/coverage",
    response_model=MastgCoverageResponse,
    summary="Get MASTG coverage for project",
)
def get_mastg_coverage(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> MastgCoverageResponse:
    """Get MASTG coverage statistics for a project."""
    service = ApkAnalysisService(db)
    coverage = service.get_mastg_coverage(project_id)

    return MastgCoverageResponse(**coverage)


@router.post(
    "/methodology/seed",
    response_model=dict,
    summary="Seed MASTG methodology",
)
def seed_mastg(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> dict:
    """Seed the MASTG methodology into the database."""
    seed_mastg_methodology(db)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.SCAN_COMPLETE.value,
        entity_type="methodology",
        entity_id=None,
        details={"methodology": "OWASP MASTG / MASVS", "action": "seed"},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return {"status": "seeded", "methodology": "OWASP MASTG / MASVS"}


# Need to add MastgTestCaseResponse and MastgCoverageResponse to schemas
# These will be added in a patch

from pathlib import Path


def _extract_package_name(apk_content: bytes) -> str:
    """Quickly extract package name from APK without full extraction."""
    import zipfile
    import io
    import xml.etree.ElementTree as ET

    try:
        with zipfile.ZipFile(io.BytesIO(apk_content), "r") as zip_ref:
            # Try to find AndroidManifest.xml
            for name in zip_ref.namelist():
                if name.endswith("AndroidManifest.xml"):
                    with zip_ref.open(name) as manifest_file:
                        manifest_content = manifest_file.read()
                        # Parse binary XML or try as text
                        try:
                            root = ET.fromstring(manifest_content)
                            package = root.get("package")
                            if package:
                                return package
                        except ET.ParseError:
                            # Binary XML - would need axmlparser
                            pass
    except Exception:
        pass

    return "unknown.package"