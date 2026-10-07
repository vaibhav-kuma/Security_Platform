"""API Security Assessment API router (v1)."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_project_member
from app.core.rate_limit import strict_rate_limit
from app.db.session import get_db
from app.models.api_assets import (
    ApiAuthScheme,
    ApiAuthzContext,
    ApiDefinition,
    ApiEndpoint,
    ApiRateLimitProfile,
    ApiSchema,
)
from app.models.audit import AuditLog
from app.models.enums import SecurityEventType
from app.models.identity import User
from app.models.methodology import MethodologyVersion, TestCase
from app.schemas.api_security import (
    ApiAuthSchemeResponse,
    ApiAuthzContextResponse,
    ApiDefinitionCreate,
    ApiDefinitionResponse,
    ApiDefinitionUpdate,
    ApiEndpointResponse,
    ApiRateLimitProfileResponse,
    ApiSchemaResponse,
    APISecurityObservationResponse,
    APISecurityScanRequest,
    APISecurityScanResponse,
    MethodologyCoverageResponse,
    OpenAPIImportRequest,
    OpenAPIImportResponse,
)
from app.services.methodology import CoverageEngine, TestPlanner
from app.services.openapi_importer import import_openapi_spec
from app.services.owasp_api_methodology import seed_owasp_api_security_methodology

router = APIRouter(prefix="/projects/{project_id}/api-security", tags=["api-security"])


# ============ API Definition Management ============

@router.post(
    "/definitions",
    response_model=ApiDefinitionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API definition",
)
@strict_rate_limit()
def create_api_definition(
    project_id: UUID,
    data: ApiDefinitionCreate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ApiDefinitionResponse:
    """Create a new API definition manually."""
    api_def = ApiDefinition(
        asset_id=data.asset_id,
        name=data.name,
        base_url=data.base_url,
        spec_format=data.spec_format,
        spec_version=data.spec_version,
        spec=data.spec,
    )
    db.add(api_def)
    db.commit()
    db.refresh(api_def)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.OTHER.value,
        entity_type="api_definition",
        entity_id=api_def.id,
        details={"name": api_def.name, "project_id": str(project_id)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    return ApiDefinitionResponse.model_validate(api_def)


@router.post(
    "/definitions/import",
    response_model=OpenAPIImportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Import OpenAPI/Swagger specification",
)
@strict_rate_limit()
def import_openapi(
    project_id: UUID,
    data: OpenAPIImportRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> OpenAPIImportResponse:
    """Import an OpenAPI 3.x or Swagger 2.0 specification."""
    if not data.asset_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="asset_id is required for OpenAPI import",
        )

    api_def = import_openapi_spec(db, data.spec, data.asset_id, data.name)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.OTHER.value,
        entity_type="api_definition",
        entity_id=api_def.id,
        details={
            "name": api_def.name,
            "project_id": str(project_id),
            "imported_from": "openapi_spec",
        },
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()

    # Count created objects
    endpoints_count = db.query(ApiEndpoint).filter(
        ApiEndpoint.api_definition_id == api_def.id
    ).count()
    schemas_count = db.query(ApiSchema).filter(
        ApiSchema.api_definition_id == api_def.id
    ).count()
    auth_schemes_count = db.query(ApiAuthScheme).filter(
        ApiAuthScheme.api_definition_id == api_def.id
    ).count()
    authz_contexts_count = db.query(ApiAuthzContext).filter(
        ApiAuthzContext.api_definition_id == api_def.id
    ).count()

    return OpenAPIImportResponse(
        api_definition=ApiDefinitionResponse.model_validate(api_def),
        endpoints_count=endpoints_count,
        schemas_count=schemas_count,
        auth_schemes_count=auth_schemes_count,
        authz_contexts_count=authz_contexts_count,
    )


@router.get(
    "/definitions",
    response_model=list[ApiDefinitionResponse],
    summary="List API definitions",
)
def list_api_definitions(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    asset_id: UUID | None = None,
) -> list[ApiDefinitionResponse]:
    """List API definitions for a project."""
    stmt = select(ApiDefinition)
    if asset_id:
        stmt = stmt.where(ApiDefinition.asset_id == asset_id)
    stmt = stmt.order_by(ApiDefinition.created_at.desc())
    api_defs = db.scalars(stmt).all()
    return [ApiDefinitionResponse.model_validate(d) for d in api_defs]


@router.get(
    "/definitions/{definition_id}",
    response_model=ApiDefinitionResponse,
    summary="Get API definition",
)
def get_api_definition(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> ApiDefinitionResponse:
    """Get API definition by ID."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")
    return ApiDefinitionResponse.model_validate(api_def)


@router.patch(
    "/definitions/{definition_id}",
    response_model=ApiDefinitionResponse,
    summary="Update API definition",
)
def update_api_definition(
    project_id: UUID,
    definition_id: UUID,
    data: ApiDefinitionUpdate,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> ApiDefinitionResponse:
    """Update API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    if data.name is not None:
        api_def.name = data.name
    if data.base_url is not None:
        api_def.base_url = data.base_url
    if data.spec is not None:
        api_def.spec = data.spec

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.OTHER.value,
        entity_type="api_definition",
        entity_id=definition_id,
        details={"updated_fields": data.model_dump(exclude_unset=True)},
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()
    db.refresh(api_def)

    return ApiDefinitionResponse.model_validate(api_def)


@router.delete(
    "/definitions/{definition_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete API definition",
)
def delete_api_definition(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> None:
    """Soft delete API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    from app.repositories.base import SoftDeleteRepository
    repo = SoftDeleteRepository(db, ApiDefinition)
    repo.soft_delete(api_def)

    # Audit log
    audit = AuditLog(
        actor_id=current_user.id,
        action=SecurityEventType.OTHER.value,
        entity_type="api_definition",
        entity_id=definition_id,
        source_ip=request.client.host if request.client else None,
    )
    db.add(audit)
    db.commit()


# ============ API Definition Details ============

@router.get(
    "/definitions/{definition_id}/endpoints",
    response_model=list[ApiEndpointResponse],
    summary="List API endpoints",
)
def list_api_endpoints(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiEndpointResponse]:
    """List endpoints for an API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    endpoints = db.query(ApiEndpoint).filter(
        ApiEndpoint.api_definition_id == definition_id
    ).all()
    return [ApiEndpointResponse.model_validate(e) for e in endpoints]


@router.get(
    "/definitions/{definition_id}/schemas",
    response_model=list[ApiSchemaResponse],
    summary="List API schemas",
)
def list_api_schemas(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiSchemaResponse]:
    """List schemas for an API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    schemas = db.query(ApiSchema).filter(
        ApiSchema.api_definition_id == definition_id
    ).all()
    return [ApiSchemaResponse.model_validate(s) for s in schemas]


@router.get(
    "/definitions/{definition_id}/auth-schemes",
    response_model=list[ApiAuthSchemeResponse],
    summary="List API authentication schemes",
)
def list_api_auth_schemes(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiAuthSchemeResponse]:
    """List authentication schemes for an API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    auth_schemes = db.query(ApiAuthScheme).filter(
        ApiAuthScheme.api_definition_id == definition_id
    ).all()
    return [ApiAuthSchemeResponse.model_validate(a) for a in auth_schemes]


@router.get(
    "/definitions/{definition_id}/authz-contexts",
    response_model=list[ApiAuthzContextResponse],
    summary="List API authorization contexts",
)
def list_api_authz_contexts(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiAuthzContextResponse]:
    """List authorization contexts for an API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    authz_contexts = db.query(ApiAuthzContext).filter(
        ApiAuthzContext.api_definition_id == definition_id
    ).all()
    return [ApiAuthzContextResponse.model_validate(a) for a in authz_contexts]


@router.get(
    "/definitions/{definition_id}/rate-limit-profiles",
    response_model=list[ApiRateLimitProfileResponse],
    summary="List API rate limit profiles",
)
def list_api_rate_limit_profiles(
    project_id: UUID,
    definition_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> list[ApiRateLimitProfileResponse]:
    """List rate limit profiles for an API definition."""
    api_def = db.get(ApiDefinition, definition_id)
    if not api_def:
        raise HTTPException(status_code=404, detail="API definition not found")

    profiles = db.query(ApiRateLimitProfile).filter(
        ApiRateLimitProfile.api_definition_id == definition_id
    ).all()
    return [ApiRateLimitProfileResponse.model_validate(p) for p in profiles]


# ============ API Security Scanning ============

@router.post(
    "/scan",
    response_model=APISecurityScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start API security scan",
)
@strict_rate_limit()
def start_api_security_scan(
    project_id: UUID,
    data: APISecurityScanRequest,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    request: Request,
) -> APISecurityScanResponse:
    """Start an API security scan using the API Security Scanner plugin."""
    # This would integrate with the scan execution system
    # For now, return a placeholder response
    return APISecurityScanResponse(
        scan_id=UUID(int=0),  # Placeholder
        status="pending",
        message="API security scan queued. Use the scans API to track progress.",
    )


@router.get(
    "/scan/{scan_id}/observations",
    response_model=list[APISecurityObservationResponse],
    summary="Get API security scan observations",
)
def get_api_security_observations(
    project_id: UUID,
    scan_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    category: str | None = None,
) -> list[APISecurityObservationResponse]:
    """Get observations from an API security scan."""
    # This would query observations from the scan
    # For now, return empty list
    return []


# ============ Methodology Coverage ============

@router.post(
    "/methodology/seed",
    response_model=dict,
    summary="Seed OWASP API Security methodology",
)
def seed_methodology(
    project_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Seed the OWASP API Security Top 10 2023 methodology and detection rules."""
    methodology = seed_owasp_api_security_methodology(db)

    # Also seed detection rules
    from app.services.api_security_detection_rules import seed_api_security_detection_rules
    rules = seed_api_security_detection_rules(db)

    return {
        "methodology": methodology.name,
        "version": 2023,
        "test_cases_created": db.query(func.count(TestCase.id)).filter(
            TestCase.methodology_version_id.in_(
                db.query(MethodologyVersion.id).filter(
                    MethodologyVersion.methodology_id == methodology.id
                )
            )
        ).scalar() or 0,
        "detection_rules_created": len(rules),
    }


@router.get(
    "/methodology/coverage/{methodology_version_id}",
    response_model=MethodologyCoverageResponse,
    summary="Get methodology coverage for API definition",
)
def get_methodology_coverage(
    project_id: UUID,
    methodology_version_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    scan_id: UUID | None = None,
) -> MethodologyCoverageResponse:
    """Get methodology coverage for an API definition."""
    engine = CoverageEngine(db)
    coverage = engine.calculate_coverage(project_id, methodology_version_id, scan_id)

    return MethodologyCoverageResponse(
        methodology_version_id=methodology_version_id,
        total_tests=coverage["total"],
        passed_tests=coverage["tested"],
        failed_tests=coverage["needs_review"],
        skipped_tests=coverage["not_applicable"],
        coverage_percentage=coverage["coverage_percentage"],
        by_category=coverage["by_category"],
    )


@router.post(
    "/methodology/plan/{methodology_version_id}",
    response_model=dict,
    summary="Plan test cases for API definition",
)
def plan_test_cases(
    project_id: UUID,
    methodology_version_id: UUID,
    current_user: Annotated[User, Depends(require_project_member)],
    db: Annotated[Session, Depends(get_db)],
    target_type: str = "api",
    discovered_technologies: list[str] | None = None,
    has_authenticated_access: bool = False,
    has_api_schema: bool = True,
    has_web_application: bool = False,
    testing_profile: str = "default",
) -> dict[str, Any]:
    """Plan applicable test cases for an API definition."""
    planner = TestPlanner(db)
    test_cases = planner.select_test_cases(
        methodology_version_id=methodology_version_id,
        target_type=target_type,
        discovered_technologies=discovered_technologies,
        has_authenticated_access=has_authenticated_access,
        has_api_schema=has_api_schema,
        has_web_application=has_web_application,
        testing_profile=testing_profile,
    )

    return {
        "methodology_version_id": str(methodology_version_id),
        "test_cases": [
            {
                "id": str(tc.id),
                "identifier": tc.identifier,
                "name": tc.name,
                "category": tc.category,
                "order": tc.order,
                "passive_mode": tc.passive_mode,
                "active_mode": tc.active_mode,
                "safe_mode_compatible": tc.safe_mode_compatible,
            }
            for tc in test_cases
        ],
        "total": len(test_cases),
    }
