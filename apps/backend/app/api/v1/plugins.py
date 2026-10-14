"""Plugin API endpoints."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from app.auth.dependencies import get_current_user
from app.models.identity import User
from app.schemas.plugins import (
    PluginCategoryListResponse,
    PluginConfigSchema,
    PluginConfigUpdateRequest,
    PluginExecutionListResponse,
    PluginExecutionRequest,
    PluginExecutionResponse,
    PluginInstallResponse,
    PluginListResponse,
    PluginManifestSchemaResponse,
    PluginResponse,
    PluginUpdateRequest,
    PluginValidationResponse,
)
from app.services.plugins import PluginService

router = APIRouter(prefix="/plugins", tags=["plugins"])


def get_plugin_service() -> PluginService:
    """Get plugin service instance."""
    return PluginService()


# Plugin Management Endpoints

@router.get("", response_model=PluginListResponse)
async def list_plugins(
    category: str | None = None,
    enabled_only: bool = False,
    limit: int = 100,
    offset: int = 0,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginListResponse:
    """List installed plugins."""
    plugins, total = service.list_plugins(
        category=category,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )

    return PluginListResponse(
        plugins=[
            PluginResponse(
                id=p.id,
                name=p.name,
                version=p.version,
                description=p.description,
                author=p.author,
                license=p.license,
                homepage=p.homepage,
                repository=p.repository,
                category=p.category,
                tags=p.tags,
                min_core_version=p.min_core_version,
                max_core_version=p.max_core_version,
                python_version=p.python_version,
                capabilities=p.capabilities,
                permissions=p.permissions,
                resource_limits=p.resource_limits,
                config_schema=p.config_schema,
                entry_point=p.entry_point,
                dependencies=p.dependencies,
                checksum=p.checksum,
                enabled=p.enabled,
                installed_at=p.installed_at,
                last_executed_at=p.last_executed_at,
                default_config=p.default_config,
            )
            for p in plugins
        ],
        total=total,
    )


@router.post("", response_model=PluginInstallResponse, status_code=status.HTTP_201_CREATED)
async def install_plugin(
    manifest_json: str = Form(...),
    plugin_file: UploadFile = File(...),
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginInstallResponse:
    """
    Install a plugin from uploaded package.

    The plugin should be uploaded as a ZIP file containing:
    - manifest.json
    - Plugin code (Python modules)
    """
    import json
    import tempfile
    import zipfile
    from pathlib import Path

    from app.plugins.sdk.manifest import PluginManifest

    # Parse manifest
    try:
        manifest_data = json.loads(manifest_json)
        manifest = PluginManifest(**manifest_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid manifest: {e}",
        )

    # Save uploaded file to temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "plugin.zip"
        with open(zip_path, "wb") as f:
            content = await plugin_file.read()
            f.write(content)

        # Extract ZIP
        extract_dir = Path(tmpdir) / "plugin"
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid ZIP file: {e}",
            )

        # Find plugin directory (might be nested)
        plugin_dirs = list(extract_dir.iterdir())
        if len(plugin_dirs) == 1 and plugin_dirs[0].is_dir():
            package_path = plugin_dirs[0]
        else:
            package_path = extract_dir

        # Install plugin
        success, errors, plugin_record = service.install_plugin(
            manifest=manifest,
            package_path=package_path,
            uploaded_by=current_user.id,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors},
            )

        return PluginInstallResponse(
            success=True,
            plugin_id=str(plugin_record.id),
            errors=[],
        )


@router.get("/{plugin_id}", response_model=PluginResponse)
async def get_plugin(
    plugin_id: UUID,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginResponse:
    """Get plugin details."""
    plugin = service.get_plugin(plugin_id)
    if not plugin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin not found",
        )

    return PluginResponse(
        id=plugin.id,
        name=plugin.name,
        version=plugin.version,
        description=plugin.description,
        author=plugin.author,
        license=plugin.license,
        homepage=plugin.homepage,
        repository=plugin.repository,
        category=plugin.category,
        tags=plugin.tags,
        min_core_version=plugin.min_core_version,
        max_core_version=plugin.max_core_version,
        python_version=plugin.python_version,
        capabilities=plugin.capabilities,
        permissions=plugin.permissions,
        resource_limits=plugin.resource_limits,
        config_schema=plugin.config_schema,
        entry_point=plugin.entry_point,
        dependencies=plugin.dependencies,
        checksum=plugin.checksum,
        enabled=plugin.enabled,
        installed_at=plugin.installed_at,
        last_executed_at=plugin.last_executed_at,
        default_config=plugin.default_config,
    )


@router.patch("/{plugin_id}", response_model=PluginResponse)
async def update_plugin(
    plugin_id: UUID,
    request: PluginUpdateRequest,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginResponse:
    """Update plugin (enable/disable/config)."""
    plugin = service.get_plugin(plugin_id)
    if not plugin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin not found",
        )

    if request.enabled is not None:
        if request.enabled:
            success, errors = service.enable_plugin(plugin_id, current_user.id)
        else:
            success, errors = service.disable_plugin(plugin_id, current_user.id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors},
            )

    if request.default_config is not None:
        success, errors = service.update_plugin_config(plugin_id, request.default_config, current_user.id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors},
            )

    # Return updated plugin
    plugin = service.get_plugin(plugin_id)
    return PluginResponse(
        id=plugin.id,
        name=plugin.name,
        version=plugin.version,
        description=plugin.description,
        author=plugin.author,
        license=plugin.license,
        homepage=plugin.homepage,
        repository=plugin.repository,
        category=plugin.category,
        tags=plugin.tags,
        min_core_version=plugin.min_core_version,
        max_core_version=plugin.max_core_version,
        python_version=plugin.python_version,
        capabilities=plugin.capabilities,
        permissions=plugin.permissions,
        resource_limits=plugin.resource_limits,
        config_schema=plugin.config_schema,
        entry_point=plugin.entry_point,
        dependencies=plugin.dependencies,
        checksum=plugin.checksum,
        enabled=plugin.enabled,
        installed_at=plugin.installed_at,
        last_executed_at=plugin.last_executed_at,
        default_config=plugin.default_config,
    )


@router.delete("/{plugin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def uninstall_plugin(
    plugin_id: UUID,
    remove_data: bool = False,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> None:
    """Uninstall a plugin."""
    success, errors = service.uninstall_plugin(plugin_id, remove_data, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )


# Plugin Configuration Endpoints

@router.get("/{plugin_id}/config/{project_id}", response_model=PluginConfigSchema)
async def get_project_config(
    plugin_id: UUID,
    project_id: UUID,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginConfigSchema:
    """Get plugin configuration for a project."""
    config = service.get_project_config(plugin_id, project_id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plugin configuration not found",
        )

    return PluginConfigSchema(
        plugin_id=config.plugin_id,
        project_id=config.project_id,
        config=config.config,
        enabled=config.enabled,
        overridden_by=config.overridden_by,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


@router.put("/{plugin_id}/config/{project_id}", response_model=PluginConfigSchema)
async def set_project_config(
    plugin_id: UUID,
    project_id: UUID,
    request: PluginConfigUpdateRequest,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginConfigSchema:
    """Set plugin configuration for a project."""
    success, errors, config = service.set_project_config(
        plugin_id=plugin_id,
        project_id=project_id,
        config=request.config,
        enabled=request.enabled,
        overridden_by=current_user.id,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )

    return PluginConfigSchema(
        plugin_id=config.plugin_id,
        project_id=config.project_id,
        config=config.config,
        enabled=config.enabled,
        overridden_by=config.overridden_by,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


# Plugin Execution Endpoints

@router.post("/{plugin_id}/execute", response_model=PluginExecutionResponse)
async def execute_plugin(
    plugin_id: UUID,
    request: PluginExecutionRequest,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginExecutionResponse:
    """Execute a plugin manually."""
    from app.plugins.sdk.base import ScanContext

    # Validate scan context
    try:
        context = ScanContext(**request.scan_context)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan context: {e}",
        )

    success, errors, execution = service.execute_plugin(
        plugin_id=plugin_id,
        scan_context=request.scan_context,
        plugin_config=request.plugin_config,
        project_id=context.project_id,
        scan_id=context.scan_id,
        scan_job_id=context.scan_job_id,
        triggered_by=current_user.id,
        trigger_type="manual",
        mode=request.mode,
        timeout=request.timeout,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )

    return PluginExecutionResponse(
        id=execution.id,
        plugin_id=execution.plugin_id,
        project_id=execution.project_id,
        scan_id=execution.scan_id,
        scan_job_id=execution.scan_job_id,
        triggered_by=execution.triggered_by,
        trigger_type=execution.trigger_type,
        status=execution.status,
        started_at=execution.started_at,
        finished_at=execution.finished_at,
        result=execution.result,
        error=execution.error,
        warnings=execution.warnings,
        metrics=execution.metrics,
        cpu_time_ms=execution.cpu_time_ms,
        memory_peak_mb=execution.memory_peak_mb,
    )


@router.post("/{plugin_id}/validate", response_model=PluginValidationResponse)
async def validate_plugin(
    plugin_id: UUID,
    scan_context: dict[str, Any],
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginValidationResponse:
    """Validate plugin against a scan context."""
    valid, errors, warnings, required_permissions, estimated_resources = service.validate_plugin(
        plugin_id=plugin_id,
        scan_context=scan_context,
    )

    return PluginValidationResponse(
        valid=valid,
        errors=errors,
        warnings=warnings,
        required_permissions=required_permissions,
        estimated_resources=estimated_resources,
    )


@router.get("/{plugin_id}/executions", response_model=PluginExecutionListResponse)
async def get_execution_history(
    plugin_id: UUID,
    project_id: UUID | None = None,
    limit: int = 50,
    offset: int = 0,
    service: PluginService = Depends(get_plugin_service),
    current_user: User = Depends(get_current_user),
) -> PluginExecutionListResponse:
    """Get plugin execution history."""
    executions, total = service.get_execution_history(
        plugin_id=plugin_id,
        project_id=project_id,
        limit=limit,
        offset=offset,
    )

    return PluginExecutionListResponse(
        executions=[
            PluginExecutionResponse(
                id=e.id,
                plugin_id=e.plugin_id,
                project_id=e.project_id,
                scan_id=e.scan_id,
                scan_job_id=e.scan_job_id,
                triggered_by=e.triggered_by,
                trigger_type=e.trigger_type,
                status=e.status,
                started_at=e.started_at,
                finished_at=e.finished_at,
                result=e.result,
                error=e.error,
                warnings=e.warnings,
                metrics=e.metrics,
                cpu_time_ms=e.cpu_time_ms,
                memory_peak_mb=e.memory_peak_mb,
            )
            for e in executions
        ],
        total=total,
    )


# Utility Endpoints

@router.get("/categories/list", response_model=PluginCategoryListResponse)
async def list_categories(
    current_user: User = Depends(get_current_user),
) -> PluginCategoryListResponse:
    """List available plugin categories."""
    from app.plugins.sdk.manifest import PluginCategory
    return PluginCategoryListResponse(
        categories=[c.value for c in PluginCategory]
    )


@router.get("/manifest/schema", response_model=PluginManifestSchemaResponse)
async def get_manifest_schema(
    current_user: User = Depends(get_current_user),
) -> PluginManifestSchemaResponse:
    """Get plugin manifest JSON schema."""
    from app.plugins.sdk.manifest import PluginManifestSchema
    return PluginManifestSchemaResponse(
        schema=PluginManifestSchema.get_schema()
    )
