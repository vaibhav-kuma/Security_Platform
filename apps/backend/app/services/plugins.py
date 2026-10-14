"""Plugin lifecycle management service."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.db.session import get_engine, make_session_factory
from app.models.plugins import Plugin, PluginExecution, PluginProjectConfig
from app.plugins.permissions import get_permission_evaluator
from app.plugins.sdk.loader import PluginLoader
from app.plugins.sdk.manifest import PluginManifest
from app.plugins.sdk.registry import PluginRegistry, get_plugin_registry


def get_db_session() -> Session:
    """Get a new database session."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


class PluginService:
    """Service for managing plugin lifecycle."""

    def __init__(self, registry: PluginRegistry | None = None):
        """Initialize service with registry."""
        self.registry = registry or get_plugin_registry()
        self.loader = PluginLoader(self.registry)
        self.permission_evaluator = get_permission_evaluator()

    def install_plugin(
        self,
        manifest: PluginManifest,
        package_path: Path,
        uploaded_by: UUID | None = None,
    ) -> tuple[bool, list[str], Plugin | None]:
        """
        Install a plugin from package.

        Args:
            manifest: Plugin manifest
            package_path: Path to plugin package directory
            uploaded_by: User ID who uploaded the plugin

        Returns:
            Tuple of (success, errors, plugin_record)
        """
        db = get_db_session()
        try:
            # Check if plugin already exists
            existing = db.scalar(
                select(Plugin).where(Plugin.name == manifest.name)
            )
            if existing:
                return False, [f"Plugin {manifest.name} already installed"], None

            # Install via loader (copies files, validates)
            success, errors = self.loader.install_plugin(package_path)
            if not success:
                return False, errors, None

            # Create database record
            plugin_record = Plugin(
                name=manifest.name,
                version=manifest.version,
                description=manifest.description,
                author=manifest.author,
                license=manifest.license,
                homepage=manifest.homepage,
                repository=manifest.repository,
                category=manifest.category.value,
                tags=manifest.tags,
                min_core_version=manifest.min_core_version,
                max_core_version=manifest.max_core_version,
                python_version=manifest.python_version,
                capabilities=manifest.capabilities,
                permissions=[p.value for p in manifest.permissions],
                resource_limits=manifest.resource_limits.model_dump(),
                config_schema=manifest.config_schema,
                entry_point=manifest.entry_point,
                dependencies=manifest.dependencies,
                checksum=manifest.checksum,
                plugin_path=str(self.registry.plugins_dir / manifest.name),
                default_config={},
                installed_at=datetime.now(UTC),
            )

            db.add(plugin_record)
            db.commit()
            db.refresh(plugin_record)

            # Log audit event
            self._audit_plugin_event(
                "plugin.installed",
                plugin_record.id,
                uploaded_by,
                {"version": manifest.version, "category": manifest.category.value}
            )

            return True, [], plugin_record

        except Exception as e:
            db.rollback()
            return False, [str(e)], None
        finally:
            db.close()

    def uninstall_plugin(
        self,
        plugin_id: UUID,
        remove_data: bool = False,
        removed_by: UUID | None = None,
    ) -> tuple[bool, list[str]]:
        """Uninstall a plugin."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"]

            # Uninstall via registry
            success, errors = self.registry.uninstall_plugin(plugin.name)
            if not success:
                return False, errors

            # Remove database record
            db.delete(plugin)
            db.commit()

            # Log audit event
            self._audit_plugin_event(
                "plugin.uninstalled",
                plugin_id,
                removed_by,
                {"name": plugin.name, "version": plugin.version}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def enable_plugin(self, plugin_id: UUID, enabled_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Enable a plugin."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"]

            success, errors = self.registry.enable_plugin(plugin.name)
            if not success:
                return False, errors

            plugin.enabled = True
            db.commit()

            self._audit_plugin_event(
                "plugin.enabled",
                plugin_id,
                enabled_by,
                {"name": plugin.name}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def disable_plugin(self, plugin_id: UUID, disabled_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Disable a plugin."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"]

            success, errors = self.registry.disable_plugin(plugin.name)
            if not success:
                return False, errors

            plugin.enabled = False
            db.commit()

            self._audit_plugin_event(
                "plugin.disabled",
                plugin_id,
                disabled_by,
                {"name": plugin.name}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def get_plugin(self, plugin_id: UUID) -> Plugin | None:
        """Get plugin by ID."""
        db = get_db_session()
        try:
            return db.get(Plugin, plugin_id)
        finally:
            db.close()

    def get_plugin_by_name(self, name: str) -> Plugin | None:
        """Get plugin by name."""
        db = get_db_session()
        try:
            return db.scalar(select(Plugin).where(Plugin.name == name))
        finally:
            db.close()

    def list_plugins(
        self,
        category: str | None = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Plugin], int]:
        """List plugins with filters."""
        db = get_db_session()
        try:
            query = select(Plugin)

            if category:
                query = query.where(Plugin.category == category)
            if enabled_only:
                query = query.where(Plugin.enabled == True)

            total = db.scalar(select(Plugin.id).select_from(query.subquery()).count())

            query = query.order_by(Plugin.name).limit(limit).offset(offset)
            plugins = db.scalars(query).all()

            return list(plugins), total

        finally:
            db.close()

    def update_plugin_config(
        self,
        plugin_id: UUID,
        config: dict[str, Any] | None = None,
        updated_by: UUID | None = None,
    ) -> tuple[bool, list[str]]:
        """Update plugin default configuration."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"]

            if config is not None:
                # Validate against schema
                valid, errors = self._validate_config(config, plugin.config_schema)
                if not valid:
                    return False, errors

                plugin.default_config = config

            db.commit()

            self._audit_plugin_event(
                "plugin.config_updated",
                plugin_id,
                updated_by,
                {"config": config}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def get_project_config(
        self,
        plugin_id: UUID,
        project_id: UUID,
    ) -> PluginProjectConfig | None:
        """Get plugin configuration for a project."""
        db = get_db_session()
        try:
            return db.scalar(
                select(PluginProjectConfig).where(
                    PluginProjectConfig.plugin_id == plugin_id,
                    PluginProjectConfig.project_id == project_id,
                )
            )
        finally:
            db.close()

    def set_project_config(
        self,
        plugin_id: UUID,
        project_id: UUID,
        config: dict[str, Any] | None = None,
        enabled: bool | None = None,
        overridden_by: UUID | None = None,
    ) -> tuple[bool, list[str], PluginProjectConfig | None]:
        """Set plugin configuration for a project."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"], None

            project_config = db.scalar(
                select(PluginProjectConfig).where(
                    PluginProjectConfig.plugin_id == plugin_id,
                    PluginProjectConfig.project_id == project_id,
                )
            )

            if not project_config:
                project_config = PluginProjectConfig(
                    plugin_id=plugin_id,
                    project_id=project_id,
                    config=config or plugin.default_config,
                    enabled=enabled if enabled is not None else True,
                    overridden_by=overridden_by,
                )
                db.add(project_config)
            else:
                if config is not None:
                    # Validate against schema
                    valid, errors = self._validate_config(config, plugin.config_schema)
                    if not valid:
                        return False, errors, None
                    project_config.config = config
                if enabled is not None:
                    project_config.enabled = enabled
                project_config.overridden_by = overridden_by

            db.commit()
            db.refresh(project_config)

            return True, [], project_config

        except Exception as e:
            db.rollback()
            return False, [str(e)], None
        finally:
            db.close()

    def execute_plugin(
        self,
        plugin_id: UUID,
        scan_context: dict[str, Any],
        plugin_config: dict[str, Any] | None = None,
        project_id: UUID | None = None,
        scan_id: UUID | None = None,
        scan_job_id: UUID | None = None,
        triggered_by: UUID | None = None,
        trigger_type: str = "manual",
        mode: str = "thread",
        timeout: int | None = None,
    ) -> tuple[bool, list[str], PluginExecution | None]:
        """
        Execute a plugin.

        Args:
            plugin_id: Plugin UUID
            scan_context: Scan context dictionary
            plugin_config: Plugin-specific configuration
            project_id: Project UUID
            scan_id: Scan UUID
            scan_job_id: Scan job UUID
            triggered_by: User who triggered execution
            trigger_type: manual, scheduled, scan
            mode: thread or process
            timeout: Execution timeout in seconds

        Returns:
            Tuple of (success, errors, execution_record)
        """
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"], None

            if not plugin.enabled:
                return False, ["Plugin is disabled"], None

            # Check permissions
            from app.plugins.sdk.manifest import PluginPermission, ResourceLimits
            permissions = [PluginPermission(p) for p in plugin.permissions]
            limits = ResourceLimits(**plugin.resource_limits)

            allowed, granted, denied = self.permission_evaluator.evaluate(
                permissions, limits, plugin_trusted=False
            )

            if not allowed:
                return False, [f"Permissions denied: {denied}"], None

            # Get project-specific config if available
            if project_id:
                project_config = self.get_project_config(plugin_id, project_id)
                if project_config and not project_config.enabled:
                    return False, ["Plugin disabled for this project"], None
                if project_config:
                    plugin_config = {**plugin.default_config, **project_config.config, **(plugin_config or {})}
                else:
                    plugin_config = {**plugin.default_config, **(plugin_config or {})}
            else:
                plugin_config = {**plugin.default_config, **(plugin_config or {})}

            # Create execution record
            execution = PluginExecution(
                plugin_id=plugin_id,
                project_id=project_id,
                scan_id=scan_id,
                scan_job_id=scan_job_id,
                triggered_by=triggered_by,
                trigger_type=trigger_type,
                status="running",
                started_at=datetime.now(UTC),
                input_context=scan_context,
                plugin_config=plugin_config,
            )
            db.add(execution)
            db.flush()

            # Execute plugin
            from app.plugins.sdk.base import PluginConfig, ScanContext
            from app.plugins.sdk.loader import execute_plugin

            context = ScanContext(**scan_context)
            config_obj = PluginConfig(
                plugin_id=plugin.name,
                config=plugin_config,
            ) if plugin_config else None

            success, result = execute_plugin(
                plugin.name,
                context,
                config_obj,
                mode=mode,
                timeout=timeout,
            )

            finished_at = datetime.now(UTC)

            if success:
                execution.status = "succeeded"
                execution.result = result
            else:
                execution.status = "failed"
                execution.error = result.get("error", "Unknown error")

            execution.finished_at = finished_at
            execution.warnings = result.get("warnings", [])
            execution.metrics = result.get("metrics", {})

            # Update plugin last executed
            plugin.last_executed_at = finished_at

            db.commit()
            db.refresh(execution)

            self._audit_plugin_event(
                "plugin.executed",
                plugin_id,
                triggered_by,
                {
                    "execution_id": str(execution.id),
                    "status": execution.status,
                    "trigger_type": trigger_type,
                }
            )

            return success, [execution.error] if execution.error else [], execution

        except Exception as e:
            db.rollback()
            return False, [str(e)], None
        finally:
            db.close()

    def get_execution_history(
        self,
        plugin_id: UUID,
        project_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PluginExecution], int]:
        """Get plugin execution history."""
        db = get_db_session()
        try:
            query = select(PluginExecution).where(PluginExecution.plugin_id == plugin_id)

            if project_id:
                query = query.where(PluginExecution.project_id == project_id)

            total = db.scalar(
                select(PluginExecution.id).select_from(query.subquery()).count()
            )

            query = query.order_by(PluginExecution.started_at.desc()).limit(limit).offset(offset)
            executions = db.scalars(query).all()

            return list(executions), total

        finally:
            db.close()

    def validate_plugin(
        self,
        plugin_id: UUID,
        scan_context: dict[str, Any],
    ) -> tuple[bool, list[str], list[str], list[str], dict[str, Any]]:
        """Validate plugin against scan context."""
        db = get_db_session()
        try:
            plugin = db.get(Plugin, plugin_id)
            if not plugin:
                return False, ["Plugin not found"], [], [], {}

            if not plugin.enabled:
                return False, ["Plugin is disabled"], [], [], {}

            from app.plugins.sdk.base import ScanContext
            context = ScanContext(**scan_context)

            result = self.registry.validate_plugin(plugin.name, context)

            return (
                result.valid,
                result.errors,
                result.warnings,
                result.required_permissions,
                result.estimated_resources,
            )

        finally:
            db.close()

    def _validate_config(self, config: dict[str, Any], schema: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate config against JSON schema."""
        if not schema:
            return True, []

        try:
            import jsonschema
            jsonschema.validate(config, schema)
            return True, []
        except Exception as e:
            return False, [str(e)]

    def _audit_plugin_event(
        self,
        event_type: str,
        plugin_id: UUID,
        user_id: UUID | None,
        payload: dict[str, Any],
    ) -> None:
        """Log plugin audit event."""
        from app.core.audit import log_security_event
        from app.models.enums import SecurityEventType

        try:
            # Map event types
            event_map = {
                "plugin.installed": SecurityEventType.PLUGIN_INSTALL,
                "plugin.uninstalled": SecurityEventType.PLUGIN_UNINSTALL,
                "plugin.enabled": SecurityEventType.PLUGIN_ENABLE,
                "plugin.disabled": SecurityEventType.PLUGIN_DISABLE,
                "plugin.config_updated": SecurityEventType.PLUGIN_CONFIG_UPDATE,
                "plugin.executed": SecurityEventType.PLUGIN_EXECUTE,
            }

            event = event_map.get(event_type, SecurityEventType.PLUGIN_EXECUTE)
            log_security_event(
                event_type=event,
                user_id=user_id,
                resource_type="plugin",
                resource_id=str(plugin_id),
                details=payload,
            )
        except Exception:
            # Don't fail plugin operations on audit logging failure
            pass


# Celery task for async plugin execution
@celery_app.task(bind=True, name="app.plugins.tasks.execute_plugin_async")
def execute_plugin_async(
    self,
    plugin_id: str,
    scan_context: dict[str, Any],
    plugin_config: dict[str, Any] | None = None,
    project_id: str | None = None,
    scan_id: str | None = None,
    scan_job_id: str | None = None,
    triggered_by: str | None = None,
    trigger_type: str = "scheduled",
) -> dict[str, Any]:
    """Async plugin execution task."""
    from uuid import UUID

    service = PluginService()
    success, errors, execution = service.execute_plugin(
        plugin_id=UUID(plugin_id),
        scan_context=scan_context,
        plugin_config=plugin_config,
        project_id=UUID(project_id) if project_id else None,
        scan_id=UUID(scan_id) if scan_id else None,
        scan_job_id=UUID(scan_job_id) if scan_job_id else None,
        triggered_by=UUID(triggered_by) if triggered_by else None,
        trigger_type=trigger_type,
        mode="process",
    )

    return {
        "success": success,
        "errors": errors,
        "execution_id": str(execution.id) if execution else None,
    }
