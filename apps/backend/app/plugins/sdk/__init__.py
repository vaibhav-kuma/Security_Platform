"""Plugin SDK package initialization."""

from app.plugins.permissions import (
    ExecutionIsolation,
    NetworkPolicyManager,
    PermissionEvaluator,
    PermissionPolicy,
    check_network_access,
    evaluate_plugin_permissions,
    get_execution_isolation,
    get_network_policy_manager,
    get_permission_evaluator,
)
from app.plugins.sdk.base import (
    BasePlugin,
    MethodologyPlugin,
    PluginConfig,
    PluginMetadata,
    PluginResult,
    PluginValidationResult,
    ReportingPlugin,
    ScanContext,
    ScannerPlugin,
    create_plugin_instance,
)
from app.plugins.sdk.loader import (
    PluginExecutionError,
    PluginExecutor,
    PluginLoader,
    PluginLoadError,
    execute_plugin,
    load_and_install_plugin,
)
from app.plugins.sdk.manifest import (
    PluginCategory,
    PluginManifest,
    PluginManifestSchema,
    PluginPermission,
    ResourceLimits,
)
from app.plugins.sdk.registry import (
    PluginRegistry,
    get_plugin_registry,
    set_plugin_registry,
)

__all__ = [
    # Base classes
    "BasePlugin",
    "ScannerPlugin",
    "MethodologyPlugin",
    "ReportingPlugin",
    "PluginConfig",
    "PluginResult",
    "PluginValidationResult",
    "ScanContext",
    "PluginMetadata",
    "create_plugin_instance",
    # Manifest
    "PluginManifest",
    "PluginManifestSchema",
    "PluginCategory",
    "PluginPermission",
    "ResourceLimits",
    # Registry
    "PluginRegistry",
    "get_plugin_registry",
    "set_plugin_registry",
    # Loader
    "PluginLoader",
    "PluginExecutor",
    "PluginLoadError",
    "PluginExecutionError",
    "execute_plugin",
    "load_and_install_plugin",
    # Permissions
    "PermissionEvaluator",
    "ExecutionIsolation",
    "NetworkPolicyManager",
    "PermissionPolicy",
    "get_permission_evaluator",
    "get_execution_isolation",
    "get_network_policy_manager",
    "evaluate_plugin_permissions",
    "check_network_access",
]
