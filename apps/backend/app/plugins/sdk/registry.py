"""Plugin registry for discovery, loading, and management."""

import importlib
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

from app.plugins.sdk.base import (
    BasePlugin,
    PluginConfig,
    PluginMetadata,
    PluginValidationResult,
    ScanContext,
)
from app.plugins.sdk.manifest import PluginManifest, PluginManifestSchema


class PluginRegistry:
    """Central registry for plugin management."""

    def __init__(self, plugins_dir: Path | None = None):
        """Initialize registry with plugins directory."""
        self.plugins_dir = plugins_dir or Path(__file__).parent.parent.parent / "plugins" / "installed"
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

        self._plugins: dict[str, PluginMetadata] = {}
        self._instances: dict[str, BasePlugin] = {}
        self._manifests: dict[str, PluginManifest] = {}
        self._plugin_classes: dict[str, type[BasePlugin]] = {}

    def discover_plugins(self) -> list[PluginMetadata]:
        """Discover installed plugins from plugins directory."""
        discovered = []
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir():
                manifest_path = plugin_dir / "manifest.json"
                if manifest_path.exists():
                    try:
                        manifest = PluginManifest.from_file(manifest_path)
                        metadata = self._load_plugin_metadata(manifest, plugin_dir)
                        self._plugins[manifest.name] = metadata
                        self._manifests[manifest.name] = manifest
                        discovered.append(metadata)
                    except Exception:
                        # Log error but continue discovery
                        pass
        return discovered

    def _load_plugin_metadata(self, manifest: PluginManifest, plugin_dir: Path) -> PluginMetadata:
        """Load plugin metadata from manifest and verify checksum."""
        # Try to load plugin class to get additional metadata
        try:
            plugin_class = self._load_plugin_class(manifest, plugin_dir)
            if plugin_class:
                # Create temporary instance to get metadata
                instance = plugin_class()
                return instance.metadata
        except Exception:
            pass

        # Fallback to manifest data
        return PluginMetadata(
            plugin_id=manifest.name,
            name=manifest.name,
            version=manifest.version,
            category=manifest.category.value,
            description=manifest.description,
            author=manifest.author,
            entry_point=manifest.entry_point,
            permissions=[p.value for p in manifest.permissions],
            resource_limits=manifest.resource_limits.model_dump(),
            config_schema=manifest.config_schema,
            checksum=manifest.checksum,
        )

    def _load_plugin_class(self, manifest: PluginManifest, plugin_dir: Path) -> type[BasePlugin] | None:
        """Load plugin class from entry point."""
        if manifest.name in self._plugin_classes:
            return self._plugin_classes[manifest.name]

        # Add plugin directory to path temporarily
        old_path = sys.path[:]
        sys.path.insert(0, str(plugin_dir))

        try:
            # Parse entry point (module.ClassName)
            module_path, class_name = manifest.entry_point.rsplit(".", 1)
            module = importlib.import_module(module_path)
            plugin_class = getattr(module, class_name)

            # Verify it's a BasePlugin subclass
            if not issubclass(plugin_class, BasePlugin):
                raise ValueError(f"Plugin class {class_name} is not a BasePlugin subclass")

            self._plugin_classes[manifest.name] = plugin_class
            return plugin_class

        except Exception:
            return None
        finally:
            sys.path = old_path

    def get_plugin(self, plugin_id: str) -> BasePlugin | None:
        """Get or create plugin instance."""
        if plugin_id in self._instances:
            return self._instances[plugin_id]

        manifest = self._manifests.get(plugin_id)
        if not manifest:
            return None

        plugin_dir = self.plugins_dir / plugin_id
        plugin_class = self._load_plugin_class(manifest, plugin_dir)
        if not plugin_class:
            return None

        # Create instance with default config
        config = PluginConfig(plugin_id=plugin_id)
        instance = plugin_class(config)
        self._instances[plugin_id] = instance
        return instance

    def get_plugin_with_config(self, plugin_id: str, config: PluginConfig) -> BasePlugin | None:
        """Get plugin instance with specific configuration."""
        manifest = self._manifests.get(plugin_id)
        if not manifest:
            return None

        plugin_dir = self.plugins_dir / plugin_id
        plugin_class = self._load_plugin_class(manifest, plugin_dir)
        if not plugin_class:
            return None

        instance = plugin_class(config)
        return instance

    def install_plugin(self, package_path: Path, manifest: PluginManifest) -> tuple[bool, list[str]]:
        """
        Install a plugin from a package directory.

        Args:
            package_path: Path to plugin package directory
            manifest: Plugin manifest

        Returns:
            Tuple of (success, error_messages)
        """
        errors = []

        # Validate manifest
        valid, manifest_errors = PluginManifestSchema.validate_manifest(manifest.model_dump())
        if not valid:
            return False, manifest_errors

        # Verify checksum if provided
        if manifest.checksum:
            computed = manifest.compute_checksum(package_path)
            if computed != manifest.checksum:
                return False, [f"Checksum mismatch: expected {manifest.checksum}, got {computed}"]

        # Check for conflicts
        if manifest.name in self._plugins:
            return False, [f"Plugin {manifest.name} already installed"]

        # Check core version compatibility
        from app.config import get_settings
        settings = get_settings()
        core_version = settings.app_version
        if not self._check_version_compatibility(manifest, core_version):
            return False, [f"Plugin requires core version {manifest.min_core_version} - {manifest.max_core_version or 'any'}, current is {core_version}"]

        # Copy plugin to installed directory
        target_dir = self.plugins_dir / manifest.name
        try:
            shutil.copytree(package_path, target_dir)
        except Exception as e:
            return False, [f"Failed to copy plugin: {e}"]

        # Save manifest
        manifest_path = target_dir / "manifest.json"
        try:
            with open(manifest_path, "w") as f:
                f.write(manifest.to_json())
        except Exception as e:
            shutil.rmtree(target_dir, ignore_errors=True)
            return False, [f"Failed to write manifest: {e}"]

        # Load plugin
        try:
            metadata = self._load_plugin_metadata(manifest, target_dir)
            self._plugins[manifest.name] = metadata
            self._manifests[manifest.name] = manifest
        except Exception as e:
            shutil.rmtree(target_dir, ignore_errors=True)
            return False, [f"Failed to load plugin: {e}"]

        return True, []

    def uninstall_plugin(self, plugin_id: str, remove_data: bool = False) -> tuple[bool, list[str]]:
        """Uninstall a plugin."""
        errors = []

        if plugin_id not in self._plugins:
            return False, [f"Plugin {plugin_id} not installed"]

        # Remove instances
        self._instances.pop(plugin_id, None)
        self._plugin_classes.pop(plugin_id, None)

        # Remove plugin directory
        plugin_dir = self.plugins_dir / plugin_id
        if plugin_dir.exists():
            try:
                shutil.rmtree(plugin_dir)
            except Exception as e:
                errors.append(f"Failed to remove plugin directory: {e}")

        # Remove from registry
        self._plugins.pop(plugin_id, None)
        self._manifests.pop(plugin_id, None)

        return len(errors) == 0, errors

    def enable_plugin(self, plugin_id: str) -> tuple[bool, list[str]]:
        """Enable a plugin."""
        if plugin_id not in self._plugins:
            return False, [f"Plugin {plugin_id} not installed"]

        self._plugins[plugin_id].enabled = True
        return True, []

    def disable_plugin(self, plugin_id: str) -> tuple[bool, list[str]]:
        """Disable a plugin."""
        if plugin_id not in self._plugins:
            return False, [f"Plugin {plugin_id} not installed"]

        self._plugins[plugin_id].enabled = False
        # Remove cached instance
        self._instances.pop(plugin_id, None)
        return True, []

    def list_plugins(self, enabled_only: bool = False) -> list[PluginMetadata]:
        """List all installed plugins."""
        plugins = list(self._plugins.values())
        if enabled_only:
            plugins = [p for p in plugins if p.enabled]
        return plugins

    def get_plugin_metadata(self, plugin_id: str) -> PluginMetadata | None:
        """Get plugin metadata."""
        return self._plugins.get(plugin_id)

    def get_manifest(self, plugin_id: str) -> PluginManifest | None:
        """Get plugin manifest."""
        return self._manifests.get(plugin_id)

    def validate_plugin(self, plugin_id: str, context: ScanContext) -> PluginValidationResult:
        """Validate plugin against a scan context."""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            return PluginValidationResult(
                valid=False,
                errors=[f"Plugin {plugin_id} not found or failed to load"]
            )

        if not self._plugins[plugin_id].enabled:
            return PluginValidationResult(
                valid=False,
                errors=[f"Plugin {plugin_id} is disabled"]
            )

        return plugin.validate(context)

    def execute_plugin(
        self,
        plugin_id: str,
        context: ScanContext,
        config: PluginConfig | None = None,
    ) -> tuple[bool, Any]:
        """Execute a plugin with context and optional config."""
        if config:
            plugin = self.get_plugin_with_config(plugin_id, config)
        else:
            plugin = self.get_plugin(plugin_id)

        if not plugin:
            return False, {"error": f"Plugin {plugin_id} not found or failed to load"}

        if not self._plugins[plugin_id].enabled:
            return False, {"error": f"Plugin {plugin_id} is disabled"}

        # Validate first
        validation = plugin.validate(context)
        if not validation.valid:
            return False, {"error": "Validation failed", "details": validation.errors}

        try:
            # Execute scan
            raw_result = plugin.scan(context)

            # Normalize result
            normalized_result = plugin.normalize(raw_result, context)

            return True, normalized_result.model_dump()

        except Exception as e:
            return False, {"error": str(e), "type": type(e).__name__}

    def _check_version_compatibility(self, manifest: PluginManifest, core_version: str) -> bool:
        """Check if plugin is compatible with core version."""
        from packaging import version

        core_ver = version.parse(core_version)
        min_ver = version.parse(manifest.min_core_version)

        if core_ver < min_ver:
            return False

        if manifest.max_core_version:
            max_ver = version.parse(manifest.max_core_version)
            if core_ver > max_ver:
                return False

        return True

    def get_plugins_by_category(self, category: str) -> list[PluginMetadata]:
        """Get plugins filtered by category."""
        return [p for p in self._plugins.values() if p.category == category]

    def get_plugins_by_capability(self, capability: str) -> list[PluginMetadata]:
        """Get plugins that have a specific capability."""
        return [p for p in self._plugins.values() if capability in p.capabilities]


# Global registry instance
_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    """Get global plugin registry instance."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry


def set_plugin_registry(registry: PluginRegistry) -> None:
    """Set global plugin registry instance (for testing)."""
    global _registry
    _registry = registry
