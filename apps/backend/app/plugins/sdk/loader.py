"""Plugin loader with secure execution isolation."""

import asyncio
import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

from app.plugins.sdk.base import BasePlugin, PluginConfig, PluginResult, ScanContext
from app.plugins.sdk.manifest import PluginManifest, ResourceLimits
from app.plugins.sdk.registry import PluginRegistry, get_plugin_registry


class PluginLoadError(Exception):
    """Raised when plugin fails to load."""
    pass


class PluginExecutionError(Exception):
    """Raised when plugin execution fails."""
    pass


class PluginExecutor:
    """Secure plugin executor with resource limits and isolation."""

    def __init__(self, registry: PluginRegistry | None = None):
        """Initialize executor with plugin registry."""
        self.registry = registry or get_plugin_registry()

    def execute_plugin_in_process(
        self,
        plugin_id: str,
        context: ScanContext,
        config: PluginConfig | None = None,
        timeout: int | None = None,
    ) -> PluginResult:
        """
        Execute plugin in a separate process for isolation.

        This is the most secure mode - plugin runs in completely separate process
        with resource limits enforced by OS.
        """
        manifest = self.registry.get_manifest(plugin_id)
        if not manifest:
            raise PluginExecutionError(f"Plugin {plugin_id} not found")

        # Prepare execution script
        script = self._create_execution_script(plugin_id, context, config, manifest)

        # Execute in subprocess with resource limits
        return self._run_subprocess(script, manifest.resource_limits, timeout)

    def execute_plugin_in_thread(
        self,
        plugin_id: str,
        context: ScanContext,
        config: PluginConfig | None = None,
        timeout: int | None = None,
    ) -> PluginResult:
        """
        Execute plugin in current process (thread) with soft limits.

        Less isolated but faster. Uses Python's resource module for limits.
        """
        manifest = self.registry.get_manifest(plugin_id)
        if not manifest:
            raise PluginExecutionError(f"Plugin {plugin_id} not found")

        # Get plugin instance
        plugin = self.registry.get_plugin_with_config(plugin_id, config) if config else self.registry.get_plugin(plugin_id)
        if not plugin:
            raise PluginExecutionError(f"Plugin {plugin_id} failed to load")

        # Apply resource limits
        self._apply_resource_limits(manifest.resource_limits)

        try:
            # Validate
            validation = plugin.validate(context)
            if not validation.valid:
                return PluginResult(
                    success=False,
                    errors=validation.errors,
                )

            # Execute with timeout
            if timeout is None:
                timeout = manifest.resource_limits.time_seconds

            # Run in thread with timeout
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                raw_result = loop.run_until_complete(
                    asyncio.wait_for(
                        asyncio.to_thread(plugin.scan, context),
                        timeout=timeout,
                    )
                )
            finally:
                loop.close()

            # Normalize
            normalized_result = plugin.normalize(raw_result, context)
            return normalized_result

        except TimeoutError:
            return PluginResult(
                success=False,
                errors=[f"Plugin execution timed out after {timeout} seconds"],
            )
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[f"Plugin execution failed: {e}"],
            )

    def _create_execution_script(
        self,
        plugin_id: str,
        context: ScanContext,
        config: PluginConfig | None,
        manifest: PluginManifest,
    ) -> str:
        """Create a standalone execution script for the plugin."""
        import json

        # Serialize context and config
        context_json = context.model_dump_json()
        config_json = config.model_dump_json() if config else "null"
        manifest_json = manifest.model_dump_json()

        script = f'''
import asyncio
import json
import sys
import traceback
from pathlib import Path

# Add plugin directory to path
plugin_dir = Path("{self.registry.plugins_dir / plugin_id}")
sys.path.insert(0, str(plugin_dir))

from app.plugins.sdk.base import BasePlugin, PluginConfig, ScanContext, PluginResult
from app.plugins.sdk.manifest import PluginManifest

# Deserialize inputs
context_data = json.loads(''' + json.dumps(context_json) + ''')
config_data = json.loads(''' + json.dumps(config_json) + ''')
manifest_data = json.loads(''' + json.dumps(manifest_json) + ''')

context = ScanContext(**context_data)
config = PluginConfig(**config_data) if config_data else None
manifest = PluginManifest(**manifest_data)

# Load plugin class
module_path, class_name = manifest.entry_point.rsplit(".", 1)
module = __import__(module_path, fromlist=[class_name])
plugin_class = getattr(module, class_name)

# Create instance
plugin = plugin_class(config)

# Validate
validation = plugin.validate(context)
if not validation.valid:
    result = PluginResult(
        success=False,
        errors=validation.errors,
    )
    print("RESULT:" + result.model_dump_json())
    sys.exit(0)

# Execute scan
try:
    raw_result = plugin.scan(context)
    normalized_result = plugin.normalize(raw_result, context)
    print("RESULT:" + normalized_result.model_dump_json())
except Exception as e:
    result = PluginResult(
        success=False,
        errors=[f"Plugin execution failed: {{e}}"],
    )
    print("RESULT:" + result.model_dump_json())
'''
        return script

    def _run_subprocess(
        self,
        script: str,
        limits: ResourceLimits,
        timeout: int | None = None,
    ) -> PluginResult:
        """Run plugin script in subprocess with resource limits."""
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            # Prepare environment
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).parent.parent.parent.parent)  # Project root

            # Run subprocess with resource limits
            proc = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=self._set_resource_limits(limits) if sys.platform != "win32" else None,
            )

            try:
                stdout, stderr = proc.communicate(
                    timeout=timeout or limits.time_seconds
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                return PluginResult(
                    success=False,
                    errors=[f"Execution timed out after {timeout or limits.time_seconds} seconds"],
                )

            # Parse result from stdout
            for line in stdout.decode().splitlines():
                if line.startswith("RESULT:"):
                    result_json = line[7:]  # Remove "RESULT:" prefix
                    return PluginResult.model_validate_json(result_json)

            # No result found
            error_msg = stderr.decode() if stderr else "No result output"
            return PluginResult(
                success=False,
                errors=[f"Plugin produced no result: {error_msg}"],
            )

        finally:
            # Cleanup
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def _set_resource_limits(self, limits: ResourceLimits):
        """Create preexec function to set resource limits (Unix only)."""
        def set_limits():
            # CPU time limit
            resource.setrlimit(resource.RLIMIT_CPU, (limits.time_seconds, limits.time_seconds))
            # Memory limit (in bytes)
            mem_bytes = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            # File size limit
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
            # Process limit
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            # Disable core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        return set_limits

    def _apply_resource_limits(self, limits: ResourceLimits) -> None:
        """Apply resource limits to current process (soft limits)."""
        if sys.platform == "win32":
            return  # resource module not available on Windows

        try:
            # CPU time
            resource.setrlimit(resource.RLIMIT_CPU, (limits.time_seconds, limits.time_seconds))
            # Memory
            mem_bytes = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            # File size
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except Exception:
            # Ignore if we can't set limits (e.g., not root, already limited)
            pass


class PluginLoader:
    """Plugin loader with validation and secure loading."""

    def __init__(self, registry: PluginRegistry | None = None):
        """Initialize loader."""
        self.registry = registry or get_plugin_registry()
        self.executor = PluginExecutor(registry)

    def load_plugin_from_package(self, package_path: Path) -> tuple[bool, list[str], PluginManifest | None]:
        """
        Load and validate plugin from package directory.

        Returns:
            Tuple of (success, errors, manifest)
        """
        errors = []

        # Check for manifest
        manifest_path = package_path / "manifest.json"
        if not manifest_path.exists():
            return False, ["manifest.json not found in package"], None

        # Load manifest
        try:
            manifest = PluginManifest.from_file(manifest_path)
        except Exception as e:
            return False, [f"Invalid manifest: {e}"], None

        # Validate manifest
        valid, manifest_errors = PluginManifestSchema.validate_manifest(manifest.model_dump())
        if not valid:
            return False, manifest_errors, None

        # Verify checksum
        if manifest.checksum:
            computed = manifest.compute_checksum(package_path)
            if computed != manifest.checksum:
                return False, [f"Checksum mismatch: expected {manifest.checksum}, got {computed}"], manifest

        # Try to load plugin class
        try:
            plugin_class = self._load_plugin_class(manifest, package_path)
            if not plugin_class:
                return False, ["Failed to load plugin class from entry point"], manifest

            # Validate it's a proper plugin
            instance = plugin_class()
            if not isinstance(instance, BasePlugin):
                return False, ["Plugin class is not a BasePlugin subclass"], manifest

        except Exception as e:
            return False, [f"Plugin class validation failed: {e}"], manifest

        return True, [], manifest

    def _load_plugin_class(self, manifest: PluginManifest, plugin_dir: Path) -> type[BasePlugin] | None:
        """Load plugin class from entry point."""
        import importlib
        import sys

        old_path = sys.path[:]
        sys.path.insert(0, str(plugin_dir))

        try:
            module_path, class_name = manifest.entry_point.rsplit(".", 1)
            module = importlib.import_module(module_path)
            plugin_class = getattr(module, class_name)

            if not issubclass(plugin_class, BasePlugin):
                return None

            return plugin_class
        except Exception:
            return None
        finally:
            sys.path = old_path

    def install_plugin(self, package_path: Path) -> tuple[bool, list[str]]:
        """Install plugin from package directory."""
        # Load and validate
        success, errors, manifest = self.load_plugin_from_package(package_path)
        if not success:
            return False, errors

        # Install via registry
        return self.registry.install_plugin(package_path, manifest)

    def uninstall_plugin(self, plugin_id: str) -> tuple[bool, list[str]]:
        """Uninstall plugin."""
        return self.registry.uninstall_plugin(plugin_id)


# Convenience functions
def execute_plugin(
    plugin_id: str,
    context: ScanContext,
    config: PluginConfig | None = None,
    mode: str = "thread",  # "thread" or "process"
    timeout: int | None = None,
) -> PluginResult:
    """Execute a plugin with the given context."""
    executor = PluginExecutor()
    if mode == "process":
        return executor.execute_plugin_in_process(plugin_id, context, config, timeout)
    else:
        return executor.execute_plugin_in_thread(plugin_id, context, config, timeout)


def load_and_install_plugin(package_path: Path) -> tuple[bool, list[str]]:
    """Load and install a plugin from package directory."""
    loader = PluginLoader()
    return loader.install_plugin(package_path)
