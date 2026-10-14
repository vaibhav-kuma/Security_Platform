"""ReconPlugin interface and base classes."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass
class ReconPluginConfig:
    """Configuration for a recon plugin."""

    name: str
    version: str
    description: str
    target_types: list[str] = field(default_factory=list)  # e.g., ["domain", "ip", "url"]
    requires_network: bool = True
    timeout_seconds: int = 300
    rate_limit_per_minute: int = 60
    configuration_schema: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.target_types is None:
            self.target_types = []
        if self.configuration_schema is None:
            self.configuration_schema = {}


@dataclass
class ReconResult:
    """Normalized result from a recon plugin."""

    asset_kind: str  # maps to AssetKind enum
    value: str  # canonical identifier
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)  # (target_asset_value, relationship_type, note)
    source: str  # plugin name
    confidence: str = "medium"  # very_low, low, medium, high, very_high
    scope_status: str = "unknown"  # in_scope, out_of_scope, unknown, third_party
    first_seen: str | None = None  # ISO timestamp
    last_seen: str | None = None  # ISO timestamp


@dataclass
class ReconContext:
    """Context passed to recon plugins during execution."""

    project_id: UUID
    scan_id: UUID
    scan_job_id: UUID
    target_id: UUID | None
    target_value: str
    target_type: str
    scope_rules: list[dict[str, Any]]  # Serialized scope rules
    execution_policy: dict[str, Any]
    rate_limits: dict[str, Any]
    configuration: dict[str, Any]


class ReconPlugin(ABC):
    """Abstract base class for reconnaissance plugins.

    All recon plugins must implement:
    - validate(): Check if plugin can run against the target
    - run(): Execute the reconnaissance and return normalized results
    - normalize(): Convert raw results to ReconResult objects (optional, can be done in run)
    """

    @property
    @abstractmethod
    def config(self) -> ReconPluginConfig:
        """Return plugin configuration metadata."""
        pass

    @abstractmethod
    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that this plugin can run against the given target.

        Args:
            context: Execution context with target and scope information

        Returns:
            Tuple of (is_valid, error_message). If not valid, error_message explains why.
        """
        pass

    @abstractmethod
    def run(self, context: ReconContext) -> list[ReconResult]:
        """Execute the reconnaissance plugin.

        Args:
            context: Execution context with target and scope information

        Returns:
            List of normalized ReconResult objects
        """
        pass

    def normalize(self, raw_results: list[Any], context: ReconContext) -> list[ReconResult]:
        """Normalize raw plugin results to ReconResult objects.

        Default implementation assumes run() already returns ReconResult.
        Override if run() returns raw data that needs normalization.

        Args:
            raw_results: Raw results from run()
            context: Execution context

        Returns:
            List of normalized ReconResult objects
        """
        return raw_results

    def get_default_config(self) -> dict[str, Any]:
        """Get default configuration for this plugin."""
        return {}

    def get_required_permissions(self) -> list[str]:
        """Get list of required permissions for this plugin.

        Permissions are strings like 'network.dns', 'network.http', 'network.tls', etc.
        """
        return []


class ReconPluginRegistry:
    """Registry for managing recon plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, ReconPlugin] = {}

    def register(self, plugin: ReconPlugin) -> None:
        """Register a plugin."""
        name = plugin.config.name
        if name in self._plugins:
            raise ValueError(f"Plugin already registered: {name}")
        self._plugins[name] = plugin

    def unregister(self, name: str) -> None:
        """Unregister a plugin."""
        if name in self._plugins:
            del self._plugins[name]

    def get(self, name: str) -> ReconPlugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_all(self) -> list[ReconPlugin]:
        """Get all registered plugins."""
        return list(self._plugins.values())

    def get_for_target(self, target_type: str) -> list[ReconPlugin]:
        """Get plugins that support the given target type."""
        return [
            p for p in self._plugins.values()
            if not p.config.target_types or target_type in p.config.target_types
        ]

    def get_plugin_names(self) -> list[str]:
        """Get all registered plugin names."""
        return list(self._plugins.keys())


# Global registry instance
_plugin_registry = ReconPluginRegistry()


def get_plugin_registry() -> ReconPluginRegistry:
    """Get the global plugin registry."""
    return _plugin_registry


def register_plugin(plugin: ReconPlugin) -> None:
    """Register a plugin in the global registry."""
    _plugin_registry.register(plugin)


def unregister_plugin(name: str) -> None:
    """Unregister a plugin from the global registry."""
    _plugin_registry.unregister(name)
