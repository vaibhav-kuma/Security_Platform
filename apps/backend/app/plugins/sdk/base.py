"""Base plugin classes for the scanner plugin SDK."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ScanContext(BaseModel):
    """Context passed to plugins during scan execution."""

    project_id: UUID
    scan_id: UUID
    scan_job_id: UUID
    target_id: UUID | None = None
    target_value: str
    target_type: str
    scope_rules: list[dict[str, Any]] = Field(default_factory=list)
    execution_policy: dict[str, Any] = Field(default_factory=dict)
    rate_limits: dict[str, Any] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    plugin_config: dict[str, Any] = Field(default_factory=dict)
    credentials: dict[str, str] = Field(default_factory=dict)  # Injected secrets


class PluginConfig(BaseModel):
    """Plugin configuration provided by user."""

    project_id: UUID | None = None
    plugin_id: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PluginResult(BaseModel):
    """Result returned by plugin execution."""

    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    assets: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: float = 0.0


class PluginValidationResult(BaseModel):
    """Result of plugin validation."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    estimated_resources: dict[str, Any] = Field(default_factory=dict)


@dataclass
class PluginMetadata:
    """Metadata about a loaded plugin."""

    plugin_id: str
    name: str
    version: str
    category: str
    description: str
    author: str
    entry_point: str
    permissions: list[str]
    resource_limits: dict[str, Any]
    config_schema: dict[str, Any]
    loaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    enabled: bool = True
    checksum: str | None = None


class BasePlugin(ABC):
    """Base class for all plugins."""

    # Class attributes to be overridden by subclasses
    PLUGIN_ID: str = ""
    PLUGIN_NAME: str = ""
    PLUGIN_VERSION: str = "1.0.0"
    PLUGIN_CATEGORY: str = "other"
    PLUGIN_DESCRIPTION: str = ""
    PLUGIN_AUTHOR: str = ""
    PLUGIN_PERMISSIONS: list[str] = field(default_factory=list)
    PLUGIN_RESOURCE_LIMITS: dict[str, Any] = field(default_factory=dict)
    PLUGIN_CONFIG_SCHEMA: dict[str, Any] = field(default_factory=dict)

    def __init__(self, config: PluginConfig | None = None):
        """Initialize plugin with optional configuration."""
        self.config = config or PluginConfig(plugin_id=self.PLUGIN_ID)
        self._metadata = PluginMetadata(
            plugin_id=self.PLUGIN_ID,
            name=self.PLUGIN_NAME,
            version=self.PLUGIN_VERSION,
            category=self.PLUGIN_CATEGORY,
            description=self.PLUGIN_DESCRIPTION,
            author=self.PLUGIN_AUTHOR,
            entry_point=self.__class__.__module__ + "." + self.__class__.__name__,
            permissions=self.PLUGIN_PERMISSIONS,
            resource_limits=self.PLUGIN_RESOURCE_LIMITS,
            config_schema=self.PLUGIN_CONFIG_SCHEMA,
        )

    @property
    def metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return self._metadata

    @abstractmethod
    def validate(self, context: ScanContext) -> PluginValidationResult:
        """
        Validate if plugin can run against the target.

        Called before scan execution to check:
        - Target compatibility
        - Required permissions
        - Configuration validity
        - Resource requirements

        Args:
            context: Scan context with target and policy info

        Returns:
            Validation result with errors/warnings
        """
        pass

    @abstractmethod
    def scan(self, context: ScanContext) -> PluginResult:
        """
        Execute the plugin scan.

        This is the main execution method. Implement your scanning logic here.

        Args:
            context: Scan context with target, policy, and configuration

        Returns:
            Plugin result with findings, assets, evidence
        """
        pass

    @abstractmethod
    def normalize(self, raw_result: PluginResult, context: ScanContext) -> PluginResult:
        """
        Normalize raw scan results into standard format.

        Called after scan() to convert plugin-specific output to platform format.

        Args:
            raw_result: Raw result from scan()
            context: Scan context

        Returns:
            Normalized result
        """
        pass

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return self.metadata

    def get_config_schema(self) -> dict[str, Any]:
        """Get configuration JSON schema."""
        return self.PLUGIN_CONFIG_SCHEMA

    def validate_config(self, config: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate plugin configuration against schema."""
        # Basic validation - can be overridden for complex validation
        if not isinstance(config, dict):
            return False, ["Config must be a dictionary"]
        return True, []


class ScannerPlugin(BasePlugin):
    """Base class for scanner plugins (recon, web, API, mobile, etc.)."""

    PLUGIN_CATEGORY: str = "scanner"

    def validate(self, context: ScanContext) -> PluginValidationResult:
        """Default validation - can be overridden."""
        return PluginValidationResult(
            valid=True,
            required_permissions=self.PLUGIN_PERMISSIONS,
            estimated_resources=self.PLUGIN_RESOURCE_LIMITS,
        )

    def normalize(self, raw_result: PluginResult, context: ScanContext) -> PluginResult:
        """Default normalization - returns result as-is."""
        return raw_result


class MethodologyPlugin(BasePlugin):
    """Base class for methodology plugins (testing guides, checklists)."""

    PLUGIN_CATEGORY: str = "methodology"

    def validate(self, context: ScanContext) -> PluginValidationResult:
        """Methodology plugins typically always valid."""
        return PluginValidationResult(valid=True)

    def scan(self, context: ScanContext) -> PluginResult:
        """Methodology plugins don't scan - they provide guidance."""
        return PluginResult(
            success=True,
            data={"methodology": self.PLUGIN_NAME, "version": self.PLUGIN_VERSION},
            metrics={"type": "methodology"},
        )

    def normalize(self, raw_result: PluginResult, context: ScanContext) -> PluginResult:
        return raw_result


class ReportingPlugin(BasePlugin):
    """Base class for reporting plugins (custom report formats)."""

    PLUGIN_CATEGORY: str = "reporting"

    def validate(self, context: ScanContext) -> PluginValidationResult:
        return PluginValidationResult(valid=True)

    def scan(self, context: ScanContext) -> PluginResult:
        """Reporting plugins generate reports from existing data."""
        return PluginResult(
            success=True,
            data={"report_type": self.PLUGIN_NAME},
            metrics={"type": "reporting"},
        )

    def normalize(self, raw_result: PluginResult, context: ScanContext) -> PluginResult:
        return raw_result


# Plugin factory function type
PluginFactory = type[BasePlugin]


def create_plugin_instance(
    plugin_class: PluginFactory,
    config: PluginConfig | None = None,
) -> BasePlugin:
    """Create a plugin instance with configuration."""
    return plugin_class(config)
