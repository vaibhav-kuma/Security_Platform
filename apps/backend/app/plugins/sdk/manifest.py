"""Plugin manifest schema and validation."""

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class PluginCategory(str, Enum):
    """Plugin category enumeration."""
    RECON = "recon"
    WEB = "web"
    API = "api"
    MOBILE = "mobile"
    DNS = "dns"
    TLS = "tls"
    TECHNOLOGY = "technology"
    CONFIGURATION = "configuration"
    VULNERABILITY = "vulnerability"
    REPORTING = "reporting"
    METHODOLOGY = "methodology"
    OTHER = "other"


class PluginPermission(str, Enum):
    """Plugin permission enumeration."""
    NETWORK_REQUEST = "network.request"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    PROCESS_EXECUTE = "process.execute"
    DATABASE_QUERY = "database.query"
    CACHE_ACCESS = "cache.access"
    SECRET_READ = "secret.read"


class ResourceLimits(BaseModel):
    """Resource limits for plugin execution."""
    cpu_percent: int = Field(default=50, ge=1, le=100, description="Max CPU percentage")
    memory_mb: int = Field(default=256, ge=64, le=4096, description="Max memory in MB")
    time_seconds: int = Field(default=300, ge=10, le=3600, description="Max execution time in seconds")
    network_egress_allowlist: list[str] = Field(
        default_factory=list,
        description="Allowed network destinations (host:port or CIDR)"
    )


class PluginManifest(BaseModel):
    """Plugin manifest declaring metadata, capabilities, and requirements."""

    # Core metadata
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+(-[a-zA-Z0-9\-\.]+)?$")
    description: str = Field(..., min_length=10, max_length=500)
    author: str = Field(..., min_length=1, max_length=100)
    license: str = Field(default="MIT", max_length=50)
    homepage: str | None = Field(default=None, max_length=200)
    repository: str | None = Field(default=None, max_length=200)

    # Classification
    category: PluginCategory = PluginCategory.OTHER
    tags: list[str] = Field(default_factory=list, max_length=10)

    # Compatibility
    min_core_version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    max_core_version: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")
    python_version: str = Field(default=">=3.12", pattern=r"^>=?\d+\.\d+$")

    # Capabilities
    capabilities: list[str] = Field(default_factory=list, max_length=20)
    # e.g., ["domain_enumeration", "port_scanning", "ssl_analysis"]

    # Permissions
    permissions: list[PluginPermission] = Field(default_factory=list)

    # Resource limits
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)

    # Configuration schema
    config_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema for plugin configuration"
    )

    # Entry point
    entry_point: str = Field(
        ...,
        description="Module path to plugin class (e.g., 'my_plugin.MyPlugin')"
    )

    # Dependencies
    dependencies: list[str] = Field(
        default_factory=list,
        description="Python package dependencies (pip installable)"
    )

    # Integrity
    checksum: str | None = Field(default=None, description="SHA256 of plugin package")

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        """Validate tags are lowercase alphanumeric with hyphens."""
        for tag in v:
            if not tag or not tag.islower() or not all(c.isalnum() or c == "-" for c in tag):
                raise ValueError(f"Invalid tag: {tag}. Must be lowercase alphanumeric with hyphens.")
        return v

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, v: list[str]) -> list[str]:
        """Validate capabilities format."""
        for cap in v:
            if not cap or not all(c.isalnum() or c == "_" for c in cap):
                raise ValueError(f"Invalid capability: {cap}. Must be alphanumeric with underscores.")
        return v

    @model_validator(mode="after")
    def validate_version_compatibility(self) -> "PluginManifest":
        """Validate version range makes sense."""
        if self.max_core_version:
            from packaging import version
            if version.parse(self.min_core_version) > version.parse(self.max_core_version):
                raise ValueError("min_core_version cannot exceed max_core_version")
        return self

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json(indent=indent, exclude_none=True)

    @classmethod
    def from_json(cls, json_str: str) -> "PluginManifest":
        """Deserialize from JSON string."""
        return cls.model_validate_json(json_str)

    @classmethod
    def from_file(cls, path: str | Path) -> "PluginManifest":
        """Load manifest from file."""
        with open(path) as f:
            data = json.load(f)
        return cls.model_validate(data)

    def compute_checksum(self, plugin_path: Path) -> str:
        """Compute SHA256 checksum of plugin directory."""
        hasher = hashlib.sha256()
        for file_path in sorted(plugin_path.rglob("*")):
            if file_path.is_file():
                hasher.update(file_path.read_bytes())
        return hasher.hexdigest()

    def verify_checksum(self, plugin_path: Path) -> bool:
        """Verify plugin checksum matches manifest."""
        if not self.checksum:
            return True  # No checksum to verify
        return self.compute_checksum(plugin_path) == self.checksum


class PluginManifestSchema:
    """JSON Schema for plugin manifest validation."""

    @staticmethod
    def get_schema() -> dict[str, Any]:
        """Get JSON Schema for plugin manifest."""
        return PluginManifest.model_json_schema()

    @staticmethod
    def validate_manifest(data: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate manifest data against schema."""
        try:
            PluginManifest.model_validate(data)
            return True, []
        except Exception as e:
            return False, [str(e)]
