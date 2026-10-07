"""Execution policy for scan execution controls."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TestingMode(StrEnum):
    """Testing mode for scans."""

    PASSIVE = "passive"  # Non-intrusive, read-only
    ACTIVE = "active"    # May send payloads, interact with target
    SAFE = "safe"        # Only safe checks, no exploitation attempts


class RateLimitScope(StrEnum):
    """Scope for rate limiting."""

    PROJECT = "project"
    TARGET = "target"
    GLOBAL = "global"


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_allowance: int = 10
    scope: RateLimitScope = RateLimitScope.TARGET


@dataclass
class ExecutionPolicy:
    """Execution policy controlling scan behavior."""

    # Testing mode
    testing_mode: TestingMode = TestingMode.PASSIVE

    # Safe mode - only run checks marked as safe
    safe_mode: bool = True

    # Rate limiting
    rate_limits: dict[str, RateLimitConfig] = field(default_factory=dict)

    # Timeouts (seconds)
    default_timeout: int = 300
    plugin_timeouts: dict[str, int] = field(default_factory=dict)

    # Concurrency
    max_concurrent_jobs: int = 5
    max_concurrent_plugins: int = 3

    # Resource limits
    max_memory_mb: int = 512
    max_cpu_percent: int = 50

    # Network restrictions
    allow_external_network: bool = True
    allowed_domains: list[str] = field(default_factory=list)  # If empty, all allowed
    blocked_domains: list[str] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)

    # Target restrictions
    max_targets_per_scan: int = 100
    max_depth: int = 3  # For crawlers
    max_pages: int = 1000  # For crawlers

    # Plugin controls
    enabled_plugins: list[str] | None = None  # None = all
    disabled_plugins: list[str] = field(default_factory=list)
    plugin_configurations: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Retry policy
    max_retries: int = 3
    retry_delay_seconds: int = 60
    retry_exponential_backoff: bool = True

    # Output controls
    store_raw_evidence: bool = True
    redact_secrets: bool = True
    redact_pii: bool = True

    @classmethod
    def default_passive(cls) -> "ExecutionPolicy":
        """Create a default passive testing policy."""
        return cls(
            testing_mode=TestingMode.PASSIVE,
            safe_mode=True,
            rate_limits={
                "default": RateLimitConfig(requests_per_minute=30, requests_per_hour=500)
            },
            default_timeout=300,
            max_concurrent_jobs=3,
            max_concurrent_plugins=2,
        )

    @classmethod
    def default_active(cls) -> "ExecutionPolicy":
        """Create a default active testing policy."""
        return cls(
            testing_mode=TestingMode.ACTIVE,
            safe_mode=False,
            rate_limits={
                "default": RateLimitConfig(requests_per_minute=60, requests_per_hour=1000)
            },
            default_timeout=600,
            max_concurrent_jobs=5,
            max_concurrent_plugins=3,
        )

    @classmethod
    def default_safe(cls) -> "ExecutionPolicy":
        """Create a default safe mode policy."""
        return cls(
            testing_mode=TestingMode.SAFE,
            safe_mode=True,
            rate_limits={
                "default": RateLimitConfig(requests_per_minute=20, requests_per_hour=300)
            },
            default_timeout=300,
            max_concurrent_jobs=2,
            max_concurrent_plugins=1,
        )

    def get_rate_limit(self, key: str = "default") -> RateLimitConfig:
        """Get rate limit config for a key, falling back to default."""
        return self.rate_limits.get(key, self.rate_limits.get("default", RateLimitConfig()))

    def get_plugin_timeout(self, plugin_name: str) -> int:
        """Get timeout for a specific plugin, falling back to default."""
        return self.plugin_timeouts.get(plugin_name, self.default_timeout)

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled."""
        if self.enabled_plugins is not None:
            return plugin_name in self.enabled_plugins
        return plugin_name not in self.disabled_plugins

    def get_plugin_config(self, plugin_name: str) -> dict[str, Any]:
        """Get configuration for a specific plugin."""
        return self.plugin_configurations.get(plugin_name, {})
