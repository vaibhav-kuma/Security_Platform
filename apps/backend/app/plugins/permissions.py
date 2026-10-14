"""Plugin permission system and execution isolation."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.plugins.sdk.manifest import PluginPermission, ResourceLimits


class PermissionPolicy(str, Enum):
    """Permission policy modes."""
    DENY_ALL = "deny_all"  # No permissions by default
    ALLOW_SAFE = "allow_safe"  # Allow safe permissions only
    ALLOW_ALL = "allow_all"  # Allow all declared permissions (for trusted plugins)


@dataclass
class PermissionRule:
    """Rule for permission evaluation."""
    permission: PluginPermission
    allowed: bool
    conditions: dict[str, Any] = None  # e.g., {"domains": ["example.com"]}


class PermissionEvaluator:
    """Evaluates plugin permissions against policy."""

    # Safe permissions that don't require explicit approval
    SAFE_PERMISSIONS = {
        PluginPermission.CACHE_ACCESS,
    }

    # Dangerous permissions requiring explicit approval
    DANGEROUS_PERMISSIONS = {
        PluginPermission.PROCESS_EXECUTE,
        PluginPermission.FILE_WRITE,
        PluginPermission.SECRET_READ,
        PluginPermission.DATABASE_QUERY,
    }

    # Network permissions require egress allowlist
    NETWORK_PERMISSIONS = {
        PluginPermission.NETWORK_REQUEST,
    }

    def __init__(self, policy: PermissionPolicy = PermissionPolicy.ALLOW_SAFE):
        """Initialize evaluator with policy."""
        self.policy = policy
        self.custom_rules: list[PermissionRule] = []

    def add_rule(self, rule: PermissionRule) -> None:
        """Add custom permission rule."""
        self.custom_rules.append(rule)

    def evaluate(
        self,
        requested_permissions: list[PluginPermission],
        resource_limits: ResourceLimits,
        plugin_trusted: bool = False,
    ) -> tuple[bool, list[str], list[str]]:
        """
        Evaluate if requested permissions are allowed.

        Returns:
            Tuple of (allowed, granted_permissions, denied_permissions)
        """
        granted = []
        denied = []

        for perm in requested_permissions:
            allowed = self._check_permission(perm, resource_limits, plugin_trusted)
            if allowed:
                granted.append(perm.value)
            else:
                denied.append(perm.value)

        return len(denied) == 0, granted, denied

    def _check_permission(
        self,
        permission: PluginPermission,
        resource_limits: ResourceLimits,
        plugin_trusted: bool,
    ) -> bool:
        """Check if a single permission is allowed."""
        # Check custom rules first
        for rule in self.custom_rules:
            if rule.permission == permission:
                return rule.allowed

        # Trusted plugins get all declared permissions
        if plugin_trusted:
            return True

        # Policy-based evaluation
        if self.policy == PermissionPolicy.DENY_ALL:
            return False

        if self.policy == PermissionPolicy.ALLOW_ALL:
            return True

        # ALLOW_SAFE policy
        if permission in self.SAFE_PERMISSIONS:
            return True

        if permission in self.DANGEROUS_PERMISSIONS:
            return False  # Requires explicit approval

        if permission in self.NETWORK_PERMISSIONS:
            # Network requests allowed only with egress allowlist
            return len(resource_limits.network_egress_allowlist) > 0

        return True  # Default allow for unknown permissions

    def get_required_approvals(self, requested_permissions: list[PluginPermission]) -> list[PluginPermission]:
        """Get permissions that require explicit approval."""
        approvals = []
        for perm in requested_permissions:
            if not self._check_permission(perm, ResourceLimits(), plugin_trusted=False):
                approvals.append(perm)
        return approvals


class ExecutionIsolation:
    """Manages execution isolation for plugins."""

    def __init__(self):
        """Initialize isolation manager."""
        self.active_executions: dict[str, dict[str, Any]] = {}

    def create_sandbox(self, plugin_id: str, limits: ResourceLimits) -> dict[str, Any]:
        """Create execution sandbox for plugin."""
        sandbox = {
            "plugin_id": plugin_id,
            "limits": limits,
            "start_time": time.time(),
            "resources": {
                "cpu_time": 0,
                "memory_bytes": 0,
                "network_requests": 0,
            },
        }
        self.active_executions[plugin_id] = sandbox
        return sandbox

    def check_limits(self, plugin_id: str) -> tuple[bool, list[str]]:
        """Check if plugin execution is within limits."""
        sandbox = self.active_executions.get(plugin_id)
        if not sandbox:
            return False, ["No active sandbox"]

        limits = sandbox["limits"]
        resources = sandbox["resources"]
        violations = []

        # Check CPU time
        if resources["cpu_time"] > limits.time_seconds:
            violations.append(f"CPU time exceeded: {resources['cpu_time']}s > {limits.time_seconds}s")

        # Check memory
        if resources["memory_bytes"] > limits.memory_mb * 1024 * 1024:
            violations.append(f"Memory exceeded: {resources['memory_bytes']} > {limits.memory_mb}MB")

        return len(violations) == 0, violations

    def record_network_request(self, plugin_id: str, destination: str) -> bool:
        """Record and validate network request."""
        sandbox = self.active_executions.get(plugin_id)
        if not sandbox:
            return False

        limits = sandbox["limits"]
        allowlist = limits.network_egress_allowlist

        # Check against allowlist
        allowed = False
        for allowed_dest in allowlist:
            if self._match_destination(destination, allowed_dest):
                allowed = True
                break

        if allowed:
            sandbox["resources"]["network_requests"] += 1
            return True

        return False

    def _match_destination(self, destination: str, pattern: str) -> bool:
        """Match destination against allowlist pattern."""
        # Simple pattern matching - can be extended
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return destination.startswith(prefix)
        return destination == pattern

    def destroy_sandbox(self, plugin_id: str) -> dict[str, Any] | None:
        """Destroy sandbox and return final resource usage."""
        return self.active_executions.pop(plugin_id, None)


class NetworkPolicyManager:
    """Manages network policies for plugin execution."""

    def __init__(self):
        """Initialize network policy manager."""
        self.global_allowlist: set[str] = set()
        self.plugin_policies: dict[str, set[str]] = {}

    def add_global_allowlist(self, destinations: list[str]) -> None:
        """Add destinations to global allowlist."""
        self.global_allowlist.update(destinations)

    def set_plugin_policy(self, plugin_id: str, destinations: list[str]) -> None:
        """Set plugin-specific network policy."""
        self.plugin_policies[plugin_id] = set(destinations)

    def is_allowed(self, plugin_id: str, destination: str) -> bool:
        """Check if destination is allowed for plugin."""
        # Check plugin-specific policy first
        if plugin_id in self.plugin_policies:
            return self._match_any(destination, self.plugin_policies[plugin_id])

        # Fall back to global allowlist
        return self._match_any(destination, self.global_allowlist)

    def _match_any(self, destination: str, patterns: set[str]) -> bool:
        """Match destination against any pattern."""
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern.endswith("*"):
                if destination.startswith(pattern[:-1]):
                    return True
            if destination == pattern:
                return True
        return False


# Global instances
_permission_evaluator = PermissionEvaluator()
_execution_isolation = ExecutionIsolation()
_network_policy_manager = NetworkPolicyManager()


def get_permission_evaluator() -> PermissionEvaluator:
    """Get global permission evaluator."""
    return _permission_evaluator


def get_execution_isolation() -> ExecutionIsolation:
    """Get global execution isolation."""
    return _execution_isolation


def get_network_policy_manager() -> NetworkPolicyManager:
    """Get global network policy manager."""
    return _network_policy_manager


def evaluate_plugin_permissions(
    plugin_id: str,
    permissions: list[PluginPermission],
    limits: ResourceLimits,
    trusted: bool = False,
) -> tuple[bool, list[str], list[str]]:
    """Convenience function to evaluate plugin permissions."""
    evaluator = get_permission_evaluator()
    return evaluator.evaluate(permissions, limits, trusted)


def check_network_access(plugin_id: str, destination: str) -> bool:
    """Check if plugin can access network destination."""
    manager = get_network_policy_manager()
    return manager.is_allowed(plugin_id, destination)


# Need to import time
import time
