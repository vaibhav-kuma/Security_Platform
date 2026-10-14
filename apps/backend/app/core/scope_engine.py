"""Scope Engine - Core pattern matching for scope rule evaluation.

This module provides the core logic for evaluating whether a target
is in scope based on include/exclude rules with various target types.
"""

import ipaddress
from enum import Enum

from app.models.enums import ScopeRuleEffect, ScopeRuleTargetType, ScopeStatus


class MatchResult(Enum):
    """Result of scope rule evaluation."""
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    NO_MATCH = "no_match"


class ScopeEngine:
    """Evaluates targets against scope rules.

    Rules are evaluated in order. The first matching rule determines the result:
    - If an INCLUDE rule matches -> IN_SCOPE
    - If an EXCLUDE rule matches -> OUT_OF_SCOPE
    - If no rules match -> UNKNOWN (or default based on configuration)

    Supports target types:
    - DOMAIN: exact domain match (e.g., "example.com")
    - SUBDOMAIN_PATTERN: wildcard subdomain (e.g., "*.example.com")
    - IP: exact IP address (e.g., "192.168.1.1")
    - CIDR: CIDR notation (e.g., "192.168.1.0/24")
    - URL: URL pattern matching (e.g., "https://example.com/*")
    - API: API endpoint pattern (e.g., "api.example.com/v1/*")
    - APK: package name (e.g., "com.example.app")
    """

    def __init__(self, default_status: ScopeStatus = ScopeStatus.UNKNOWN):
        self.default_status = default_status
        self._compiled_patterns = {}

    def evaluate_target(
        self,
        target_value: str,
        target_type: ScopeRuleTargetType,
        rules: list,
    ) -> ScopeStatus:
        """Evaluate a target against a list of scope rules.

        Args:
            target_value: The value to check (domain, IP, URL, etc.)
            target_type: The type of target being evaluated
            rules: List of ScopeRule objects ordered by priority
            
        Returns:
            ScopeStatus indicating the authorization result
        """
        for rule in rules:
            if rule.target_type != target_type:
                continue

            match_result = self._match_rule(target_value, rule)
            if match_result == MatchResult.IN_SCOPE:
                return ScopeStatus.IN_SCOPE
            elif match_result == MatchResult.OUT_OF_SCOPE:
                return ScopeStatus.OUT_OF_SCOPE

        return self.default_status

    def evaluate_multiple_types(
        self,
        target_value: str,
        rules: list,
    ) -> ScopeStatus:
        """Evaluate a target against rules of multiple types.

        Useful when a target could match different rule types
        (e.g., a domain could match both DOMAIN and SUBDOMAIN_PATTERN rules).

        Rules are evaluated in their original order (first match wins).
        """
        # Evaluate rules in their original order - first match wins
        for rule in rules:
            match_result = self._match_rule(target_value, rule)
            if match_result == MatchResult.IN_SCOPE:
                return ScopeStatus.IN_SCOPE
            elif match_result == MatchResult.OUT_OF_SCOPE:
                return ScopeStatus.OUT_OF_SCOPE

        return self.default_status

    def _match_rule(self, target_value: str, rule) -> MatchResult:
        """Check if a target matches a specific rule."""
        pattern = rule.pattern.strip()

        if rule.target_type == ScopeRuleTargetType.DOMAIN:
            return self._match_domain(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.SUBDOMAIN_PATTERN:
            return self._match_subdomain_pattern(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.IP:
            return self._match_ip(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.CIDR:
            return self._match_cidr(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.URL:
            return self._match_url(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.API:
            return self._match_api(target_value, pattern, rule.effect)
        elif rule.target_type == ScopeRuleTargetType.APK:
            return self._match_apk(target_value, pattern, rule.effect)
        else:
            return MatchResult.NO_MATCH

    def _match_domain(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """Exact domain match (case-insensitive)."""
        if target.lower() == pattern.lower():
            return (
                MatchResult.IN_SCOPE
                if effect == ScopeRuleEffect.INCLUDE
                else MatchResult.OUT_OF_SCOPE
            )
        return MatchResult.NO_MATCH

    def _match_subdomain_pattern(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """Wildcard subdomain pattern matching.

        Patterns:
        - "*.example.com" matches "api.example.com", "www.example.com"
        - "example.com" matches exact domain only
        - "*.example.com" does NOT match "example.com" (no subdomain)
        - "*.example.com" does NOT match "evil.example.com.attacker.com" (suffix match only)
        """
        target = target.lower()
        pattern = pattern.lower()

        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            # Must have at least one subdomain part before the suffix
            # AND the suffix must match at a domain label boundary
            if target.endswith(suffix):
                # Check that the character before the suffix is a dot (or it's the start)
                prefix = target[:-len(suffix)]
                # prefix must be non-empty, not end with dot, and the full
                # match must be at a label boundary
                if prefix and not prefix.endswith(".") and (prefix + suffix == target):
                    # Verify the suffix starts at a label boundary (preceded
                    # by dot or is the entire domain)
                    # The suffix starts with ".", so we need to ensure it's
                    # at a label boundary
                    return (
                        MatchResult.IN_SCOPE
                        if effect == ScopeRuleEffect.INCLUDE
                        else MatchResult.OUT_OF_SCOPE
                    )
        elif target == pattern:
            return (
                MatchResult.IN_SCOPE
                if effect == ScopeRuleEffect.INCLUDE
                else MatchResult.OUT_OF_SCOPE
            )

        return MatchResult.NO_MATCH

    def _match_ip(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """Exact IP address match."""
        try:
            target_ip = ipaddress.ip_address(target)
            pattern_ip = ipaddress.ip_address(pattern)
            if target_ip == pattern_ip:
                return (
                    MatchResult.IN_SCOPE
                    if effect == ScopeRuleEffect.INCLUDE
                    else MatchResult.OUT_OF_SCOPE
                )
        except ValueError:
            pass
        return MatchResult.NO_MATCH

    def _match_cidr(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """CIDR network range matching.

        Uses strict=True to require valid CIDR network notation (e.g., 192.168.1.0/24).
        Host addresses like 192.168.1.5/24 are rejected to prevent ambiguity.
        """
        import ipaddress

        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(pattern, strict=True)
        except ValueError:
            return MatchResult.NO_MATCH

        if target_ip in network:
            return (
                MatchResult.IN_SCOPE
                if effect == ScopeRuleEffect.INCLUDE
                else MatchResult.OUT_OF_SCOPE
            )

        return MatchResult.NO_MATCH

    def _match_url(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """URL pattern matching with wildcard support.

        Patterns:
        - "https://example.com/*" matches any path under example.com
        - "https://example.com/api/*" matches /api/ paths
        - "https://example.com" matches exact URL
        """
        # Parse both URLs
        from urllib.parse import urlparse

        try:
            target_parsed = urlparse(target)
            pattern_parsed = urlparse(pattern)
        except ValueError:
            return MatchResult.NO_MATCH

        # Must have matching scheme
        if target_parsed.scheme != pattern_parsed.scheme:
            return MatchResult.NO_MATCH

        # Normalize netloc (host:port) - compare host only, ignore default ports
        target_host = target_parsed.netloc.split(":")[0].lower()
        pattern_host = pattern_parsed.netloc.split(":")[0].lower()

        # Handle default ports
        target_port = target_parsed.port
        pattern_port = pattern_parsed.port
        if target_port is None:
            target_port = 443 if target_parsed.scheme == "https" else 80
        if pattern_port is None:
            pattern_port = 443 if pattern_parsed.scheme == "https" else 80

        if target_host != pattern_host or target_port != pattern_port:
            return MatchResult.NO_MATCH

        # If pattern ends with *, match path prefix
        pattern_path = pattern_parsed.path.rstrip("/")
        target_path = target_parsed.path.rstrip("/")

        if pattern_path.endswith("*"):
            prefix = pattern_path[:-1]
            if target_path.startswith(prefix):
                return (
                    MatchResult.IN_SCOPE
                    if effect == ScopeRuleEffect.INCLUDE
                    else MatchResult.OUT_OF_SCOPE
                )
        elif target_path == pattern_path:
            # Also compare query params if present
            if target_parsed.query == pattern_parsed.query:
                return (
                    MatchResult.IN_SCOPE
                    if effect == ScopeRuleEffect.INCLUDE
                    else MatchResult.OUT_OF_SCOPE
                )

        return MatchResult.NO_MATCH

    def _match_api(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """API endpoint pattern matching.

        Similar to URL but for API endpoints specifically.
        """
        return self._match_url(target, pattern, effect)

    def _match_apk(self, target: str, pattern: str, effect: ScopeRuleEffect) -> MatchResult:
        """APK package name matching.

        Supports exact match and wildcard prefix:
        - "com.example.app" exact match
        - "com.example.*" matches any package under com.example
        """
        target = target.lower()
        pattern = pattern.lower()

        if pattern.endswith("*"):
            # Pattern like "com.example.*" - match all packages under com.example
            prefix = pattern[:-1]  # "com.example."
            if not prefix.endswith("."):
                return MatchResult.NO_MATCH
            if target.startswith(prefix) or target == prefix.rstrip("."):
                return MatchResult.IN_SCOPE if effect == ScopeRuleEffect.INCLUDE else MatchResult.OUT_OF_SCOPE
        elif target == pattern:
            return MatchResult.IN_SCOPE if effect == ScopeRuleEffect.INCLUDE else MatchResult.OUT_OF_SCOPE

        return MatchResult.NO_MATCH


def create_scope_engine(default_status: ScopeStatus = ScopeStatus.UNKNOWN) -> ScopeEngine:
    """Factory function to create a ScopeEngine instance."""
    return ScopeEngine(default_status=default_status)
