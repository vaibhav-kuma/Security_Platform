"""Unit tests for ScopeEngine."""

import pytest

from app.core.scope_engine import (
    create_scope_engine,
)
from app.models.enums import (
    ScopeRuleEffect,
    ScopeRuleTargetType,
)


class TestScopeEngine:
    """Test cases for ScopeEngine pattern matching."""

    @pytest.fixture
    def engine(self):
        return create_scope_engine()

    @pytest.fixture
    def sample_rules(self):
        """Create sample rules for testing."""
        from unittest.mock import Mock

        def make_rule(effect, target_type, pattern):
            rule = Mock()
            rule.effect = effect
            rule.target_type = target_type
            rule.pattern = pattern
            return rule

        return {
            "include_example_com": make_rule(
                ScopeRuleEffect.INCLUDE,
                ScopeRuleTargetType.DOMAIN,
                "example.com"
            ),
            "exclude_subdomain": make_rule(
                ScopeRuleEffect.EXCLUDE,
                ScopeRuleTargetType.SUBDOMAIN_PATTERN,
                "*.internal.example.com"
            ),
            "include_cidr": make_rule(
                ScopeRuleEffect.INCLUDE,
                ScopeRuleTargetType.CIDR,
                "192.168.1.0/24"
            ),
            "exclude_ip": make_rule(
                ScopeRuleEffect.EXCLUDE,
                ScopeRuleTargetType.IP,
                "10.0.0.1"
            ),
            "include_url": make_rule(
                ScopeRuleEffect.INCLUDE,
                ScopeRuleTargetType.URL,
                "https://api.example.com/*"
            ),
            "exclude_apk": make_rule(
                ScopeRuleEffect.EXCLUDE,
                ScopeRuleTargetType.APK,
                "com.malicious.*"
            ),
        }

    # ---- DOMAIN tests ----
    def test_domain_exact_match_include(self, engine, sample_rules):
        result = engine.evaluate_target(
            "example.com",
            "domain",
            [sample_rules["include_example_com"]]
        )
        assert result == "in_scope"

    def test_domain_exact_match_exclude(self, engine, sample_rules):
        result = engine.evaluate_target(
            "example.com",
            "domain",
            [sample_rules["exclude_subdomain"]]  # This won't match as domain
        )
        assert result == "unknown"

    def test_domain_case_insensitive(self, engine, sample_rules):
        result = engine.evaluate_target(
            "EXAMPLE.COM",
            "domain",
            [sample_rules["include_example_com"]]
        )
        assert result == "in_scope"

    def test_domain_no_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "other.com",
            "domain",
            [sample_rules["include_example_com"]]
        )
        assert result == "unknown"

    # ---- SUBDOMAIN_PATTERN tests ----
    def test_subdomain_pattern_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "api.internal.example.com",
            "subdomain_pattern",
            [sample_rules["exclude_subdomain"]]
        )
        assert result == "out_of_scope"

    def test_subdomain_pattern_no_match_exact_domain(self, engine, sample_rules):
        # "*.internal.example.com" should NOT match "internal.example.com" (no subdomain)
        result = engine.evaluate_target(
            "internal.example.com",
            "subdomain_pattern",
            [sample_rules["exclude_subdomain"]]
        )
        assert result == "unknown"

    def test_subdomain_pattern_no_match_different_domain(self, engine, sample_rules):
        result = engine.evaluate_target(
            "api.other.com",
            "subdomain_pattern",
            [sample_rules["exclude_subdomain"]]
        )
        assert result == "unknown"

    def test_subdomain_pattern_multiple_levels(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.INCLUDE
        rule.target_type = "subdomain_pattern"
        rule.pattern = "*.example.com"

        engine = create_scope_engine()
        result = engine.evaluate_target(
            "deep.nested.example.com",
            "subdomain_pattern",
            [rule]
        )
        assert result == "in_scope"

    # ---- IP tests ----
    def test_ip_exact_match_include(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.INCLUDE
        rule.target_type = "ip"
        rule.pattern = "192.168.1.100"

        engine = create_scope_engine()
        result = engine.evaluate_target("192.168.1.100", "ip", [rule])
        assert result == "in_scope"

    def test_ip_exact_match_exclude(self, engine, sample_rules):
        result = engine.evaluate_target("10.0.0.1", "ip", [sample_rules["exclude_ip"]])
        assert result == "out_of_scope"

    def test_ip_no_match(self, engine, sample_rules):
        result = engine.evaluate_target("10.0.0.2", "ip", [sample_rules["exclude_ip"]])
        assert result == "unknown"

    # ---- CIDR tests ----
    def test_cidr_match_include(self, engine, sample_rules):
        result = engine.evaluate_target("192.168.1.50", "cidr", [sample_rules["include_cidr"]])
        assert result == "in_scope"

    def test_cidr_match_exclude(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.EXCLUDE
        rule.target_type = "cidr"
        rule.pattern = "10.0.0.0/8"

        engine = create_scope_engine()
        result = engine.evaluate_target("10.1.2.3", "cidr", [rule])
        assert result == "out_of_scope"

    def test_cidr_ipv6(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.INCLUDE
        rule.target_type = "cidr"
        rule.pattern = "2001:db8::/32"

        engine = create_scope_engine()
        result = engine.evaluate_target("2001:db8::1", "cidr", [rule])
        assert result == "in_scope"

    # ---- URL tests ----
    def test_url_wildcard_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "https://api.example.com/v1/users",
            "url",
            [sample_rules["include_url"]]
        )
        assert result == "in_scope"

    def test_url_exact_match(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.INCLUDE
        rule.target_type = "url"
        rule.pattern = "https://example.com"

        engine = create_scope_engine()
        result = engine.evaluate_target("https://example.com", "url", [rule])
        assert result == "in_scope"

    def test_url_no_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "https://other.com/api",
            "url",
            [sample_rules["include_url"]]
        )
        assert result == "unknown"

    # ---- APK tests ----
    def test_apk_wildcard_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "com.malicious.app",
            "apk",
            [sample_rules["exclude_apk"]]
        )
        assert result == "out_of_scope"

    def test_apk_exact_match(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        rule = Mock()
        rule.effect = ScopeRuleEffect.INCLUDE
        rule.target_type = "apk"
        rule.pattern = "com.example.app"

        engine = create_scope_engine()
        result = engine.evaluate_target("com.example.app", "apk", [rule])
        assert result == "in_scope"

    def test_apk_no_match(self, engine, sample_rules):
        result = engine.evaluate_target(
            "com.legitimate.app",
            "apk",
            [sample_rules["exclude_apk"]]
        )
        assert result == "unknown"

    # ---- Rule ordering / priority tests ----
    def test_first_matching_rule_wins(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        # First rule includes, second excludes - first should win
        include_rule = Mock()
        include_rule.effect = ScopeRuleEffect.INCLUDE
        include_rule.target_type = "domain"
        include_rule.pattern = "example.com"

        exclude_rule = Mock()
        exclude_rule.effect = ScopeRuleEffect.EXCLUDE
        exclude_rule.target_type = "domain"
        exclude_rule.pattern = "example.com"

        engine = create_scope_engine()
        result = engine.evaluate_target("example.com", "domain", [include_rule, exclude_rule])
        assert result == "in_scope"

    def test_exclude_overrides_when_first(self, engine):
        from unittest.mock import Mock

        from app.models.enums import ScopeRuleEffect

        # First rule excludes, second includes - first should win
        exclude_rule = Mock()
        exclude_rule.effect = ScopeRuleEffect.EXCLUDE
        exclude_rule.target_type = "domain"
        exclude_rule.pattern = "example.com"

        include_rule = Mock()
        include_rule.effect = ScopeRuleEffect.INCLUDE
        include_rule.target_type = "domain"
        include_rule.pattern = "example.com"

        engine = create_scope_engine()
        result = engine.evaluate_target("example.com", "domain", [exclude_rule, include_rule])
        assert result == "out_of_scope"

    # ---- Multiple target types ----
    def test_evaluate_multiple_types(self, engine, sample_rules):
        # Target is a domain, but we have rules for multiple types
        result = engine.evaluate_multiple_types("example.com", [
            sample_rules["include_example_com"],  # domain
            sample_rules["include_cidr"],  # cidr - won't match
        ])
        assert result == "in_scope"

    def test_default_status(self, engine):
        # No rules matching should return default
        result = engine.evaluate_target("unknown.com", "domain", [])
        assert result == "unknown"

    def test_custom_default_status(self):
        engine = create_scope_engine(default_status="out_of_scope")
        result = engine.evaluate_target("unknown.com", "domain", [])
        assert result == "out_of_scope"
