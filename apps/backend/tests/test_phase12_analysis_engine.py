"""Unit tests for Phase 12: Security Analysis Engine components."""

import pytest
from uuid import uuid4

from app.core.analysis_engine import IngestionContext, IngestionResult, get_analysis_engine
from app.core.cvss import (
    CVSSVector,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    calculate_cvss_base_score,
    get_default_vector,
)
from app.core.evidence_sanitizer import (
    EvidenceSanitizer,
    SecretRedactor,
    PIIRedactor,
    CredentialDetector,
    RedactionReason,
    sanitize_evidence,
)
from app.core.finding_correlation import (
    FindingCorrelationEngine,
    CorrelationType,
    NormalizedFindingKey,
    normalize_vulnerability_type,
    normalize_asset_value,
    get_correlation_engine,
)
from app.core.manual_review import (
    ManualReviewQueue,
    ReviewPriority,
    ReviewReason,
    ReviewStatus,
    DEFAULT_REVIEW_POLICY,
    should_queue_for_review,
)
from app.models.detection import DetectionRule, Finding, Observation
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingStatus,
    ObservationType,
    ReviewPriority as ReviewPriorityEnum,
    ReviewReason as ReviewReasonEnum,
    ReviewStatus as ReviewStatusEnum,
    Severity,
)


# =============================================================================
# Evidence Sanitizer Tests
# =============================================================================

class TestSecretRedactor:
    def test_redact_aws_keys(self):
        redactor = SecretRedactor()
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_AWS_ACCESS_KEY_ID" in result.redacted

    def test_redact_github_token(self):
        redactor = SecretRedactor()
        text = "ghp_12345678901234567890123456789012345678"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_GITHUB_TOKEN" in result.redacted

    def test_redact_jwt(self):
        redactor = SecretRedactor()
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_JWT_TOKEN" in result.redacted

    def test_redact_private_key(self):
        redactor = SecretRedactor()
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_PRIVATE_KEY" in result.redacted

    def test_no_false_positive_on_normal_text(self):
        redactor = SecretRedactor()
        text = "This is a normal sentence without secrets."
        result = redactor.redact(text)
        assert not result.was_redacted
        assert result.redacted == text


class TestPIIRedactor:
    def test_redact_email(self):
        redactor = PIIRedactor()
        text = "Contact us at user@example.com for more info."
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_EMAIL" in result.redacted

    def test_redact_phone_us(self):
        redactor = PIIRedactor()
        text = "Call us at 555-123-4567 or (555) 123-4567"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_PHONE_US" in result.redacted

    def test_redact_ssn(self):
        redactor = PIIRedactor()
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_SSN" in result.redacted

    def test_redact_private_ip(self):
        redactor = PIIRedactor()
        text = "Internal server at 192.168.1.100"
        result = redactor.redact(text)
        assert result.was_redacted
        assert "REDACTED_PRIVATE_IP" in result.redacted


class TestCredentialDetector:
    def test_redact_basic_auth_in_url(self):
        detector = CredentialDetector()
        text = "https://user:password@example.com/api"
        result = detector.redact(text)
        assert result.was_redacted
        assert "REDACTED_BASIC_AUTH_IN_URL" in result.redacted

    def test_redact_auth_header(self):
        detector = CredentialDetector()
        text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
        result = detector.redact(text)
        assert result.was_redacted
        assert "REDACTED_AUTH_HEADER" in result.redacted

    def test_redact_form_password(self):
        detector = CredentialDetector()
        text = "password=mysecretpassword123"
        result = detector.redact(text)
        assert result.was_redacted
        assert "REDACTED_FORM_PASSWORD" in result.redacted


class TestEvidenceSanitizer:
    def test_sanitize_combined(self):
        sanitizer = EvidenceSanitizer()
        stripe_secret = "sk_" + "live_123456789012345678901234"
        text = """
        API Key: {stripe_secret}
        Email: user@example.com
        Auth: Bearer token12345678901234567890
        """
        text = text.format(stripe_secret=stripe_secret)
        result = sanitizer.sanitize(text)
        assert result.was_redacted
        assert "REDACTED_STRIPE_SECRET_KEY" in result.redacted
        assert "REDACTED_EMAIL" in result.redacted
        # Bearer token gets redacted as BEARER_TOKEN, not AUTH_HEADER
        assert "REDACTED_BEARER_TOKEN" in result.redacted

    def test_sanitize_dict(self):
        sanitizer = EvidenceSanitizer()
        data = {
            "request": {
                "headers": {"Authorization": "Bearer secret12345678901234567890"},
                "body": {"api_key": "sk_" + "live_abcdefghijklmnopqrstuvwxyz"}
            },
            "response": {"user_email": "user@example.com"}
        }
        result = sanitizer.sanitize_dict(data)
        # The Authorization header with Bearer token gets sanitized
        assert "REDACTED_BEARER_TOKEN" in str(result) or "REDACTED_AUTH_HEADER" in str(result) or "***" in str(result)
        assert "REDACTED_STRIPE_SECRET_KEY" in str(result)
        assert "REDACTED_EMAIL" in str(result)


# =============================================================================
# CVSS Tests
# =============================================================================

class TestCVSS:
    def test_critical_vector(self):
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )
        score = calculate_cvss_base_score(vector)
        assert score.base_score == 9.8
        assert score.severity == "CRITICAL"

    def test_high_vector(self):
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )
        score = calculate_cvss_base_score(vector)
        assert 7.0 <= score.base_score <= 8.9
        assert score.severity == "HIGH"

    def test_medium_vector(self):
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        score = calculate_cvss_base_score(vector)
        assert 4.0 <= score.base_score <= 6.9
        assert score.severity == "MEDIUM"

    def test_low_vector(self):
        vector = CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )
        score = calculate_cvss_base_score(vector)
        assert 0.1 <= score.base_score <= 3.9
        assert score.severity == "LOW"

    def test_vector_string_roundtrip(self):
        vector = get_default_vector("SQL_INJECTION")
        assert vector is not None
        vector_str = vector.to_string()
        parsed = CVSSVector.from_string(vector_str)
        assert parsed.attack_vector == vector.attack_vector
        assert parsed.attack_complexity == vector.attack_complexity

    def test_default_vectors_exist(self):
        # Test that default vectors exist for common categories
        for category in ["SQL_INJECTION", "XSS_REFLECTED", "SSRF", "BOLA", "IDOR"]:
            vector = get_default_vector(category)
            assert vector is not None, f"Missing default vector for {category}"
            score = calculate_cvss_base_score(vector)
            assert score.base_score > 0


# =============================================================================
# Finding Correlation Tests
# =============================================================================

class TestFindingCorrelation:
    def test_normalize_vulnerability_type(self):
        assert normalize_vulnerability_type("sql injection") == "SQL_INJECTION"
        assert normalize_vulnerability_type("XSS") == "XSS"
        assert normalize_vulnerability_type("BOLA") == "BOLA"
        assert normalize_vulnerability_type("idor") == "IDOR"

    def test_normalize_asset_value(self):
        assert normalize_asset_value("Example.com", "domain") == "example.com"
        assert normalize_asset_value("API.EXAMPLE.COM", "subdomain") == "api.example.com"
        assert normalize_asset_value("192.168.1.1", "ip") == "192.168.1.1"
        assert "https://api.example.com/v1/users" in normalize_asset_value(
            "https://api.example.com/v1/users/", "url"
        )

    def test_compute_normalized_key(self):
        engine = FindingCorrelationEngine()
        key = engine.compute_normalized_key(
            asset_value="example.com",
            asset_type="domain",
            vulnerability_type="SQL_INJECTION",
            location="/api/users",
            parameter="id",
            rule_identity="rule_001",
            http_method="GET",
        )
        assert key.asset_value == "example.com"
        assert key.asset_type == "domain"
        assert key.vulnerability_type == "SQL_INJECTION"

    def test_exact_duplicate_detection(self):
        engine = FindingCorrelationEngine()
        key1 = engine.compute_normalized_key(
            asset_value="example.com", asset_type="domain",
            vulnerability_type="SQL_INJECTION", location="/api/users",
            parameter="id", rule_identity="rule_001", http_method="GET"
        )
        key2 = engine.compute_normalized_key(
            asset_value="example.com", asset_type="domain",
            vulnerability_type="SQL_INJECTION", location="/api/users",
            parameter="id", rule_identity="rule_001", http_method="GET"
        )
        assert key1.to_tuple() == key2.to_tuple()

    def test_similarity_calculation(self):
        engine = FindingCorrelationEngine()
        key1 = engine.compute_normalized_key(
            asset_value="example.com", asset_type="domain",
            vulnerability_type="SQL_INJECTION", location="/api/users",
            parameter="id", rule_identity="rule_001", http_method="GET"
        )
        key2 = engine.compute_normalized_key(
            asset_value="example.com", asset_type="domain",
            vulnerability_type="SQL_INJECTION", location="/api/users",
            parameter="user_id", rule_identity="rule_001", http_method="GET"
        )
        similarity = engine._calculate_similarity(key1, key2)
        assert similarity > 0.8  # High similarity, different parameter


# =============================================================================
# Manual Review Tests
# =============================================================================

class TestManualReview:
    def test_should_queue_low_confidence(self):
        from unittest.mock import Mock
        observation = Mock()
        observation.confidence_hint = Confidence.LOW
        observation.severity_hint = Severity.MEDIUM
        observation.observation_type = ObservationType.RESPONSE_BEHAVIOR
        observation.scope_status = "in_scope"

        detection_rule = Mock()  # Provide detection rule so HEURISTIC_ONLY doesn't trigger
        should_queue, reason, priority = should_queue_for_review(observation, detection_rule, DEFAULT_REVIEW_POLICY)
        assert should_queue
        assert reason == ReviewReason.LOW_CONFIDENCE

    def test_should_queue_high_severity(self):
        from unittest.mock import Mock
        observation = Mock()
        observation.confidence_hint = Confidence.HIGH
        observation.severity_hint = Severity.CRITICAL
        observation.observation_type = ObservationType.RESPONSE_BEHAVIOR
        observation.scope_status = "in_scope"

        detection_rule = Mock()  # Provide detection rule so HEURISTIC_ONLY doesn't trigger
        should_queue, reason, priority = should_queue_for_review(observation, detection_rule, DEFAULT_REVIEW_POLICY)
        assert should_queue
        assert reason == ReviewReason.AMBIGUOUS_SEVERITY
        assert priority == ReviewPriority.HIGH

    def test_should_queue_heuristic_only(self):
        from unittest.mock import Mock
        observation = Mock()
        observation.confidence_hint = Confidence.HIGH
        observation.severity_hint = Severity.MEDIUM
        observation.observation_type = ObservationType.RESPONSE_BEHAVIOR
        observation.scope_status = "in_scope"

        should_queue, reason, priority = should_queue_for_review(observation, None, DEFAULT_REVIEW_POLICY)
        assert should_queue
        assert reason == ReviewReason.HEURISTIC_ONLY

    def test_should_not_queue_high_confidence_medium_severity(self):
        from unittest.mock import Mock
        observation = Mock()
        observation.confidence_hint = Confidence.HIGH
        observation.severity_hint = Severity.MEDIUM
        observation.observation_type = ObservationType.RESPONSE_BEHAVIOR
        observation.scope_status = "in_scope"

        detection_rule = Mock()
        should_queue, reason, priority = should_queue_for_review(observation, detection_rule, DEFAULT_REVIEW_POLICY)
        assert not should_queue


# =============================================================================
# Analysis Engine Integration Tests
# =============================================================================

class TestAnalysisEngineIntegration:
    def test_ingestion_context_creation(self):
        context = IngestionContext(
            project_id=uuid4(),
            scan_id=uuid4(),
            asset_id=uuid4(),
            source="scanner",
            scanner_name="test_scanner",
        )
        assert context.project_id is not None
        assert context.source == "scanner"

    def test_ingestion_result_enum(self):
        assert IngestionResult.OBSERVATION_CREATED.value == "observation_created"
        assert IngestionResult.FINDING_PROMOTED.value == "finding_promoted"
        assert IngestionResult.QUEUED_FOR_REVIEW.value == "queued_for_review"
        assert IngestionResult.DUPLICATE_OBSERVATION.value == "duplicate_observation"
        assert IngestionResult.OUT_OF_SCOPE.value == "out_of_scope"
        assert IngestionResult.ERROR.value == "error"


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])