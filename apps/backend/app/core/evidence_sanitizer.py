"""Secret redaction, PII detection, and credential detection for evidence sanitization.

This module provides the core redaction pipeline components that must process
ALL evidence before storage or display. Never bypass these components.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class RedactionReason(Enum):
    """Reason for redaction - used for audit trail."""

    SECRET = "secret"
    PII = "pii"
    CREDENTIAL = "credential"
    TOKEN = "token"
    KEY = "key"
    INTERNAL = "internal"
    CUSTOM = "custom"


@dataclass(frozen=True)
class RedactionMatch:
    """A single redaction match with context."""

    reason: RedactionReason
    pattern_name: str
    match_text: str
    start: int
    end: int
    replacement: str
    confidence: float  # 0.0 - 1.0


@dataclass(frozen=True)
class RedactionResult:
    """Result of redacting a piece of content."""

    original: str
    redacted: str
    matches: list[RedactionMatch]
    was_redacted: bool


# =============================================================================
# SecretRedactor - Detects and redacts API keys, tokens, secrets
# =============================================================================

class SecretRedactor:
    """Redacts secrets, API keys, tokens, and other credentials from text."""

    # Common secret patterns with high confidence
    SECRET_PATTERNS: list[tuple[str, str, RedactionReason, float]] = [
        # AWS
        (r"\b(AKIA[0-9A-Z]{16})\b", "AWS_ACCESS_KEY_ID", RedactionReason.KEY, 0.99),
        (r"\b(aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40})\b", "AWS_SECRET_ACCESS_KEY", RedactionReason.SECRET, 0.99),
        # Generic API keys
        (r"\b(api[_-]?key\s*[=:]\s*[A-Za-z0-9_\-]{20,})\b", "GENERIC_API_KEY", RedactionReason.KEY, 0.85),
        (r"\b(secret[_-]?key\s*[=:]\s*[A-Za-z0-9_\-]{20,})\b", "SECRET_KEY", RedactionReason.SECRET, 0.9),
        # GitHub
        (r"\b(gh[opsu]_[A-Za-z0-9_]{36,})\b", "GITHUB_TOKEN", RedactionReason.TOKEN, 0.99),
        # GitLab
        (r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", "GITLAB_TOKEN", RedactionReason.TOKEN, 0.99),
        # Slack
        (r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", "SLACK_TOKEN", RedactionReason.TOKEN, 0.99),
        # Stripe
        (r"\b(sk_live_[A-Za-z0-9]{24,})\b", "STRIPE_SECRET_KEY", RedactionReason.KEY, 0.99),
        (r"\b(pk_live_[A-Za-z0-9]{24,})\b", "STRIPE_PUBLISHABLE_KEY", RedactionReason.KEY, 0.9),
        # Generic Bearer tokens
        (r"\b(Bearer\s+[A-Za-z0-9_\-=.]{20,})\b", "BEARER_TOKEN", RedactionReason.TOKEN, 0.8),
        # JWT tokens (compact serialization)
        (r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "JWT_TOKEN", RedactionReason.TOKEN, 0.95),
        # Private keys (PEM)
        (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "PRIVATE_KEY", RedactionReason.KEY, 0.99),
        # Database URLs with credentials
        (r"\b(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+", "DATABASE_URL_WITH_CREDS", RedactionReason.CREDENTIAL, 0.95),
        # Generic password in config
        (r"\b(password\s*[=:]\s*[^\s]{8,})\b", "PASSWORD_IN_CONFIG", RedactionReason.CREDENTIAL, 0.8),
        # SSH keys
        (r"ssh-(rsa|ed25519|ecdsa) [A-Za-z0-9+/=]{100,}", "SSH_PUBLIC_KEY", RedactionReason.KEY, 0.9),
        # Docker registry auth
        (r"\b(docker login -u [^ ]+ -p [^ ]+)\b", "DOCKER_LOGIN", RedactionReason.CREDENTIAL, 0.9),
        # Kubernetes service account tokens
        (r"\b(eyJhbGciOiJSUzI1NiIsImtpZCI6)[A-Za-z0-9_\-=.]{50,}", "K8S_SA_TOKEN", RedactionReason.TOKEN, 0.9),
        # Azure
        (r"\b(AccountKey=[A-Za-z0-9+/=]{88})\b", "AZURE_STORAGE_KEY", RedactionReason.KEY, 0.99),
        # GCP
        (r"\b(\"type\":\s*\"service_account\"[\s\S]{100,}?\"private_key\":\s*\")", "GCP_SERVICE_ACCOUNT", RedactionReason.KEY, 0.95),
        # Heroku
        (r"\b(heroku_[A-Za-z0-9]{32,})\b", "HEROKU_API_KEY", RedactionReason.KEY, 0.95),
        # npm
        (r"\b(npm_[A-Za-z0-9]{32,})\b", "NPM_TOKEN", RedactionReason.TOKEN, 0.95),
        # Generic high-entropy strings (potential secrets)
        (r"\b([A-Za-z0-9+/=]{40,})\b", "HIGH_ENTROPY_STRING", RedactionReason.SECRET, 0.3),
    ]

    def __init__(self, custom_patterns: list[tuple[str, str, RedactionReason, float]] | None = None) -> None:
        """Initialize with optional custom patterns.

        Args:
            custom_patterns: List of (regex, name, reason, confidence) tuples
        """
        self._patterns = self.SECRET_PATTERNS.copy()
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        # Pre-compile regexes
        self._compiled = [(re.compile(pattern, re.IGNORECASE), name, reason, conf) for pattern, name, reason, conf in self._patterns]

    def find_matches(self, text: str) -> list[RedactionMatch]:
        """Find all secret matches in text without redacting."""
        matches = []
        for regex, name, reason, confidence in self._compiled:
            for match in regex.finditer(text):
                matches.append(RedactionMatch(
                    reason=reason,
                    pattern_name=name,
                    match_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    replacement=self._generate_replacement(name),
                    confidence=confidence,
                ))
        # Sort by position, then by confidence (highest first)
        matches.sort(key=lambda m: (m.start, -m.confidence))
        return matches

    def redact(self, text: str) -> RedactionResult:
        """Redact all secrets from text."""
        matches = self.find_matches(text)
        if not matches:
            return RedactionResult(original=text, redacted=text, matches=[], was_redacted=False)

        # Build redacted text by replacing from end to start
        redacted = text
        for match in reversed(matches):
            redacted = redacted[:match.start] + match.replacement + redacted[match.end:]

        return RedactionResult(
            original=text,
            redacted=redacted,
            matches=matches,
            was_redacted=True,
        )

    def _generate_replacement(self, pattern_name: str) -> str:
        """Generate a replacement string for a pattern."""
        return f"[REDACTED_{pattern_name}]"


# =============================================================================
# PIIRedactor - Detects and redacts personally identifiable information
# =============================================================================

class PIIRedactor:
    """Redacts personally identifiable information from text."""

    PII_PATTERNS: list[tuple[str, str, RedactionReason, float]] = [
        # Email addresses
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL", RedactionReason.PII, 0.95),
        # Phone numbers (various formats)
        (r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", "PHONE_US", RedactionReason.PII, 0.85),
        (r"\b\+[1-9]\d{1,14}\b", "PHONE_INTERNATIONAL", RedactionReason.PII, 0.8),
        # Social Security Numbers (US)
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN", RedactionReason.PII, 0.9),
        # Credit card numbers (Luhn check not performed here - pattern only)
        (r"\b(?:\d[ -]*?){13,16}\b", "CREDIT_CARD", RedactionReason.PII, 0.5),
        # IP addresses (could be internal infrastructure)
        (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "PRIVATE_IP", RedactionReason.INTERNAL, 0.9),
        # IPv6 private
        (r"\b(?:fc00:|fd00:)[0-9a-f:]+", "IPV6_PRIVATE", RedactionReason.INTERNAL, 0.85),
        # MAC addresses
        (r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", "MAC_ADDRESS", RedactionReason.INTERNAL, 0.9),
        # UUIDs (could be internal IDs)
        (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "UUID", RedactionReason.INTERNAL, 0.4),
        # Names (heuristic - capitalized words, may have false positives)
        # Disabled by default due to false positives - enable with custom patterns
    ]

    def __init__(self, custom_patterns: list[tuple[str, str, RedactionReason, float]] | None = None, enabled: bool = True) -> None:
        """Initialize PII redactor.

        Args:
            custom_patterns: Additional patterns
            enabled: Whether PII redaction is enabled (can be disabled for low false-positive needs)
        """
        self._enabled = enabled
        self._patterns = self.PII_PATTERNS.copy()
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        self._compiled = [(re.compile(pattern), name, reason, conf) for pattern, name, reason, conf in self._patterns]

    def find_matches(self, text: str) -> list[RedactionMatch]:
        if not self._enabled:
            return []
        matches = []
        for regex, name, reason, confidence in self._compiled:
            for match in regex.finditer(text):
                matches.append(RedactionMatch(
                    reason=reason,
                    pattern_name=name,
                    match_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    replacement=self._generate_replacement(name),
                    confidence=confidence,
                ))
        matches.sort(key=lambda m: (m.start, -m.confidence))
        return matches

    def redact(self, text: str) -> RedactionResult:
        if not self._enabled:
            return RedactionResult(original=text, redacted=text, matches=[], was_redacted=False)
        matches = self.find_matches(text)
        if not matches:
            return RedactionResult(original=text, redacted=text, matches=[], was_redacted=False)
        redacted = text
        for match in reversed(matches):
            redacted = redacted[:match.start] + match.replacement + redacted[match.end:]
        return RedactionResult(original=text, redacted=redacted, matches=matches, was_redacted=True)

    def _generate_replacement(self, pattern_name: str) -> str:
        return f"[REDACTED_{pattern_name}]"


# =============================================================================
# CredentialDetector - Specialized detector for authentication credentials
# =============================================================================

class CredentialDetector:
    """Detects authentication credentials in various formats."""

    CREDENTIAL_PATTERNS: list[tuple[str, str, RedactionReason, float]] = [
        # Basic auth in URLs
        (r"\bhttps?://[^:]+:[^@]+@", "BASIC_AUTH_IN_URL", RedactionReason.CREDENTIAL, 0.95),
        # Authorization headers
        (r"\bAuthorization:\s*(Basic|Bearer|Digest|OAuth|ApiKey)\s+[A-Za-z0-9+/=_\-]{10,}", "AUTH_HEADER", RedactionReason.CREDENTIAL, 0.95),
        # Cookie with session
        (r"\b(session|sessionid|sid|auth_token|access_token|refresh_token|jwt)=[A-Za-z0-9+/=_\-]{10,}", "SESSION_COOKIE", RedactionReason.CREDENTIAL, 0.9),
        # Form passwords
        (r"\b(password|passwd|pwd)\s*[=:]\s*[^\s&]{4,}", "FORM_PASSWORD", RedactionReason.CREDENTIAL, 0.85),
        # OAuth tokens
        (r"\b(ya29\.[A-Za-z0-9_\-]{50,}|ya29\.[A-Za-z0-9_\-]{100,})\b", "OAUTH_GOOGLE", RedactionReason.TOKEN, 0.95),
        # API keys in headers
        (r"\b(X-API-Key|X-Auth-Token|X-Access-Token):\s*[A-Za-z0-9_\-]{20,}", "API_KEY_HEADER", RedactionReason.KEY, 0.9),
        # Database connection strings
        (r"\b(Server|Data Source|Host|ServerName)=[^;]+;.*(Uid|User ID|Username|Password|Pwd)=[^;]+", "DB_CONNECTION_STRING", RedactionReason.CREDENTIAL, 0.9),
        # .env style
        (r"\b[A-Z_]+(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS)\s*=\s*[^\s#]+", "ENV_VAR_SECRET", RedactionReason.SECRET, 0.85),
    ]

    def __init__(self, custom_patterns: list[tuple[str, str, RedactionReason, float]] | None = None) -> None:
        self._patterns = self.CREDENTIAL_PATTERNS.copy()
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        self._compiled = [(re.compile(pattern, re.IGNORECASE), name, reason, conf) for pattern, name, reason, conf in self._patterns]

    def find_matches(self, text: str) -> list[RedactionMatch]:
        matches = []
        for regex, name, reason, confidence in self._compiled:
            for match in regex.finditer(text):
                matches.append(RedactionMatch(
                    reason=reason,
                    pattern_name=name,
                    match_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    replacement=self._generate_replacement(name),
                    confidence=confidence,
                ))
        matches.sort(key=lambda m: (m.start, -m.confidence))
        return matches

    def redact(self, text: str) -> RedactionResult:
        matches = self.find_matches(text)
        if not matches:
            return RedactionResult(original=text, redacted=text, matches=[], was_redacted=False)
        redacted = text
        for match in reversed(matches):
            redacted = redacted[:match.start] + match.replacement + redacted[match.end:]
        return RedactionResult(original=text, redacted=redacted, matches=matches, was_redacted=True)

    def _generate_replacement(self, pattern_name: str) -> str:
        return f"[REDACTED_{pattern_name}]"


# =============================================================================
# EvidenceSanitizer - Main pipeline combining all redactors
# =============================================================================

class EvidenceSanitizer:
    """Main evidence sanitization pipeline.

    Combines SecretRedactor, PIIRedactor, and CredentialDetector.
    All evidence MUST pass through this before storage or display.
    """

    def __init__(
        self,
        secret_redactor: SecretRedactor | None = None,
        pii_redactor: PIIRedactor | None = None,
        credential_detector: CredentialDetector | None = None,
        enable_pii: bool = True,
    ) -> None:
        """Initialize sanitizer with optional custom redactors."""
        self.secret_redactor = secret_redactor or SecretRedactor()
        self.pii_redactor = pii_redactor or PIIRedactor(enabled=enable_pii)
        self.credential_detector = credential_detector or CredentialDetector()

    def sanitize(self, content: str, evidence_type: str | None = None) -> RedactionResult:
        """Sanitize evidence content through all redactors.

        Args:
            content: Raw evidence content
            evidence_type: Type of evidence (for logging/context)

        Returns:
            RedactionResult with redacted content and all matches
        """
        # Order matters: credentials first (most specific), then secrets, then PII
        current = content
        all_matches: list[RedactionMatch] = []

        # Credential detector (most specific patterns)
        cred_result = self.credential_detector.redact(current)
        all_matches.extend(cred_result.matches)
        current = cred_result.redacted

        # Secret redactor
        secret_result = self.secret_redactor.redact(current)
        all_matches.extend(secret_result.matches)
        current = secret_result.redacted

        # PII redactor
        pii_result = self.pii_redactor.redact(current)
        all_matches.extend(pii_result.matches)
        current = pii_result.redacted

        was_redacted = cred_result.was_redacted or secret_result.was_redacted or pii_result.was_redacted

        return RedactionResult(
            original=content,
            redacted=current,
            matches=all_matches,
            was_redacted=was_redacted,
        )

    def sanitize_dict(self, data: dict[str, Any], evidence_type: str | None = None) -> dict[str, Any]:
        """Sanitize a dictionary recursively (for JSON evidence)."""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized = self.sanitize(value, evidence_type)
                result[key] = sanitized.redacted
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value, evidence_type)
            elif isinstance(value, list):
                result[key] = [
                    self.sanitize_dict(item, evidence_type) if isinstance(item, dict)
                    else self.sanitize(item, evidence_type).redacted if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result


# =============================================================================
# Dependency Injection
# =============================================================================


def get_sanitizer() -> EvidenceSanitizer:
    """Create a fresh evidence sanitizer instance.

    Creates a new instance per call to avoid shared mutable state.
    """
    return EvidenceSanitizer()


def sanitize_evidence(content: str, evidence_type: str | None = None) -> RedactionResult:
    """Convenience function to sanitize evidence using a fresh sanitizer."""
    return get_sanitizer().sanitize(content, evidence_type)
