"""Finding correlation and deduplication engine.

Correlates findings across scanners, methodology test cases, domains, web applications,
APIs, APKs, and runtime data. Deduplication is based on normalized asset, vulnerability
type, location, parameter, and rule identity.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID


class CorrelationType(Enum):
    """Type of correlation relationship."""

    DUPLICATE = "duplicate"           # Same vulnerability, different scanner/observation
    RELATED = "related"               # Different but related vulnerabilities
    VARIANT = "variant"               # Variant of same vulnerability class
    PREREQUISITE = "prerequisite"     # One enables the other
    CHAIN = "chain"                   # Part of an attack chain
    SAME_ROOT_CAUSE = "same_root_cause"  # Different symptoms, same root cause


@dataclass(frozen=True)
class NormalizedFindingKey:
    """Normalized key for finding deduplication.

    Two findings with the same key are considered duplicates.
    """
    asset_value: str          # Normalized asset (domain, IP, URL, etc.)
    asset_type: str           # Type of asset (domain, ip, url, endpoint, apk, etc.)
    vulnerability_type: str   # Normalized vuln type (e.g., "SQL_INJECTION", "XSS", "BOLA")
    location: str             # Normalized location (endpoint path, parameter name, etc.)
    parameter: str | None     # Parameter name if applicable
    rule_identity: str        # Detection rule ID or signature
    http_method: str | None = None  # HTTP method for web/API findings

    def to_tuple(self) -> tuple:
        """Convert to tuple for hashing/comparison."""
        return (
            self.asset_value.lower(),
            self.asset_type.lower(),
            self.vulnerability_type.upper(),
            self.location.lower(),
            (self.parameter or "").lower(),
            self.rule_identity.lower(),
            (self.http_method or "").upper(),
        )


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""

    finding_id: UUID
    correlated_finding_id: UUID
    correlation_type: CorrelationType
    confidence: float  # 0.0 - 1.0
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class FindingCluster:
    """A cluster of correlated findings (duplicates and related)."""

    primary_finding_id: UUID
    duplicate_finding_ids: list[UUID] = field(default_factory=list)
    related_finding_ids: list[UUID] = field(default_factory=list)
    variant_finding_ids: list[UUID] = field(default_factory=list)
    total_count: int = 1

    def all_finding_ids(self) -> list[UUID]:
        """Get all finding IDs in this cluster."""
        return (
            [self.primary_finding_id] +
            self.duplicate_finding_ids +
            self.related_finding_ids +
            self.variant_finding_ids
        )


# =============================================================================
# Vulnerability Type Normalization
# =============================================================================

# Maps various vulnerability names/types to canonical types
VULNERABILITY_TYPE_MAP: dict[str, str] = {
    # SQL Injection variants
    "sql injection": "SQL_INJECTION",
    "sqli": "SQL_INJECTION",
    "sql-injection": "SQL_INJECTION",
    "blind sql injection": "SQL_INJECTION_BLIND",
    "time-based sql injection": "SQL_INJECTION_TIME_BASED",
    "union sql injection": "SQL_INJECTION_UNION",

    # XSS variants
    "cross-site scripting": "XSS",
    "xss": "XSS",
    "reflected xss": "XSS_REFLECTED",
    "stored xss": "XSS_STORED",
    "dom xss": "XSS_DOM",
    "dom-based xss": "XSS_DOM",

    # Command Injection
    "command injection": "COMMAND_INJECTION",
    "rce": "COMMAND_INJECTION",
    "remote code execution": "COMMAND_INJECTION",
    "code injection": "COMMAND_INJECTION",

    # LDAP Injection
    "ldap injection": "LDAP_INJECTION",

    # Path Traversal
    "path traversal": "PATH_TRAVERSAL",
    "directory traversal": "PATH_TRAVERSAL",
    "file inclusion": "FILE_INCLUSION",
    "lfi": "FILE_INCLUSION",
    "rfi": "FILE_INCLUSION",

    # SSRF
    "server-side request forgery": "SSRF",
    "ssrf": "SSRF",

    # XXE
    "xml external entity": "XXE",
    "xxe": "XXE",

    # Deserialization
    "insecure deserialization": "UNSAFE_DESERIALIZATION",
    "deserialization": "UNSAFE_DESERIALIZATION",

    # Authentication/Authorization
    "broken authentication": "BROKEN_AUTH",
    "authentication bypass": "BROKEN_AUTH",
    "broken authorization": "BROKEN_AUTHZ",
    "authorization bypass": "BROKEN_AUTHZ",
    "privilege escalation": "PRIVILEGE_ESCALATION",
    "idor": "IDOR",
    "insecure direct object reference": "IDOR",
    "bolo": "BOLA",
    "broken object level authorization": "BOLA",
    "bopla": "BOPLA",
    "broken object property level authorization": "BOPLA",
    "bfla": "BFLA",
    "broken function level authorization": "BFLA",

    # API Security
    "excessive data exposure": "API_EXCESSIVE_DATA",
    "mass assignment": "API_MASS_ASSIGNMENT",
    "api rate limiting": "RATE_LIMIT_BYPASS",
    "unrestricted resource consumption": "UNBOUNDED_RESOURCE",

    # Information Exposure
    "information disclosure": "INFO_EXPOSURE",
    "information exposure": "INFO_EXPOSURE",
    "sensitive data exposure": "SENSITIVE_DATA_EXPOSURE",
    "debug endpoint": "DEBUG_ENDPOINT",
    "default credentials": "DEFAULT_CREDENTIALS",
    "missing security headers": "MISSING_SECURITY_HEADERS",
    "cors misconfiguration": "CORS_MISCONFIG",

    # Mobile/APK
    "insecure storage": "INSECURE_STORAGE",
    "insecure communication": "INSECURE_COMMUNICATION",
    "weak crypto": "WEAK_CRYPTO",
    "hardcoded secrets": "HARDCODED_SECRETS",

    # Generic
    "misconfiguration": "SECURITY_MISCONFIGURATION",
    "security misconfiguration": "SECURITY_MISCONFIGURATION",
}


def normalize_vulnerability_type(vuln_type: str) -> str:
    """Normalize vulnerability type to canonical form."""
    normalized = vuln_type.strip().lower()
    return VULNERABILITY_TYPE_MAP.get(normalized, vuln_type.upper().replace(" ", "_"))


# =============================================================================
# Asset Value Normalization
# =============================================================================

def normalize_asset_value(asset_value: str, asset_type: str) -> str:
    """Normalize asset value for deduplication."""
    value = asset_value.strip()

    if asset_type.lower() in ("domain", "subdomain"):
        return value.lower().rstrip(".")
    elif asset_type.lower() in ("ip", "ip_address"):
        return value.lower()
    elif asset_type.lower() == "url":
        # Normalize URL: lowercase scheme/host, remove default ports, normalize path
        from urllib.parse import urlparse, urlunparse
        try:
            parsed = urlparse(value)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            # Remove default ports
            if (scheme == "http" and netloc.endswith(":80")) or \
               (scheme == "https" and netloc.endswith(":443")):
                netloc = netloc.rsplit(":", 1)[0]
            path = parsed.path.rstrip("/") or "/"
            return urlunparse((scheme, netloc, path, "", "", ""))
        except Exception:
            return value.lower()
    elif asset_type.lower() == "endpoint":
        # For endpoints, normalize path
        return value.rstrip("/").lower()
    elif asset_type.lower() == "apk":
        return value.lower()
    else:
        return value.lower()


def normalize_location(location: str) -> str:
    """Normalize location (endpoint path, parameter location)."""
    return location.strip().rstrip("/").lower()


def normalize_parameter(param: str | None) -> str | None:
    """Normalize parameter name."""
    if param is None:
        return None
    return param.strip().lower()


# =============================================================================
# FindingCorrelationEngine
# =============================================================================

class FindingCorrelationEngine:
    """Engine for correlating and deduplicating findings."""

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        """Initialize correlation engine.

        Args:
            similarity_threshold: Threshold for considering findings as duplicates (0.0-1.0)
        """
        self.similarity_threshold = similarity_threshold
        self._finding_index: dict[tuple, UUID] = {}  # Normalized key -> finding_id

    def compute_normalized_key(
        self,
        asset_value: str,
        asset_type: str,
        vulnerability_type: str,
        location: str,
        parameter: str | None = None,
        rule_identity: str = "",
        http_method: str | None = None,
    ) -> NormalizedFindingKey:
        """Compute normalized key for a finding."""
        return NormalizedFindingKey(
            asset_value=normalize_asset_value(asset_value, asset_type),
            asset_type=asset_type.lower(),
            vulnerability_type=normalize_vulnerability_type(vulnerability_type),
            location=normalize_location(location),
            parameter=normalize_parameter(parameter),
            rule_identity=rule_identity.lower(),
            http_method=http_method,
        )

    def find_duplicates(self, key: NormalizedFindingKey) -> list[UUID]:
        """Find existing findings that match the normalized key (exact duplicates)."""
        key_tuple = key.to_tuple()
        return [self._finding_index[key_tuple]] if key_tuple in self._finding_index else []

    def find_similar(
        self,
        key: NormalizedFindingKey,
        existing_findings: list[dict[str, Any]],
    ) -> list[CorrelationResult]:
        """Find similar findings based on partial matching."""
        results = []
        key_tuple = key.to_tuple()

        for finding in existing_findings:
            existing_key = NormalizedFindingKey(
                asset_value=finding.get("asset_value", ""),
                asset_type=finding.get("asset_type", ""),
                vulnerability_type=finding.get("vulnerability_type", ""),
                location=finding.get("location", ""),
                parameter=finding.get("parameter"),
                rule_identity=finding.get("rule_identity", ""),
                http_method=finding.get("http_method"),
            )
            existing_tuple = existing_key.to_tuple()

            if existing_tuple == key_tuple:
                # Exact duplicate
                results.append(CorrelationResult(
                    finding_id=finding["id"],
                    correlated_finding_id=finding["id"],
                    correlation_type=CorrelationType.DUPLICATE,
                    confidence=1.0,
                    evidence={"match_type": "exact", "key": str(key_tuple)},
                ))
            else:
                # Calculate similarity
                similarity = self._calculate_similarity(key, existing_key)
                if similarity >= self.similarity_threshold:
                    corr_type = self._determine_correlation_type(key, existing_key, similarity)
                    results.append(CorrelationResult(
                        finding_id=finding["id"],
                        correlated_finding_id=finding["id"],
                        correlation_type=corr_type,
                        confidence=similarity,
                        evidence={
                            "match_type": "similarity",
                            "similarity_score": similarity,
                            "key": str(key_tuple),
                            "existing_key": str(existing_tuple),
                        },
                    ))

        return results

    def _calculate_similarity(self, key1: NormalizedFindingKey, key2: NormalizedFindingKey) -> float:
        """Calculate similarity between two normalized keys (0.0 - 1.0)."""
        # Weighted similarity
        weights = {
            "asset_value": 0.30,
            "asset_type": 0.10,
            "vulnerability_type": 0.25,
            "location": 0.20,
            "parameter": 0.10,
            "rule_identity": 0.05,
            "http_method": 0.0,
        }

        score = 0.0
        total_weight = 0.0

        for field_name, weight in weights.items():
            val1 = getattr(key1, field_name, None)
            val2 = getattr(key2, field_name, None)

            if val1 is None and val2 is None:
                score += weight
            elif val1 is not None and val2 is not None:
                if val1 == val2:
                    score += weight
                elif field_name == "vulnerability_type":
                    # Check if same category
                    if self._same_vuln_category(val1, val2):
                        score += weight * 0.5
            total_weight += weight

        return score / total_weight if total_weight > 0 else 0.0

    def _same_vuln_category(self, v1: str, v2: str) -> bool:
        """Check if two vulnerability types are in the same category."""
        categories = {
            "INJECTION": {"SQL_INJECTION", "COMMAND_INJECTION", "LDAP_INJECTION", "XSS", "XSS_REFLECTED", "XSS_STORED", "XSS_DOM"},
            "AUTH": {"BROKEN_AUTH", "BROKEN_AUTHZ", "PRIVILEGE_ESCALATION", "IDOR", "BOLA", "BOPLA", "BFLA"},
            "INFO_EXPOSURE": {"INFO_EXPOSURE", "SENSITIVE_DATA_EXPOSURE", "DEBUG_ENDPOINT"},
            "SSRF": {"SSRF"},
            "XXE": {"XXE"},
            "DESERIALIZATION": {"UNSAFE_DESERIALIZATION"},
            "DOS": {"RATE_LIMIT_BYPASS", "UNBOUNDED_RESOURCE"},
        }
        for cat_types in categories.values():
            if v1 in cat_types and v2 in cat_types:
                return True
        return False

    def _determine_correlation_type(
        self,
        key1: NormalizedFindingKey,
        key2: NormalizedFindingKey,
        similarity: float,
    ) -> CorrelationType:
        """Determine correlation type based on similarity and differences."""
        if similarity >= 0.95:
            return CorrelationType.DUPLICATE
        elif key1.vulnerability_type == key2.vulnerability_type:
            if key1.asset_value == key2.asset_value:
                return CorrelationType.VARIANT
            else:
                return CorrelationType.RELATED
        elif self._same_vuln_category(key1.vulnerability_type, key2.vulnerability_type):
            return CorrelationType.SAME_ROOT_CAUSE
        else:
            return CorrelationType.RELATED

    def index_finding(self, finding_id: UUID, key: NormalizedFindingKey) -> None:
        """Add a finding to the correlation index."""
        self._finding_index[key.to_tuple()] = finding_id

    def remove_finding(self, key: NormalizedFindingKey) -> None:
        """Remove a finding from the correlation index."""
        self._finding_index.pop(key.to_tuple(), None)

    def build_clusters(self, findings: list[dict[str, Any]]) -> list[FindingCluster]:
        """Build correlation clusters from a list of findings."""
        clusters: dict[UUID, FindingCluster] = {}
        processed: set[UUID] = set()

        for finding in findings:
            fid = finding["id"]
            if fid in processed:
                continue

            key = NormalizedFindingKey(
                asset_value=finding.get("asset_value", ""),
                asset_type=finding.get("asset_type", ""),
                vulnerability_type=finding.get("vulnerability_type", ""),
                location=finding.get("location", ""),
                parameter=finding.get("parameter"),
                rule_identity=finding.get("rule_identity", ""),
                http_method=finding.get("http_method"),
            )

            # Find all correlated findings
            correlations = self.find_similar(key, findings)

            # Group by correlation type
            duplicates = []
            related = []
            variants = []

            for corr in correlations:
                if corr.correlation_type == CorrelationType.DUPLICATE:
                    duplicates.append(corr.correlated_finding_id)
                elif corr.correlation_type == CorrelationType.VARIANT:
                    variants.append(corr.correlated_finding_id)
                else:
                    related.append(corr.correlated_finding_id)

            # Create cluster
            cluster = FindingCluster(
                primary_finding_id=fid,
                duplicate_finding_ids=duplicates,
                related_finding_ids=related,
                variant_finding_ids=variants,
                total_count=1 + len(duplicates) + len(related) + len(variants),
            )
            clusters[fid] = cluster

            # Mark all as processed
            processed.add(fid)
            processed.update(duplicates)
            processed.update(related)
            processed.update(variants)

        return list(clusters.values())


# =============================================================================
# Default instance
# =============================================================================

_default_correlation_engine: FindingCorrelationEngine | None = None


def get_correlation_engine() -> FindingCorrelationEngine:
    """Get default correlation engine instance."""
    global _default_correlation_engine
    if _default_correlation_engine is None:
        _default_correlation_engine = FindingCorrelationEngine()
    return _default_correlation_engine
