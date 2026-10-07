"""CVSS v3.1 Calculator for vulnerability scoring.

Implements the Common Vulnerability Scoring System v3.1 specification.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AttackVector(Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass(frozen=True)
class CVSSVector:
    """CVSS v3.1 vector components."""

    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact

    def to_string(self) -> str:
        """Convert to CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."""
        return (
            f"CVSS:3.1/"
            f"AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality.value}/"
            f"I:{self.integrity.value}/"
            f"A:{self.availability.value}"
        )

    @classmethod
    def from_string(cls, vector_str: str) -> "CVSSVector":
        """Parse CVSS vector string."""
        if not vector_str.startswith("CVSS:3.1/"):
            raise ValueError("Only CVSS v3.1 vectors supported")

        parts = vector_str.split("/")
        metrics = {}
        for part in parts[1:]:  # Skip "CVSS:3.1"
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        return cls(
            attack_vector=AttackVector(metrics["AV"]),
            attack_complexity=AttackComplexity(metrics["AC"]),
            privileges_required=PrivilegesRequired(metrics["PR"]),
            user_interaction=UserInteraction(metrics["UI"]),
            scope=Scope(metrics["S"]),
            confidentiality=Impact(metrics["C"]),
            integrity=Impact(metrics["I"]),
            availability=Impact(metrics["A"]),
        )


@dataclass(frozen=True)
class CVSSScore:
    """CVSS score with metadata."""

    base_score: float
    severity: str
    vector: CVSSVector

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_score": self.base_score,
            "severity": self.severity,
            "vector": self.vector.to_string(),
        }


# CVSS v3.1 Base Metric Weights
_AV_WEIGHTS = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.2,
}

_AC_WEIGHTS = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

_PR_WEIGHTS_UNCHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

_PR_WEIGHTS_CHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.5,
}

_UI_WEIGHTS = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

_IMPACT_WEIGHTS = {
    Impact.NONE: 0.0,
    Impact.LOW: 0.22,
    Impact.HIGH: 0.56,
}


def _round_up_1dp(value: float) -> float:
    """Round up to 1 decimal place per CVSS spec."""
    import math
    return math.ceil(value * 10) / 10


def calculate_cvss_base_score(vector: CVSSVector) -> CVSSScore:
    """Calculate CVSS v3.1 base score from vector.

    Implements the official CVSS v3.1 calculation per FIRST specification.
    """
    # Exploitability sub-score
    exploitability = 8.22 * _AV_WEIGHTS[vector.attack_vector] * _AC_WEIGHTS[vector.attack_complexity]

    if vector.scope == Scope.UNCHANGED:
        exploitability *= _PR_WEIGHTS_UNCHANGED[vector.privileges_required]
    else:
        exploitability *= _PR_WEIGHTS_CHANGED[vector.privileges_required]

    exploitability *= _UI_WEIGHTS[vector.user_interaction]

    # Impact sub-score
    isc_base = 1 - (
        (1 - _IMPACT_WEIGHTS[vector.confidentiality]) *
        (1 - _IMPACT_WEIGHTS[vector.integrity]) *
        (1 - _IMPACT_WEIGHTS[vector.availability])
    )

    if vector.scope == Scope.UNCHANGED:
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    # Base score
    if impact <= 0:
        base_score = 0.0
    elif vector.scope == Scope.UNCHANGED:
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    base_score = _round_up_1dp(base_score)

    # Severity rating
    if base_score == 0:
        severity = "NONE"
    elif base_score <= 3.9:
        severity = "LOW"
    elif base_score <= 6.9:
        severity = "MEDIUM"
    elif base_score <= 8.9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return CVSSScore(base_score=base_score, severity=severity, vector=vector)


# =============================================================================
# Default CVSS vectors for common vulnerability categories
# =============================================================================

DEFAULT_CVSS_VECTORS: dict[str, CVSSVector] = {
    # Injection vulnerabilities
    "SQL_INJECTION": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "COMMAND_INJECTION": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "LDAP_INJECTION": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
    ),

    # XSS
    "XSS_REFLECTED": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "XSS_STORED": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "XSS_DOM": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),

    # Authentication/Authorization
    "BROKEN_AUTH": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "BROKEN_AUTHZ": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "IDOR": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "PRIVILEGE_ESCALATION": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),

    # Information exposure
    "INFO_EXPOSURE": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "SENSITIVE_DATA_EXPOSURE": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),

    # SSRF
    "SSRF": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.LOW,
    ),

    # XXE
    "XXE": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),

    # Deserialization
    "UNSAFE_DESERIALIZATION": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),

    # Rate limiting / DoS
    "RATE_LIMIT_BYPASS": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.HIGH,
    ),
    "UNBOUNDED_RESOURCE": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.NONE,
        integrity=Impact.NONE,
        availability=Impact.HIGH,
    ),

    # Security misconfiguration
    "DEBUG_ENDPOINT": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "DEFAULT_CREDENTIALS": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
    "MISSING_SECURITY_HEADERS": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "CORS_MISCONFIG": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),

    # API-specific
    "BOLA": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "BOPLA": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "BFLA": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "API_EXCESSIVE_DATA": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "API_MASS_ASSIGNMENT": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),

    # Generic defaults
    "LOW": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.HIGH,
        user_interaction=UserInteraction.REQUIRED,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.NONE,
        availability=Impact.NONE,
    ),
    "MEDIUM": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.LOW,
        integrity=Impact.LOW,
        availability=Impact.NONE,
    ),
    "HIGH": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.NONE,
    ),
    "CRITICAL": CVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.HIGH,
    ),
}


def get_default_vector(category: str) -> CVSSVector | None:
    """Get default CVSS vector for a vulnerability category."""
    return DEFAULT_CVSS_VECTORS.get(category.upper())


def calculate_cvss_for_category(category: str) -> CVSSScore | None:
    """Calculate CVSS score for a vulnerability category using default vector."""
    vector = get_default_vector(category)
    if vector is None:
        return None
    return calculate_cvss_base_score(vector)
