"""Domain enums persisted as native PostgreSQL enum types.

Invariants (see docs/progress/current-phase.md):
- severity and confidence are independent enums — never derive one from the other;
- scope status is ``in_scope | out_of_scope | unknown | third_party``;
- finding status covers the full triage lifecycle.

``values_callable`` stores the enum *values* (lowercase) in the database rather
than Python member names, keeping SQL readable.
"""

from enum import StrEnum

from sqlalchemy import Enum


class ScopeStatus(StrEnum):
    """Authorization status of a target/asset relative to a project scope."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"
    THIRD_PARTY = "third_party"


class FindingStatus(StrEnum):
    """Triage lifecycle of a finding. Observations never carry this field."""

    OPEN = "open"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class Severity(StrEnum):
    """Impact severity. Independent of confidence — never derived from it."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Assessor confidence. Independent of severity — never derived from it."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class AssetKind(StrEnum):
    """Node type of the asset graph."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    URL = "url"
    ENDPOINT = "endpoint"
    WEB_APPLICATION = "web_application"
    API_DEFINITION = "api_definition"
    APK = "apk"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    OTHER = "other"


class ProjectStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class RoleScope(StrEnum):
    """Level at which a role applies."""

    SYSTEM = "system"
    ORGANIZATION = "organization"
    PROJECT = "project"


class ScopeRuleEffect(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ScopeRuleTargetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN_PATTERN = "subdomain_pattern"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    API = "api"
    APK = "apk"
    OTHER = "other"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(StrEnum):
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    METHODOLOGY = "methodology"
    MANUAL = "manual"
    OTHER = "other"


class ScanJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetRelationshipType(StrEnum):
    CONTAINS = "contains"
    RESOLVES_TO = "resolves_to"
    SERVES = "serves"
    REDIRECTS_TO = "redirects_to"
    USES = "uses"
    DERIVED_FROM = "derived_from"
    OTHER = "other"


class PortProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class HttpMethod(StrEnum):
    GET = "get"
    POST = "post"
    PUT = "put"
    PATCH = "patch"
    DELETE = "delete"
    HEAD = "head"
    OPTIONS = "options"
    OTHER = "other"


class ObservationType(StrEnum):
    RESPONSE_BEHAVIOR = "response_behavior"
    CONFIGURATION = "configuration"
    INFORMATION_EXPOSURE = "information_exposure"
    ANOMALY = "anomaly"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    CERTIFICATE_DETAIL = "certificate_detail"
    OTHER = "other"


class EvidenceType(StrEnum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    CONSOLE_LOG = "console_log"
    FILE = "file"
    SNIPPET = "snippet"
    OTHER = "other"


class FindingRelationType(StrEnum):
    DUPLICATE_OF = "duplicate_of"
    RELATED_TO = "related_to"
    PREREQUISITE_OF = "prerequisite_of"
    VARIANT_OF = "variant_of"


class ParameterLocation(StrEnum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"


class ApkComponentType(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"
    LIBRARY = "library"
    OTHER = "other"


class TestCaseRunStatus(StrEnum):
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    FULL = "full"
    CUSTOM = "custom"


class ReportStatus(StrEnum):
    DRAFT = "draft"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class SecurityEventType(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_REGISTER = "auth_register"
    AUTH_TOKEN_REFRESH = "auth_token_refresh"
    SCOPE_VIOLATION = "scope_violation"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    # Resource CRUD events
    ORG_CREATE = "org_create"
    ORG_UPDATE = "org_update"
    ORG_DELETE = "org_delete"
    PROJECT_CREATE = "project_create"
    PROJECT_UPDATE = "project_update"
    PROJECT_DELETE = "project_delete"
    PROJECT_MEMBER_ADD = "project_member_add"
    PROJECT_MEMBER_REMOVE = "project_member_remove"
    SCOPE_CREATE = "scope_create"
    SCOPE_UPDATE = "scope_update"
    SCOPE_DELETE = "scope_delete"
    SCOPE_RULE_CREATE = "scope_rule_create"
    SCOPE_RULE_UPDATE = "scope_rule_update"
    SCOPE_RULE_DELETE = "scope_rule_delete"
    SCOPE_VERSION_INCREMENT = "scope_version_increment"
    TARGET_CREATE = "target_create"
    TARGET_UPDATE = "target_update"
    TARGET_DELETE = "target_delete"
    # Scope evaluation events (Phase 4)
    SCOPE_EVALUATE = "scope_evaluate"
    SCOPE_EVALUATE_BULK = "scope_evaluate_bulk"
    SCOPE_STATUS_OVERRIDE = "scope_status_override"
    # Scan events (Phase 6)
    SCAN_CREATE = "scan_create"
    SCAN_START = "scan_start"
    SCAN_UPDATE = "scan_update"
    SCAN_DELETE = "scan_delete"
    SCAN_CANCEL = "scan_cancel"
    SCAN_PAUSE = "scan_pause"
    SCAN_RESUME = "scan_resume"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    # Finding events (Phase 12)
    FINDING_CREATE = "finding_create"
    FINDING_UPDATE = "finding_update"
    FINDING_DELETE = "finding_delete"
    FINDING_PROMOTE = "finding_promote"
    FINDING_STATUS_CHANGE = "finding_status_change"
    OBSERVATION_CREATE = "observation_create"
    OBSERVATION_DISMISS = "observation_dismiss"
    EVIDENCE_ADD = "evidence_add"
    REVIEW_QUEUE_ENQUEUE = "review_queue_enqueue"
    REVIEW_QUEUE_DECIDE = "review_queue_decide"
    OTHER = "other"


class ReviewPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    NEEDS_MORE_INFO = "needs_more_info"
    PROMOTED_TO_FINDING = "promoted_to_finding"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class ReviewReason(StrEnum):
    LOW_CONFIDENCE = "low_confidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    AMBIGUOUS_SEVERITY = "ambiguous_severity"
    HEURISTIC_ONLY = "heuristic_only"
    NO_DETECTION_RULE = "no_detection_rule"
    CONFLICTING_SIGNALS = "conflicting_signals"
    NEW_VULNERABILITY_TYPE = "new_vulnerability_type"
    SCOPE_UNCLEAR = "scope_unclear"
    POLICY_REQUIRES_REVIEW = "policy_requires_review"
    CUSTOM = "custom"


def native_enum(enum_cls: type[StrEnum]) -> Enum:
    """SQLAlchemy Enum column type backed by a native PostgreSQL enum."""
    return Enum(
        enum_cls,
        name=f"{enum_cls.__name__.lower()}",
        native_enum=True,
        values_callable=lambda cls: [member.value for member in cls],
    )
