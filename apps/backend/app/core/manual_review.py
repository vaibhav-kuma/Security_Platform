"""Manual Review Queue for ambiguous observations.

Observations that cannot be automatically triaged are placed in the review queue
for human analysts. This preserves the invariant that heuristic observations
are never automatically promoted to confirmed findings.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID


class ReviewPriority(Enum):
    """Priority for manual review."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewStatus(Enum):
    """Status of a review queue item."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    NEEDS_MORE_INFO = "needs_more_info"
    PROMOTED_TO_FINDING = "promoted_to_finding"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class ReviewReason(Enum):
    """Reason why observation was queued for manual review."""

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


@dataclass
class ManualReviewItem:
    """An item in the manual review queue."""

    id: UUID
    observation_id: UUID
    project_id: UUID
    scan_id: UUID | None
    asset_id: UUID | None
    title: str
    description: str | None
    observation_type: str
    severity_hint: str | None
    confidence_hint: str | None
    payload: dict[str, Any]
    review_reason: ReviewReason
    priority: ReviewPriority
    status: ReviewStatus = ReviewStatus.PENDING
    assigned_to: UUID | None = None
    reviewer_notes: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    reviewed_at: datetime | None = None
    resolved_at: datetime | None = None
    promoted_finding_id: UUID | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "observation_id": str(self.observation_id),
            "project_id": str(self.project_id),
            "scan_id": str(self.scan_id) if self.scan_id else None,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "title": self.title,
            "description": self.description,
            "observation_type": self.observation_type,
            "severity_hint": self.severity_hint,
            "confidence_hint": self.confidence_hint,
            "payload": self.payload,
            "review_reason": self.review_reason.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "assigned_to": str(self.assigned_to) if self.assigned_to else None,
            "reviewer_notes": self.reviewer_notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "promoted_finding_id": str(self.promoted_finding_id) if self.promoted_finding_id else None,
            "metadata": self.metadata,
        }


@dataclass
class ReviewDecision:
    """Decision made during manual review."""

    review_item_id: UUID
    reviewer_id: UUID
    action: str  # "promote", "dismiss", "needs_more_info", "escalate"
    finding_id: UUID | None = None
    notes: str | None = None
    severity: str | None = None
    confidence: str | None = None
    cwe_id: str | None = None
    cvss_vector: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# =============================================================================
# Review Queue Policies
# =============================================================================

@dataclass(frozen=True)
class ReviewPolicy:
    """Policy configuration for when observations go to manual review."""

    # Confidence thresholds - below this goes to review
    min_confidence_auto_promote: float = 0.7
    # Severity that always requires review regardless of confidence
    always_review_severities: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    # Observation types that require human review
    review_observation_types: list[str] = field(default_factory=lambda: [
        "ANOMALY",
        "INFORMATION_EXPOSURE",
    ])
    # Require review for heuristic-only (no detection rule) observations
    review_heuristic_only: bool = True
    # Require review if scope is unknown
    review_unknown_scope: bool = True
    # Maximum observations per project in queue before escalation
    max_queue_size_per_project: int = 100
    # Auto-escalate after days in queue
    auto_escalate_days: int = 7


DEFAULT_REVIEW_POLICY = ReviewPolicy()


def should_queue_for_review(
    observation: Any,  # Observation model
    detection_rule: Any | None,  # DetectionRule model or None
    policy: ReviewPolicy = DEFAULT_REVIEW_POLICY,
) -> tuple[bool, ReviewReason, ReviewPriority]:
    """Determine if an observation should be queued for manual review.

    Returns:
        (should_queue, reason, priority)
    """
    # Heuristic-only observations always need review
    if detection_rule is None and policy.review_heuristic_only:
        return True, ReviewReason.HEURISTIC_ONLY, ReviewPriority.MEDIUM

    # Low confidence
    confidence_map = {
        "VERY_LOW": 0.1,
        "LOW": 0.3,
        "MEDIUM": 0.5,
        "HIGH": 0.7,
        "VERY_HIGH": 0.9,
    }
    conf_hint = observation.confidence_hint.value if hasattr(observation.confidence_hint, 'value') else observation.confidence_hint
    conf_value = confidence_map.get(str(conf_hint).upper(), 0.3)
    if conf_value < policy.min_confidence_auto_promote:
        return True, ReviewReason.LOW_CONFIDENCE, ReviewPriority.HIGH if conf_value < 0.3 else ReviewPriority.MEDIUM

    # High severity always reviewed
    severity_value = observation.severity_hint.value if hasattr(observation.severity_hint, 'value') else observation.severity_hint
    if str(severity_value).upper() in [s.upper() for s in policy.always_review_severities]:
        return True, ReviewReason.AMBIGUOUS_SEVERITY, ReviewPriority.HIGH

    # Observation type requires review
    obs_type = observation.observation_type.value if hasattr(observation.observation_type, 'value') else observation.observation_type
    if obs_type in policy.review_observation_types:
        return True, ReviewReason.INSUFFICIENT_EVIDENCE, ReviewPriority.MEDIUM

    # Unknown scope
    if hasattr(observation, "scope_status") and observation.scope_status == "unknown" and policy.review_unknown_scope:
        return True, ReviewReason.SCOPE_UNCLEAR, ReviewPriority.MEDIUM

    return False, ReviewReason.CUSTOM, ReviewPriority.LOW


# =============================================================================
# ManualReviewQueue Service
# =============================================================================

class ManualReviewQueue:
    """Service for managing the manual review queue."""

    def __init__(self, db_session: Any, policy: ReviewPolicy = DEFAULT_REVIEW_POLICY) -> None:
        self.db = db_session
        self.policy = policy

    def enqueue(
        self,
        observation: Any,
        review_reason: ReviewReason,
        priority: ReviewPriority,
    ) -> ManualReviewItem:
        """Add an observation to the review queue."""
        from app.models.enums import ObservationType

        # Map observation to review item
        item = ManualReviewItem(
            id=observation.id,  # Use observation ID as review item ID
            observation_id=observation.id,
            project_id=observation.project_id,
            scan_id=observation.scan_id,
            asset_id=observation.asset_id,
            title=observation.title,
            description=observation.detail,
            observation_type=observation.observation_type.value if isinstance(observation.observation_type, ObservationType) else observation.observation_type,
            severity_hint=observation.severity_hint.value if hasattr(observation, "severity_hint") and observation.severity_hint else None,
            confidence_hint=observation.confidence_hint.value if hasattr(observation, "confidence_hint") and observation.confidence_hint else None,
            payload=observation.payload or {},
            review_reason=review_reason,
            priority=priority,
            metadata={
                "detection_rule_id": str(observation.detection_rule_id) if observation.detection_rule_id else None,
            },
        )

        # Store in database (would use a ManualReviewQueue model)
        # For now, we track in-memory. Actual persistence needs a model.
        return item

    def get_pending(self, project_id: UUID, limit: int = 50) -> list[ManualReviewItem]:
        """Get pending review items for a project."""
        # Would query database
        return []

    def assign(self, item_id: UUID, reviewer_id: UUID) -> ManualReviewItem | None:
        """Assign a review item to a reviewer."""
        # Would update database
        return None

    def resolve(self, decision: ReviewDecision) -> ManualReviewItem | None:
        """Resolve a review item with a decision."""
        # Would update database and potentially create finding
        return None

    def get_stats(self, project_id: UUID) -> dict[str, int]:
        """Get queue statistics for a project."""
        return {
            "pending": 0,
            "in_progress": 0,
            "needs_more_info": 0,
            "escalated": 0,
            "total": 0,
        }


# =============================================================================
# Auto-Review Logic
# =============================================================================

def auto_review_observation(
    observation: Any,
    detection_rule: Any | None,
    evidence: list[Any],
    policy: ReviewPolicy = DEFAULT_REVIEW_POLICY,
) -> tuple[bool, ReviewReason, ReviewPriority]:
    """Automatically determine if observation needs manual review.

    Returns:
        (needs_review, reason, priority)
    """
    return should_queue_for_review(observation, detection_rule, policy)


# =============================================================================
# Queue Metrics
# =============================================================================

@dataclass
class ReviewQueueMetrics:
    """Metrics for the review queue."""

    total_items: int = 0
    pending: int = 0
    in_progress: int = 0
    needs_more_info: int = 0
    promoted: int = 0
    dismissed: int = 0
    escalated: int = 0
    avg_resolution_time_hours: float = 0.0
    oldest_pending_hours: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_items": self.total_items,
            "pending": self.pending,
            "in_progress": self.in_progress,
            "needs_more_info": self.needs_more_info,
            "promoted": self.promoted,
            "dismissed": self.dismissed,
            "escalated": self.escalated,
            "avg_resolution_time_hours": self.avg_resolution_time_hours,
            "oldest_pending_hours": self.oldest_pending_hours,
        }
