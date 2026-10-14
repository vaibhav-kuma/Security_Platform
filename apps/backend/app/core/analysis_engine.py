"""Analysis Engine - Central orchestrator for security analysis pipeline.

Transforms scanner output into trustworthy observations and findings.
Implements the complete pipeline: ingest -> sanitize -> correlate -> triage -> review.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cvss import CVSSScore, CVSSVector, calculate_cvss_base_score, get_default_vector
from app.core.evidence_sanitizer import (
    EvidenceSanitizer,
    RedactionResult,
)
from app.core.finding_correlation import (
    FindingCorrelationEngine,
    get_correlation_engine,
)
from app.core.manual_review import (
    DEFAULT_REVIEW_POLICY,
    ManualReviewQueue,
    auto_review_observation,
)
from app.models.detection import DetectionRule, Evidence, Finding, Observation
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingStatus,
    ObservationType,
    Severity,
)


class IngestionResult(Enum):
    """Result of observation ingestion."""

    OBSERVATION_CREATED = "observation_created"
    FINDING_PROMOTED = "finding_promoted"
    QUEUED_FOR_REVIEW = "queued_for_review"
    DUPLICATE_OBSERVATION = "duplicate_observation"
    OUT_OF_SCOPE = "out_of_scope"
    ERROR = "error"


@dataclass
class IngestionContext:
    """Context for observation ingestion."""

    project_id: UUID
    scan_id: UUID | None = None
    asset_id: UUID | None = None
    target_id: UUID | None = None
    source: str = "scanner"  # scanner, manual, methodology, correlation
    scanner_name: str | None = None
    scanner_version: str | None = None
    execution_policy: dict[str, Any] = field(default_factory=dict)
    scope_status: str = "unknown"


@dataclass
class IngestionResultData:
    """Result data from ingestion."""

    result: IngestionResult
    observation_id: UUID | None = None
    finding_id: UUID | None = None
    review_item_id: UUID | None = None
    correlation_results: list[Any] = field(default_factory=list)
    sanitization_result: RedactionResult | None = None
    message: str = ""
    errors: list[str] = field(default_factory=list)


# =============================================================================
# AnalysisEngine - Main orchestrator
# =============================================================================

class AnalysisEngine:
    """Central analysis engine for transforming scanner output into findings.

    Pipeline:
    1. Ingest raw observation data
    2. Sanitize evidence (secrets, PII, credentials)
    3. Create Observation record
    4. Check for duplicates
    5. Auto-promote to Finding if high confidence + sufficient evidence
    6. Otherwise queue for manual review
    7. Correlate with existing findings
    """

    def __init__(
        self,
        db_session: Any,
        sanitizer: EvidenceSanitizer | None = None,
        correlation_engine: FindingCorrelationEngine | None = None,
        review_queue: ManualReviewQueue | None = None,
        review_policy=DEFAULT_REVIEW_POLICY,
    ) -> None:
        self.db = db_session
        self.sanitizer = sanitizer or EvidenceSanitizer()
        self.correlation_engine = correlation_engine or get_correlation_engine()
        self.review_queue = review_queue or ManualReviewQueue(db_session, review_policy)
        self.review_policy = review_policy

    def ingest_observation(
        self,
        context: IngestionContext,
        title: str,
        observation_type: ObservationType,
        detail: str | None = None,
        payload: dict[str, Any] | None = None,
        severity_hint: Severity | None = None,
        confidence_hint: Confidence | None = None,
        detection_rule_id: UUID | None = None,
        evidence_items: list[dict[str, Any]] | None = None,
    ) -> IngestionResultData:
        """Ingest a raw observation from a scanner or manual source.

        This is the main entry point for all observation data.
        """
        errors: list[str] = []

        try:
            # Step 1: Sanitize payload and evidence
            sanitized_payload = self._sanitize_payload(payload or {})
            sanitized_evidence = self._sanitize_evidence_items(evidence_items or [])

            # Step 2: Create Observation record
            observation = self._create_observation(
                context=context,
                title=title,
                observation_type=observation_type,
                detail=detail,
                payload=sanitized_payload,
                severity_hint=severity_hint,
                confidence_hint=confidence_hint,
                detection_rule_id=detection_rule_id,
            )

            # Step 3: Check for duplicate observations
            if self._is_duplicate_observation(observation):
                return IngestionResultData(
                    result=IngestionResult.DUPLICATE_OBSERVATION,
                    observation_id=observation.id,
                    message="Duplicate observation detected",
                )

            # Step 4: Save observation
            self.db.add(observation)
            self.db.flush()

            # Step 5: Attach sanitized evidence
            self._attach_evidence(observation.id, sanitized_evidence)

            # Step 6: Check if should auto-promote to finding
            detection_rule = None
            if detection_rule_id:
                detection_rule = self.db.get(DetectionRule, detection_rule_id)

            # Sanitize evidence content for the auto-review decision
            evidence_for_review = [e.get("content", "") for e in sanitized_evidence if e.get("content")]

            # Step 7: Determine if manual review needed
            needs_review, review_reason, review_priority = auto_review_observation(
                observation=observation,
                detection_rule=detection_rule,
                evidence=evidence_for_review,
                policy=self.review_policy,
            )

            if needs_review:
                # Queue for manual review
                review_item = self.review_queue.enqueue(observation, review_reason, review_priority)

                # Correlate with existing findings
                correlations = self._correlate_observation(observation)

                return IngestionResultData(
                    result=IngestionResult.QUEUED_FOR_REVIEW,
                    observation_id=observation.id,
                    review_item_id=review_item.id,
                    correlation_results=correlations,
                    sanitization_result=sanitized_evidence[0] if sanitized_evidence else None,
                    message=f"Queued for manual review: {review_reason.value}",
                )
            else:
                # Auto-promote to finding
                finding = self._promote_to_finding(
                    observation=observation,
                    detection_rule=detection_rule,
                    evidence=sanitized_evidence,
                )

                # Correlate with existing findings
                correlations = self._correlate_finding(finding)

                return IngestionResultData(
                    result=IngestionResult.FINDING_PROMOTED,
                    observation_id=observation.id,
                    finding_id=finding.id,
                    correlation_results=correlations,
                    sanitization_result=sanitized_evidence[0] if sanitized_evidence else None,
                    message="Auto-promoted to finding",
                )

        except Exception as e:
            errors.append(str(e))
            return IngestionResultData(
                result=IngestionResult.ERROR,
                errors=errors,
                message=f"Ingestion failed: {e}",
            )

    def _sanitize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Sanitize observation payload."""
        return self.sanitizer.sanitize_dict(payload)

    def _sanitize_evidence_items(self, evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sanitize evidence items."""
        sanitized = []
        for item in evidence_items:
            sanitized_item = item.copy()
            if "content" in sanitized_item and isinstance(sanitized_item["content"], str):
                result = self.sanitizer.sanitize(sanitized_item["content"])
                sanitized_item["content"] = result.redacted
                sanitized_item["redacted"] = result.was_redacted
                sanitized_item["redaction_matches"] = [
                    {
                        "reason": m.reason.value,
                        "pattern": m.pattern_name,
                        "confidence": m.confidence,
                    }
                    for m in result.matches
                ]
            elif "content" in sanitized_item and isinstance(sanitized_item["content"], dict):
                sanitized_item["content"] = self.sanitizer.sanitize_dict(sanitized_item["content"])
            sanitized.append(sanitized_item)
        return sanitized

    def _create_observation(
        self,
        context: IngestionContext,
        title: str,
        observation_type: ObservationType,
        detail: str | None,
        payload: dict[str, Any],
        severity_hint: Severity | None,
        confidence_hint: Confidence | None,
        detection_rule_id: UUID | None,
    ) -> Observation:
        """Create an Observation record."""
        return Observation(
            project_id=context.project_id,
            scan_id=context.scan_id,
            asset_id=context.asset_id,
            detection_rule_id=detection_rule_id,
            observation_type=observation_type,
            title=title,
            detail=detail,
            payload=payload,
        )

    def _is_duplicate_observation(self, observation: Observation) -> bool:
        """Check if observation is a duplicate (same project, scan, rule, title)."""
        from sqlalchemy import and_

        existing = self.db.query(Observation).filter(
            and_(
                Observation.project_id == observation.project_id,
                Observation.scan_id == observation.scan_id,
                Observation.detection_rule_id == observation.detection_rule_id,
                Observation.title == observation.title,
                Observation.deleted_at.is_(None),
            )
        ).first()

        return existing is not None

    def _attach_evidence(self, observation_id: UUID, evidence_items: list[dict[str, Any]]) -> list[Evidence]:
        """Attach sanitized evidence to observation (via finding after promotion)."""
        # Evidence is attached to findings, not observations directly
        # This stores for later when promoted
        return []

    def _promote_to_finding(
        self,
        observation: Observation,
        detection_rule: DetectionRule | None,
        evidence: list[dict[str, Any]],
    ) -> Finding:
        """Promote observation to a Finding."""
        # Determine severity and confidence
        severity = observation.severity_hint
        confidence = observation.confidence_hint

        if detection_rule:
            severity = severity or detection_rule.severity_hint
            confidence = confidence or detection_rule.confidence_hint

        # Default values
        severity = severity or Severity.INFO
        confidence = confidence or Confidence.LOW

        # Calculate CVSS if possible
        cvss_score: CVSSScore | None = None
        cvss_vector: CVSSVector | None = None
        cwe_id: str | None = None

        if detection_rule and detection_rule.metadata_:
            category = detection_rule.metadata_.get("category", "")
            if category:
                cvss_vector = get_default_vector(category)
                if cvss_vector:
                    cvss_score = calculate_cvss_base_score(cvss_vector)
                    cwe_id = detection_rule.metadata_.get("cwe_id")

        finding = Finding(
            project_id=observation.project_id,
            promoted_from_observation_id=observation.id,
            asset_id=observation.asset_id,
            title=observation.title,
            status=FindingStatus.OPEN,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            cvss_score=cvss_score.base_score if cvss_score else None,
            recommendation=self._generate_recommendation(observation, detection_rule),
        )

        self.db.add(finding)
        self.db.flush()

        # Attach evidence to finding
        self._attach_evidence_to_finding(finding.id, evidence)

        return finding

    def _attach_evidence_to_finding(self, finding_id: UUID, evidence_items: list[dict[str, Any]]) -> list[Evidence]:
        """Attach sanitized evidence to a finding."""
        evidence_records = []
        for item in evidence_items:
            evidence = Evidence(
                finding_id=finding_id,
                evidence_type=EvidenceType(item.get("type", "snippet")),
                storage=item.get("storage", "inline"),
                content=item.get("content"),
                object_key=item.get("object_key"),
                sha256=item.get("sha256"),
                redacted=item.get("redacted", False),
                redacted_at=datetime.now(UTC) if item.get("redacted") else None,
                metadata_=item.get("metadata", {}),
            )
            self.db.add(evidence)
            evidence_records.append(evidence)

        self.db.flush()
        return evidence_records

    def _generate_recommendation(self, observation: Observation, detection_rule: DetectionRule | None) -> str:
        """Generate remediation recommendation."""
        if detection_rule and detection_rule.metadata_:
            return detection_rule.metadata_.get("recommendation", "Review and remediate the identified issue.")

        # Generic recommendations by observation type
        recommendations = {
            ObservationType.RESPONSE_BEHAVIOR: "Investigate the unexpected response behavior and implement proper validation.",
            ObservationType.CONFIGURATION: "Review and harden the configuration according to security best practices.",
            ObservationType.INFORMATION_EXPOSURE: "Remove or restrict access to the exposed information.",
            ObservationType.ANOMALY: "Investigate the anomalous behavior to determine if it indicates a vulnerability.",
            ObservationType.TECHNOLOGY_FINGERPRINT: "Ensure the identified technology is properly configured and patched.",
            ObservationType.CERTIFICATE_DETAIL: "Review certificate configuration and validity.",
        }
        return recommendations.get(observation.observation_type, "Review and remediate the identified issue.")

    def _correlate_observation(self, observation: Observation) -> list[Any]:
        """Correlate observation with existing findings."""
        if not observation.asset_id:
            return []

        # Get asset info for correlation
        from app.models.assets import Asset
        asset = self.db.get(Asset, observation.asset_id)
        if not asset:
            return []

        # Build normalized key
        key = self.correlation_engine.compute_normalized_key(
            asset_value=asset.value,
            asset_type=asset.kind.value,
            vulnerability_type=observation.observation_type.value,
            location=observation.payload.get("location", ""),
            parameter=observation.payload.get("parameter"),
            rule_identity=str(observation.detection_rule_id) if observation.detection_rule_id else "manual",
            http_method=observation.payload.get("http_method"),
        )

        # Get existing findings in project
        existing_findings = self._get_project_findings(observation.project_id)

        return self.correlation_engine.find_similar(key, existing_findings)

    def _correlate_finding(self, finding: Finding) -> list[Any]:
        """Correlate new finding with existing findings."""
        if not finding.asset_id:
            return []

        from app.models.assets import Asset
        asset = self.db.get(Asset, finding.asset_id)
        if not asset:
            return []

        key = self.correlation_engine.compute_normalized_key(
            asset_value=asset.value,
            asset_type=asset.kind.value,
            vulnerability_type=finding.cwe_id or "UNKNOWN",
            location=finding.title,
            parameter=None,
            rule_identity=finding.cwe_id or "unknown",
            http_method=None,
        )

        existing_findings = self._get_project_findings(finding.project_id)

        return self.correlation_engine.find_similar(key, existing_findings)

    def _get_project_findings(self, project_id: UUID) -> list[dict[str, Any]]:
        """Get all findings in a project for correlation."""
        findings = self.db.query(Finding).filter(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        ).all()

        return [
            {
                "id": f.id,
                "asset_value": "",
                "asset_type": "",
                "vulnerability_type": f.cwe_id or "UNKNOWN",
                "location": f.title,
                "parameter": None,
                "rule_identity": f.cwe_id or "unknown",
                "http_method": None,
            }
            for f in findings
        ]

    # =========================================================================
    # Finding Management
    # =========================================================================

    def update_finding_status(
        self,
        finding_id: UUID,
        status: FindingStatus,
        user_id: UUID,
        notes: str | None = None,
    ) -> Finding | None:
        """Update finding status with audit trail."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            return None

        old_status = finding.status
        finding.status = status
        finding.updated_at = datetime.now(UTC)

        # Add comment if notes provided
        if notes:
            from app.models.detection import FindingComment
            comment = FindingComment(
                finding_id=finding_id,
                author_id=user_id,
                body=f"Status changed from {old_status.value} to {status.value}: {notes}",
            )
            self.db.add(comment)

        self.db.flush()
        return finding

    def promote_observation(
        self,
        observation_id: UUID,
        user_id: UUID,
        severity: Severity,
        confidence: Confidence,
        cwe_id: str | None = None,
        cvss_vector: CVSSVector | None = None,
        recommendation: str | None = None,
    ) -> Finding | None:
        """Manually promote an observation to a finding (from review queue)."""
        observation = self.db.get(Observation, observation_id)
        if not observation:
            return None

        # Calculate CVSS score if vector provided
        cvss_score = None
        if cvss_vector:
            cvss_score = calculate_cvss_base_score(cvss_vector)

        finding = Finding(
            project_id=observation.project_id,
            promoted_from_observation_id=observation.id,
            asset_id=observation.asset_id,
            title=observation.title,
            status=FindingStatus.OPEN,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            cvss_score=cvss_score.base_score if cvss_score else None,
            recommendation=recommendation or self._generate_recommendation(observation, None),
        )

        self.db.add(finding)
        self.db.flush()

        # Move evidence from observation payload to finding
        # (In practice, evidence would be attached separately)

        return finding

    def dismiss_observation(
        self,
        observation_id: UUID,
        user_id: UUID,
        reason: str,
    ) -> Observation | None:
        """Dismiss an observation (mark as reviewed, not a finding)."""
        observation = self.db.get(Observation, observation_id)
        if not observation:
            return None

        observation.payload = {
            **observation.payload,
            "dismissed": True,
            "dismissed_by": str(user_id),
            "dismissed_at": datetime.now(UTC).isoformat(),
            "dismissal_reason": reason,
        }
        observation.updated_at = datetime.now(UTC)
        self.db.flush()
        return observation


# =============================================================================
# Batch Processing
# =============================================================================

@dataclass
class BatchIngestionResult:
    """Result of batch ingestion."""

    total: int = 0
    observations_created: int = 0
    findings_promoted: int = 0
    queued_for_review: int = 0
    duplicates: int = 0
    errors: int = 0
    results: list[IngestionResultData] = field(default_factory=list)


def ingest_observations_batch(
    engine: AnalysisEngine,
    observations: list[dict[str, Any]],
    context: IngestionContext,
) -> BatchIngestionResult:
    """Ingest multiple observations in batch."""
    result = BatchIngestionResult(total=len(observations))

    for obs_data in observations:
        ingestion_result = engine.ingest_observation(
            context=context,
            title=obs_data.get("title", "Untitled"),
            observation_type=ObservationType(obs_data.get("type", "OTHER")),
            detail=obs_data.get("detail"),
            payload=obs_data.get("payload", {}),
            severity_hint=Severity(obs_data["severity"]) if obs_data.get("severity") else None,
            confidence_hint=Confidence(obs_data["confidence"]) if obs_data.get("confidence") else None,
            detection_rule_id=UUID(obs_data["detection_rule_id"]) if obs_data.get("detection_rule_id") else None,
            evidence_items=obs_data.get("evidence", []),
        )
        result.results.append(ingestion_result)

        if ingestion_result.result == IngestionResult.OBSERVATION_CREATED:
            result.observations_created += 1
        elif ingestion_result.result == IngestionResult.FINDING_PROMOTED:
            result.findings_promoted += 1
        elif ingestion_result.result == IngestionResult.QUEUED_FOR_REVIEW:
            result.queued_for_review += 1
        elif ingestion_result.result == IngestionResult.DUPLICATE_OBSERVATION:
            result.duplicates += 1
        elif ingestion_result.result == IngestionResult.ERROR:
            result.errors += 1

    return result


# =============================================================================
# Dependency Injection
# =============================================================================


def get_analysis_engine(db_session: Any) -> AnalysisEngine:
    """Create analysis engine for a database session.

    Creates a fresh instance per request to avoid session leakage.
    """
    return AnalysisEngine(db_session)
