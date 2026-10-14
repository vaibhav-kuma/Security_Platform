"""Services for findings, observations, evidence, correlation, and manual review."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.analysis_engine import (
    BatchIngestionResult,
    IngestionContext,
    IngestionResultData,
    get_analysis_engine,
    ingest_observations_batch,
)
from app.core.cvss import (
    CVSSVector,
    calculate_cvss_base_score,
    calculate_cvss_for_category,
    get_default_vector,
)
from app.core.evidence_sanitizer import EvidenceSanitizer, sanitize_evidence
from app.core.finding_correlation import (
    FindingCluster,
    get_correlation_engine,
)
from app.core.manual_review import (
    DEFAULT_REVIEW_POLICY,
    ManualReviewItem,
    ManualReviewQueue,
    ReviewDecision,
    ReviewPriority,
    ReviewReason,
)
from app.models.assets import Asset
from app.models.detection import (
    Evidence,
    Finding,
    FindingComment,
    FindingRelationship,
    Observation,
)
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingStatus,
    ObservationType,
    Severity,
)

# =============================================================================
# FindingService
# =============================================================================

class FindingService:
    """Service for finding CRUD and lifecycle management."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.analysis_engine = get_analysis_engine(db)

    def create_finding(
        self,
        project_id: UUID,
        title: str,
        severity: Severity,
        confidence: Confidence,
        asset_id: UUID | None = None,
        promoted_from_observation_id: UUID | None = None,
        cwe_id: str | None = None,
        cvss_vector: CVSSVector | None = None,
        recommendation: str | None = None,
        status: FindingStatus = FindingStatus.OPEN,
    ) -> Finding:
        """Create a finding manually."""
        cvss_score = None
        if cvss_vector:
            cvss_result = calculate_cvss_base_score(cvss_vector)
            cvss_score = cvss_result.base_score

        finding = Finding(
            project_id=project_id,
            promoted_from_observation_id=promoted_from_observation_id,
            asset_id=asset_id,
            title=title,
            status=status,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            recommendation=recommendation,
        )
        self.db.add(finding)
        self.db.flush()
        return finding

    def get_finding(self, finding_id: UUID) -> Finding | None:
        """Get finding by ID."""
        return self.db.get(Finding, finding_id)

    def get_finding_detail(self, finding_id: UUID) -> Finding | None:
        """Get finding with evidence and comments loaded."""
        finding = self.db.get(Finding, finding_id)
        if finding:
            # Access relationships to load them
            _ = finding.evidence
            _ = finding.comments
        return finding

    def list_findings(
        self,
        project_id: UUID,
        page: int = 1,
        page_size: int = 20,
        status_filter: str | None = None,
        severity_filter: str | None = None,
        confidence_filter: str | None = None,
        asset_id: UUID | None = None,
    ) -> tuple[list[Finding], int]:
        """List findings with pagination and filters."""
        stmt = select(Finding).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        )

        if status_filter:
            try:
                stmt = stmt.where(Finding.status == FindingStatus(status_filter))
            except ValueError:
                pass

        if severity_filter:
            try:
                stmt = stmt.where(Finding.severity == Severity(severity_filter))
            except ValueError:
                pass

        if confidence_filter:
            try:
                stmt = stmt.where(Finding.confidence == Confidence(confidence_filter))
            except ValueError:
                pass

        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)

        # Count total
        total_stmt = select(func.count(Finding.id)).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        )
        if status_filter:
            try:
                total_stmt = total_stmt.where(Finding.status == FindingStatus(status_filter))
            except ValueError:
                pass
        total = self.db.scalar(total_stmt) or 0

        # Paginate
        stmt = stmt.order_by(Finding.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        findings = self.db.scalars(stmt).all()

        return list(findings), total

    def update_finding(
        self,
        finding_id: UUID,
        data: dict[str, Any],
        user_id: UUID,
    ) -> Finding | None:
        """Update finding fields."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            return None

        old_status = finding.status

        for key, value in data.items():
            if hasattr(finding, key) and key not in ("id", "project_id", "created_at", "promoted_from_observation_id"):
                setattr(finding, key, value)

        finding.updated_at = datetime.now(UTC)

        # Add audit comment if status changed
        if "status" in data and data["status"] != old_status.value:
            comment = FindingComment(
                finding_id=finding_id,
                author_id=user_id,
                body=f"Status changed from {old_status.value} to {data['status']}",
            )
            self.db.add(comment)

        self.db.flush()
        return finding

    def update_finding_status(
        self,
        finding_id: UUID,
        status: FindingStatus,
        user_id: UUID,
        notes: str | None = None,
    ) -> Finding | None:
        """Update finding status with audit trail."""
        return self.analysis_engine.update_finding_status(finding_id, status, user_id, notes)

    def delete_finding(self, finding_id: UUID) -> bool:
        """Soft delete finding."""
        from app.repositories.base import SoftDeleteRepository
        repo = SoftDeleteRepository(self.db, Finding)
        finding = self.db.get(Finding, finding_id)
        if not finding:
            return False
        repo.soft_delete(finding)
        return True

    def add_evidence(
        self,
        finding_id: UUID,
        evidence_type: EvidenceType,
        content: str | None = None,
        object_key: str | None = None,
        sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence | None:
        """Add evidence to a finding."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            return None

        # Sanitize content if provided
        redacted = False
        redacted_at = None
        sanitized_content = content
        if content:
            result = sanitize_evidence(content)
            sanitized_content = result.redacted
            redacted = result.was_redacted
            if redacted:
                redacted_at = datetime.now(UTC)

        evidence = Evidence(
            finding_id=finding_id,
            evidence_type=evidence_type,
            storage="inline" if content else "object",
            content=sanitized_content,
            object_key=object_key,
            sha256=sha256,
            redacted=redacted,
            redacted_at=redacted_at,
            metadata_=metadata or {},
        )
        self.db.add(evidence)
        self.db.flush()
        return evidence

    def get_evidence(self, finding_id: UUID) -> list[Evidence]:
        """Get all evidence for a finding."""
        stmt = select(Evidence).where(Evidence.finding_id == finding_id)
        return list(self.db.scalars(stmt).all())

    def add_comment(self, finding_id: UUID, author_id: UUID, body: str) -> FindingComment | None:
        """Add comment to finding."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            return None

        comment = FindingComment(
            finding_id=finding_id,
            author_id=author_id,
            body=body,
        )
        self.db.add(comment)
        self.db.flush()
        return comment

    def get_comments(self, finding_id: UUID) -> list[FindingComment]:
        """Get all comments for a finding."""
        stmt = select(FindingComment).where(FindingComment.finding_id == finding_id).order_by(FindingComment.created_at.desc())
        return list(self.db.scalars(stmt).all())

    def add_relationship(
        self,
        source_finding_id: UUID,
        target_finding_id: UUID,
        relationship_type: str,
    ) -> FindingRelationship | None:
        """Add relationship between findings."""
        if source_finding_id == target_finding_id:
            return None

        source = self.db.get(Finding, source_finding_id)
        target = self.db.get(Finding, target_finding_id)
        if not source or not target:
            return None

        relationship = FindingRelationship(
            source_finding_id=source_finding_id,
            target_finding_id=target_finding_id,
            relationship_type=relationship_type,
        )
        self.db.add(relationship)
        self.db.flush()
        return relationship

    def get_relationships(self, finding_id: UUID) -> list[FindingRelationship]:
        """Get all relationships for a finding."""
        stmt = select(FindingRelationship).where(
            (FindingRelationship.source_finding_id == finding_id) |
            (FindingRelationship.target_finding_id == finding_id)
        )
        return list(self.db.scalars(stmt).all())

    def get_finding_stats(self, project_id: UUID) -> dict[str, int]:
        """Get finding statistics for a project."""
        stmt = select(Finding.status, func.count(Finding.id)).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        ).group_by(Finding.status)
        results = self.db.execute(stmt).all()
        stats = {status.value: count for status, count in results}

        # Ensure all statuses present
        for status in FindingStatus:
            stats.setdefault(status.value, 0)

        # Severity breakdown
        severity_stmt = select(Finding.severity, func.count(Finding.id)).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        ).group_by(Finding.severity)
        severity_results = self.db.execute(severity_stmt).all()
        stats["severity"] = {sev.value: count for sev, count in severity_results}

        # Confidence breakdown
        conf_stmt = select(Finding.confidence, func.count(Finding.id)).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        ).group_by(Finding.confidence)
        conf_results = self.db.execute(conf_stmt).all()
        stats["confidence"] = {conf.value: count for conf, count in conf_results}

        return stats


# =============================================================================
# ObservationService
# =============================================================================

class ObservationService:
    """Service for observation management."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.analysis_engine = get_analysis_engine(db)

    def create_observation(
        self,
        project_id: UUID,
        title: str,
        observation_type: ObservationType,
        scan_id: UUID | None = None,
        asset_id: UUID | None = None,
        detection_rule_id: UUID | None = None,
        detail: str | None = None,
        payload: dict[str, Any] | None = None,
        severity_hint: Severity | None = None,
        confidence_hint: Confidence | None = None,
    ) -> Observation:
        """Create an observation manually."""
        observation = Observation(
            project_id=project_id,
            scan_id=scan_id,
            asset_id=asset_id,
            detection_rule_id=detection_rule_id,
            observation_type=observation_type,
            title=title,
            detail=detail,
            payload=payload or {},
        )
        self.db.add(observation)
        self.db.flush()
        return observation

    def get_observation(self, observation_id: UUID) -> Observation | None:
        """Get observation by ID."""
        return self.db.get(Observation, observation_id)

    def list_observations(
        self,
        project_id: UUID,
        page: int = 1,
        page_size: int = 20,
        scan_id: UUID | None = None,
        asset_id: UUID | None = None,
        observation_type: str | None = None,
    ) -> tuple[list[Observation], int]:
        """List observations with pagination."""
        stmt = select(Observation).where(
            Observation.project_id == project_id,
        )

        if scan_id:
            stmt = stmt.where(Observation.scan_id == scan_id)
        if asset_id:
            stmt = stmt.where(Observation.asset_id == asset_id)
        if observation_type:
            try:
                stmt = stmt.where(Observation.observation_type == ObservationType(observation_type))
            except ValueError:
                pass

        total_stmt = select(func.count(Observation.id)).where(Observation.project_id == project_id)
        if scan_id:
            total_stmt = total_stmt.where(Observation.scan_id == scan_id)
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(Observation.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        observations = self.db.scalars(stmt).all()

        return list(observations), total

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
        """Ingest observation through analysis engine."""
        return self.analysis_engine.ingest_observation(
            context=context,
            title=title,
            observation_type=observation_type,
            detail=detail,
            payload=payload,
            severity_hint=severity_hint,
            confidence_hint=confidence_hint,
            detection_rule_id=detection_rule_id,
            evidence_items=evidence_items,
        )

    def ingest_batch(
        self,
        observations: list[dict[str, Any]],
        context: IngestionContext,
    ) -> BatchIngestionResult:
        """Batch ingest observations."""
        return ingest_observations_batch(self.analysis_engine, observations, context)

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
        """Manually promote observation to finding."""
        return self.analysis_engine.promote_observation(
            observation_id=observation_id,
            user_id=user_id,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            cvss_vector=cvss_vector,
            recommendation=recommendation,
        )

    def dismiss_observation(
        self,
        observation_id: UUID,
        user_id: UUID,
        reason: str,
    ) -> Observation | None:
        """Dismiss an observation."""
        return self.analysis_engine.dismiss_observation(observation_id, user_id, reason)


# =============================================================================
# EvidenceService
# =============================================================================

class EvidenceService:
    """Service for evidence management and sanitization."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.sanitizer = EvidenceSanitizer()

    def sanitize_and_store(
        self,
        finding_id: UUID,
        evidence_type: EvidenceType,
        content: str | None = None,
        object_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """Sanitize evidence content and store."""
        finding = self.db.get(Finding, finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        redacted = False
        redacted_at = None
        sanitized_content = content

        if content:
            result = self.sanitizer.sanitize(content)
            sanitized_content = result.redacted
            redacted = result.was_redacted
            if redacted:
                redacted_at = datetime.now(UTC)

            # Store redaction metadata
            if metadata is None:
                metadata = {}
            metadata["redaction_matches"] = [
                {
                    "reason": m.reason.value,
                    "pattern": m.pattern_name,
                    "confidence": m.confidence,
                }
                for m in result.matches
            ]

        evidence = Evidence(
            finding_id=finding_id,
            evidence_type=evidence_type,
            storage="inline" if content else "object",
            content=sanitized_content,
            object_key=object_key,
            redacted=redacted,
            redacted_at=redacted_at,
            metadata_=metadata or {},
        )
        self.db.add(evidence)
        self.db.flush()
        return evidence

    def get_evidence(self, evidence_id: UUID) -> Evidence | None:
        """Get evidence by ID."""
        return self.db.get(Evidence, evidence_id)

    def list_evidence(
        self,
        finding_id: UUID,
        evidence_type: EvidenceType | None = None,
    ) -> list[Evidence]:
        """List evidence for a finding."""
        stmt = select(Evidence).where(Evidence.finding_id == finding_id)
        if evidence_type:
            stmt = stmt.where(Evidence.evidence_type == evidence_type)
        return list(self.db.scalars(stmt).all())

    def download_evidence(self, evidence_id: UUID) -> tuple[str, str] | None:
        """Get evidence content for download (returns content, filename)."""
        evidence = self.db.get(Evidence, evidence_id)
        if not evidence:
            return None

        if evidence.storage == "inline" and evidence.content:
            return evidence.content, f"evidence_{evidence_id}.txt"
        elif evidence.object_key:
            # Would integrate with object storage (MinIO/S3)
            return f"[Object storage: {evidence.object_key}]", f"evidence_{evidence_id}.bin"
        return None

    def redact_evidence(self, evidence_id: UUID, custom_patterns: list[tuple[str, str, str, float]] | None = None) -> Evidence | None:
        """Re-redact evidence with optional custom patterns."""
        evidence = self.db.get(Evidence, evidence_id)
        if not evidence or not evidence.content:
            return evidence

        sanitizer = EvidenceSanitizer()
        if custom_patterns:
            # Would need to add custom patterns to secret redactor
            pass

        result = sanitizer.sanitize(evidence.content)
        evidence.content = result.redacted
        evidence.redacted = True
        evidence.redacted_at = datetime.now(UTC)
        evidence.metadata_ = {
            **evidence.metadata_,
            "redaction_matches": [
                {
                    "reason": m.reason.value,
                    "pattern": m.pattern_name,
                    "confidence": m.confidence,
                }
                for m in result.matches
            ],
        }
        self.db.flush()
        return evidence


# =============================================================================
# CorrelationService
# =============================================================================

class CorrelationService:
    """Service for finding correlation and deduplication."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.correlation_engine = get_correlation_engine()

    def correlate_finding(self, finding_id: UUID) -> list[dict[str, Any]]:
        """Find correlations for a specific finding."""
        finding = self.db.get(Finding, finding_id)
        if not finding or not finding.asset_id:
            return []

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
        )

        existing_findings = self._get_project_findings(finding.project_id)
        correlations = self.correlation_engine.find_similar(key, existing_findings)

        return [
            {
                "finding_id": str(c.finding_id),
                "correlated_finding_id": str(c.correlated_finding_id),
                "correlation_type": c.correlation_type.value,
                "confidence": c.confidence,
                "evidence": c.evidence,
            }
            for c in correlations
        ]

    def correlate_all_findings(self, project_id: UUID) -> list[FindingCluster]:
        """Build correlation clusters for all findings in a project."""
        findings = self._get_project_findings(project_id)
        return self.correlation_engine.build_clusters(findings)

    def get_finding_clusters(self, project_id: UUID) -> list[FindingCluster]:
        """Get deduplication clusters for a project."""
        return self.correlate_all_findings(project_id)

    def _get_project_findings(self, project_id: UUID) -> list[dict[str, Any]]:
        """Get all findings in a project for correlation."""
        stmt = select(Finding).where(
            Finding.project_id == project_id,
            Finding.deleted_at.is_(None),
        )
        findings = self.db.scalars(stmt).all()

        result = []
        for f in findings:
            asset_value = ""
            asset_type = ""
            if f.asset_id:
                asset = self.db.get(Asset, f.asset_id)
                if asset:
                    asset_value = asset.value
                    asset_type = asset.kind.value

            result.append({
                "id": f.id,
                "asset_value": asset_value,
                "asset_type": asset_type,
                "vulnerability_type": f.cwe_id or "UNKNOWN",
                "location": f.title,
                "parameter": None,
                "rule_identity": f.cwe_id or "unknown",
                "http_method": None,
            })
        return result

    def mark_duplicate(self, source_finding_id: UUID, target_finding_id: UUID, user_id: UUID) -> FindingRelationship | None:
        """Mark one finding as duplicate of another."""
        from app.models.enums import FindingRelationType

        relationship = FindingRelationship(
            source_finding_id=source_finding_id,
            target_finding_id=target_finding_id,
            relationship_type=FindingRelationType.DUPLICATE_OF,
        )
        self.db.add(relationship)

        # Update source finding status
        source = self.db.get(Finding, source_finding_id)
        if source:
            source.status = FindingStatus.DUPLICATE
            source.updated_at = datetime.now(UTC)

        self.db.flush()
        return relationship


# =============================================================================
# ManualReviewService
# =============================================================================

class ManualReviewService:
    """Service for manual review queue management."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.review_queue = ManualReviewQueue(db, DEFAULT_REVIEW_POLICY)

    def enqueue_observation(
        self,
        observation: Observation,
        reason: ReviewReason,
        priority: ReviewPriority,
    ) -> ManualReviewItem:
        """Add observation to manual review queue."""
        return self.review_queue.enqueue(observation, reason, priority)

    def get_pending_reviews(
        self,
        project_id: UUID,
        page: int = 1,
        page_size: int = 20,
        status_filter: str | None = None,
        priority_filter: str | None = None,
    ) -> tuple[list[ManualReviewItem], int]:
        """Get pending review items (would query actual queue table)."""
        # In a real implementation, this would query a ManualReviewQueue table
        # For now, return empty as we don't have the table yet
        return [], 0

    def get_review_item(self, item_id: UUID) -> ManualReviewItem | None:
        """Get review queue item by ID."""
        # Would query queue table
        return None

    def assign_reviewer(self, item_id: UUID, reviewer_id: UUID) -> ManualReviewItem | None:
        """Assign review item to a reviewer."""
        return self.review_queue.assign(item_id, reviewer_id)

    def resolve_review(self, decision: ReviewDecision) -> ManualReviewItem | None:
        """Resolve a review item."""
        return self.review_queue.resolve(decision)

    def promote_from_review(
        self,
        review_item_id: UUID,
        reviewer_id: UUID,
        severity: Severity,
        confidence: Confidence,
        cwe_id: str | None = None,
        cvss_vector: CVSSVector | None = None,
        recommendation: str | None = None,
    ) -> Finding | None:
        """Promote observation to finding from review queue."""
        # Get review item and associated observation
        # For now, use analysis engine directly
        engine = get_analysis_engine(self.db)
        return engine.promote_observation(
            observation_id=review_item_id,  # Using observation_id as review_item_id
            user_id=reviewer_id,
            severity=severity,
            confidence=confidence,
            cwe_id=cwe_id,
            cvss_vector=cvss_vector,
            recommendation=recommendation,
        )

    def dismiss_from_review(
        self,
        review_item_id: UUID,
        reviewer_id: UUID,
        reason: str,
    ) -> Observation | None:
        """Dismiss observation from review queue."""
        engine = get_analysis_engine(self.db)
        return engine.dismiss_observation(review_item_id, reviewer_id, reason)

    def get_queue_stats(self, project_id: UUID) -> dict[str, int]:
        """Get review queue statistics."""
        return self.review_queue.get_stats(project_id)


# =============================================================================
# CVSS Service
# =============================================================================

class CVSSService:
    """Service for CVSS scoring."""

    @staticmethod
    def calculate(vector: CVSSVector) -> tuple[float, str]:
        """Calculate CVSS score and severity."""
        result = calculate_cvss_base_score(vector)
        return result.base_score, result.severity

    @staticmethod
    def calculate_for_category(category: str) -> tuple[float, str] | None:
        """Calculate CVSS for a vulnerability category."""
        result = calculate_cvss_for_category(category)
        if result:
            return result.base_score, result.severity
        return None

    @staticmethod
    def get_default_vector(category: str) -> CVSSVector | None:
        """Get default CVSS vector for category."""
        return get_default_vector(category)

    @staticmethod
    def parse_vector(vector_str: str) -> CVSSVector:
        """Parse CVSS vector string."""
        return CVSSVector.from_string(vector_str)
