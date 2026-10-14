"""APK Analysis Service - orchestrates APK static analysis and methodology integration."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.analysis_engine import IngestionContext, get_analysis_engine
from app.core.apk_analyzer import ApkAnalyzer
from app.core.evidence_sanitizer import sanitize_evidence
from app.models.apk import ApkComponent, ApkFile
from app.models.assets import Asset
from app.models.detection import Evidence, Finding, Observation
from app.models.enums import (
    Confidence,
    EvidenceType,
    FindingStatus,
    ObservationType,
    Severity,
)
from app.models.methodology import Methodology, MethodologyVersion, TestCase, TestCaseRun
from app.schemas.apk import (
    ApkAnalysisRequest,
    ApkAnalysisResultCreate,
    ApkFileCreate,
    ApkUploadRequest,
)


class ApkAnalysisService:
    """Service for managing APK analysis workflow."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.analysis_engine = get_analysis_engine(db)

    def create_apk_file_record(
        self,
        project_id: UUID,
        asset_id: UUID,
        package_name: str,
        version_name: str | None,
        version_code: int | None,
        sha256: str,
        object_key: str | None,
    ) -> ApkFile:
        """Create an APK file record in the database."""
        apk_file = ApkFile(
            asset_id=asset_id,
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            sha256=sha256,
            object_key=object_key,
        )
        self.db.add(apk_file)
        self.db.flush()
        return apk_file

    def get_apk_file(self, apk_file_id: UUID) -> ApkFile | None:
        """Get APK file by ID."""
        return self.db.get(ApkFile, apk_file_id)

    def list_apk_files(
        self,
        project_id: UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ApkFile], int]:
        """List APK files for a project."""
        stmt = select(ApkFile).join(Asset).where(
            Asset.project_id == project_id,
            ApkFile.deleted_at.is_(None),
        )

        total_stmt = select(func.count(ApkFile.id)).join(Asset).where(
            Asset.project_id == project_id,
            ApkFile.deleted_at.is_(None),
        )
        total = self.db.scalar(total_stmt) or 0

        stmt = stmt.order_by(ApkFile.created_at.desc()).limit(page_size).offset((page - 1) * page_size)
        apk_files = list(self.db.scalars(stmt).all())

        return apk_files, total

    def analyze_apk(self, apk_file_id: UUID, analysis_types: list[str] | None = None) -> dict[str, Any]:
        """Run static analysis on an APK file."""
        apk_file = self.get_apk_file(apk_file_id)
        if not apk_file:
            raise ValueError(f"APK file {apk_file_id} not found")

        # Get asset to find object_key
        asset = self.db.get(Asset, apk_file.asset_id)
        if not asset:
            raise ValueError(f"Asset {apk_file.asset_id} not found")

        # Construct path to APK file (in MinIO or local storage)
        # For now, we assume the APK is accessible via object_key
        # In production, this would download from MinIO to a temp location
        apk_path = Path(apk_file.object_key) if apk_file.object_key else Path(f"/tmp/{apk_file.sha256}.apk")

        if not apk_path.exists():
            # Try to find it in upload directory
            upload_path = Path(f"/uploads/{apk_file.sha256}.apk")
            if upload_path.exists():
                apk_path = upload_path
            else:
                raise ValueError(f"APK file not found at {apk_path}")

        # Run analysis
        analyzer = ApkAnalyzer(apk_path, str(apk_file_id), apk_file.package_name)
        try:
            result = analyzer.analyze(analysis_types)
        finally:
            analyzer.cleanup()

        # Store analysis results as observations/findings
        self._store_analysis_results(apk_file, result)

        return result

    def _store_analysis_results(self, apk_file: ApkFile, result: dict[str, Any]) -> None:
        """Store analysis results as observations and findings."""
        project_id = None
        asset = self.db.get(Asset, apk_file.asset_id)
        if asset:
            project_id = asset.project_id

        if not project_id:
            return

        for finding_data in result.get("findings", []):
            # Create observation first
            observation = Observation(
                project_id=project_id,
                asset_id=apk_file.asset_id,
                observation_type=ObservationType.CONFIGURATION,
                title=finding_data.get("title", "APK Analysis Finding"),
                detail=finding_data.get("description"),
                payload={
                    "analyzer": finding_data.get("analyzer_name"),
                    "location": finding_data.get("location"),
                    "evidence": finding_data.get("evidence", {}),
                    "mastg_references": finding_data.get("mastg_references", []),
                    "masvs_references": finding_data.get("masvs_references", []),
                },
            )

            # Map severity and confidence hints
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            confidence_map = {
                "very_high": Confidence.VERY_HIGH,
                "high": Confidence.HIGH,
                "medium": Confidence.MEDIUM,
                "low": Confidence.LOW,
                "very_low": Confidence.VERY_LOW,
            }

            observation.severity_hint = severity_map.get(
                finding_data.get("severity_hint", "info"),
                Severity.INFO
            )
            observation.confidence_hint = confidence_map.get(
                finding_data.get("confidence_hint", "medium"),
                Confidence.MEDIUM
            )

            self.db.add(observation)
            self.db.flush()

            # Add evidence if present
            evidence_data = finding_data.get("evidence", {})
            if evidence_data:
                sanitized = sanitize_evidence(str(evidence_data))
                evidence = Evidence(
                    finding_id=None,  # Will be set if promoted
                    evidence_type=EvidenceType.SNIPPET,
                    storage="inline",
                    content=sanitized.redacted,
                    redacted=sanitized.was_redacted,
                    metadata_={
                        "original_evidence": evidence_data,
                        "redaction_matches": [
                            {"reason": m.reason.value, "pattern": m.pattern_name, "confidence": m.confidence}
                            for m in sanitized.matches
                        ],
                    },
                )
                self.db.add(evidence)

            # Auto-promote high severity findings with high confidence
            if (observation.severity_hint in (Severity.HIGH, Severity.CRITICAL) and
                observation.confidence_hint in (Confidence.HIGH, Confidence.VERY_HIGH)):
                finding = Finding(
                    project_id=project_id,
                    promoted_from_observation_id=observation.id,
                    asset_id=apk_file.asset_id,
                    title=observation.title,
                    status=FindingStatus.OPEN,
                    severity=observation.severity_hint,
                    confidence=observation.confidence_hint,
                    cwe_id=observation.payload.get("cwe_id"),
                    recommendation=f"Review the {finding_data.get('analyzer_name', 'APK analysis')} finding: {observation.detail}",
                )
                self.db.add(finding)
                self.db.flush()

                # Move evidence to finding
                if evidence_data:
                    evidence.finding_id = finding.id

    def get_apk_components(self, apk_file_id: UUID) -> list[ApkComponent]:
        """Get all components for an APK file."""
        stmt = select(ApkComponent).where(ApkComponent.apk_file_id == apk_file_id)
        return list(self.db.scalars(stmt).all())

    def store_apk_components(self, apk_file_id: UUID, components: list[dict[str, Any]]) -> list[ApkComponent]:
        """Store APK components from manifest analysis."""
        stored_components = []
        for comp_data in components:
            component = ApkComponent(
                apk_file_id=apk_file_id,
                component_type=comp_data.get("component_type", "other"),
                name=comp_data.get("name", ""),
                exported=comp_data.get("exported", False),
                intent_filters=comp_data.get("intent_filters", []),
            )
            self.db.add(component)
            stored_components.append(component)

        self.db.flush()
        return stored_components

    def get_mastg_test_cases(self, category: str | None = None) -> list[TestCase]:
        """Get MASTG test cases, optionally filtered by category."""
        stmt = select(TestCase).join(MethodologyVersion).join(Methodology).where(
            Methodology.name == "OWASP MASTG / MASVS",
            MethodologyVersion.is_active == True,
        )
        if category:
            stmt = stmt.where(TestCase.category == category)

        stmt = stmt.order_by(TestCase.order)
        return list(self.db.scalars(stmt).all())

    def run_mastg_test_case(
        self,
        test_case_id: UUID,
        project_id: UUID,
        apk_file_id: UUID,
        scan_id: UUID | None = None,
    ) -> TestCaseRun:
        """Create a test case run for MASTG methodology."""
        test_case = self.db.get(TestCase, test_case_id)
        if not test_case:
            raise ValueError(f"Test case {test_case_id} not found")

        run = TestCaseRun(
            test_case_id=test_case_id,
            project_id=project_id,
            scan_id=scan_id,
            status="pending",
            coverage_status="not_tested",
        )
        self.db.add(run)
        self.db.flush()
        return run

    def update_test_case_run(
        self,
        run_id: UUID,
        status: str,
        coverage_status: str | None = None,
        evidence_count: int = 0,
        notes: str | None = None,
    ) -> TestCaseRun | None:
        """Update a test case run."""
        run = self.db.get(TestCaseRun, run_id)
        if not run:
            return None

        run.status = status
        if coverage_status:
            run.coverage_status = coverage_status
        run.evidence_count = evidence_count
        run.notes = notes
        run.updated_at = datetime.now(UTC)

        self.db.flush()
        return run

    def get_mastg_coverage(self, project_id: UUID) -> dict[str, Any]:
        """Get MASTG coverage statistics for a project."""
        stmt = select(TestCaseRun).where(TestCaseRun.project_id == project_id)
        runs = list(self.db.scalars(stmt).all())

        total = len(runs)
        tested = len([r for r in runs if r.coverage_status == "tested"])
        not_tested = len([r for r in runs if r.coverage_status == "not_tested"])
        needs_review = len([r for r in runs if r.coverage_status == "needs_review"])
        not_applicable = len([r for r in runs if r.coverage_status == "not_applicable"])

        # By category
        categories: dict[str, dict[str, int]] = {}
        for run in runs:
            test_case = self.db.get(TestCase, run.test_case_id)
            if test_case and test_case.category:
                cat = test_case.category
                if cat not in categories:
                    categories[cat] = {"total": 0, "tested": 0, "not_tested": 0, "needs_review": 0, "not_applicable": 0}
                categories[cat]["total"] += 1
                categories[cat][run.coverage_status] += 1

        return {
            "total": total,
            "tested": tested,
            "not_tested": not_tested,
            "needs_review": needs_review,
            "not_applicable": not_applicable,
            "coverage_percent": (tested / total * 100) if total > 0 else 0,
            "by_category": categories,
        }