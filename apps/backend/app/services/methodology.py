"""Methodology service layer - Test Planning and Coverage Engine.

This module contains the service classes for methodology-driven test planning
and coverage tracking. These are separate from the model definitions to maintain
clean architecture separation.
"""

import uuid
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.models.enums import TestCaseRunStatus
from app.models.methodology import MethodologyVersion, TestCase, TestCaseRun

# Type aliases for coverage status
CoverageStatus = Literal["tested", "not_tested", "needs_review", "not_applicable"]


class TestPlanner:
    """Dynamically selects applicable test cases based on context."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def select_test_cases(
        self,
        methodology_version_id: uuid.UUID,
        target_type: str,
        discovered_technologies: list[str] | None = None,
        has_authenticated_access: bool = False,
        has_api_schema: bool = False,
        has_web_application: bool = False,
        scope_rules: list[Any] | None = None,
        testing_profile: str = "default",  # passive, safe, active
    ) -> list[TestCase]:
        """Select applicable test cases based on context.

        Args:
            methodology_version_id: The methodology version to select from
            target_type: Type of target (url, web_application, api, domain, etc.)
            discovered_technologies: List of detected technologies (e.g., ["react", "nginx", "php"])
            has_authenticated_access: Whether authenticated access is available
            has_api_schema: Whether API schema (OpenAPI/Swagger) is available
            has_web_application: Whether target is a web application
            scope_rules: Project scope rules for authorization
            testing_profile: Testing profile (passive, safe, active)

        Returns:
            List of applicable TestCase objects
        """
        # Get all test cases for this methodology version
        query = self.session.query(TestCase).filter(
            TestCase.methodology_version_id == methodology_version_id
        )
        all_cases = query.all()

        applicable = []
        for case in all_cases:
            if self._is_applicable(
                case,
                target_type,
                discovered_technologies,
                has_authenticated_access,
                has_api_schema,
                has_web_application,
                testing_profile,
            ):
                applicable.append(case)

        # Sort by category and identifier
        applicable.sort(key=lambda c: (c.category or "", c.identifier or ""))

        return applicable

    def _is_applicable(
        self,
        case: "TestCase",
        target_type: str,
        discovered_technologies: list[str] | None,
        has_authenticated_access: bool,
        has_api_schema: bool,
        has_web_application: bool,
        testing_profile: str,
    ) -> bool:
        """Determine if a test case is applicable given the context."""

        # Check target type compatibility
        supported = case.supported_target_types or []
        if supported and target_type not in supported:
            # Check if target_type is a subtype of a supported type
            type_map = {
                "web_application": ["url", "web_application"],
                "api": ["api", "url"],
                "domain": ["domain"],
            }
            # Check if target_type is a subtype of any supported type
            for s in supported:
                if target_type in type_map.get(s, [s]):
                    break
            else:
                return False

        # Check prerequisites
        prerequisites = case.prerequisites or []
        for prereq in prerequisites:
            if prereq == "authenticated_user" and not has_authenticated_access:
                return False
            if prereq == "api_schema" and not has_api_schema:
                return False
            if prereq == "web_application" and not has_web_application:
                return False

        # Check testing profile compatibility
        if testing_profile == "passive":
            if not case.passive_mode:
                return False
        elif testing_profile == "safe":
            if not case.safe_mode_compatible:
                return False
        elif testing_profile == "active":
            if not case.active_mode:
                return False

        return True

    def create_test_case_runs(
        self,
        project_id: uuid.UUID,
        scan_id: uuid.UUID | None,
        methodology_version_id: uuid.UUID,
        target_type: str,
        discovered_technologies: list[str] | None = None,
        has_authenticated_access: bool = False,
        has_api_schema: bool = False,
        has_web_application: bool = False,
        testing_profile: str = "default",
    ) -> list["TestCaseRun"]:
        """Create TestCaseRun records for all applicable test cases.

        Returns:
            List of created TestCaseRun objects
        """
        applicable = self.select_test_cases(
            methodology_version_id=methodology_version_id,
            target_type=target_type,
            discovered_technologies=discovered_technologies,
            has_authenticated_access=has_authenticated_access,
            has_api_schema=has_api_schema,
            has_web_application=has_web_application,
            testing_profile=testing_profile,
        )

        runs = []
        for case in applicable:
            run = TestCaseRun(
                test_case_id=case.id,
                scan_id=None,
                project_id=project_id,
                status=TestCaseRunStatus.PENDING,
                coverage_status="not_tested",
                notes=f"Auto-generated from methodology {case.identifier}",
            )
            self.session.add(run)
            runs.append(run)

        self.session.flush()
        return runs


class CoverageEngine:
    """Tracks and reports methodology coverage for a project/scan."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def calculate_coverage(
        self,
        project_id: uuid.UUID,
        methodology_version_id: uuid.UUID,
        scan_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Calculate methodology coverage for a project/scan.

        Returns:
            Dictionary with coverage statistics
        """
        # Get all test cases for this methodology version (preload to avoid N+1)
        test_cases = self.session.query(TestCase).filter(
            TestCase.methodology_version_id == methodology_version_id
        ).all()

        total_cases = len(test_cases)

        # Create a lookup dict for test cases by ID
        test_case_lookup = {tc.id: tc for tc in test_cases}

        if total_cases == 0:
            return {
                "total": 0,
                "tested": 0,
                "not_tested": 0,
                "needs_review": 0,
                "not_applicable": 0,
                "coverage_percentage": 0.0,
                "by_category": {},
            }

        # Get test case runs
        query = self.session.query(TestCaseRun).join(TestCase).filter(
            TestCase.methodology_version_id == methodology_version_id,
            TestCaseRun.project_id == project_id,
        )
        if scan_id:
            query = query.filter(TestCaseRun.scan_id == scan_id)

        runs = query.all()

        # Count by coverage status
        status_counts: dict[CoverageStatus, int] = {
            "tested": 0,
            "not_tested": 0,
            "needs_review": 0,
            "not_applicable": 0,
        }

        by_category: dict[str, dict[str, int]] = {}

        for run in runs:
            # Get test case for category (using preloaded lookup - no N+1)
            case = test_case_lookup.get(run.test_case_id)
            if not case:
                continue
            category = case.category or "uncategorized"

            if category not in by_category:
                by_category[category] = {
                    "tested": 0,
                    "not_tested": 0,
                    "needs_review": 0,
                    "not_applicable": 0,
                    "total": 0,
                }

            by_category[category]["total"] += 1

            status = run.coverage_status
            if status in status_counts:
                status_counts[status] += 1
                by_category[category][status] += 1

        tested = status_counts["tested"]
        coverage_pct = (tested / total_cases * 100) if total_cases > 0 else 0.0

        return {
            "total": total_cases,
            "tested": status_counts["tested"],
            "not_tested": status_counts["not_tested"],
            "needs_review": status_counts["needs_review"],
            "not_applicable": status_counts["not_applicable"],
            "coverage_percentage": round(coverage_pct, 2),
            "by_category": by_category,
        }

    def get_coverage_dashboard_data(
        self,
        project_id: uuid.UUID,
        methodology_version_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """Get comprehensive dashboard data for methodology coverage."""
        version = None
        if methodology_version_id is None:
            # Get active version
            version = self.session.query(MethodologyVersion).filter(
                MethodologyVersion.is_active
            ).first()
            if not version:
                return {"error": "No active methodology version"}
            methodology_version_id = version.id

        coverage = self.calculate_coverage(project_id, methodology_version_id)

        # Get version info - reuse from calculate_coverage or fetch if needed
        if version is None:
            version = self.session.query(MethodologyVersion).get(methodology_version_id)

        # Get breakdown by test case status
        runs_query = self.session.query(TestCaseRun).join(TestCase).filter(
            TestCase.methodology_version_id == methodology_version_id,
            TestCaseRun.project_id == project_id,
        )
        runs = runs_query.all()

        run_status_counts = {
            TestCaseRunStatus.PENDING.value: 0,
            TestCaseRunStatus.PASSED.value: 0,
            TestCaseRunStatus.FAILED.value: 0,
            TestCaseRunStatus.SKIPPED.value: 0,
            TestCaseRunStatus.BLOCKED.value: 0,
        }

        for run in runs:
            if run.status.value in run_status_counts:
                run_status_counts[run.status.value] += 1

        # Add security warning if coverage is incomplete
        security_warning = None
        if coverage["coverage_percentage"] < 100.0:
            security_warning = "Incomplete coverage does not imply security."

        return {
            "methodology": {
                "id": str(version.id) if version else None,
                "name": version.methodology.name if version and version.methodology else None,
                "version": version.version if version else None,
            },
            "coverage": coverage,
            "run_status_breakdown": run_status_counts,
            "security_warning": security_warning,
        }

    def mark_test_case_coverage(
        self,
        run_id: uuid.UUID,
        coverage_status: CoverageStatus,
        coverage_reason: str | None = None,
    ) -> bool:
        """Manually update coverage status for a test case run."""
        valid_statuses: set[CoverageStatus] = {
            "tested",
            "not_tested",
            "needs_review",
            "not_applicable",
        }
        if coverage_status not in valid_statuses:
            raise ValueError(f"Invalid coverage_status: {coverage_status}")

        run = self.session.query(TestCaseRun).get(run_id)
        if not run:
            return False

        run.coverage_status = coverage_status
        if coverage_reason is not None:
            run.coverage_reason = coverage_reason
        self.session.flush()
        return True
