"""Scan confirmation service for security confirmation view.

Provides server-side validation and confirmation data generation
for active scan initiation. Ensures scope and authorization are
visible and enforced before any testing begins.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import write_audit_log
from app.core.exceptions import ForbiddenError, NotFoundError
from app.core.scope_engine import create_scope_engine
from app.models.enums import ScopeRuleTargetType, ScopeStatus, SecurityEventType
from app.models.projects import Project, Scope, Target
from app.schemas.targets import TargetResponse


class ScanConfirmationService:
    """Service for generating security confirmation data for target scanning."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.engine = create_scope_engine()

    def get_scan_confirmation(
        self,
        project_id: uuid.UUID,
        target_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
        source_ip: str | None = None,
    ) -> dict:
        """Get security confirmation data for a target before scan execution.

        Returns comprehensive confirmation data including:
        - Target details and scope status
        - Applicable scope rules summary
        - Testing profile recommendations
        - Rate limit restrictions
        - Authorization disclaimer

        Raises NotFoundError if target not found or doesn't belong to project.
        Raises ForbiddenError if target is out of scope or third-party.
        """
        # Get target and verify project membership
        target = self.session.get(Target, target_id)
        if not target:
            raise NotFoundError("Target", str(target_id))

        if target.project_id != project_id:
            raise ForbiddenError("Target does not belong to the specified project")

        # Evaluate target against scope rules
        updated_target = self.validate_target(target_id, project_id, user_id, source_ip)

        # Get project details for context
        project = self.session.get(Project, project_id)
        if not project:
            raise NotFoundError("Project", str(project_id))

        # Get active scopes for this project
        scopes = self.session.scalars(
            select(Scope).where(
                Scope.project_id == project_id,
                Scope.is_active == True,  # noqa: E712
            )
        ).all()

        # Collect all rules from active scopes
        all_rules = []
        for scope in scopes:
            all_rules.extend(scope.rules)

        # Build rule summary
        rule_summary = self._build_rule_summary(all_rules, scopes)

        # Determine testing profile
        testing_profile = self._determine_testing_profile(updated_target, rule_summary)

        # Get rate limit information
        rate_limit_info = self._get_rate_limit_info(updated_target, scopes)

        # Build confirmation data
        confirmation = {
            "target_id": str(target.id),
            "target_name": target.name,
            "target_type": target.target_type or "DOMAIN",
            "target_description": target.description or "",
            "scope_status": updated_target.scope_status.value,
            "is_in_scope": updated_target.scope_status == ScopeStatus.IN_SCOPE,
            "project_id": str(project_id),
            "project_name": project.name,
            "scopes": [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "is_active": s.is_active,
                }
                for s in scopes
            ],
            "rule_summary": rule_summary,
            "testing_profile": testing_profile,
            "rate_limit": rate_limit_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "authorization_disclaimer": (
                "Scope status indicates authorization boundary. "
                "ScopeEngine is an independent security boundary. "
                "Graph relationships never constitute proof of authorization."
            ),
        }

        # Audit log
        if user_id:
            write_audit_log(
                self.session,
                event_type=SecurityEventType.SCOPE_EVALUATE,
                user_id=user_id,
                entity_type="target",
                entity_id=str(target.id),
                details={
                    "target_name": target.name,
                    "scope_status": updated_target.scope_status.value,
                    "project_id": str(project_id),
                    "confirmation_generated": True,
                },
                source_ip=source_ip,
            )

        return confirmation

    def validate_target_for_scan(
        self,
        target_id: uuid.UUID,
        project_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
        source_ip: str | None = None,
    ) -> Target:
        """Validate target for scanning and return updated target.

        Returns the target with scope_status updated based on scope evaluation.
        Raises ForbiddenError if target is out of scope or third-party.
        """
        target = self.session.get(Target, target_id)
        if not target:
            raise NotFoundError("Target", str(target_id))

        if target.project_id != project_id:
            raise ForbiddenError("Target does not belong to the specified project")

        # Evaluate target against scope rules
        updated_target = self._evaluate_and_update_target(target)

        self.session.flush()

        # Check if target is in-scope for scanning
        if updated_target.scope_status == ScopeStatus.OUT_OF_SCOPE:
            raise ForbiddenError("Target is out of scope - cannot initiate scan")
        elif updated_target.scope_status == ScopeStatus.THIRD_PARTY:
            raise ForbiddenError("Target is third party - cannot initiate scan")
        elif updated_target.scope_status == ScopeStatus.UNKNOWN:
            raise ForbiddenError("Target scope is unknown - run scope evaluation first")

        return updated_target

    def _evaluate_and_update_target(self, target: Target) -> Target:
        """Evaluate target against applicable scope rules and update status."""
        project = self.session.get(Project, target.project_id)
        if not project:
            target.scope_status = ScopeStatus.UNKNOWN
            return target

        # Get active scopes for this project
        scopes = self.session.scalars(
            select(Scope).where(
                Scope.project_id == target.project_id,
                Scope.is_active == True,  # noqa: E712
            )
        ).all()

        if not scopes:
            target.scope_status = ScopeStatus.UNKNOWN
            return target

        # Collect all rules from active scopes
        all_rules = []
        for scope in scopes:
            rules = scope.rules
            all_rules.extend(rules)

        # If target has a specific scope_id, prioritize that scope's rules
        if target.scope_id:
            specific_scope = self.session.get(Scope, target.scope_id)
            if specific_scope and specific_scope in scopes:
                specific_rules = specific_scope.rules
                other_rules = [r for r in all_rules if r not in specific_rules]
                all_rules = list(specific_rules) + other_rules

        # Determine target type
        if target.target_type:
            try:
                from app.models.enums import ScopeRuleTargetType
                target_type = ScopeRuleTargetType(target.target_type)
            except ValueError:
                target_type = self._infer_target_type(target.name)
        else:
            target_type = self._infer_target_type(target.name)
            target.target_type = target_type.value

        # Evaluate - use multiple types since a target could match different rule types
        status = self.engine.evaluate_multiple_types(
            target_value=target.name,
            rules=all_rules,
        )

        target.scope_status = status
        return target

    def _build_rule_summary(
        self, rules: list, scopes: list[Scope]
    ) -> dict:
        """Build a human-readable summary of scope rules."""
        if not rules:
            return {
                "total_rules": 0,
                "include_count": 0,
                "exclude_count": 0,
                "rules": [],
            }

        include_rules = [r for r in rules if r.effect.value == "include"]
        exclude_rules = [r for r in rules if r.effect.value == "exclude"]

        rule_descriptions = []
        for rule in rules[:20]:  # Limit to first 20 for display
            target_type_display = rule.target_type.value if rule.target_type else "ANY"
            description = (
                f"{rule.effect.value.upper()}: {target_type_display} - {rule.pattern}"
            )
            if rule.note:
                description += f" ({rule.note})"
            rule_descriptions.append(description)

        return {
            "total_rules": len(rules),
            "include_count": len(include_rules),
            "exclude_count": len(exclude_rules),
            "rules": rule_descriptions,
        }

    def _determine_testing_profile(
        self, target: Target, rule_summary: dict
    ) -> dict:
        """Determine appropriate testing profile based on target and rules."""
        scope_status = target.scope_status

        if scope_status == ScopeStatus.IN_SCOPE:
            if rule_summary.get("total_rules", 0) > 0:
                # Has specific rules - targeted testing
                return {
                    "profile": "targeted",
                    "description": "Targeted testing based on specific scope rules",
                    "risk_level": "medium",
                }
            else:
                # No specific rules - broad testing
                return {
                    "profile": "broad",
                    "description": "Broad testing within project scope",
                    "risk_level": "medium",
                }
        elif scope_status == ScopeStatus.OUT_OF_SCOPE:
            return {
                "profile": "blocked",
                "description": "Target is out of scope - testing blocked",
                "risk_level": "high",
            }
        elif scope_status == ScopeStatus.THIRD_PARTY:
            return {
                "profile": "blocked",
                "description": "Target is third party - testing blocked",
                "risk_level": "high",
            }
        else:
            # unknown - needs evaluation
            return {
                "profile": "evaluate",
                "description": "Target scope unknown - evaluation required",
                "risk_level": "high",
            }

    def _get_rate_limit_info(
        self, target: Target, scopes: list[Scope]
    ) -> dict | None:
        """Get rate limit information for the target."""
        # Check if any scope has rate limits configured
        for scope in scopes:
            # Look for rules with rate limit information in notes or properties
            for rule in scope.rules:
                if rule.note and "rate_limit" in rule.note.lower():
                    # Parse rate limit from note
                    return {
                        "limit": "configured",
                        "details": rule.note,
                        "source_scope": scope.name,
                    }

        # Default rate limit for in-scope targets
        return {
            "limit": "default",
            "details": "Default rate limit applies: 10 requests/second per target",
            "source_scope": None,
        }

    def _infer_target_type(self, target_name: str) -> ScopeRuleTargetType:
        """Infer target type from the target name format."""
        import ipaddress

        # Check for CIDR notation
        if "/" in target_name:
            try:
                ipaddress.ip_network(target_name, strict=False)
                return ScopeRuleTargetType.CIDR
            except ValueError:
                pass

        # Check for IP address
        try:
            ipaddress.ip_address(target_name)
            return ScopeRuleTargetType.IP
        except ValueError:
            pass

        # Check for URL
        if target_name.startswith(("http://", "https://")):
            return ScopeRuleTargetType.URL

        # Check for APK package name (reverse domain notation with multiple dots)
        if target_name.count(".") >= 2 and not target_name.startswith(("http://", "https://")):
            parts = target_name.split(".")
            if all(part.isidentifier() or part == "*" for part in parts):
                if parts[-1] in ("com", "org", "net", "io", "app", "dev", "co"):
                    return ScopeRuleTargetType.DOMAIN
                return ScopeRuleTargetType.APK

        # Check for domain pattern (has dots, not IP)
        if "." in target_name and not target_name.startswith(("http://", "https://")):
            if target_name.startswith("*."):
                return ScopeRuleTargetType.SUBDOMAIN_PATTERN
            return ScopeRuleTargetType.DOMAIN

        # Default to DOMAIN
        return ScopeRuleTargetType.DOMAIN