"""Target validation service using ScopeEngine."""

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import write_audit_log
from app.core.exceptions import ForbiddenError, NotFoundError
from app.core.scope_engine import create_scope_engine
from app.models.enums import ScopeRuleTargetType, SecurityEventType
from app.models.projects import Project, Scope, ScopeStatus, Target


class TargetValidationService:
    """Service for validating targets against scope rules.

    This service:
    1. Fetches active scopes and rules for a project
    2. Uses ScopeEngine to evaluate targets against rules
    3. Updates target.scope_status based on evaluation
    4. Handles exclusion patterns and authorization checks
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.engine = create_scope_engine()

    def validate_target(
        self,
        target_id: uuid.UUID,
        project_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
        source_ip: str | None = None,
    ) -> Target:
        """Validate a single target against its project's scope rules.

        Updates the target's scope_status based on scope evaluation.
        """
        target = self.session.get(Target, target_id)
        if not target:
            raise NotFoundError("Target", str(target_id))

        # Verify target belongs to the specified project (IDOR protection)
        if target.project_id != project_id:
            raise ForbiddenError("Target does not belong to the specified project")

        updated_target = self._evaluate_and_update_target(target)
        self.session.flush()

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
                    "project_id": str(target.project_id),
                },
                source_ip=source_ip,
            )

        return updated_target

    def validate_targets_in_project(
        self, project_id: uuid.UUID, page: int = 1, page_size: int = 50
    ) -> Sequence[Target]:
        """Validate all targets in a project against scope rules.

        Returns paginated list of updated targets.
        """
        # Get all targets in project with pagination
        targets = self.session.scalars(
            select(Target)
            .where(Target.project_id == project_id, Target.deleted_at.is_(None))
            .limit(page_size)
            .offset((page - 1) * page_size)
        ).all()

        if not targets:
            return []

        # Batch evaluation: collect all rules once, then evaluate all targets
        # This avoids repeated scope rule fetching per target
        updated = self._batch_evaluate_targets(targets)

        self.session.flush()
        return updated

    def _batch_evaluate_targets(self, targets: list[Target]) -> list[Target]:
        """Evaluate multiple targets in batch to avoid repeated rule fetching."""
        if not targets:
            return []

        # Get project from first target (all targets should be in same project)
        project_id = targets[0].project_id

        # Get active scopes and rules for this project once
        project = self.session.get(Project, project_id)
        if not project:
            for target in targets:
                target.scope_status = ScopeStatus.UNKNOWN
            return targets

        # Get active scopes for this project
        scopes = self.session.scalars(
            select(Scope).where(
                Scope.project_id == project_id,
                Scope.is_active == True  # noqa: E712
            )
        ).all()

        if not scopes:
            for target in targets:
                target.scope_status = ScopeStatus.UNKNOWN
            return targets

        # Collect all rules from active scopes
        all_rules = []
        for scope in scopes:
            all_rules.extend(scope.rules)

        # Create a map of target -> specific scope rules for prioritization
        target_specific_rules: dict[uuid.UUID, list] = {}
        for target in targets:
            if target.scope_id:
                specific_scope = self.session.get(Scope, target.scope_id)
                if specific_scope and specific_scope in scopes:
                    target_specific_rules[target.id] = list(specific_scope.rules)

        # Evaluate all targets
        updated = []
        for target in targets:
            # Determine rules to use (specific scope rules first, then general)
            rules = all_rules
            if target.id in target_specific_rules:
                specific_rules = target_specific_rules[target.id]
                other_rules = [r for r in all_rules if r not in specific_rules]
                rules = specific_rules + other_rules

            # Determine target type
            if target.target_type:
                try:
                    target_type = ScopeRuleTargetType(target.target_type)
                except ValueError:
                    target_type = self._infer_target_type(target.name)
            else:
                target_type = self._infer_target_type(target.name)
                target.target_type = target_type.value

            # Evaluate
            status = self.engine.evaluate_multiple_types(
                target_value=target.name,
                rules=rules,
            )
            target.scope_status = status
            updated.append(target)

        return updated

    def validate_targets_in_scope(
        self,
        scope_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
        source_ip: str | None = None,
    ) -> Sequence[Target]:
        """Validate all targets associated with a specific scope."""
        scope = self.session.get(Scope, scope_id)
        if not scope:
            raise NotFoundError("Scope", str(scope_id))

        targets = self.session.scalars(
            select(Target).where(Target.scope_id == scope_id, Target.deleted_at.is_(None))
        ).all()

        updated = []
        for target in targets:
            updated_target = self._evaluate_and_update_target(target)
            updated.append(updated_target)

        self.session.flush()

        # Audit log
        if user_id:
            write_audit_log(
                self.session,
                event_type=SecurityEventType.SCOPE_EVALUATE_BULK,
                user_id=user_id,
                entity_type="scope",
                entity_id=str(scope.id),
                details={
                    "scope_name": scope.name,
                    "total_evaluated": len(updated),
                    "project_id": str(scope.project_id),
                },
                source_ip=source_ip,
            )

        return updated

    def _evaluate_and_update_target(self, target: Target) -> Target:
        """Evaluate a target against applicable scope rules and update status."""
        # Get project to find active scopes
        project = self.session.get(Project, target.project_id)
        if not project:
            target.scope_status = ScopeStatus.UNKNOWN
            return target

        # Get active scopes for this project
        scopes = self.session.scalars(
            select(Scope).where(
                Scope.project_id == target.project_id,
                Scope.is_active == True  # noqa: E712
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
                # Move specific scope rules to front for priority evaluation
                specific_rules = specific_scope.rules
                other_rules = [r for r in all_rules if r not in specific_rules]
                all_rules = list(specific_rules) + other_rules

        # Handle exclusion patterns - filter out exclude rules
        include_rules, is_excluded = self._handle_exclusion_patterns(
            target, all_rules
        )

        if is_excluded:
            target.scope_status = ScopeStatus.OUT_OF_SCOPE
            return target

        # Determine target type - use stored type if available, otherwise infer
        if target.target_type:
            try:
                target_type = ScopeRuleTargetType(target.target_type)
            except ValueError:
                target_type = self._infer_target_type(target.name)
        else:
            target_type = self._infer_target_type(target.name)
            # Store inferred type for future evaluations
            target.target_type = target_type.value

        # Evaluate - use multiple types since a target could match different rule types
        status = self.engine.evaluate_multiple_types(
            target_value=target.name,
            rules=include_rules,
        )

        target.scope_status = status
        return target

    def _infer_target_type(self, target_name: str) -> ScopeRuleTargetType:
        """Infer target type from the target name format."""
        # Check for CIDR notation
        if "/" in target_name:
            try:
                import ipaddress
                ipaddress.ip_network(target_name, strict=False)
                return ScopeRuleTargetType.CIDR
            except ValueError:
                pass

        # Check for IP address
        try:
            import ipaddress
            ipaddress.ip_address(target_name)
            return ScopeRuleTargetType.IP
        except ValueError:
            pass

        # Check for URL
        if target_name.startswith(("http://", "https://")):
            return ScopeRuleTargetType.URL

        # Check for APK package name (reverse domain notation with multiple dots)
        if target_name.count(".") >= 2 and not target_name.startswith(("http://", "https://")):
            # Could be domain or APK - check if it looks like a package
            parts = target_name.split(".")
            if all(part.isidentifier() or part == "*" for part in parts):
                # Check if last part looks like TLD or common package suffix
                if parts[-1] in ("com", "org", "net", "io", "app", "dev", "co"):
                    return ScopeRuleTargetType.DOMAIN
                return ScopeRuleTargetType.APK

        # Check for domain pattern (has dots, not IP)
        if "." in target_name and not target_name.startswith(("http://", "https://")):
            # Check if it's a subdomain pattern
            if target_name.startswith("*."):
                return ScopeRuleTargetType.SUBDOMAIN_PATTERN
            return ScopeRuleTargetType.DOMAIN

        # Default to DOMAIN for anything else
        return ScopeRuleTargetType.DOMAIN

    def _handle_exclusion_patterns(
        self, target: Target, all_rules: list
    ) -> list:
        """Filter out exclusion patterns from the rule set.

        Scope rules with effect='exclude' remove targets from scope.
        This method separates exclude rules and returns only include rules
        for evaluation, while tracking excluded patterns for reporting.
        """
        include_rules = []
        exclude_rules = []

        for rule in all_rules:
            if rule.effect.value == "exclude":
                exclude_rules.append(rule)
            else:
                include_rules.append(rule)

        # Check if target matches any exclude pattern
        for exclude_rule in exclude_rules:
            if self._target_matches_pattern(target.name, exclude_rule.pattern):
                # Target is excluded - mark as out of scope
                return include_rules, True

        return include_rules, False

    @staticmethod
    def _target_matches_pattern(target_name: str, pattern: str) -> bool:
        """Check if a target name matches a scope rule pattern.

        Supports simple wildcard (*) matching and exact matching.
        """
        import fnmatch

        try:
            return fnmatch.fnmatch(target_name, pattern)
        except Exception:
            # Fallback to exact match if pattern is invalid
            return target_name == pattern

    def update_target_status_manually(
        self,
        target_id: uuid.UUID,
        status: ScopeStatus,
        user_id: uuid.UUID | None = None,
        source_ip: str | None = None,
    ) -> Target:
        """Manually override a target's scope status."""
        target = self.session.get(Target, target_id)
        if not target:
            raise NotFoundError("Target", str(target_id))

        old_status = target.scope_status
        target.scope_status = status
        self.session.flush()

        # Audit log
        if user_id:
            write_audit_log(
                self.session,
                event_type=SecurityEventType.SCOPE_STATUS_OVERRIDE,
                user_id=user_id,
                entity_type="target",
                entity_id=str(target.id),
                details={
                    "target_name": target.name,
                    "old_status": old_status.value,
                    "new_status": status.value,
                    "project_id": str(target.project_id),
                },
                source_ip=source_ip,
            )

        return target


def validate_target_for_scan(
    session: Session,
    project_id: uuid.UUID,
    target_id: uuid.UUID,
) -> tuple[bool, str | None]:
    """
    Validate a target for scanning.

    This is a convenience function that checks if a target is in scope
    and can be scanned. Returns (is_valid, error_message).
    """
    service = TargetValidationService(session)
    try:
        target = service.validate_target(target_id, project_id)
        if target.scope_status == ScopeStatus.IN_SCOPE:
            return True, None
        elif target.scope_status == ScopeStatus.OUT_OF_SCOPE:
            return False, "Target is out of scope"
        elif target.scope_status == ScopeStatus.THIRD_PARTY:
            return False, "Target is third party"
        else:
            return False, "Target scope is unknown - run scope evaluation first"
    except NotFoundError:
        return False, "Target not found"
    except ForbiddenError as e:
        return False, str(e)


# For backward compatibility with existing code
class TargetScopeValidationService:
    """Legacy alias for TargetValidationService."""
    pass
