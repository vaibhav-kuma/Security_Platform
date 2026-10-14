"""Recon engine orchestrating plugin execution."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.scope_engine import create_scope_engine
from app.models.assets import Asset, AssetRelationship
from app.models.enums import AssetKind, AssetRelationshipType, ScopeStatus
from app.models.scans import Scan, ScanJob
from app.recon.normalizer import NormalizedTarget, TargetNormalizer
from app.recon.plugins import (
    ReconContext,
    ReconPlugin,
    ReconPluginRegistry,
    ReconResult,
    get_plugin_registry,
)
from app.recon.policy import ExecutionPolicy
from app.recon.rate_limiter import InMemoryRateLimiter, ReconRateLimiter
import asyncio


class ReconEngine:
    """Orchestrates reconnaissance plugin execution."""

    def __init__(
        self,
        db_session: Any,
        policy: ExecutionPolicy | None = None,
        rate_limiter: ReconRateLimiter | InMemoryRateLimiter | None = None,
        normalizer: TargetNormalizer | None = None,
        plugin_registry: ReconPluginRegistry | None = None,
    ) -> None:
        self.db = db_session
        self.policy = policy or ExecutionPolicy.default_passive()
        self.rate_limiter = rate_limiter or InMemoryRateLimiter()
        self.normalizer = normalizer or TargetNormalizer()
        self.plugin_registry = plugin_registry or get_plugin_registry()
        self.scope_engine = create_scope_engine()

    def run_recon(
        self,
        scan: Scan,
        job: ScanJob,
        target_value: str,
        target_type: str,
        scope_rules: list[dict[str, Any]],
        plugin_names: list[str] | None = None,
    ) -> list[ReconResult]:
        """Run reconnaissance plugins for a target.

        Args:
            scan: Parent scan
            job: Scan job executing the recon
            target_value: Target value to recon
            target_type: Type of target (domain, ip, url, etc.)
            scope_rules: Serialized scope rules for evaluation
            plugin_names: Optional list of plugin names to run (None = all applicable)

        Returns:
            List of all ReconResult from all plugins
        """
        # Run the async version
        import asyncio
        return asyncio.run(self.run_recon_async(scan, job, target_value, target_type, scope_rules, plugin_names))

    async def run_recon_async(
        self,
        scan: Scan,
        job: ScanJob,
        target_value: str,
        target_type: str,
        scope_rules: list[dict[str, Any]],
        plugin_names: list[str] | None = None,
    ) -> list[ReconResult]:
        """Async version of run_recon for parallel plugin execution."""
        # Get applicable plugins
        if plugin_names:
            plugins: list[ReconPlugin] = [
                plugin for name in plugin_names
                if (plugin := self.plugin_registry.get(name)) is not None
            ]
        else:
            plugins = self.plugin_registry.get_for_target(target_type)

        # Filter by policy
        plugins = [p for p in plugins if self.policy.is_plugin_enabled(p.config.name)]

        # Create execution context
        context = ReconContext(
            project_id=scan.project_id,
            scan_id=scan.id,
            scan_job_id=job.id,
            target_id=scan.target_id,
            target_value=target_value,
            target_type=target_type,
            scope_rules=scope_rules,
            execution_policy={
                "testing_mode": self.policy.testing_mode.value,
                "safe_mode": self.policy.safe_mode,
                "rate_limits": {
                    k: {
                        "requests_per_minute": v.requests_per_minute,
                        "requests_per_hour": v.requests_per_hour,
                        "scope": v.scope.value,
                    }
                    for k, v in self.policy.rate_limits.items()
                },
            },
            rate_limits={},
            configuration={
                **job.configuration,
                **self.policy.get_plugin_config(plugins[0].config.name),
            } if plugins else job.configuration,
        )

        all_results: list[ReconResult] = []

        # Use semaphore to limit concurrent plugin executions
        # This prevents overwhelming the target while allowing parallelism
        max_concurrent_plugins = getattr(self.policy, 'max_concurrent_plugins', 3)
        semaphore = asyncio.Semaphore(max_concurrent_plugins)

        async def run_plugin_async(plugin: ReconPlugin) -> list[ReconResult]:
            """Run a single plugin with rate limiting and semaphore."""
            async with semaphore:
                # Validate plugin can run
                is_valid, error = plugin.validate(context)
                if not is_valid:
                    self._emit_event(
                        scan.id,
                        job.id,
                        "plugin.skipped",
                        "info",
                        f"Plugin {plugin.config.name} skipped: {error}",
                        {"plugin": plugin.config.name, "reason": error},
                    )
                    return []

                # Check rate limit
                rate_limit = self.policy.get_rate_limit(plugin.config.name)
                identifier = f"{scan.project_id}:{target_value}"
                rate_result = self.rate_limiter.check_limit_sliding(
                    identifier=identifier,
                    limit=rate_limit.requests_per_minute,
                    window_seconds=60,
                    scope="target",
                )

                if not rate_result.allowed:
                    self._emit_event(
                        scan.id,
                        job.id,
                        "plugin.rate_limited",
                        "warning",
                        f"Plugin {plugin.config.name} rate limited",
                        {
                            "plugin": plugin.config.name,
                            "retry_after": rate_result.retry_after_seconds,
                        },
                    )
                    return []

                # Execute plugin with timeout
                try:
                    # Run sync plugin.run in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()
                    results = await loop.run_in_executor(None, plugin.run, context)
                    normalized_results = plugin.normalize(results, context)

                    processed_results = []
                    for result in normalized_results:
                        processed = self._process_result(
                            scan, job, target_value, target_type, result, scope_rules
                        )
                        if processed:
                            processed_results.append(processed)
                    return processed_results

                except Exception as e:
                    self._emit_event(
                        scan.id,
                        job.id,
                        "plugin.error",
                        "error",
                        f"Plugin {plugin.config.name} failed: {e}",
                        {"plugin": plugin.config.name, "error": str(e)},
                    )
                    return []

        # Run all plugins concurrently
        plugin_tasks = [run_plugin_async(plugin) for plugin in plugins]
        all_plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)

        # Flatten results and handle exceptions
        for plugin_results in all_plugin_results:
            if isinstance(plugin_results, Exception):
                self._emit_event(
                    scan.id,
                    job.id,
                    "plugin.error",
                    "error",
                    f"Plugin task failed: {plugin_results}",
                    {"error": str(plugin_results)},
                )
            else:
                all_results.extend(plugin_results)

        return all_results

    def _process_result(
        self,
        scan: Scan,
        job: ScanJob,
        source_target_value: str,
        source_target_type: str,
        result: ReconResult,
        scope_rules: list[dict[str, Any]],
    ) -> ReconResult | None:
        """Process a recon result: scope evaluation, deduplication, persistence."""
        # Normalize the result value
        normalized = self.normalizer.normalize(result.value, result.asset_kind)

        # Check deduplication
        existing_asset = self._find_existing_asset(scan.project_id, normalized)
        if existing_asset:
            # Update last_seen
            existing_asset.updated_at = datetime.now(UTC)
            # Update attributes if new info
            if result.attributes:
                existing_asset.attributes = {
                    **existing_asset.attributes,
                    **result.attributes,
                }
            # Update scope status if it changed
            if result.scope_status != "unknown":
                existing_asset.scope_status = ScopeStatus(result.scope_status)
            self.db.flush()
            return None  # Indicate deduplicated

        # Evaluate scope status if not provided
        if result.scope_status == "unknown":
            scope_status = self._evaluate_scope(normalized, scope_rules)
            result.scope_status = scope_status.value

        # Create asset
        asset = Asset(
            project_id=scan.project_id,
            target_id=scan.target_id,
            kind=AssetKind(result.asset_kind),
            value=normalized.value,
            scope_status=ScopeStatus(result.scope_status),
            attributes={
                **result.attributes,
                "source": result.source,
                "confidence": result.confidence,
                "first_seen": result.first_seen or datetime.now(UTC).isoformat(),
                "last_seen": result.last_seen or datetime.now(UTC).isoformat(),
                "normalized_value": normalized.canonical_value,
                "normalized_metadata": normalized.metadata,
            },
        )
        self.db.add(asset)
        self.db.flush()

        # Create relationships
        for rel in result.relationships:
            target_value = rel.get("target_value")
            rel_type = rel.get("relationship_type", "related_to")
            note = rel.get("note")

            if not target_value:
                continue

            # Find or create target asset
            target_normalized = self.normalizer.normalize(target_value, "domain")  # Best effort
            target_asset = self._find_existing_asset(scan.project_id, target_normalized)

            if target_asset:
                relationship = AssetRelationship(
                    source_asset_id=asset.id,
                    target_asset_id=target_asset.id,
                    relationship_type=AssetRelationshipType(rel_type),
                    note=note,
                )
                self.db.add(relationship)

        # Emit asset discovered event
        self._emit_event(
            scan.id,
            job.id,
            "asset.discovered",
            "info",
            f"Discovered {result.asset_kind}: {normalized.value}",
            {
                "asset_id": str(asset.id),
                "asset_kind": result.asset_kind,
                "value": normalized.value,
                "scope_status": result.scope_status,
                "confidence": result.confidence,
                "source": result.source,
            },
        )

        return result

    def _find_existing_asset(
        self, project_id: UUID, normalized: NormalizedTarget
    ) -> Asset | None:
        """Find existing asset by deduplication key."""
        result = self.db.query(Asset).filter(
            Asset.project_id == project_id,
            Asset.kind == AssetKind(normalized.target_type),
            Asset.value == normalized.value,
        ).first()
        return result  # type: ignore[return-value]

    def _evaluate_scope(
        self, normalized: NormalizedTarget, scope_rules: list[dict[str, Any]]
    ) -> ScopeStatus:
        """Evaluate scope status for a normalized target."""
        # Convert scope rules to objects the scope engine can use
        # This is a simplified version - in production, we'd use the actual ScopeRule objects
        from app.models.enums import ScopeRuleEffect, ScopeRuleTargetType

        class RuleProxy:
            def __init__(self, data: dict[str, Any]) -> None:
                self.effect = ScopeRuleEffect(data["effect"])
                self.target_type = ScopeRuleTargetType(data["target_type"])
                self.pattern = data["pattern"]

        rules = [RuleProxy(r) for r in scope_rules]

        # Map asset kind to scope rule target type
        target_type_map: dict[str, ScopeRuleTargetType] = {
            "domain": ScopeRuleTargetType.DOMAIN,
            "subdomain": ScopeRuleTargetType.SUBDOMAIN_PATTERN,
            "ip_address": ScopeRuleTargetType.IP,
            "cidr": ScopeRuleTargetType.CIDR,
            "url": ScopeRuleTargetType.URL,
            "endpoint": ScopeRuleTargetType.API,
            "apk": ScopeRuleTargetType.APK,
        }

        target_type = target_type_map.get(normalized.target_type, ScopeRuleTargetType.DOMAIN)
        return self.scope_engine.evaluate_target(
            target_value=normalized.value,
            target_type=target_type,
            rules=rules,
        )

    def _emit_event(
        self,
        scan_id: UUID,
        job_id: UUID,
        event_type: str,
        level: str,
        message: str,
        payload: dict[str, Any],
    ) -> None:
        """Emit a scan event."""
        from app.models.scans import ScanEvent

        event = ScanEvent(
            scan_id=scan_id,
            scan_job_id=job_id,
            event_type=event_type,
            level=level,
            message=message,
            payload=payload,
        )
        self.db.add(event)


class ReconEngineFactory:
    """Factory for creating ReconEngine instances."""

    @staticmethod
    def create(
        db_session: Any,
        policy: ExecutionPolicy | None = None,
        rate_limiter: ReconRateLimiter | InMemoryRateLimiter | None = None,
    ) -> ReconEngine:
        """Create a ReconEngine with explicit configuration.

        Args:
            db_session: Database session
            policy: Execution policy (optional)
            rate_limiter: Rate limiter instance. Must be provided explicitly
                for production use. For testing, InMemoryRateLimiter can be passed.
        """
        if rate_limiter is None:
            raise ValueError(
                "rate_limiter must be provided explicitly. "
                "Use InMemoryRateLimiter() for testing or ReconRateLimiter(redis_url=...) for production."
            )

        return ReconEngine(
            db_session=db_session,
            policy=policy,
            rate_limiter=rate_limiter,
        )
