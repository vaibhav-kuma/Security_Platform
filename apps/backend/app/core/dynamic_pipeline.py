"""Dynamic Analysis Pipeline - orchestrates APK → emulator → execution → observation pipeline."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from app.core.adb import AdbClient, AdbManager
from app.core.apk_analyzer import ApkAnalyzer
from app.core.emulator import EmulatorManager, EmulatorProfile, EmulatorInstance, EmulatorStatus
from app.core.analysis_engine import get_analysis_engine, IngestionContext, IngestionResult
from app.core.evidence_sanitizer import sanitize_evidence
from app.models.dynamic import (
    DynamicAnalysisRun,
    DynamicAnalysisEvidence,
    EmulatorInstance,
    EmulatorProfile,
    EmulatorStatus,
    FileObservation,
    IpcObservation,
    NetworkObservation,
    RuntimeEvent,
)
from app.models.scans import Scan, ScanJob
from app.models.enums import (
    EvidenceType,
    ObservationType,
    ScanJobStatus,
    ScanStatus,
    SecurityEventType,
)
from app.services.apk_analysis import ApkAnalysisService

logger = logging.getLogger(__name__)


@dataclass
class PipelineContext:
    """Context for dynamic analysis pipeline execution."""
    scan: Scan
    scan_job: ScanJob
    dynamic_run: DynamicAnalysisRun
    emulator_instance: EmulatorInstance
    apk_path: Path
    package_name: str
    start_time: datetime


@dataclass
class PipelineResult:
    """Result of pipeline execution."""
    success: bool
    events_captured: int = 0
    network_observations: int = 0
    file_operations: int = 0
    ipc_events: int = 0
    crypto_operations: int = 0
    evidence_artifacts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class DynamicAnalysisPipeline:
    """Orchestrates the complete dynamic analysis workflow."""

    def __init__(
        self,
        db_session: Any,
        emulator_manager: EmulatorManager,
        adb_client: Any,
        evidence_base_path: Path = Path("/evidence/dynamic"),
    ) -> None:
        self.db = db_session
        self.emulator_manager = emulator_manager
        self.adb_client = adb_client
        self.evidence_base_path = evidence_base_path
        self.analysis_engine = get_analysis_engine(db_session)
        self.apk_analysis_service = ApkAnalysisService(db_session)

        # Ensure evidence directory exists
        self.evidence_base_path.mkdir(parents=True, exist_ok=True)

    async def run_pipeline(
        self,
        scan: Scan,
        scan_job: ScanJob,
        profile: EmulatorProfile,
        apk_path: Path,
        package_name: str,
        test_context: str = "default",
        network_policy: str = "proxy_only",
        frida_scripts: list[str] | None = None,
        resource_limits: dict[str, Any] | None = None,
    ) -> PipelineResult:
        """
        Execute the complete dynamic analysis pipeline.

        Steps:
        1. Create/start emulator instance
        2. Install APK
        3. Configure proxy and monitoring
        4. Launch application with monitoring
        5. Execute test scenarios
        6. Collect runtime events
        7. Collect network observations
        8. Collect file observations
        9. Collect IPC observations
        9. Correlate with static analysis
        10. Store evidence
        11. Cleanup
        """
        start_time = time.time()
        logger.info(f"Starting dynamic analysis pipeline for scan {scan.id}")

        # Create dynamic analysis run record
        dynamic_run = DynamicAnalysisRun(
            scan_id=scan.id,
            apk_file_id=None,  # Will be set after APK analysis
            test_context=test_context,
            network_policy=network_policy,
            proxy_configuration={},
            frida_scripts=frida_scripts or [],
            resource_limits=resource_limits or {},
            status="preparing",
        )
        self.db.add(dynamic_run)
        self.db.flush()

        # Create emulator instance
        emulator_instance = await self.emulator_manager.create_instance(
            profile=EmulatorProfile(
                id=profile.id,
                avd_name=profile.avd_name,
                api_level=profile.api_level,
                abi=profile.abi,
                ram_mb=profile.ram_mb,
                storage_mb=profile.storage_mb,
                gpu_enabled=profile.gpu_enabled,
                camera_enabled=profile.camera_enabled,
                gps_enabled=profile.gps_enabled,
                proxy_host=profile.proxy_host,
                proxy_port=profile.proxy_port,
                network_policy=profile.network_policy,
                max_cpu_percent=profile.max_cpu_percent,
                max_memory_mb=profile.max_memory_mb,
                max_execution_time_seconds=profile.max_execution_time_seconds,
            )
        )
        dynamic_run.emulator_instance_id = emulator_instance.id
        self.db.flush()

        # Start emulator
        if not await self.emulator_manager.start_instance(emulator_instance):
            dynamic_run.status = "failed"
            dynamic_run.error = "Failed to start emulator"
            dynamic_run.finished_at = datetime.now(UTC)
            self.db.flush()
            return PipelineResult(success=False, error="Failed to start emulator")

        # Create pipeline context
        ctx = PipelineContext(
            scan=scan,
            scan_job=scan_job,
            dynamic_run=dynamic_run,
            emulator_instance=emulator_instance,
            apk_path=apk_path,
            package_name=package_name,
            start_time=datetime.now(UTC),
        )

        # Initialize ADB manager for the emulator
        adb_manager = AdbManager()
        adb_manager.set_target(f"emulator-{emulator_instance.adb_port}")

        try:
            # Step 1: Prepare device for analysis
            logger.info("Preparing device for analysis")
            if not await self._prepare_device(ctx, adb_manager, package_name):
                raise RuntimeError("Failed to prepare device")

            # Step 2: Install APK
            logger.info("Installing APK")
            if not await self._install_apk(ctx):
                raise RuntimeError("Failed to install APK")

            # Step 3: Configure proxy and monitoring
            logger.info("Configuring proxy and monitoring")
            await self._configure_monitoring(ctx, network_policy)

            # Step 3b: Start static analysis correlation
            await self._correlate_static_findings(ctx)

            # Step 4: Launch application
            logger.info("Launching application")
            dynamic_run.status = "running"
            dynamic_run.started_at = datetime.now(UTC)
            self.db.flush()

            if not await self._launch_application(ctx):
                raise RuntimeError("Failed to launch application")

            # Step 5: Execute test scenarios
            logger.info("Executing test scenarios")
            await self._execute_test_scenarios(ctx, test_context)

            # Step 6: Collect runtime events
            logger.info("Collecting runtime events")
            await self._collect_runtime_events(ctx)

            # Step 7: Collect network observations
            logger.info("Collecting network observations")
            await self._collect_network_observations(ctx)

            # Step 8: Collect file observations
            logger.info("Collecting file observations")
            await self._collect_file_observations(ctx)

            # Step 9: Collect IPC observations
            logger.info("Collecting IPC observations")
            await self._collect_ipc_observations(ctx)

            # Step 10: Correlate with static analysis
            logger.info("Correlating with static analysis")
            await self._correlate_findings(ctx)

            # Step 11: Store evidence
            logger.info("Storing evidence")
            await self._store_evidence(ctx)

            dynamic_run.status = "completed"
            dynamic_run.finished_at = datetime.now(UTC)

            duration = time.time() - start_time
            logger.info(f"Dynamic analysis completed in {duration:.2f}s")

            return PipelineResult(
                success=True,
                events_captured=dynamic_run.events_captured,
                network_observations=dynamic_run.network_observations,
                file_observations=dynamic_run.file_operations,
                ipc_events=dynamic_run.ipc_events,
                crypto_operations=dynamic_run.crypto_operations,
                evidence_artifacts=dynamic_run.evidence_artifacts,
            )

        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            dynamic_run.status = "failed"
            dynamic_run.error = str(e)
            dynamic_run.finished_at = datetime.now(UTC)
            self.db.flush()
            return PipelineResult(success=False, error=str(e))

        finally:
            # Cleanup
            logger.info("Cleaning up")
            await self.emulator_manager.stop_instance(emulator_instance)

    async def _prepare_device(
        self,
        ctx: PipelineContext,
        adb_manager: Any,
        package_name: str,
    ) -> bool:
        """Prepare device for analysis."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"

        # Wait for device
        if not await adb_manager.client.wait_for_device(serial, timeout=120):
            logger.error("Device not ready")
            return False

        # Install APK
        apk_path = Path(ctx.apk_path)
        if not await adb_manager.client.install_apk(serial, Path(ctx.apk_path)):
            logger.error("Failed to install APK")
            return False

        # Grant permissions
        permissions = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]
        await adb_manager.client.grant_permissions(serial, package_name, permissions)

        # Clear app data for clean state
        await adb_manager.client.clear_app_data(serial, package_name)
        await adb_manager.client.force_stop(serial, package_name)

        return True

    async def _install_apk(self, ctx: PipelineContext) -> bool:
        """Install APK and extract package info."""
        # Run static analysis on APK first
        analyzer = ApkAnalyzer(ctx.apk_path, str(ctx.dynamic_run.id))
        static_results = analyzer.analyze()

        # Store static findings
        for finding in static_results.get("findings", []):
            from app.core.analysis_engine import IngestionContext, IngestionResult
            ingestion_ctx = IngestionContext(
                project_id=ctx.scan.project_id,
                scan_id=ctx.scan.id,
                source="static_analysis",
            )
            self.analysis_engine.ingest_observation(
                context=ingestion_ctx,
                title=finding.get("title", "Static Finding"),
                observation_type=ObservationType.CONFIGURATION,
                detail=finding.get("description"),
                payload=finding.get("evidence", {}),
                severity_hint=finding.get("severity_hint"),
                confidence_hint=finding.get("confidence_hint"),
                evidence_items=[finding.get("evidence", {})],
            )

        return True

    async def _configure_monitoring(
        self,
        ctx: PipelineContext,
        network_policy: str,
    ) -> None:
        """Configure proxy and monitoring."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"

        # Configure proxy based on network policy
        if network_policy == "proxy_only":
            # Configure emulator proxy
            pass
        elif network_policy == "controlled":
            # Configure controlled network access
            pass

        # Start logcat capture
        # This would be handled by a background task in production

    async def _correlate_static_findings(self, ctx: PipelineContext) -> None:
        """Correlate static findings with dynamic run."""
        # Query static findings for this APK
        from app.models.detection import Observation, Finding
        from sqlalchemy import select

        static_obs = self.db.scalars(
            select(Observation).where(
                Observation.scan_id == ctx.scan.id,
                Observation.payload.contains({"source": "static_analysis"}),
            )
        ).all()

        ctx.dynamic_run.metadata_ = {
            **ctx.dynamic_run.metadata_,
            "static_findings_count": len(static_obs),
        }
        self.db.flush()

    async def _launch_application(self, ctx: PipelineContext) -> bool:
        """Launch the target application."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        adb_manager = AdbManager()
        adb_manager.set_target(serial)

        success = await adb_manager.launch_app_with_monitoring(
            package_name=ctx.package_name,
            intent_action="android.intent.action.MAIN",
            intent_data=None,
        )

        # Give app time to start
        await asyncio.sleep(5)

        return success

    async def _execute_test_scenarios(
        self,
        ctx: PipelineContext,
        test_context: str,
    ) -> None:
        """Execute test scenarios based on context."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"

        # Basic scenarios for all contexts
        scenarios = [
            self._test_cold_start,
            self._test_ui_interaction,
            self._test_network_activity,
            self._test_file_operations,
            self._test_permissions,
        ]

        if test_context == "mitm":
            scenarios.append(self._test_mitm_scenarios)
        elif test_context == "frida":
            scenarios.append(self._test_frida_instrumentation)

        for scenario in scenarios:
            try:
                await scenario(ctx)
                await asyncio.sleep(2)
            except Exception as e:
                logger.warning(f"Scenario {scenario.__name__} failed: {e}")

    async def _test_cold_start(self, ctx: PipelineContext) -> None:
        """Test application cold start."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        # App is already launched, just verify it's running
        await asyncio.sleep(3)

    async def _test_ui_interaction(self, ctx: PipelineContext) -> None:
        """Test basic UI interactions."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        # Simulate basic taps/swipes via adb
        adb_client = AdbClient()
        await adb_client.shell(serial, "input tap 500 1000")
        await asyncio.sleep(1)
        await adb_client.shell(serial, "input swipe 500 1500 500 500 300")
        await asyncio.sleep(1)

    async def _test_network_activity(self, ctx: PipelineContext) -> None:
        """Trigger network activity."""
        # Navigate to trigger network requests
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        adb_client = AdbClient()
        # This would be app-specific in production
        await asyncio.sleep(5)

    async def _test_file_operations(self, ctx: PipelineContext) -> None:
        """Test file operations."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        adb_client = AdbClient()
        # Check app data directory
        await adb_client.shell(serial, "ls -la /data/data/" + ctx.package_name)
        await asyncio.sleep(1)

    async def _test_permissions(self, ctx: PipelineContext) -> None:
        """Test permission requests."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        adb_client = AdbClient()
        # Check granted permissions
        await adb_client.shell(serial, f"dumpsys package {ctx.package_name} | grep permission")
        await asyncio.sleep(1)

    async def _test_mitm_scenarios(self, ctx: PipelineContext) -> None:
        """Test MITM scenarios."""
        # Additional network interception tests
        await asyncio.sleep(5)

    async def _test_frida_instrumentation(self, ctx: PipelineContext) -> None:
        """Test Frida instrumentation."""
        # This would run Frida scripts in production
        await asyncio.sleep(5)

    async def _collect_runtime_events(self, ctx: PipelineContext) -> None:
        """Collect runtime events from logcat and other sources."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        # Use injected adb_client
        adb_client = self.adb_client

        # Get logcat
        result = await adb_client.get_logcat(serial, format="threadtime")
        events = []
        if result.returncode == 0:
            events = self._parse_logcat_events(result.stdout, ctx.package_name)
            for event in events:
                await self._store_runtime_event(ctx, event)

        ctx.dynamic_run.events_captured = len(events)
        self.db.flush()

    def _parse_logcat_events(self, logcat: str, package_name: str) -> list[dict]:
        """Parse logcat output into structured events."""
        events = []
        for line in logcat.split("\n"):
            if package_name in line:
                # Parse logcat line
                parts = line.split(" ", 5)
                if len(parts) >= 6:
                    events.append({
                        "event_type": "log",
                        "event_subtype": "logcat",
                        "description": parts[5] if len(parts) > 5 else line,
                        "raw_data": {"line": line},
                        "severity": "info",
                        "confidence": "medium",
                    })
        return events

    async def _store_runtime_event(self, ctx: PipelineContext, event: dict) -> None:
        """Store a runtime event."""
        # Sanitize event data
        sanitized = sanitize_evidence(str(event.get("raw_data", {})))
        event_record = RuntimeEvent(
            analysis_run_id=ctx.dynamic_run.id,
            event_type=event.get("event_type", "unknown"),
            event_subtype=event.get("event_subtype"),
            description=event.get("description", ""),
            raw_data=event.get("raw_data", {}),
            severity=event.get("severity", "info"),
            confidence=event.get("confidence", "medium"),
            evidence_artifacts=event.get("raw_data", {}),
        )
        self.db.add(event_record)
        ctx.dynamic_run.events_captured += 1
        self.db.flush()

    async def _collect_network_observations(self, ctx: PipelineContext) -> None:
        """Collect network observations."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        # Use injected adb_client
        adb_client = self.adb_client

        # Get network connections
        connections = await adb_client.get_network_connections(serial)

        for conn in connections:
            if conn.process_name == ctx.package_name:
                net_obs = NetworkObservation(
                    analysis_run_id=ctx.dynamic_run.id,
                    protocol=conn.protocol,
                    direction="outbound" if conn.remote_address else "inbound",
                    source_package=ctx.package_name,
                    destination_host=conn.remote_address,
                    destination_port=conn.remote_port,
                )
                self.db.add(net_obs)
                ctx.dynamic_run.network_observations += 1

        self.db.flush()

    async def _collect_file_observations(self, ctx: PipelineContext) -> None:
        """Collect file operation observations."""
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        # Use injected adb_client
        adb_client = self.adb_client

        # List app data directory
        files = await adb_client.list_files(serial, f"/data/data/{ctx.package_name}")

        for file_info in files[:50]:  # Limit to prevent excessive storage
            # Parse file info
            file_obs = FileObservation(
                analysis_run_id=ctx.dynamic_run.id,
                operation="read",
                file_path=f"/data/data/{ctx.package_name}/...",
                source_package=ctx.package_name,
            )
            self.db.add(file_obs)
            ctx.dynamic_run.file_operations += 1

        self.db.flush()

    async def _collect_ipc_observations(self, ctx: PipelineContext) -> None:
        """Collect IPC observations."""
        # In production, this would use Frida or logcat intent monitoring
        serial = f"emulator-{ctx.emulator_instance.adb_port}"
        adb_client = AdbClient()

        # Get recent intents from logcat
        result = await adb_client.get_logcat(serial, filters=["ActivityManager:I"])
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "START" in line and ctx.package_name in line:
                    ipc_obs = IpcObservation(
                        analysis_run_id=ctx.dynamic_run.id,
                        ipc_type="intent",
                        source_package=ctx.package_name,
                        description=line[:500],
                        raw_data={"logcat_line": line},
                    )
                    self.db.add(ipc_obs)
                    ctx.dynamic_run.ipc_events += 1

        self.db.flush()

    async def _correlate_findings(self, ctx: PipelineContext) -> None:
        """Correlate dynamic findings with static/API findings."""
        # This would use the correlation engine
        from app.core.finding_correlation import get_correlation_engine
        from app.models.detection import Finding

        engine = get_correlation_engine()

        # Get dynamic findings (runtime events that could be findings)
        from app.models.detection import Observation
        from sqlalchemy import select

        dynamic_obs = self.db.scalars(
            select(Observation).where(
                Observation.scan_id == ctx.scan.id,
                Observation.payload.contains({"source": "dynamic_analysis"}),
            )
        ).all()

        for dyn_obs in dynamic_obs:
            # Find static findings with same package
            static_findings = self.db.scalars(
                select(Finding).where(
                    Finding.project_id == ctx.scan.project_id,
                    Finding.deleted_at.is_(None),
                )
            ).all()

            for finding in static_findings:
                # Simple correlation by package name
                if ctx.package_name in str(finding.title) or ctx.package_name in str(finding.recommendation):
                    ctx.dynamic_run.correlated_static_findings += 1
                    break

        self.db.flush()

    async def _store_evidence(self, ctx: PipelineContext) -> None:
        """Store evidence artifacts."""
        # Create evidence directory for this run
        evidence_dir = self.evidence_base_path / str(ctx.dynamic_run.id)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # In production, would capture:
        # - PCAP file
        # - Screenshots
        # - Logcat dump
        # - Frida output
        # - Heap dumps
        # - Traces

        ctx.dynamic_run.evidence_artifacts = {
            "logcat": str(evidence_dir / "logcat.txt"),
            "screenshots": str(evidence_dir / "screenshots"),
            "pcap": str(evidence_dir / "capture.pcap"),
        }

        # Create evidence records
        for artifact_type, path in ctx.dynamic_run.evidence_artifacts.items():
            evidence = DynamicAnalysisEvidence(
                analysis_run_id=ctx.dynamic_run.id,
                evidence_type=artifact_type,
                storage="object",
                object_key=path,
                description=f"{artifact_type} from dynamic analysis",
            )
            self.db.add(evidence)

        self.db.flush()


class DynamicAnalysisPipelineFactory:
    """Factory for creating DynamicAnalysisPipeline instances."""

    @staticmethod
    def create(db_session: Any) -> DynamicAnalysisPipeline:
        """Create a pipeline with default configuration."""
        emulator_manager = EmulatorManager(db_session)
        adb_client = AdbClient()
        return DynamicAnalysisPipeline(
            db_session=db_session,
            emulator_manager=emulator_manager,
            adb_client=adb_client,
        )

    @staticmethod
    def create_for_testing(db_session: Any, evidence_base_path: Path) -> DynamicAnalysisPipeline:
        """Create a pipeline for testing with custom evidence path."""
        emulator_manager = EmulatorManager(db_session)
        adb_client = AdbClient()
        return DynamicAnalysisPipeline(
            db_session=db_session,
            emulator_manager=emulator_manager,
            adb_client=adb_client,
            evidence_base_path=evidence_base_path,
        )