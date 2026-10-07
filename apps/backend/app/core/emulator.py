"""Android Emulator Manager for dynamic analysis."""

import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from app.models.dynamic import EmulatorInstance, EmulatorProfile, EmulatorStatus
from app.models.enums import native_enum

logger = logging.getLogger(__name__)


@dataclass
class EmulatorConfig:
    """Runtime configuration for an emulator instance."""
    avd_name: str
    api_level: int
    abi: str
    ram_mb: int
    storage_mb: int
    gpu_enabled: bool
    camera_enabled: bool
    gps_enabled: bool
    proxy_host: str | None = None
    proxy_port: int | None = None
    network_policy: str = "proxy_only"


class EmulatorManager:
    """Manages Android emulator instances for dynamic analysis."""

    def __init__(
        self,
        db_session: Any,
        emulator_base_path: Path = Path("/opt/android/avd"),
        adb_path: str = "adb",
        emulator_path: str = "emulator",
    ) -> None:
        self.db = db_session
        self.emulator_base_path = emulator_base_path
        self.adb_path = adb_path
        self.emulator_path = emulator_path
        self._running_instances: dict[UUID, EmulatorInstance] = {}

    async def create_instance(
        self,
        profile: EmulatorProfile,
        instance_name: str | None = None,
    ) -> EmulatorInstance:
        """Create a new emulator instance from a profile."""
        # Generate unique instance name
        if not instance_name:
            instance_name = f"{profile.avd_name}_{int(time.time())}"

        # Create AVD if it doesn't exist
        await self._ensure_avd_exists(profile)

        # Create instance record
        instance = EmulatorInstance(
            profile_id=profile.id,
            status=EmulatorStatus.STOPPED,
            metadata_={
                "instance_name": instance_name,
                "avd_name": profile.avd_name,
            },
        )
        self.db.add(instance)
        self.db.flush()

        return instance

    async def start_instance(self, instance: EmulatorInstance) -> bool:
        """Start an emulator instance."""
        profile = self.db.get(EmulatorProfile, instance.profile_id)
        if not profile:
            instance.status = EmulatorStatus.ERROR
            instance.last_error = "Profile not found"
            self.db.flush()
            return False

        try:
            instance.status = EmulatorStatus.STARTING
            self.db.flush()

            # Build emulator command
            cmd = self._build_emulator_command(profile, instance)

            # Start emulator process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            instance.pid = process.pid
            instance.status = EmulatorStatus.RUNNING
            instance.started_at = datetime.now(UTC)
            self.db.flush()

            # Wait for boot completion
            await self._wait_for_boot(instance)

            # Get ADB port
            instance.adb_port = await self._get_adb_port(instance)
            self.db.flush()

            logger.info(f"Emulator instance {instance.id} started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start emulator {instance.id}: {e}")
            instance.status = EmulatorStatus.ERROR
            instance.last_error = str(e)
            self.db.flush()
            return False

    async def stop_instance(self, instance: EmulatorInstance) -> bool:
        """Stop an emulator instance."""
        try:
            instance.status = EmulatorStatus.STOPPING
            self.db.flush()

            # Kill the emulator process
            if instance.pid:
                try:
                    os.kill(instance.pid, 15)  # SIGTERM
                    await asyncio.sleep(2)
                    # Force kill if still running
                    try:
                        os.kill(instance.pid, 0)
                        os.kill(instance.pid, 9)  # SIGKILL
                    except ProcessLookupError:
                        pass
                except ProcessLookupError:
                    pass

            # Also try adb emu kill
            if instance.adb_port:
                try:
                    await self._run_adb_command(instance.adb_port, ["emu", "kill"])
                except Exception:
                    pass

            instance.status = EmulatorStatus.STOPPED
            instance.stopped_at = datetime.now(UTC)
            self.db.flush()

            return True

        except Exception as e:
            logger.error(f"Failed to stop emulator {instance.id}: {e}")
            instance.status = EmulatorStatus.ERROR
            instance.last_error = str(e)
            self.db.flush()
            return False

    async def restart_instance(self, instance: EmulatorInstance) -> bool:
        """Restart an emulator instance."""
        await self.stop_instance(instance)
        await asyncio.sleep(2)
        return await self.start_instance(instance)

    async def snapshot_instance(
        self,
        instance: EmulatorInstance,
        snapshot_name: str,
    ) -> bool:
        """Create a snapshot of the emulator state."""
        if not instance.adb_port:
            return False

        try:
            result = await self._run_adb_command(
                instance.adb_port,
                ["emu", "snapshot", "save", snapshot_name],
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            return False

    async def restore_snapshot(
        self,
        instance: EmulatorInstance,
        snapshot_name: str,
    ) -> bool:
        """Restore emulator to a snapshot."""
        if not instance.adb_port:
            return False

        try:
            result = await self._run_adb_command(
                instance.adb_port,
                ["emu", "snapshot", "load", snapshot_name],
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to restore snapshot: {e}")
            return False

    async def update_resource_usage(self, instance: EmulatorInstance) -> None:
        """Update resource usage metrics for an instance."""
        if not instance.pid:
            return

        try:
            import psutil
            process = psutil.Process(instance.pid)
            instance.cpu_percent = process.cpu_percent(interval=0.1)
            instance.memory_mb = process.memory_info().rss / (1024 * 1024)
            self.db.flush()
        except (psutil.NoSuchProcess, psutil.AccessDenied, ImportError):
            pass

    def _build_emulator_command(self, profile: EmulatorProfile, instance: EmulatorInstance) -> list[str]:
        """Build the emulator command line."""
        cmd = [
            self.emulator_path,
            "-avd", profile.avd_name,
            "-memory", str(profile.ram_mb),
            "-partition-size", str(profile.storage_mb),
        ]

        if profile.gpu_enabled:
            cmd.extend(["-gpu", "host"])
        else:
            cmd.extend(["-gpu", "off"])

        if profile.camera_enabled:
            cmd.extend(["-camera-back", "webcam0"])
        else:
            cmd.extend(["-camera-back", "none"])

        if profile.gps_enabled:
            cmd.extend(["-gps", "on"])
        else:
            cmd.extend(["-gps", "off"])

        # Network configuration
        if profile.proxy_host and profile.proxy_port:
            cmd.extend(["-http-proxy", f"http://{profile.proxy_host}:{profile.proxy_port}"])

        # Network policy
        if profile.network_policy == "none":
            cmd.extend(["-no-network"])
        elif profile.network_policy == "proxy_only":
            cmd.extend(["-no-window", "-no-audio", "-no-boot-anim"])

        # Resource limits
        if profile.max_cpu_percent < 100:
            cmd.extend(["-cpu-throttle", str(profile.max_cpu_percent)])

        # Headless mode for CI
        if os.getenv("ANDROID_EMULATOR_HEADLESS") == "true":
            cmd.extend(["-no-window", "-no-audio", "-no-boot-anim"])

        return cmd

    async def _ensure_avd_exists(self, profile: EmulatorProfile) -> bool:
        """Ensure the AVD exists, create if necessary."""
        # Check if AVD exists
        result = await self._run_command([self.emulator_path, "-list-avds"])
        if profile.avd_name in result.stdout:
            return True

        # Create AVD
        logger.info(f"Creating AVD: {profile.avd_name}")
        cmd = [
            "avdmanager", "create", "avd",
            "-n", profile.avd_name,
            "-k", f"system-images;android-{profile.api_level};default;{profile.abi}",
            "--force",
        ]
        result = await self._run_command(cmd)
        return result.returncode == 0

    async def _wait_for_boot(self, instance: EmulatorInstance, timeout: int = 300) -> bool:
        """Wait for emulator to complete boot."""
        if not instance.adb_port:
            return False

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = await self._run_adb_command(
                    instance.adb_port,
                    ["shell", "getprop", "sys.boot_completed"],
                )
                if result.stdout.strip() == "1":
                    # Additional wait for system stability
                    await asyncio.sleep(10)
                    return True
            except Exception:
                pass
            await asyncio.sleep(5)

        logger.warning(f"Emulator {instance.id} boot timeout")
        return False

    async def _get_adb_port(self, instance: EmulatorInstance) -> int | None:
        """Get the ADB port for an emulator instance."""
        try:
            result = await self._run_adb_command(
                None,
                ["devices"],
            )
            for line in result.stdout.split("\n"):
                if "emulator-" in line and "device" in line:
                    # Extract port from emulator-<port>
                    parts = line.split("\t")
                    if parts:
                        port_str = parts[0].replace("emulator-", "")
                        try:
                            return int(port_str)
                        except ValueError:
                            pass
        except Exception:
            pass
        return None

    async def _run_adb_command(
        self,
        port: int | None,
        args: list[str],
    ) -> subprocess.CompletedProcess:
        """Run an ADB command targeting a specific emulator."""
        cmd = [self.adb_path]
        if port:
            cmd.extend(["-s", f"emulator-{port}"])
        cmd.extend(args)
        return await self._run_command(cmd)

    async def _run_command(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Run a command asynchronously."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return subprocess.CompletedProcess(
            cmd,
            process.returncode,
            stdout.decode() if stdout else "",
            stderr.decode() if stderr else "",
        )

    def get_instance(self, instance_id: UUID) -> EmulatorInstance | None:
        """Get an emulator instance by ID."""
        return self.db.get(EmulatorInstance, instance_id)

    def list_instances(
        self,
        profile_id: UUID | None = None,
        status: EmulatorStatus | None = None,
    ) -> list[EmulatorInstance]:
        """List emulator instances."""
        from sqlalchemy import select
        stmt = select(EmulatorInstance)
        if profile_id:
            stmt = stmt.where(EmulatorInstance.profile_id == profile_id)
        if status:
            stmt = stmt.where(EmulatorInstance.status == status)
        return list(self.db.scalars(stmt).all())