"""ADB (Android Debug Bridge) integration for dynamic analysis."""

import asyncio
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AdbDevice:
    """Represents an ADB-connected device/emulator."""
    serial: str
    state: str  # device, offline, unauthorized
    product: str | None = None
    model: str | None = None
    device: str | None = None
    transport_id: int | None = None


@dataclass
class AppInfo:
    """Information about an installed application."""
    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    install_path: str | None = None
    data_dir: str | None = None
    permissions: list[str] = None
    is_system: bool = False
    is_debuggable: bool = False


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    ppid: int
    user: str
    name: str
    cpu_percent: float
    memory_mb: float


@dataclass
class NetworkConnection:
    """Network connection information."""
    protocol: str  # tcp, udp
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int
    process_name: str


class AdbClient:
    """Async ADB client for device/emulator interaction."""

    def __init__(
        self,
        adb_path: str = "adb",
        default_timeout: int = 30,
    ) -> None:
        self.adb_path = adb_path
        self.default_timeout = default_timeout
        self._device_cache: dict[str, AdbDevice] = {}

    async def _run_adb_command(
        self,
        args: list[str],
        serial: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run an ADB command."""
        cmd = [self.adb_path]
        if serial:
            cmd.extend(["-s", serial])
        cmd.extend(args)

        try:
            process = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=timeout or self.default_timeout,
            )
            stdout, stderr = await process.communicate()
            return subprocess.CompletedProcess(
                cmd,
                process.returncode,
                stdout.decode(errors="ignore") if stdout else "",
                stderr.decode(errors="ignore") if stderr else "",
            )
        except asyncio.TimeoutError:
            logger.error(f"ADB command timed out: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, -1, "", "timeout")
        except Exception as e:
            logger.error(f"ADB command failed: {e}")
            return subprocess.CompletedProcess(cmd, -1, "", str(e))

    async def list_devices(self) -> list[AdbDevice]:
        """List all connected devices/emulators."""
        result = await self._run_adb_command(["devices", "-l"])
        devices = []

        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            device = AdbDevice(
                serial=parts[0],
                state=parts[1],
            )

            # Parse additional properties
            for part in parts[2:]:
                if part.startswith("product:"):
                    device.product = part[8:]
                elif part.startswith("model:"):
                    device.model = part[6:]
                elif part.startswith("device:"):
                    device.device = part[7:]
                elif part.startswith("transport_id:"):
                    device.transport_id = int(part[13:])

            devices.append(device)
            self._device_cache[device.serial] = device

        return devices

    async def get_device(self, serial: str) -> AdbDevice | None:
        """Get device info by serial."""
        if serial in self._device_cache:
            return self._device_cache[serial]

        devices = await self.list_devices()
        for device in devices:
            if device.serial == serial:
                return device
        return None

    async def is_device_ready(self, serial: str) -> bool:
        """Check if device is ready for commands."""
        device = await self.get_device(serial)
        return device is not None and device.state == "device"

    async def wait_for_device(self, serial: str, timeout: int = 60) -> bool:
        """Wait for device to become ready."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if await self.is_device_ready(serial):
                return True
            await asyncio.sleep(2)
        return False

    # =========================================================================
    # Application Management
    # =========================================================================

    async def install_apk(
        self,
        serial: str,
        apk_path: Path,
        replace: bool = True,
        grant_permissions: bool = True,
    ) -> bool:
        """Install an APK on the device."""
        args = ["install"]
        if replace:
            args.append("-r")
        if grant_permissions:
            args.append("-g")
        args.append(str(apk_path))

        result = await self._run_adb_command(args, serial=serial, timeout=120)
        return result.returncode == 0 and "Success" in result.stdout

    async def uninstall_package(self, serial: str, package_name: str) -> bool:
        """Uninstall a package."""
        result = await self._run_adb_command(
            ["uninstall", package_name],
            serial=serial,
        )
        return result.returncode == 0 and "Success" in result.stdout

    async def list_packages(
        self,
        serial: str,
        system: bool = False,
        third_party: bool = False,
    ) -> list[AppInfo]:
        """List installed packages."""
        args = ["shell", "pm", "list", "packages", "-f"]
        if system:
            args.append("-s")
        elif third_party:
            args.append("-3")

        result = await self._run_adb_command(args, serial=serial)
        packages = []

        for line in result.stdout.strip().split("\n"):
            if not line.startswith("package:"):
                continue

            # package:/path/to/base.apk=com.example.app
            match = re.match(r"package:(.+)=(.+)", line)
            if not match:
                continue

            install_path, package_name = match.groups()

            # Get detailed info
            app_info = await self.get_app_info(serial, package_name)
            if app_info:
                app_info.install_path = install_path
                packages.append(app_info)

        return packages

    async def get_app_info(self, serial: str, package_name: str) -> AppInfo | None:
        """Get detailed information about a package."""
        try:
            # Get package info
            result = await self._run_adb_command(
                ["shell", "dumpsys", "package", package_name],
                serial=serial,
            )

            if "Package [\"" not in result.stdout:
                return None

            # Parse output
            info = AppInfo(package_name=package_name)

            # Extract version info
            version_match = re.search(r"versionName=([^\s]+)", result.stdout)
            if version_match:
                info.version_name = version_match.group(1)

            version_code_match = re.search(r"versionCode=(\d+)", result.stdout)
            if version_code_match:
                info.version_code = int(version_code_match.group(1))

            # Check if debuggable
            info.is_debuggable = "FLAG_DEBUGGABLE" in result.stdout

            # Check if system app
            info.is_system = "SYSTEM" in result.stdout and "USER" not in result.stdout

            # Get install location and data dir
            path_match = re.search(r"path=(/[^\s]+)", result.stdout)
            if path_match:
                info.install_path = path_match.group(1)

            data_match = re.search(r"dataDir=([^\s]+)", result.stdout)
            if data_match:
                info.data_dir = data_match.group(1)

            # Get permissions
            perm_result = await self._run_adb_command(
                ["shell", "pm", "list", "permissions", "-g", "-f", package_name],
                serial=serial,
            )
            info.permissions = self._parse_permissions(perm_result.stdout)

            return info

        except Exception as e:
            logger.error(f"Failed to get app info for {package_name}: {e}")
            return None

    def _parse_permissions(self, output: str) -> list[str]:
        """Parse permission output from dumpsys."""
        permissions = []
        for line in output.strip().split("\n"):
            if "permission:" in line:
                match = re.search(r"permission:([^\s]+)", line)
                if match:
                    permissions.append(match.group(1))
        return permissions

    async def grant_permissions(self, serial: str, package_name: str, permissions: list[str]) -> bool:
        """Grant runtime permissions to a package."""
        for perm in permissions:
            result = await self._run_adb_command(
                ["shell", "pm", "grant", package_name, perm],
                serial=serial,
            )
            if result.returncode != 0:
                logger.warning(f"Failed to grant {perm} to {package_name}")
        return True

    async def revoke_permissions(self, serial: str, package_name: str, permissions: list[str]) -> bool:
        """Revoke runtime permissions from a package."""
        for perm in permissions:
            result = await self._run_adb_command(
                ["shell", "pm", "revoke", package_name, perm],
                serial=serial,
            )
            if result.returncode != 0:
                logger.warning(f"Failed to revoke {perm} from {package_name}")
        return True

    # =========================================================================
    # Application Execution
    # =========================================================================

    async def start_activity(
        self,
        serial: str,
        package_name: str,
        activity_name: str | None = None,
        action: str | None = None,
        data_uri: str | None = None,
        extras: dict[str, str] | None = None,
        flags: list[str] | None = None,
    ) -> bool:
        """Start an activity."""
        args = ["shell", "am", "start"]

        if activity_name:
            args.extend(["-n", f"{package_name}/{activity_name}"])
        if action:
            args.extend(["-a", action])
        if data_uri:
            args.extend(["-d", data_uri])
        if extras:
            for key, value in extras.items():
                args.extend(["-e", key, value])
        if flags:
            for flag in flags:
                args.extend(["-f", flag])

        result = await self._run_adb_command(args, serial=serial)
        return result.returncode == 0 and "Starting:" in result.stdout

    async def force_stop(self, serial: str, package_name: str) -> bool:
        """Force stop an application."""
        result = await self._run_adb_command(
            ["shell", "am", "force-stop", package_name],
            serial=serial,
        )
        return result.returncode == 0

    async def clear_app_data(self, serial: str, package_name: str) -> bool:
        """Clear application data."""
        result = await self._run_adb_command(
            ["shell", "pm", "clear", package_name],
            serial=serial,
        )
        return result.returncode == 0

    # =========================================================================
    # File Operations
    # =========================================================================

    async def push_file(
        self,
        serial: str,
        local_path: Path,
        remote_path: str,
    ) -> bool:
        """Push a file to the device."""
        result = await self._run_adb_command(
            ["push", str(local_path), remote_path],
            serial=serial,
            timeout=60,
        )
        return result.returncode == 0

    async def pull_file(
        self,
        serial: str,
        remote_path: str,
        local_path: Path,
    ) -> bool:
        """Pull a file from the device."""
        result = await self._run_adb_command(
            ["pull", remote_path, str(local_path)],
            serial=serial,
            timeout=60,
        )
        return result.returncode == 0

    async def shell(self, serial: str, command: str) -> subprocess.CompletedProcess:
        """Execute a shell command."""
        return await self._run_adb_command(["shell", command], serial=serial)

    async def list_files(self, serial: str, path: str) -> list[str]:
        """List files in a directory."""
        result = await self._run_adb_command(
            ["shell", "ls", "-la", path],
            serial=serial,
        )
        files = []
        for line in result.stdout.strip().split("\n"):
            if line.strip() and not line.startswith("total"):
                files.append(line)
        return files

    async def read_file(self, serial: str, path: str) -> str | None:
        """Read a file from the device."""
        result = await self._run_adb_command(
            ["shell", "cat", path],
            serial=serial,
        )
        if result.returncode == 0:
            return result.stdout
        return None

    async def write_file(self, serial: str, path: str, content: str) -> bool:
        """Write content to a file on the device."""
        # Use base64 to handle binary content
        import base64
        encoded = base64.b64encode(content.encode()).decode()
        result = await self._run_adb_command(
            ["shell", f"echo {encoded} | base64 -d > {path}"],
            serial=serial,
        )
        return result.returncode == 0

    # =========================================================================
    # Process and System Information
    # =========================================================================

    async def get_processes(self, serial: str) -> list[ProcessInfo]:
        """Get running processes."""
        result = await self._run_adb_command(
            ["shell", "ps", "-A"],
            serial=serial,
        )

        processes = []
        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 9:
                try:
                    processes.append(ProcessInfo(
                        user=parts[0],
                        pid=int(parts[1]),
                        ppid=int(parts[2]),
                        name=parts[8],
                        cpu_percent=0.0,
                        memory_mb=0.0,
                    ))
                except (ValueError, IndexError):
                    pass
        return processes

    async def get_process_info(self, serial: str, pid: int) -> ProcessInfo | None:
        """Get detailed process information."""
        result = await self._run_adb_command(
            ["shell", "cat", f"/proc/{pid}/status"],
            serial=serial,
        )

        if result.returncode != 0:
            return None

        info = {"pid": pid}
        for line in result.stdout.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip().lower()] = value.strip()

        return ProcessInfo(
            pid=pid,
            ppid=int(info.get("ppid", 0)),
            user=info.get("uid", "").split()[0] if "uid" in info else "",
            name=info.get("name", ""),
            cpu_percent=0.0,
            memory_mb=0.0,
        )

    async def kill_process(self, serial: str, pid: int, signal: int = 9) -> bool:
        """Kill a process."""
        result = await self._run_adb_command(
            ["shell", "kill", f"-{signal}", str(pid)],
            serial=serial,
        )
        return result.returncode == 0

    # =========================================================================
    # Network Information
    # =========================================================================

    async def get_network_connections(self, serial: str) -> list[NetworkConnection]:
        """Get active network connections."""
        result = await self._run_adb_command(
            ["shell", "netstat", "-tunp"],
            serial=serial,
        )

        connections = []
        for line in result.stdout.strip().split("\n")[2:]:  # Skip headers
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 7:
                try:
                    connections.append(NetworkConnection(
                        protocol=parts[0],
                        local_address=parts[3].split(":")[0],
                        local_port=int(parts[3].split(":")[1]),
                        remote_address=parts[4].split(":")[0],
                        remote_port=int(parts[4].split(":")[1]),
                        state=parts[5],
                        pid=int(parts[6].split("/")[0]) if "/" in parts[6] else 0,
                        process_name=parts[6].split("/")[1] if "/" in parts[6] else "",
                    ))
                except (ValueError, IndexError):
                    pass
        return connections

    async def get_open_ports(self, serial: str) -> list[int]:
        """Get list of open ports."""
        connections = await self.get_network_connections(serial)
        ports = set()
        for conn in connections:
            if conn.state == "LISTEN":
                ports.add(conn.local_port)
        return sorted(ports)

    # =========================================================================
    # Logs and Monitoring
    # =========================================================================

    async def get_logcat(
        self,
        serial: str,
        filters: list[str] | None = None,
        format: str = "brief",
        clear_first: bool = False,
    ) -> subprocess.CompletedProcess:
        """Get logcat output."""
        args = ["logcat"]
        if clear_first:
            args.append("-c")
            await self._run_adb_command(args, serial=serial)
            args = ["logcat"]

        if format:
            args.extend(["-v", format])
        if filters:
            for f in filters:
                args.extend(["-s", f])

        return await self._run_adb_command(args, serial=serial)

    async def stream_logcat(
        self,
        serial: str,
        callback: callable,
        filters: list[str] | None = None,
    ) -> None:
        """Stream logcat output to a callback."""
        args = ["logcat", "-v", "threadtime"]
        if filters:
            for f in filters:
                args.extend(["-s", f])

        process = await asyncio.create_subprocess_exec(
            self.adb_path,
            "-s", serial,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            callback(line.decode(errors="ignore").strip())

    async def get_system_properties(self, serial: str) -> dict[str, str]:
        """Get system properties."""
        result = await self._run_adb_command(
            ["shell", "getprop"],
            serial=serial,
        )

        props = {}
        for line in result.stdout.split("\n"):
            match = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]", line)
            if match:
                props[match.group(1)] = match.group(2)
        return props

    # =========================================================================
    # Screen Capture and Recording
    # =========================================================================

    async def take_screenshot(
        self,
        serial: str,
        local_path: Path,
        remote_path: str = "/sdcard/screenshot.png",
    ) -> bool:
        """Take a screenshot."""
        # Capture screenshot on device
        result = await self._run_adb_command(
            ["shell", "screencap", "-p", remote_path],
            serial=serial,
        )
        if result.returncode != 0:
            return False

        # Pull to local
        return await self.pull_file(serial, remote_path, Path(local_path))

    async def start_screen_record(
        self,
        serial: str,
        remote_path: str = "/sdcard/recording.mp4",
        time_limit: int = 180,
        bit_rate: int = 4000000,
    ) -> bool:
        """Start screen recording."""
        result = await self._run_adb_command(
            ["shell", "screenrecord", "--time-limit", str(time_limit),
             "--bit-rate", str(bit_rate), remote_path],
            serial=serial,
        )
        return result.returncode == 0

    async def stop_screen_record(
        self,
        serial: str,
        remote_path: str = "/sdcard/recording.mp4",
        local_path: Path | None = None,
    ) -> bool:
        """Stop screen recording and optionally pull file."""
        # Send Ctrl-C to stop recording
        await self._run_adb_command(
            ["shell", "pkill", "-INT", "screenrecord"],
            serial=serial,
        )
        await asyncio.sleep(2)  # Wait for file to be written

        if local_path:
            return await self.pull_file(serial, remote_path, local_path)
        return True

    # =========================================================================
    # Frida Integration
    # =========================================================================

    async def is_frida_running(self, serial: str) -> bool:
        """Check if Frida server is running."""
        result = await self._run_adb_command(
            ["shell", "ps | grep frida"],
            serial=serial,
        )
        return "frida-server" in result.stdout

    async def start_frida_server(
        self,
        serial: str,
        frida_server_path: str = "/data/local/tmp/frida-server",
    ) -> bool:
        """Start Frida server on device."""
        # Check if server exists
        result = await self._run_adb_command(
            ["shell", "ls", frida_server_path],
            serial=serial,
        )
        if result.returncode != 0:
            logger.error("Frida server not found on device")
            return False

        # Make executable and start
        await self._run_adb_command(
            ["shell", "chmod", "755", frida_server_path],
            serial=serial,
        )

        # Start in background
        result = await self._run_adb_command(
            ["shell", f"{frida_server_path} &"],
            serial=serial,
        )
        await asyncio.sleep(2)
        return await self.is_frida_running(serial)

    async def run_frida_script(
        self,
        serial: str,
        package_name: str,
        script_path: str | None = None,
        script_content: str | None = None,
    ) -> str | None:
        """Run a Frida script against a package."""
        if not await self.is_frida_running(serial):
            logger.error("Frida server not running")
            return None

        if script_content and not script_path:
            # Write script to temp file and push
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(script_content)
                script_path = f.name

        if script_path:
            remote_path = "/data/local/tmp/frida_script.js"
            await self.push_file(serial, Path(script_path), remote_path)

        # Run frida
        cmd = ["frida", "-U", "-f", package_name, "-l", remote_path, "--no-pause"]
        result = await self._run_adb_command(cmd, serial=serial, timeout=60)
        return result.stdout if result.returncode == 0 else None


class AdbManager:
    """High-level ADB manager for dynamic analysis workflows."""

    def __init__(self, adb_path: str = "adb") -> None:
        self.client = AdbClient(adb_path)
        self._target_serial: str | None = None

    def set_target(self, serial: str) -> None:
        """Set the target device/emulator."""
        self._target_serial = serial

    async def prepare_for_analysis(
        self,
        serial: str,
        package_name: str,
        apk_path: Path | None = None,
        permissions: list[str] | None = None,
    ) -> bool:
        """Prepare device for dynamic analysis of a package."""
        self._target_serial = serial

        # Wait for device
        if not await self.client.wait_for_device(serial):
            logger.error("Device not ready")
            return False

        # Install APK if provided
        if apk_path:
            logger.info(f"Installing APK: {apk_path}")
            if not await self.client.install_apk(serial, apk_path):
                logger.error("Failed to install APK")
                return False

        # Grant permissions
        if permissions:
            logger.info(f"Granting permissions: {permissions}")
            await self.client.grant_permissions(serial, package_name, permissions)

        # Clear app data for clean state
        logger.info("Clearing app data")
        await self.client.clear_app_data(serial, package_name)

        # Force stop to ensure clean start
        await self.client.force_stop(serial, package_name)

        return True

    async def launch_app_with_monitoring(
        self,
        package_name: str,
        activity_name: str | None = None,
        intent_action: str | None = None,
        intent_data: str | None = None,
    ) -> bool:
        """Launch app with intent for monitoring."""
        if not self._target_serial:
            return False

        return await self.client.start_activity(
            self._target_serial,
            package_name,
            activity_name=activity_name,
            action=intent_action,
            data_uri=intent_data,
        )

    async def collect_runtime_artifacts(
        self,
        package_name: str,
        output_dir: Path,
    ) -> dict[str, Path]:
        """Collect runtime artifacts (logs, screenshots, etc.)."""
        artifacts = {}

        if not self._target_serial:
            return artifacts

        # Screenshot
        screenshot_path = output_dir / "screenshot.png"
        if await self.client.take_screenshot(self._target_serial, screenshot_path):
            artifacts["screenshot"] = screenshot_path

        # Logcat
        logcat_path = output_dir / "logcat.txt"
        result = await self.client.get_logcat(self._target_serial)
        if result.returncode == 0:
            logcat_path.write_text(result.stdout)
            artifacts["logcat"] = logcat_path

        # Dump app info
        app_info = await self.client.get_app_info(self._target_serial, package_name)
        if app_info:
            import json
            info_path = output_dir / "app_info.json"
            info_path.write_text(json.dumps(app_info.__dict__, default=str))
            artifacts["app_info"] = info_path

        return artifacts