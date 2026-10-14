"""Android APK static analysis engine.

This module provides the core analysis components for APK files,
mapping results to OWASP MASTG and MASVS frameworks.
"""

import hashlib
import logging
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


@dataclass
class AnalysisContext:
    """Context for APK analysis."""
    apk_path: Path
    apk_file_id: str
    package_name: str
    temp_dir: Path | None = None


class BaseAnalyzer(ABC):
    """Base class for APK analyzers."""

    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.results: list[dict[str, Any]] = []

    @abstractmethod
    def analyze(self) -> list[dict[str, Any]]:
        """Run the analysis and return findings."""
        pass

    def add_finding(
        self,
        finding_type: str,
        title: str,
        description: str | None = None,
        severity: str = "info",
        confidence: str = "medium",
        location: str | None = None,
        evidence: dict[str, Any] | None = None,
        mastg_refs: list[str] | None = None,
        masvs_refs: list[str] | None = None,
    ) -> None:
        """Add a finding to results."""
        self.results.append({
            "analyzer_name": self.__class__.__name__,
            "finding_type": finding_type,
            "title": title,
            "description": description,
            "severity_hint": severity,
            "confidence_hint": confidence,
            "location": location,
            "evidence": evidence or {},
            "mastg_references": mastg_refs or [],
            "masvs_references": masvs_refs or [],
        })


class ManifestAnalyzer(BaseAnalyzer):
    """Analyzes AndroidManifest.xml for security issues."""

    def analyze(self) -> list[dict[str, Any]]:
        manifest_path = self.context.temp_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            self.add_finding(
                finding_type="error",
                title="AndroidManifest.xml not found",
                description="Could not locate AndroidManifest.xml in APK",
                severity="high",
                confidence="high",
            )
            return self.results

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError as e:
            self.add_finding(
                finding_type="error",
                title="Failed to parse AndroidManifest.xml",
                description=f"XML parsing error: {e}",
                severity="high",
                confidence="high",
            )
            return self.results

        ns = {"android": "http://schemas.android.com/apk/res/android"}

        # Check for debuggable flag
        application = root.find("application")
        if application is not None:
            debuggable = application.get(f"{{{ns['android']}}}debuggable", "false")
            if debuggable.lower() == "true":
                self.add_finding(
                    finding_type="warning",
                    title="Application is debuggable",
                    description="android:debuggable=\"true\" allows debugging of the application in production",
                    severity="medium",
                    confidence="high",
                    location="AndroidManifest.xml/application@debuggable",
                    mastg_refs=["MASTG-TEST-0001"],
                    masvs_refs=["MASVS-RESILIENCE-2"],
                )

            # Check for allowBackup
            allow_backup = application.get(f"{{{ns['android']}}}allowBackup", "true")
            if allow_backup.lower() == "true":
                self.add_finding(
                    finding_type="info",
                    title="Backup is allowed",
                    description="android:allowBackup=\"true\" allows application data to be backed up",
                    severity="low",
                    confidence="medium",
                    location="AndroidManifest.xml/application@allowBackup",
                    mastg_refs=["MASTG-TEST-0014"],
                    masvs_refs=["MASVS-STORAGE-1"],
                )

            # Check for cleartext traffic
            uses_cleartext = application.get(f"{{{ns['android']}}}usesCleartextTraffic", "false")
            if uses_cleartext.lower() == "true":
                self.add_finding(
                    finding_type="warning",
                    title="Cleartext traffic permitted",
                    description="android:usesCleartextTraffic=\"true\" allows HTTP (non-HTTPS) connections",
                    severity="medium",
                    confidence="high",
                    location="AndroidManifest.xml/application@usesCleartextTraffic",
                    mastg_refs=["MASTG-TEST-0012"],
                    masvs_refs=["MASVS-NETWORK-1"],
                )

        # Check minSdkVersion and targetSdkVersion
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion")
            target_sdk = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion")
            if min_sdk and int(min_sdk) < 23:
                self.add_finding(
                    finding_type="info",
                    title="Low minSdkVersion",
                    description=f"minSdkVersion={min_sdk} (< 23) may lack modern security features",
                    severity="low",
                    confidence="medium",
                    location="AndroidManifest.xml/uses-sdk@minSdkVersion",
                    mastg_refs=["MASTG-TEST-0002"],
                )

        return self.results


class PermissionAnalyzer(BaseAnalyzer):
    """Analyzes Android permissions for security issues."""

    # Dangerous permissions from Android documentation
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
    }

    def analyze(self) -> list[dict[str, Any]]:
        manifest_path = self.context.temp_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return self.results

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError:
            return self.results

        ns = {"android": "http://schemas.android.com/apk/res/android"}

        permissions = root.findall("uses-permission")
        for perm in permissions:
            name = perm.get(f"{{{ns['android']}}}name", "")
            if not name:
                continue

            is_dangerous = name in self.DANGEROUS_PERMISSIONS
            is_custom = not name.startswith("android.permission.")

            severity = "high" if is_dangerous else "info"
            if is_custom:
                severity = "medium"

            self.add_finding(
                finding_type="observation",
                title=f"Permission declared: {name}",
                description=f"Permission {'(dangerous)' if is_dangerous else ''} {'(custom)' if is_custom else ''}",
                severity=severity,
                confidence="high",
                location=f"AndroidManifest.xml/uses-permission[@name='{name}']",
                evidence={"permission": name, "dangerous": is_dangerous, "custom": is_custom},
                mastg_refs=["MASTG-TEST-0010"] if is_dangerous else [],
                masvs_refs=["MASVS-PERMISSIONS-1"] if is_dangerous else [],
            )

        return self.results


class CertificateAnalyzer(BaseAnalyzer):
    """Analyzes APK signing certificates."""

    def analyze(self) -> list[dict[str, Any]]:
        # Find META-INF directory
        meta_inf = self.context.temp_dir / "META-INF"
        if not meta_inf.exists():
            self.add_finding(
                finding_type="error",
                title="No META-INF directory found",
                description="APK appears to be unsigned",
                severity="high",
                confidence="high",
            )
            return self.results

        # Look for .RSA or .DSA files (certificates)
        cert_files = list(meta_inf.glob("*.RSA")) + list(meta_inf.glob("*.DSA")) + list(meta_inf.glob("*.EC"))
        if not cert_files:
            self.add_finding(
                finding_type="error",
                title="No certificate files found",
                description="APK appears to be unsigned (no .RSA/.DSA/.EC files in META-INF)",
                severity="high",
                confidence="high",
            )
            return self.results

        for cert_file in cert_files:
            try:
                import subprocess
                result = subprocess.run(
                    ["openssl", "pkcs7", "-inform", "DER", "-in", str(cert_file), "-print_certs", "-text", "-noout"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self._parse_certificate_output(result.stdout, cert_file.name)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.add_finding(
                    finding_type="warning",
                    title="Could not analyze certificate",
                    description="OpenSSL not available or timeout",
                    severity="low",
                    confidence="low",
                )

        return self.results

    def _parse_certificate_output(self, output: str, cert_name: str) -> None:
        """Parse OpenSSL certificate output."""
        # Extract key information
        import re

        # Check for weak algorithms
        if "sha1WithRSAEncryption" in output or "sha256WithRSAEncryption" not in output:
            self.add_finding(
                finding_type="warning",
                title="Weak certificate signature algorithm",
                description=f"Certificate {cert_name} may use weak signature algorithm",
                severity="medium",
                confidence="medium",
                location=f"META-INF/{cert_name}",
                mastg_refs=["MASTG-TEST-0003"],
                masvs_refs=["MASVS-CRYPTO-1"],
            )

        # Check key size
        key_size_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", output)
        if key_size_match:
            key_size = int(key_size_match.group(1))
            if key_size < 2048:
                self.add_finding(
                    finding_type="warning",
                    title="Weak certificate key size",
                    description=f"Certificate {cert_name} uses {key_size}-bit key (should be >= 2048)",
                    severity="high",
                    confidence="high",
                    location=f"META-INF/{cert_name}",
                    mastg_refs=["MASTG-TEST-0003"],
                    masvs_refs=["MASVS-CRYPTO-1"],
                )

        # Check validity period
        not_after_match = re.search(r"Not After\s*:\s*(.+)", output)
        if not_after_match:
            # Could parse date and check expiry
            pass


class DexAnalyzer(BaseAnalyzer):
    """Analyzes DEX files for security issues."""

    def analyze(self) -> list[dict[str, Any]]:
        # Find classes.dex files
        dex_files = list(self.context.temp_dir.rglob("classes*.dex"))
        if not dex_files:
            self.add_finding(
                finding_type="info",
                title="No DEX files found",
                description="No classes.dex files extracted",
                severity="info",
                confidence="medium",
            )
            return self.results

        for dex_file in dex_files:
            self._analyze_dex_file(dex_file)

        return self.results

    def _analyze_dex_file(self, dex_file: Path) -> None:
        """Analyze a single DEX file."""
        try:
            # Use baksmali or similar to disassemble
            import subprocess
            output_dir = self.context.temp_dir / "dex_out" / dex_file.stem
            output_dir.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                ["baksmali", "disassemble", str(dex_file), "-o", str(output_dir)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                self._analyze_smali_files(output_dir)
            else:
                self.add_finding(
                    finding_type="warning",
                    title="Failed to disassemble DEX",
                    description=f"baksmali failed: {result.stderr}",
                    severity="low",
                    confidence="medium",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding(
                finding_type="warning",
                title="DEX disassembly tool not available",
                description="baksmali not found or timeout",
                severity="low",
                confidence="low",
            )

    def _analyze_smali_files(self, smali_dir: Path) -> None:
        """Analyze Smali files for security patterns."""
        smali_files = list(smali_dir.rglob("*.smali"))

        # Patterns to detect
        patterns = {
            "crypto_usage": [
                r"Ljavax/crypto/",
                r"Ljava/security/",
                r"Cipher\.getInstance",
                r"SecretKeySpec",
                r"IvParameterSpec",
            ],
            "weak_random": [
                r"Ljava/util/Random;",
                r"Math\.random",
                r"SecureRandom\.getInstance\s*\(\s*\"SHA1PRNG\"",
            ],
            "hardcoded_secrets": [
                r"const-string.*[Pp]assword",
                r"const-string.*[Ss]ecret",
                r"const-string.*[Aa]pi[Kk]ey",
                r"const-string.*[Tt]oken",
            ],
            "webview_usage": [
                "Landroid/webkit/WebView;",
                "loadUrl",
                "setJavaScriptEnabled",
                "addJavascriptInterface",
            ],
            "ssl_bypass": [
                "X509TrustManager",
                "checkServerTrusted",
                "TrustManager",
                "HostnameVerifier",
                "ALLOW_ALL_HOSTNAME_VERIFIER",
            ],
        }

        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = smali_file.relative_to(smali_dir)

                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if pattern in content:
                            severity_map = {
                                "crypto_usage": "info",
                                "weak_random": "medium",
                                "hardcoded_secrets": "high",
                                "webview_usage": "info",
                                "ssl_bypass": "high",
                            }
                            self.add_finding(
                                finding_type="observation",
                                title=f"Detected {category.replace('_', ' ')} pattern",
                                description=f"Found {pattern} in {rel_path}",
                                severity=severity_map.get(category, "info"),
                                confidence="medium",
                                location=str(rel_path),
                                evidence={"pattern": pattern, "category": category},
                                mastg_refs=self._get_mastg_refs(category),
                            )
            except Exception:
                pass

    def _get_mastg_refs(self, category: str) -> list[str]:
        """Get MASTG references for a category."""
        refs = {
            "crypto_usage": ["MASTG-TEST-0004", "MASTG-TEST-0005"],
            "weak_random": ["MASTG-TEST-0006"],
            "hardcoded_secrets": ["MASTG-TEST-0007"],
            "webview_usage": ["MASTG-TEST-0008"],
            "ssl_bypass": ["MASTG-TEST-0009", "MASTG-TEST-0012"],
        }
        return refs.get(category, [])


class NativeLibraryAnalyzer(BaseAnalyzer):
    """Analyzes native libraries (SO files)."""

    def analyze(self) -> list[dict[str, Any]]:
        lib_dirs = list(self.context.temp_dir.rglob("lib"))
        if not lib_dirs:
            return self.results

        so_files = []
        for lib_dir in lib_dirs:
            so_files.extend(lib_dir.rglob("*.so"))

        if not so_files:
            return self.results

        for so_file in so_files:
            self._analyze_so_file(so_file)

        return self.results

    def _analyze_so_file(self, so_file: Path) -> None:
        """Analyze a single .so file."""
        try:
            import subprocess

            # Get architecture from path
            arch = "unknown"
            parts = so_file.parts
            for part in parts:
                if part in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
                    arch = part
                    break

            # Extract strings
            result = subprocess.run(
                ["strings", str(so_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                strings = result.stdout.split("\n")
                suspicious = [s for s in strings if self._is_suspicious_string(s)]

                if suspicious:
                    self.add_finding(
                        finding_type="observation",
                        title=f"Suspicious strings in native library",
                        description=f"Found {len(suspicious)} suspicious strings in {so_file.name} ({arch})",
                        severity="medium",
                        confidence="low",
                        location=f"lib/{arch}/{so_file.name}",
                        evidence={"strings": suspicious[:50], "architecture": arch},
                        mastg_refs=["MASTG-TEST-0015"],
                    )

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _is_suspicious_string(self, s: str) -> bool:
        """Check if a string is suspicious."""
        suspicious_patterns = [
            "password", "secret", "api_key", "token", "private_key",
            "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
            "ssh-rsa", "ssh-ed25519",
            "jdbc:", "mongodb://", "redis://",
            "aws_access_key", "aws_secret",
        ]
        s_lower = s.lower()
        return any(pattern in s_lower for pattern in suspicious_patterns)


class ResourceAnalyzer(BaseAnalyzer):
    """Analyzes APK resources (res/)."""

    def analyze(self) -> list[dict[str, Any]]:
        res_dir = self.context.temp_dir / "res"
        if not res_dir.exists():
            return self.results

        # Check for hardcoded secrets in XML resources
        xml_files = list(res_dir.rglob("*.xml"))
        for xml_file in xml_files:
            try:
                content = xml_file.read_text(encoding="utf-8", errors="ignore")
                self._check_xml_for_secrets(content, xml_file.relative_to(res_dir))
            except Exception:
                pass

        # Check strings.xml
        strings_files = list(res_dir.rglob("values*/strings.xml"))
        for strings_file in strings_files:
            self._analyze_strings_xml(strings_file)

        return self.results

    def _check_xml_for_secrets(self, content: str, rel_path: Path) -> None:
        """Check XML content for secrets."""
        import re
        secret_patterns = [
            (r"password\s*[=:]\s*[^\"'\s]+", "password"),
            (r"api[_-]?key\s*[=:]\s*[^\"'\s]+", "api_key"),
            (r"secret\s*[=:]\s*[^\"'\s]+", "secret"),
            (r"token\s*[=:]\s*[^\"'\s]+", "token"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.add_finding(
                    finding_type="warning",
                    title=f"Possible {secret_type} in resource file",
                    description=f"Found potential {secret_type} in {rel_path}",
                    severity="high",
                    confidence="medium",
                    location=f"res/{rel_path}",
                    evidence={"matches": matches[:5], "secret_type": secret_type},
                    mastg_refs=["MASTG-TEST-0007"],
                )

    def _analyze_strings_xml(self, strings_file: Path) -> None:
        """Analyze strings.xml for sensitive data."""
        try:
            tree = ET.parse(strings_file)
            root = tree.getroot()

            for string_elem in root.findall("string"):
                name = string_elem.get("name", "")
                text = string_elem.text or ""

                # Check for sensitive patterns
                import re
                if re.search(r"(password|secret|api[_-]?key|token|private[_-]?key)", name, re.IGNORECASE):
                    if text and len(text) > 8:
                        self.add_finding(
                            finding_type="warning",
                            title=f"Sensitive string resource name",
                            description=f"String resource '{name}' may contain sensitive data",
                            severity="high",
                            confidence="medium",
                            location=f"res/{strings_file.relative_to(self.context.temp_dir)}/string[@name='{name}']",
                            evidence={"name": name, "value_preview": text[:20]},
                            mastg_refs=["MASTG-TEST-0007"],
                        )
        except Exception:
            pass


class UrlAnalyzer(BaseAnalyzer):
    """Extracts URLs, endpoints, and backend references from APK."""

    def analyze(self) -> list[dict[str, Any]]:
        urls_found: set[str] = set()

        # Extract from DEX (strings)
        dex_files = list(self.context.temp_dir.rglob("classes*.dex"))
        for dex_file in dex_files:
            urls_found.update(self._extract_strings_from_dex(dex_file))

        # Extract from resources
        res_dir = self.context.temp_dir / "res"
        if res_dir.exists():
            for xml_file in res_dir.rglob("*.xml"):
                try:
                    content = xml_file.read_text(encoding="utf-8", errors="ignore")
                    urls_found.update(self._extract_urls(content))
                except Exception:
                    pass

        # Extract from native libraries
        for so_file in self.context.temp_dir.rglob("*.so"):
            try:
                import subprocess
                result = subprocess.run(
                    ["strings", str(so_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    urls_found.update(self._extract_urls(result.stdout))
            except Exception:
                pass

        # Categorize URLs
        categorized = self._categorize_urls(urls_found)

        for category, urls in categorized.items():
            if urls:
                self.add_finding(
                    finding_type="observation",
                    title=f"Extracted {category.replace('_', ' ')}",
                    description=f"Found {len(urls)} {category.replace('_', ' ')} in APK",
                    severity="info",
                    confidence="medium",
                    evidence={"urls": list(urls)[:100], "category": category},
                    mastg_refs=["MASTG-TEST-0016"],
                )

        return self.results

    def _extract_strings_from_dex(self, dex_file: Path) -> set[str]:
        """Extract strings from DEX file using strings command."""
        strings_set: set[str] = set()
        try:
            import subprocess
            result = subprocess.run(
                ["strings", str(dex_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                strings_set.update(result.stdout.split("\n"))
        except Exception:
            pass
        return strings_set

    def _extract_urls(self, text: str) -> set[str]:
        """Extract URLs from text."""
        import re
        url_pattern = r"https?://[^\s\"'<>{}|\\^`\[\]]+"
        urls = re.findall(url_pattern, text)
        # Filter out common false positives
        filtered = {
            u for u in urls
            if not u.endswith((".png", ".jpg", ".jpeg", ".gif", ".xml", ".json", ".html", ".css", ".js"))
            and len(u) > 10
        }
        return filtered

    def _categorize_urls(self, urls: set[str]) -> dict[str, set[str]]:
        """Categorize URLs by type."""
        categories = {
            "api_endpoints": set(),
            "websocket_urls": set(),
            "firebase_urls": set(),
            "deep_links": set(),
            "other": set(),
        }

        for url in urls:
            url_lower = url.lower()
            if "firebase" in url_lower or "googleapis.com" in url_lower:
                categories["firebase_urls"].add(url)
            elif url_lower.startswith("wss://") or url_lower.startswith("ws://"):
                categories["websocket_urls"].add(url)
            elif "://" in url and any(api_term in url_lower for api_term in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                categories["api_endpoints"].add(url)
            elif "://" in url and ("intent://" in url_lower or "customscheme://" in url_lower):
                categories["deep_links"].add(url)
            else:
                categories["other"].add(url)

        return categories


class ConfigurationAnalyzer(BaseAnalyzer):
    """Analyzes network security configuration and app configuration."""

    def analyze(self) -> list[dict[str, Any]]:
        # Check for network_security_config.xml
        res_xml = self.context.temp_dir / "res" / "xml"
        if res_xml.exists():
            for xml_file in res_xml.glob("*.xml"):
                if "network_security" in xml_file.name.lower() or xml_file.name == "network_security_config.xml":
                    self._analyze_network_security_config(xml_file)

        # Check AndroidManifest.xml for network security config reference
        manifest_path = self.context.temp_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            self._check_manifest_network_config(manifest_path)

        return self.results

    def _analyze_network_security_config(self, config_file: Path) -> None:
        """Analyze network_security_config.xml."""
        try:
            tree = ET.parse(str(config_file))
            root = tree.getroot()

            # Check base-config cleartextTrafficPermitted
            base_config = root.find("base-config")
            if base_config is not None:
                cleartext = base_config.get("cleartextTrafficPermitted", "false")
                if cleartext.lower() == "true":
                    self.add_finding(
                        finding_type="warning",
                        title="Cleartext traffic permitted in network security config",
                        description="base-config allows cleartext (HTTP) traffic",
                        severity="medium",
                        confidence="high",
                        location=f"res/xml/{config_file.name}/base-config",
                        mastg_refs=["MASTG-TEST-0012"],
                        masvs_refs=["MASVS-NETWORK-1"],
                    )

            # Check domain-config for certificate pinning
            for domain_config in root.findall("domain-config"):
                domain = domain_config.get("domain", "")
                pin_set = domain_config.find("pin-set")
                if pin_set is not None:
                    pins = [pin.text for pin in pin_set.findall("pin") if pin.text]
                    if pins:
                        self.add_finding(
                            finding_type="info",
                            title=f"Certificate pinning configured for {domain}",
                            description=f"Found {len(pins)} certificate pins",
                            severity="info",
                            confidence="high",
                            location=f"res/xml/{config_file.name}/domain-config[@domain='{domain}']",
                            mastg_refs=["MASTG-TEST-0011"],
                            masvs_refs=["MASVS-NETWORK-2"],
                        )
                else:
                    self.add_finding(
                        finding_type="warning",
                        title=f"No certificate pinning for {domain}",
                        description=f"Domain config for {domain} does not have certificate pinning",
                        severity="medium",
                        confidence="medium",
                        location=f"res/xml/{config_file.name}/domain-config[@domain='{domain}']",
                        mastg_refs=["MASTG-TEST-0011"],
                        masvs_refs=["MASVS-NETWORK-2"],
                    )

            # Check debug-overrides
            debug_overrides = root.find("debug-overrides")
            if debug_overrides is not None:
                self.add_finding(
                    finding_type="warning",
                    title="Debug overrides in network security config",
                    description="Debug overrides may disable certificate validation in debug builds",
                    severity="medium",
                    confidence="high",
                    location=f"res/xml/{config_file.name}/debug-overrides",
                    mastg_refs=["MASTG-TEST-0011"],
                    masvs_refs=["MASVS-NETWORK-2"],
                )

        except ET.ParseError:
            pass

    def _check_manifest_network_config(self, manifest_path: Path) -> None:
        """Check manifest for network security config reference."""
        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            application = root.find("application")
            if application is not None:
                network_config = application.get(f"{{{ns['android']}}}networkSecurityConfig")
                if not network_config:
                    self.add_finding(
                        finding_type="info",
                        title="No network security config specified",
                        description="Application does not declare android:networkSecurityConfig",
                        severity="info",
                        confidence="medium",
                        location="AndroidManifest.xml/application",
                        mastg_refs=["MASTG-TEST-0011"],
                    )
        except Exception:
            pass


class ExportedComponentAnalyzer(BaseAnalyzer):
    """Analyzes exported components (activities, services, receivers, providers)."""

    def analyze(self) -> list[dict[str, Any]]:
        manifest_path = self.context.temp_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return self.results

        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()
        except ET.ParseError:
            return self.results

        ns = {"android": "http://schemas.android.com/apk/res/android"}

        application = root.find("application")
        if application is None:
            return self.results

        component_types = ["activity", "service", "receiver", "provider"]

        for comp_type in component_types:
            for component in application.findall(comp_type):
                self._analyze_component(component, comp_type, ns)

        return self.results

    def _analyze_component(self, component: ET.Element, comp_type: str, ns: dict) -> None:
        """Analyze a single component."""
        name = component.get(f"{{{ns['android']}}}name", "")
        exported = component.get(f"{{{ns['android']}}}exported", "false")
        permission = component.get(f"{{{ns['android']}}}permission", "")

        # Determine if explicitly exported
        explicit_export = exported.lower() == "true"

        # Implicit export via intent filters
        intent_filters = component.findall("intent-filter")
        implicit_export = len(intent_filters) > 0

        is_exported = explicit_export or implicit_export

        if is_exported:
            risk_level = "medium"
            if comp_type == "provider" and not permission:
                risk_level = "high"
            elif comp_type == "service" and not permission:
                risk_level = "medium"

            self.add_finding(
                finding_type="observation",
                title=f"Exported {comp_type}: {name}",
                description=f"{comp_type.capitalize()} '{name}' is exported {'explicitly' if explicit_export else 'via intent-filter'}" + (f" with permission: {permission}" if permission else " without permission"),
                severity=risk_level,
                confidence="high" if explicit_export else "medium",
                location=f"AndroidManifest.xml/{comp_type}[@name='{name}']",
                evidence={
                    "component_type": comp_type,
                    "name": name,
                    "exported": explicit_export,
                    "implicit_export": implicit_export,
                    "permission": permission,
                    "intent_filters": self._extract_intent_filters(intent_filters, ns),
                },
                mastg_refs=["MASTG-TEST-0013"],
                masvs_refs=["MASVS-PLATFORM-1"],
            )

    def _extract_intent_filters(self, intent_filters: list[ET.Element], ns: dict) -> list[dict[str, Any]]:
        """Extract intent filter details."""
        filters = []
        for intent_filter in intent_filters:
            filter_data = {"actions": [], "categories": [], "data": []}
            for action in intent_filter.findall("action"):
                name = action.get(f"{{{ns['android']}}}name")
                if name:
                    filter_data["actions"].append(name)
            for category in intent_filter.findall("category"):
                name = category.get(f"{{{ns['android']}}}name")
                if name:
                    filter_data["categories"].append(name)
            for data in intent_filter.findall("data"):
                data_attrs = {}
                for attr in ["scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"]:
                    val = data.get(f"{{{ns['android']}}}{attr}")
                    if val:
                        data_attrs[attr] = val
                if data_attrs:
                    filter_data["data"].append(data_attrs)
            filters.append(filter_data)
        return filters


class WebViewAnalyzer(BaseAnalyzer):
    """Analyzes WebView usage and configuration."""

    def analyze(self) -> list[dict[str, Any]]:
        dex_files = list(self.context.temp_dir.rglob("classes*.dex"))
        if not dex_files:
            return self.results

        for dex_file in dex_files:
            try:
                import subprocess
                result = subprocess.run(
                    ["strings", str(dex_file)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    self._analyze_webview_strings(result.stdout)
            except Exception:
                pass

        return self.results

    def _analyze_webview_strings(self, content: str) -> None:
        """Analyze strings for WebView patterns."""
        if "WebView" not in content and "webview" not in content.lower():
            return

        # Check for dangerous WebView settings
        dangerous_settings = [
            ("setJavaScriptEnabled.*true", "JavaScript enabled in WebView"),
            ("setAllowFileAccess.*true", "File access enabled in WebView"),
            ("setAllowContentAccess.*true", "Content access enabled in WebView"),
            ("setAllowUniversalAccessFromFileURLs.*true", "Universal access from file URLs enabled"),
            ("setAllowFileAccessFromFileURLs.*true", "File access from file URLs enabled"),
            ("setJavaScriptCanOpenWindowsAutomatically.*true", "JS can open windows automatically"),
            ("addJavascriptInterface", "JavaScript interface added"),
            ("setDomStorageEnabled.*true", "DOM storage enabled"),
            ("setDatabaseEnabled.*true", "Database enabled"),
        ]

        import re
        for pattern, description in dangerous_settings:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_finding(
                    finding_type="warning",
                    title=description,
                    description=f"WebView configured with {description.lower()}",
                    severity="medium" if "JavaScript" in description or "addJavascriptInterface" in description else "low",
                    confidence="medium",
                    evidence={"pattern": pattern},
                    mastg_refs=["MASTG-TEST-0008"],
                    masvs_refs=["MASVS-PLATFORM-2"],
                )


class StorageAnalyzer(BaseAnalyzer):
    """Analyzes storage usage for security issues."""

    def analyze(self) -> list[dict[str, Any]]:
        # Check for database files
        db_files = list(self.context.temp_dir.rglob("*.db")) + list(self.context.temp_dir.rglob("*.sqlite")) + list(self.context.temp_dir.rglob("*.sqlite3"))
        for db_file in db_files:
            self.add_finding(
                finding_type="observation",
                title="SQLite database found",
                description=f"Database file: {db_file.name}",
                severity="info",
                confidence="high",
                location=str(db_file.relative_to(self.context.temp_dir)),
                mastg_refs=["MASTG-TEST-0014"],
                masvs_refs=["MASVS-STORAGE-1"],
            )

        # Check for SharedPreferences
        prefs_dir = self.context.temp_dir / "shared_prefs"
        if prefs_dir.exists():
            for pref_file in prefs_dir.glob("*.xml"):
                self.add_finding(
                    finding_type="observation",
                    title="SharedPreferences file found",
                    description=f"Preferences file: {pref_file.name}",
                    severity="info",
                    confidence="high",
                    location=f"shared_prefs/{pref_file.name}",
                    mastg_refs=["MASTG-TEST-0014"],
                )

        return self.results


class CryptoAnalyzer(BaseAnalyzer):
    """Analyzes cryptographic implementations."""

    def analyze(self) -> list[dict[str, Any]]:
        dex_files = list(self.context.temp_dir.rglob("classes*.dex"))
        for dex_file in dex_files:
            self._analyze_dex_crypto(dex_file)

        # Check native libraries
        for so_file in self.context.temp_dir.rglob("*.so"):
            self._analyze_native_crypto(so_file)

        return self.results

    def _analyze_dex_crypto(self, dex_file: Path) -> None:
        """Analyze DEX for crypto usage."""
        try:
            import subprocess
            result = subprocess.run(
                ["strings", str(dex_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                content = result.stdout

                # Check for weak algorithms
                weak_patterns = {
                    "ECB": "AES/ECB mode detected (not semantically secure)",
                    "DES": "DES algorithm detected (weak)",
                    "3DES": "3DES algorithm detected (deprecated)",
                    "RC4": "RC4 algorithm detected (broken)",
                    "MD5": "MD5 hash detected (cryptographically broken)",
                    "SHA1": "SHA-1 hash detected (weak for signatures)",
                    "SHA1PRNG": "SHA1PRNG SecureRandom detected (weak)",
                }

                for pattern, description in weak_patterns.items():
                    if pattern in content:
                        self.add_finding(
                            finding_type="warning",
                            title=f"Weak cryptographic algorithm: {pattern}",
                            description=description,
                            severity="high" if pattern in ("DES", "RC4", "ECB") else "medium",
                            confidence="medium",
                            evidence={"algorithm": pattern},
                            mastg_refs=["MASTG-TEST-0004", "MASTG-TEST-0005"],
                            masvs_refs=["MASVS-CRYPTO-1"],
                        )

                # Check for hardcoded keys/secrets
                import re
                key_patterns = [
                    (r"const-string.*[Kk]ey.*[=:]\s*[A-Za-z0-9+/=]{16,}", "hardcoded_key"),
                    (r"SecretKeySpec.*[A-Za-z0-9+/=]{16,}", "hardcoded_secret_key"),
                ]

                for pattern, finding_type in key_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        self.add_finding(
                            finding_type="critical",
                            title="Possible hardcoded cryptographic key",
                            description=f"Found potential hardcoded key in DEX",
                            severity="critical",
                            confidence="medium",
                            evidence={"matches": matches[:5]},
                            mastg_refs=["MASTG-TEST-0007"],
                            masvs_refs=["MASVS-CRYPTO-1"],
                        )
        except Exception:
            pass

    def _analyze_native_crypto(self, so_file: Path) -> None:
        """Analyze native library for crypto."""
        try:
            import subprocess
            result = subprocess.run(
                ["strings", str(so_file)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                content = result.stdout
                # Check for crypto library usage
                if "openssl" in content.lower() or "boringssl" in content.lower():
                    self.add_finding(
                        finding_type="info",
                        title="OpenSSL/BoringSSL usage detected",
                        description=f"Native library {so_file.name} uses OpenSSL/BoringSSL",
                        severity="info",
                        confidence="high",
                        location=f"lib/{so_file.name}",
                        mastg_refs=["MASTG-TEST-0004"],
                    )
        except Exception:
            pass


class NetworkSecurityAnalyzer(BaseAnalyzer):
    """Analyzes network security configuration and SSL/TLS usage."""

    def analyze(self) -> list[dict[str, Any]]:
        # Check manifest for network security config
        manifest_path = self.context.temp_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            self._analyze_manifest_network(manifest_path)

        # Check DEX for SSL/TLS patterns
        dex_files = list(self.context.temp_dir.rglob("classes*.dex"))
        for dex_file in dex_files:
            self._analyze_dex_ssl(dex_file)

        return self.results

    def _analyze_manifest_network(self, manifest_path: Path) -> None:
        """Analyze manifest for network config."""
        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            application = root.find("application")
            if application is not None:
                # Check cleartext traffic
                cleartext = application.get(f"{{{ns['android']}}}usesCleartextTraffic", "false")
                if cleartext.lower() == "true":
                    self.add_finding(
                        finding_type="warning",
                        title="Cleartext traffic allowed in manifest",
                        description="android:usesCleartextTraffic=\"true\" permits HTTP connections",
                        severity="medium",
                        confidence="high",
                        location="AndroidManifest.xml/application@usesCleartextTraffic",
                        mastg_refs=["MASTG-TEST-0012"],
                        masvs_refs=["MASVS-NETWORK-1"],
                    )
        except Exception:
            pass

    def _analyze_dex_ssl(self, dex_file: Path) -> None:
        """Analyze DEX for SSL/TLS patterns."""
        try:
            import subprocess
            result = subprocess.run(
                ["strings", str(dex_file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                content = result.stdout

                # Check for SSL pinning bypasses
                bypass_patterns = [
                    "X509TrustManager",
                    "checkServerTrusted",
                    "HostnameVerifier",
                    "ALLOW_ALL_HOSTNAME_VERIFIER",
                    "TrustManager",
                    "SSLContext",
                    "init",
                ]

                for pattern in bypass_patterns:
                    if pattern in content:
                        self.add_finding(
                            finding_type="observation",
                            title=f"SSL/TLS related code: {pattern}",
                            description=f"Found {pattern} in DEX - review for proper certificate validation",
                            severity="medium",
                            confidence="low",
                            evidence={"pattern": pattern},
                            mastg_refs=["MASTG-TEST-0009", "MASTG-TEST-0012"],
                            masvs_refs=["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
                        )
        except Exception:
            pass


class ApkAnalyzer:
    """Main APK analyzer orchestrating all sub-analyzers."""

    ANALYZERS = [
        ManifestAnalyzer,
        PermissionAnalyzer,
        CertificateAnalyzer,
        DexAnalyzer,
        NativeLibraryAnalyzer,
        ResourceAnalyzer,
        UrlAnalyzer,
        ConfigurationAnalyzer,
        ExportedComponentAnalyzer,
        WebViewAnalyzer,
        StorageAnalyzer,
        CryptoAnalyzer,
        NetworkSecurityAnalyzer,
    ]

    def __init__(self, apk_path: Path, apk_file_id: str, package_name: str = "") -> None:
        self.apk_path = apk_path
        self.apk_file_id = apk_file_id
        self.package_name = package_name
        self.temp_dir: Path | None = None

    def analyze(self, analysis_types: list[str] | None = None) -> dict[str, Any]:
        """Run all or selected analyses on the APK."""
        # Extract APK
        self.temp_dir = self._extract_apk()

        # Parse manifest for package name if not provided
        if not self.package_name:
            self.package_name = self._get_package_name()

        context = AnalysisContext(
            apk_path=self.apk_path,
            apk_file_id=self.apk_file_id,
            package_name=self.package_name,
            temp_dir=self.temp_dir,
        )

        all_results: list[dict[str, Any]] = []

        # Determine which analyzers to run
        analyzers_to_run = self.ANALYZERS
        if analysis_types:
            analyzers_to_run = [
                a for a in self.ANALYZERS
                if a.__name__.replace("Analyzer", "").lower() in [t.lower() for t in analysis_types]
            ]

        # Run each analyzer
        for analyzer_class in analyzers_to_run:
            try:
                analyzer = analyzer_class(context)
                results = analyzer.analyze()
                all_results.extend(results)
                logger.info(f"{analyzer_class.__name__} completed with {len(results)} findings")
            except Exception as e:
                logger.error(f"{analyzer_class.__name__} failed: {e}")
                all_results.append({
                    "analyzer_name": analyzer_class.__name__,
                    "finding_type": "error",
                    "title": f"Analyzer failed: {analyzer_class.__name__}",
                    "description": str(e),
                    "severity_hint": "high",
                    "confidence_hint": "high",
                })

        return {
            "package_name": self.package_name,
            "findings": all_results,
            "analyzers_run": [a.__name__ for a in analyzers_to_run],
        }

    def _extract_apk(self) -> Path:
        """Extract APK to temporary directory."""
        import tempfile
        temp_dir = Path(tempfile.mkdtemp(prefix=f"apk_analysis_{self.apk_file_id}_"))

        with zipfile.ZipFile(self.apk_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        # Verify extraction
        if not (temp_dir / "AndroidManifest.xml").exists():
            # Try to find it in subdirectories
            for manifest in temp_dir.rglob("AndroidManifest.xml"):
                # Move contents up if needed
                pass

        return temp_dir

    def _get_package_name(self) -> str:
        """Extract package name from manifest."""
        manifest_path = self.temp_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                tree = ET.parse(str(manifest_path))
                root = tree.getroot()
                package = root.get("package")
                if package:
                    return package
            except Exception:
                pass
        return "unknown"

    def cleanup(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def calculate_hashes(self) -> dict[str, str]:
        """Calculate cryptographic hashes of the APK."""
        hashes = {}
        with open(self.apk_path, "rb") as f:
            content = f.read()
            hashes["sha256"] = hashlib.sha256(content).hexdigest()
            hashes["sha1"] = hashlib.sha1(content).hexdigest()
            hashes["md5"] = hashlib.md5(content).hexdigest()
        return hashes