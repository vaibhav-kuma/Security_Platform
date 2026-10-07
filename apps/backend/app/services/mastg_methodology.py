"""OWASP MASTG (Mobile Application Security Testing Guide) methodology and test cases.

This module defines the methodology version and test cases for the
OWASP MASTG, mapped to MASVS (Mobile Application Security Verification Standard) controls.
"""

from typing import TypedDict

from sqlalchemy.orm import Session

from app.models.methodology import Methodology, MethodologyVersion, TestCase


class TestCaseData(TypedDict):
    identifier: str
    name: str
    description: str
    category: str
    order: int
    supported_target_types: list[str]
    prerequisites: list[str]
    passive_mode: bool
    active_mode: bool
    safe_mode_compatible: bool
    evidence_requirements: list[str]
    detection_rules: list[str]
    references: list[str]


class MethodologyVersionData(TypedDict):
    version: int
    name: str
    description: str
    is_active: bool
    test_cases: list[TestCaseData]


class MethodologyData(TypedDict):
    name: str
    description: str
    versions: list[MethodologyVersionData]


# OWASP MASTG / MASVS Methodology
# Based on MASTG v1.5+ and MASVS v1.0+
MASTG_METHODOLOGY: MethodologyData = {
    "name": "OWASP MASTG / MASVS",
    "description": "OWASP Mobile Application Security Testing Guide mapped to Mobile Application Security Verification Standard",
    "versions": [
        {
            "version": 2024,
            "name": "MASTG v1.5 / MASVS v1.0",
            "description": "OWASP MASTG 1.5+ test cases mapped to MASVS controls",
            "is_active": True,
            "test_cases": [
                # =========================================================================
                # MASVS-ARCH: Architecture, Design and Threat Modeling
                # =========================================================================
                {
                    "identifier": "MASTG-ARCH-001",
                    "name": "Security Architecture Review",
                    "description": "Review the app's security architecture including trust boundaries, data flows, and threat model",
                    "category": "MASVS-ARCH: Architecture, Design and Threat Modeling",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file", "architecture_docs"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Architecture diagrams",
                        "Data flow diagrams",
                        "Threat model documentation",
                    ],
                    "detection_rules": ["ARCH_REVIEW"],
                    "references": [
                        "https://mas.owasp.org/MASTG/General/0x04a-Testing-Architecture/",
                        "https://mas.owasp.org/MASVS/Architecture/",
                    ],
                },
                {
                    "identifier": "MASTG-ARCH-002",
                    "name": "IPC Attack Surface Analysis",
                    "description": "Analyze Inter-Process Communication mechanisms for exposed attack surface",
                    "category": "MASVS-ARCH: Architecture, Design and Threat Modeling",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "List of exported components",
                        "Intent filter analysis",
                        "Content provider permissions",
                    ],
                    "detection_rules": ["EXPORTED_COMPONENT_ANALYSIS", "IPC_SURFACE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05g-Testing-Inter-Process-Communication/",
                    ],
                },

                # =========================================================================
                # MASVS-STORAGE: Data Storage and Privacy
                # =========================================================================
                {
                    "identifier": "MASTG-STORAGE-001",
                    "name": "Insecure Data Storage Analysis",
                    "description": "Identify sensitive data stored insecurely on the device",
                    "category": "MASVS-STORAGE: Data Storage and Privacy",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "SharedPreferences files",
                        "SQLite databases",
                        "Internal/external files",
                        "Sensitive data patterns found",
                    ],
                    "detection_rules": ["STORAGE_ANALYSIS", "SENSITIVE_DATA_IN_STORAGE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05d-Testing-Data-Storage/",
                        "https://mas.owasp.org/MASVS/Storage/",
                    ],
                },
                {
                    "identifier": "MASTG-STORAGE-002",
                    "name": "Hardcoded Secrets Detection",
                    "description": "Detect hardcoded API keys, passwords, tokens, and cryptographic keys in the APK",
                    "category": "MASVS-STORAGE: Data Storage and Privacy",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Strings from DEX/native libraries",
                        "Resource files (strings.xml, configs)",
                        "Manifest metadata",
                    ],
                    "detection_rules": ["HARDCODED_SECRETS", "SECRET_DETECTION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05e-Testing-Data-Storage/",
                    ],
                },
                {
                    "identifier": "MASTG-STORAGE-003",
                    "name": "Backup Configuration Analysis",
                    "description": "Check if application data can be backed up (allowBackup flag)",
                    "category": "MASVS-STORAGE: Data Storage and Privacy",
                    "order": 3,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "AndroidManifest.xml application@allowBackup",
                    ],
                    "detection_rules": ["BACKUP_ALLOWED"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05d-Testing-Data-Storage/",
                    ],
                },
                {
                    "identifier": "MASTG-STORAGE-004",
                    "name": "Keyboard Cache Analysis",
                    "description": "Check if sensitive input fields disable keyboard caching",
                    "category": "MASVS-STORAGE: Data Storage and Privacy",
                    "order": 4,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Input field configurations",
                        "Keyboard cache behavior",
                    ],
                    "detection_rules": ["KEYBOARD_CACHE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05d-Testing-Data-Storage/",
                    ],
                },

                # =========================================================================
                # MASVS-CRYPTO: Cryptography
                # =========================================================================
                {
                    "identifier": "MASTG-CRYPTO-001",
                    "name": "Weak Cryptographic Algorithm Detection",
                    "description": "Identify use of weak or deprecated cryptographic algorithms (DES, 3DES, RC4, MD5, SHA1, ECB mode)",
                    "category": "MASVS-CRYPTO: Cryptography",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Algorithm names in DEX/native code",
                        "Cipher instance creation patterns",
                        "Hash function usage",
                    ],
                    "detection_rules": ["WEAK_CRYPTO_ALGORITHMS", "ECB_MODE", "WEAK_HASH"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05f-Testing-Cryptography/",
                        "https://mas.owasp.org/MASVS/Crypto/",
                    ],
                },
                {
                    "identifier": "MASTG-CRYPTO-002",
                    "name": "Insecure Random Number Generation",
                    "description": "Detect use of insecure random number generators (java.util.Random, Math.random)",
                    "category": "MASVS-CRYPTO: Cryptography",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Random class usage",
                        "SecureRandom with weak providers",
                    ],
                    "detection_rules": ["WEAK_RNG", "SECURERANDOM_MISUSE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05f-Testing-Cryptography/",
                    ],
                },
                {
                    "identifier": "MASTG-CRYPTO-003",
                    "name": "Hardcoded Cryptographic Keys",
                    "description": "Detect hardcoded encryption keys, IVs, or secrets in code or resources",
                    "category": "MASVS-CRYPTO: Cryptography",
                    "order": 3,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "SecretKeySpec usage with hardcoded bytes",
                        "Hardcoded strings in DEX/native",
                        "Key derivation from static values",
                    ],
                    "detection_rules": ["HARDCODED_KEYS", "STATIC_IV"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05f-Testing-Cryptography/",
                    ],
                },
                {
                    "identifier": "MASTG-CRYPTO-004",
                    "name": "Certificate and Key Management",
                    "description": "Analyze certificate validation, pinning, and key storage practices",
                    "category": "MASVS-CRYPTO: Cryptography",
                    "order": 4,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Certificate validation code",
                        "Pinning implementation",
                        "Keystore usage",
                    ],
                    "detection_rules": ["CERT_PINNING", "TRUST_MANAGER", "HOSTNAME_VERIFIER"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05f-Testing-Cryptography/",
                    ],
                },

                # =========================================================================
                # MASVS-AUTH: Authentication and Session Management
                # =========================================================================
                {
                    "identifier": "MASTG-AUTH-001",
                    "name": "Authentication Mechanism Analysis",
                    "description": "Analyze local and remote authentication mechanisms for weaknesses",
                    "category": "MASVS-AUTH: Authentication and Session Management",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Authentication flows",
                        "Biometric usage",
                        "Session token handling",
                    ],
                    "detection_rules": ["AUTH_MECHANISM", "BIOMETRIC_USAGE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05h-Testing-Authentication/",
                        "https://mas.owasp.org/MASVS/Auth/",
                    ],
                },
                {
                    "identifier": "MASTG-AUTH-002",
                    "name": "Session Management Analysis",
                    "description": "Analyze session token generation, storage, rotation, and invalidation",
                    "category": "MASVS-AUTH: Authentication and Session Management",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Token storage locations",
                        "Token expiration",
                        "Logout implementation",
                    ],
                    "detection_rules": ["SESSION_MANAGEMENT", "TOKEN_STORAGE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05h-Testing-Authentication/",
                    ],
                },

                # =========================================================================
                # MASVS-NETWORK: Network Communication
                # =========================================================================
                {
                    "identifier": "MASTG-NETWORK-001",
                    "name": "Cleartext Traffic Detection",
                    "description": "Identify unencrypted HTTP traffic and cleartext communication",
                    "category": "MASVS-NETWORK: Network Communication",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Network security config",
                        "usesCleartextTraffic flag",
                        "HTTP URLs in code/resources",
                    ],
                    "detection_rules": ["CLEARTEXT_TRAFFIC", "HTTP_URLS", "NETWORK_SECURITY_CONFIG"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05i-Testing-Network-Communication/",
                        "https://mas.owasp.org/MASVS/Network/",
                    ],
                },
                {
                    "identifier": "MASTG-NETWORK-002",
                    "name": "Certificate Pinning Validation",
                    "description": "Verify proper certificate pinning implementation",
                    "category": "MASVS-NETWORK: Network Communication",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Network security config pin-set",
                        "Custom TrustManager/X509TrustManager",
                        "Pin validation logic",
                    ],
                    "detection_rules": ["CERT_PINNING", "PIN_VALIDATION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05i-Testing-Network-Communication/",
                    ],
                },
                {
                    "identifier": "MASTG-NETWORK-003",
                    "name": "SSL/TLS Configuration Analysis",
                    "description": "Analyze TLS version support, cipher suites, and hostname verification",
                    "category": "MASVS-NETWORK: Network Communication",
                    "order": 3,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "SSLContext configuration",
                        "Enabled protocols/ciphers",
                        "HostnameVerifier implementation",
                    ],
                    "detection_rules": ["TLS_VERSION", "WEAK_CIPHERS", "HOSTNAME_VERIFICATION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05i-Testing-Network-Communication/",
                    ],
                },

                # =========================================================================
                # MASVS-PLATFORM: Platform Interaction
                # =========================================================================
                {
                    "identifier": "MASTG-PLATFORM-001",
                    "name": "Exported Component Security",
                    "description": "Analyze exported activities, services, receivers, and providers for improper access control",
                    "category": "MASVS-PLATFORM: Platform Interaction",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Exported component list",
                        "Intent filters",
                        "Permission protection",
                    ],
                    "detection_rules": ["EXPORTED_COMPONENT", "INTENT_FILTER", "COMPONENT_PERMISSION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05g-Testing-Inter-Process-Communication/",
                        "https://mas.owasp.org/MASVS/Platform/",
                    ],
                },
                {
                    "identifier": "MASTG-PLATFORM-002",
                    "name": "WebView Security Configuration",
                    "description": "Analyze WebView settings for dangerous configurations (JS enabled, file access, universal access)",
                    "category": "MASVS-PLATFORM: Platform Interaction",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "WebView settings",
                        "JavaScript interfaces",
                        "URL loading patterns",
                    ],
                    "detection_rules": ["WEBVIEW_SETTINGS", "JS_INTERFACE", "FILE_ACCESS"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05j-Testing-WebView/",
                        "https://mas.owasp.org/MASVS/Platform/",
                    ],
                },
                {
                    "identifier": "MASTG-PLATFORM-003",
                    "name": "Intent Handling and Deep Links",
                    "description": "Analyze intent handling, deep links, and URL schemes for security issues",
                    "category": "MASVS-PLATFORM: Platform Interaction",
                    "order": 3,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Intent filter schemes",
                        "Deep link handling",
                        "URL validation",
                    ],
                    "detection_rules": ["DEEP_LINKS", "INTENT_HANDLING", "URL_SCHEMES"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05g-Testing-Inter-Process-Communication/",
                    ],
                },
                {
                    "identifier": "MASTG-PLATFORM-004",
                    "name": "Clipboard and Keyboard Cache Analysis",
                    "description": "Check if sensitive data can leak via clipboard or keyboard cache",
                    "category": "MASVS-PLATFORM: Platform Interaction",
                    "order": 4,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Clipboard usage",
                        "Input field flags",
                    ],
                    "detection_rules": ["CLIPBOARD_USAGE", "KEYBOARD_CACHE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05d-Testing-Data-Storage/",
                    ],
                },

                # =========================================================================
                # MASVS-CODE: Code Quality and Build Settings
                # =========================================================================
                {
                    "identifier": "MASTG-CODE-001",
                    "name": "Debuggable Application Check",
                    "description": "Check if application is debuggable in production build",
                    "category": "MASVS-CODE: Code Quality and Build Settings",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "AndroidManifest.xml application@debuggable",
                    ],
                    "detection_rules": ["DEBUGGABLE_APP"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05c-Testing-Code-Quality/",
                        "https://mas.owasp.org/MASVS/Code/",
                    ],
                },
                {
                    "identifier": "MASTG-CODE-002",
                    "name": "Debug Code and Logging Analysis",
                    "description": "Detect debug logging, test code, and debugging artifacts in production",
                    "category": "MASVS-CODE: Code Quality and Build Settings",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Log.d/Log.v/Log.wtf calls",
                        "BuildConfig.DEBUG usage",
                        "Test classes in production",
                    ],
                    "detection_rules": ["DEBUG_LOGGING", "TEST_CODE", "BUILD_CONFIG_DEBUG"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05c-Testing-Code-Quality/",
                    ],
                },
                {
                    "identifier": "MASTG-CODE-003",
                    "name": "Root Detection and Anti-Tampering",
                    "description": "Analyze root detection, emulator detection, and anti-tampering mechanisms",
                    "category": "MASVS-CODE: Code Quality and Build Settings",
                    "order": 3,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Root detection code",
                        "Emulator checks",
                        "Integrity checks",
                    ],
                    "detection_rules": ["ROOT_DETECTION", "EMULATOR_DETECTION", "ANTI_TAMPER"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05c-Testing-Code-Quality/",
                    ],
                },

                # =========================================================================
                # MASVS-RESILIENCE: Resilience Against Reverse Engineering
                # =========================================================================
                {
                    "identifier": "MASTG-RESILIENCE-001",
                    "name": "Code Obfuscation Analysis",
                    "description": "Analyze if code is properly obfuscated (ProGuard/R8)",
                    "category": "MASVS-RESILIENCE: Resilience Against Reverse Engineering",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Class/method/field naming patterns",
                        "Mapping file presence",
                        "String encryption",
                    ],
                    "detection_rules": ["OBFUSCATION", "MAPPING_FILE", "STRING_ENCRYPTION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05c-Testing-Code-Quality/",
                        "https://mas.owasp.org/MASVS/Resilience/",
                    ],
                },
                {
                    "identifier": "MASTG-RESILIENCE-002",
                    "name": "Native Library Protection",
                    "description": "Analyze native library stripping, obfuscation, and anti-debugging",
                    "category": "MASVS-RESILIENCE: Resilience Against Reverse Engineering",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Symbol table analysis",
                        "Anti-debugging checks",
                        "JNI method naming",
                    ],
                    "detection_rules": ["NATIVE_STRIPPING", "NATIVE_ANTI_DEBUG", "JNI_OBFUSCATION"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05c-Testing-Code-Quality/",
                    ],
                },

                # =========================================================================
                # MASVS-PERMISSIONS: Permissions
                # =========================================================================
                {
                    "identifier": "MASTG-PERMISSIONS-001",
                    "name": "Permission Analysis",
                    "description": "Analyze requested permissions for over-privilege and unnecessary dangerous permissions",
                    "category": "MASVS-PERMISSIONS: Permissions",
                    "order": 1,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Full permission list",
                        "Dangerous permissions justification",
                        "Custom permissions",
                    ],
                    "detection_rules": ["PERMISSION_ANALYSIS", "DANGEROUS_PERMISSIONS", "CUSTOM_PERMISSIONS"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05b-Testing-Permissions/",
                        "https://mas.owasp.org/MASVS/Permissions/",
                    ],
                },
                {
                    "identifier": "MASTG-PERMISSIONS-002",
                    "name": "Runtime Permission Handling",
                    "description": "Analyze runtime permission request flows and denial handling",
                    "category": "MASVS-PERMISSIONS: Permissions",
                    "order": 2,
                    "supported_target_types": ["apk"],
                    "prerequisites": ["apk_file"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Permission request code",
                        "Rationale dialogs",
                        "Denial handling",
                    ],
                    "detection_rules": ["RUNTIME_PERMISSIONS", "PERMISSION_RATIONALE"],
                    "references": [
                        "https://mas.owasp.org/MASTG/Android/0x05b-Testing-Permissions/",
                    ],
                },
            ],
        },
    ],
}


def seed_mastg_methodology(db: Session) -> None:
    """Seed the MASTG methodology into the database."""
    # Check if methodology already exists
    existing = db.query(Methodology).filter(Methodology.name == "OWASP MASTG / MASVS").first()
    if existing:
        return

    methodology_data = MASTG_METHODOLOGY

    methodology = Methodology(
        name=methodology_data["name"],
        description=methodology_data["description"],
    )
    db.add(methodology)
    db.flush()

    for version_data in methodology_data["versions"]:
        version = MethodologyVersion(
            methodology_id=methodology.id,
            version=version_data["version"],
            name=version_data["name"],
            description=version_data["description"],
            is_active=version_data["is_active"],
        )
        db.add(version)
        db.flush()

        for tc_data in version_data["test_cases"]:
            test_case = TestCase(
                methodology_version_id=version.id,
                identifier=tc_data["identifier"],
                name=tc_data["name"],
                description=tc_data["description"],
                category=tc_data["category"],
                order=tc_data["order"],
                supported_target_types=tc_data["supported_target_types"],
                prerequisites=tc_data["prerequisites"],
                passive_mode=tc_data["passive_mode"],
                active_mode=tc_data["active_mode"],
                safe_mode_compatible=tc_data["safe_mode_compatible"],
                evidence_requirements=tc_data["evidence_requirements"],
                detection_rules=tc_data["detection_rules"],
                references=tc_data["references"],
            )
            db.add(test_case)

    db.commit()