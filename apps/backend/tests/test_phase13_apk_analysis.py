"""Unit tests for Phase 13: APK Static Analysis components."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4

from app.core.apk_analyzer import (
    ApkAnalyzer,
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
    AnalysisContext,
)
from app.services.mastg_methodology import MASTG_METHODOLOGY, seed_mastg_methodology
from app.services.apk_analysis import ApkAnalysisService
from app.models.methodology import Methodology, MethodologyVersion, TestCase, TestCaseRun
from app.models.enums import AssetKind, SecurityEventType
from app.models.apk import ApkFile, ApkComponent
from app.models.assets import Asset


# =============================================================================
# MASTG Methodology Tests
# =============================================================================

class TestMastgMethodology:
    def test_methodology_structure(self):
        """Test MASTG methodology has correct structure."""
        assert MASTG_METHODOLOGY["name"] == "OWASP MASTG / MASVS"
        assert "versions" in MASTG_METHODOLOGY
        assert len(MASTG_METHODOLOGY["versions"]) == 1

        version = MASTG_METHODOLOGY["versions"][0]
        assert version["version"] == 2024
        assert version["is_active"] is True
        assert "test_cases" in version
        assert len(version["test_cases"]) > 0

    def test_test_case_structure(self):
        """Test each test case has required fields."""
        version = MASTG_METHODOLOGY["versions"][0]
        for tc in version["test_cases"]:
            required_fields = [
                "identifier", "name", "description", "category", "order",
                "supported_target_types", "prerequisites", "passive_mode",
                "active_mode", "safe_mode_compatible", "evidence_requirements",
                "detection_rules", "references"
            ]
            for field in required_fields:
                assert field in tc, f"Missing field {field} in {tc.get('identifier', 'unknown')}"

    def test_categories_covered(self):
        """Test all MASVS categories are covered."""
        version = MASTG_METHODOLOGY["versions"][0]
        categories = set(tc["category"] for tc in version["test_cases"])

        expected_categories = {
            "MASVS-ARCH: Architecture, Design and Threat Modeling",
            "MASVS-STORAGE: Data Storage and Privacy",
            "MASVS-CRYPTO: Cryptography",
            "MASVS-AUTH: Authentication and Session Management",
            "MASVS-NETWORK: Network Communication",
            "MASVS-PLATFORM: Platform Interaction",
            "MASVS-CODE: Code Quality and Build Settings",
            "MASVS-RESILIENCE: Resilience Against Reverse Engineering",
            "MASVS-PERMISSIONS: Permissions",
        }

        for cat in expected_categories:
            assert cat in categories, f"Missing category: {cat}"

    def test_seed_methodology(self):
        """Test seeding methodology into database."""
        from unittest.mock import Mock
        db = Mock()
        db.query.return_value.filter.return_value.first.return_value = None
        db.flush = Mock()
        db.commit = Mock()

        seed_mastg_methodology(db)

        # Verify methodology was added
        assert db.add.call_count >= 1
        db.commit.assert_called_once()


# =============================================================================
# Manifest Analyzer Tests
# =============================================================================

class TestManifestAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Mock()
        self.mock_context.apk_file_id = str(uuid4())
        self.mock_context.package_name = "com.example.test"
        self.analyzer = ManifestAnalyzer(self.mock_context)

    @patch("app.core.apk_analyzer.ET.parse")
    def test_detects_debuggable_true(self, mock_parse):
        """Test detection of debuggable=true."""
        mock_root = Mock()
        mock_application = Mock()
        mock_application.get.return_value = "true"
        mock_root.find.return_value = mock_application

        # Create a mock tree that has getroot() method
        mock_tree = Mock()
        mock_tree.getroot.return_value = mock_root
        mock_parse.return_value = mock_tree

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True

        # Make temp_dir / "AndroidManifest.xml" return our mock path
        mock_truediv = Mock(return_value=mock_manifest_path)
        self.mock_context.temp_dir.__truediv__ = mock_truediv

        results = self.analyzer.analyze()

        assert len(results) > 0
        debuggable_finding = next((r for r in results if "debuggable" in r["title"].lower()), None)
        assert debuggable_finding is not None
        assert debuggable_finding["severity_hint"] == "medium"

    @patch("app.core.apk_analyzer.ET.parse")
    def test_detects_allow_backup_true(self, mock_parse):
        """Test detection of allowBackup=true."""
        mock_root = Mock()
        mock_application = Mock()
        mock_application.get.side_effect = lambda key, default="false": {
            "{http://schemas.android.com/apk/res/android}debuggable": "false",
            "{http://schemas.android.com/apk/res/android}allowBackup": "true",
            "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "false",
        }.get(key, default)
        mock_root.find.return_value = mock_application

        mock_tree = Mock()
        mock_tree.getroot.return_value = mock_root
        mock_parse.return_value = mock_tree

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True
        mock_truediv = Mock(return_value=mock_manifest_path)
        self.mock_context.temp_dir.__truediv__ = mock_truediv

        results = self.analyzer.analyze()

        backup_finding = next((r for r in results if "backup" in r["title"].lower()), None)
        assert backup_finding is not None
        assert backup_finding["severity_hint"] == "low"

    @patch("app.core.apk_analyzer.ET.parse")
    def test_detects_cleartext_traffic(self, mock_parse):
        """Test detection of usesCleartextTraffic=true."""
        mock_root = Mock()
        mock_application = Mock()
        mock_application.get.side_effect = lambda key, default="false": {
            "{http://schemas.android.com/apk/res/android}debuggable": "false",
            "{http://schemas.android.com/apk/res/android}allowBackup": "false",
            "{http://schemas.android.com/apk/res/android}usesCleartextTraffic": "true",
        }.get(key, default)
        mock_root.find.return_value = mock_application

        mock_tree = Mock()
        mock_tree.getroot.return_value = mock_root
        mock_parse.return_value = mock_tree

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True
        mock_truediv = Mock(return_value=mock_manifest_path)
        self.mock_context.temp_dir.__truediv__ = mock_truediv

        results = self.analyzer.analyze()

        cleartext_finding = next((r for r in results if "cleartext" in r["title"].lower()), None)
        assert cleartext_finding is not None
        assert cleartext_finding["severity_hint"] == "medium"


# =============================================================================
# Permission Analyzer Tests
# =============================================================================

class TestPermissionAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Mock()
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = PermissionAnalyzer(self.mock_context)

    @patch("app.core.apk_analyzer.ET.parse")
    def test_detects_dangerous_permissions(self, mock_parse):
        """Test detection of dangerous permissions."""
        mock_root = Mock()
        mock_perm1 = Mock()
        mock_perm1.get.return_value = "android.permission.CAMERA"
        mock_perm2 = Mock()
        mock_perm2.get.return_value = "android.permission.INTERNET"  # Not dangerous
        mock_perm3 = Mock()
        mock_perm3.get.return_value = "com.example.custom.permission"  # Custom
        mock_root.findall.return_value = [mock_perm1, mock_perm2, mock_perm3]

        mock_tree = Mock()
        mock_tree.getroot.return_value = mock_root
        mock_parse.return_value = mock_tree

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True
        self.mock_context.temp_dir.__truediv__ = Mock(return_value=mock_manifest_path)

        results = self.analyzer.analyze()

        assert len(results) == 3
        camera_finding = next((r for r in results if "CAMERA" in r["evidence"].get("permission", "")), None)
        assert camera_finding is not None
        assert camera_finding["evidence"]["dangerous"] is True
        assert camera_finding["severity_hint"] == "high"

        internet_finding = next((r for r in results if "INTERNET" in r["evidence"].get("permission", "")), None)
        assert internet_finding is not None
        assert internet_finding["evidence"]["dangerous"] is False
        assert internet_finding["severity_hint"] == "info"

        custom_finding = next((r for r in results if "custom" in r["evidence"].get("permission", "")), None)
        assert custom_finding is not None
        assert custom_finding["evidence"]["custom"] is True
        assert custom_finding["severity_hint"] == "medium"


# =============================================================================
# Certificate Analyzer Tests
# =============================================================================

class TestCertificateAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Mock()
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = CertificateAnalyzer(self.mock_context)

    def test_no_meta_inf(self):
        """Test error when META-INF missing."""
        with patch("app.core.apk_analyzer.Path.exists", return_value=False):
            results = self.analyzer.analyze()

        assert len(results) == 1
        assert results[0]["finding_type"] == "error"
        assert "meta-inf" in results[0]["title"].lower()


# =============================================================================
# URL Analyzer Tests
# =============================================================================

class TestUrlAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Path("/tmp/test_apk")
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = UrlAnalyzer(self.mock_context)

    def test_extract_urls(self):
        """Test URL extraction from text."""
        text = "Check out https://api.example.com/v1/users and http://localhost:8080/admin"
        urls = self.analyzer._extract_urls(text)
        assert "https://api.example.com/v1/users" in urls
        assert "http://localhost:8080/admin" in urls

    def test_categorize_urls(self):
        """Test URL categorization."""
        urls = {
            "https://api.example.com/v1/users",
            "wss://ws.example.com/socket",
            "https://firebase.example.com/app",
            "https://example.com/image.png",
        }
        categorized = self.analyzer._categorize_urls(urls)

        assert "https://api.example.com/v1/users" in categorized["api_endpoints"]
        assert "wss://ws.example.com/socket" in categorized["websocket_urls"]
        assert "https://firebase.example.com/app" in categorized["firebase_urls"]
        assert "https://example.com/image.png" in categorized["other"]


# =============================================================================
# Configuration Analyzer Tests
# =============================================================================

class TestConfigurationAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Path("/tmp/test_apk")
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = ConfigurationAnalyzer(self.mock_context)

    @patch("xml.etree.ElementTree.parse")
    def test_detects_cleartext_in_network_config(self, mock_parse):
        """Test detection of cleartext traffic in network security config."""
        mock_root = Mock()
        mock_base_config = Mock()
        mock_base_config.get.return_value = "true"
        mock_root.find.return_value = mock_base_config
        mock_parse.return_value.getroot.return_value = mock_root

        config_file = Path("/tmp/test_apk/res/xml/network_security_config.xml")
        with patch("app.core.apk_analyzer.Path.exists", return_value=True):
            self.analyzer._analyze_network_security_config(config_file)

        cleartext_finding = next((r for r in self.analyzer.results if "cleartext" in r["title"].lower()), None)
        assert cleartext_finding is not None
        assert cleartext_finding["severity_hint"] == "medium"

    @patch("xml.etree.ElementTree.parse")
    def test_detects_certificate_pinning(self, mock_parse):
        """Test detection of certificate pinning."""
        mock_root = Mock()
        mock_domain_config = Mock()
        mock_domain_config.get.return_value = "example.com"
        mock_pin_set = Mock()
        mock_pin = Mock()
        mock_pin.text = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        mock_pin_set.findall.return_value = [mock_pin]
        mock_domain_config.find.return_value = mock_pin_set
        mock_root.findall.return_value = [mock_domain_config]
        mock_parse.return_value.getroot.return_value = mock_root

        config_file = Path("/tmp/test_apk/res/xml/network_security_config.xml")
        with patch("app.core.apk_analyzer.Path.exists", return_value=True):
            self.analyzer._analyze_network_security_config(config_file)

        pinning_finding = next((r for r in self.analyzer.results if "pinning" in r["title"].lower()), None)
        assert pinning_finding is not None
        assert pinning_finding["severity_hint"] == "info"


# =============================================================================
# Exported Component Analyzer Tests
# =============================================================================

class TestExportedComponentAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Mock()
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = ExportedComponentAnalyzer(self.mock_context)

    @patch("xml.etree.ElementTree.parse")
    def test_detects_exported_provider_without_permission(self, mock_parse):
        """Test detection of exported provider without permission."""
        mock_root = Mock()
        mock_application = Mock()
        mock_provider = Mock()
        mock_provider.get.side_effect = lambda key: {
            "{http://schemas.android.com/apk/res/android}name": "com.example.MyProvider",
            "{http://schemas.android.com/apk/res/android}exported": "true",
            "{http://schemas.android.com/apk/res/android}permission": "",
        }.get(key, "")
        mock_provider.findall.return_value = []
        mock_application.findall.return_value = [mock_provider]
        mock_root.find.return_value = mock_application
        mock_parse.return_value.getroot.return_value = mock_root

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True
        self.mock_context.temp_dir.__truediv__ = Mock(return_value=mock_manifest_path)

        results = self.analyzer.analyze()

        provider_finding = next((r for r in results if "provider" in r["title"].lower()), None)
        assert provider_finding is not None
        assert provider_finding["severity_hint"] == "high"
        assert provider_finding["evidence"]["component_type"] == "provider"
        assert provider_finding["evidence"]["permission"] == ""


# =============================================================================
# WebView Analyzer Tests
# =============================================================================

class TestWebViewAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Path("/tmp/test_apk")
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = WebViewAnalyzer(self.mock_context)

    def test_detects_javascript_enabled(self):
        """Test detection of JavaScript enabled in WebView."""
        content = "webView.getSettings().setJavaScriptEnabled(true);"
        self.analyzer._analyze_webview_strings(content)

        js_finding = next((r for r in self.analyzer.results if "javascript" in r["title"].lower()), None)
        assert js_finding is not None
        assert js_finding["severity_hint"] == "medium"

    def test_detects_javascript_interface(self):
        """Test detection of addJavascriptInterface."""
        content = "webView.addJavascriptInterface(new MyJSInterface(), \"Android\");"
        self.analyzer._analyze_webview_strings(content)

        js_interface_finding = next((r for r in self.analyzer.results if "javascript interface" in r["title"].lower()), None)
        assert js_interface_finding is not None
        assert js_interface_finding["severity_hint"] == "medium"


# =============================================================================
# Crypto Analyzer Tests
# =============================================================================

class TestCryptoAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Path("/tmp/test_apk")
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = CryptoAnalyzer(self.mock_context)

    @patch("subprocess.run")
    def test_detects_weak_algorithms(self, mock_run):
        """Test detection of weak crypto algorithms."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Cipher.getInstance(\"AES/ECB/PKCS5Padding\") SecretKeySpec"
        mock_run.return_value = mock_result

        dex_file = Path("/tmp/test_apk/classes.dex")
        self.analyzer._analyze_dex_crypto(dex_file)

        ecb_finding = next((r for r in self.analyzer.results if "ECB" in r["title"]), None)
        assert ecb_finding is not None
        assert ecb_finding["severity_hint"] == "high"


# =============================================================================
# Network Security Analyzer Tests
# =============================================================================

class TestNetworkSecurityAnalyzer:
    def setup_method(self):
        self.mock_context = Mock(spec=AnalysisContext)
        self.mock_context.temp_dir = Mock()
        self.mock_context.apk_file_id = str(uuid4())
        self.analyzer = NetworkSecurityAnalyzer(self.mock_context)

    @patch("xml.etree.ElementTree.parse")
    def test_detects_cleartext_in_manifest(self, mock_parse):
        """Test detection of cleartext traffic in manifest."""
        mock_root = Mock()
        mock_application = Mock()
        mock_application.get.return_value = "true"
        mock_root.find.return_value = mock_application
        mock_parse.return_value.getroot.return_value = mock_root

        # Mock the manifest path exists
        mock_manifest_path = Mock()
        mock_manifest_path.exists.return_value = True
        self.mock_context.temp_dir.__truediv__ = Mock(return_value=mock_manifest_path)

        self.analyzer._analyze_manifest_network(Path("/tmp/test_apk/AndroidManifest.xml"))

        cleartext_finding = next((r for r in self.analyzer.results if "cleartext" in r["title"].lower()), None)
        assert cleartext_finding is not None
        assert cleartext_finding["severity_hint"] == "medium"


# =============================================================================
# ApkAnalyzer Integration Tests
# =============================================================================

class TestApkAnalyzerIntegration:
    def test_analyzer_initialization(self):
        """Test ApkAnalyzer initialization."""
        analyzer = ApkAnalyzer(
            apk_path=Path("/tmp/test.apk"),
            apk_file_id=str(uuid4()),
            package_name="com.example.test"
        )
        assert analyzer.apk_path == Path("/tmp/test.apk")
        assert analyzer.package_name == "com.example.test"
        assert len(analyzer.ANALYZERS) == 13

    def test_calculate_hashes(self):
        """Test hash calculation."""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test apk content")
            temp_path = Path(f.name)

        try:
            analyzer = ApkAnalyzer(apk_path=temp_path, apk_file_id=str(uuid4()))
            hashes = analyzer.calculate_hashes()
            assert "sha256" in hashes
            assert "sha1" in hashes
            assert "md5" in hashes
            assert len(hashes["sha256"]) == 64
        finally:
            temp_path.unlink()


# =============================================================================
# ApkAnalysisService Tests
# =============================================================================

class TestApkAnalysisService:
    def setup_method(self):
        self.mock_db = Mock()
        self.service = ApkAnalysisService(self.mock_db)

    def test_get_mastg_test_cases(self):
        """Test getting MASTG test cases."""
        mock_test_case = Mock(spec=TestCase)
        mock_test_case.id = uuid4()
        mock_test_case.methodology_version_id = uuid4()
        mock_test_case.identifier = "MASTG-STORAGE-001"
        mock_test_case.name = "Insecure Data Storage"
        mock_test_case.description = "Test description"
        mock_test_case.category = "MASVS-STORAGE"
        mock_test_case.order = 1
        mock_test_case.supported_target_types = ["apk"]
        mock_test_case.prerequisites = ["apk_file"]
        mock_test_case.passive_mode = True
        mock_test_case.active_mode = False
        mock_test_case.safe_mode_compatible = True
        mock_test_case.evidence_requirements = ["evidence1"]
        mock_test_case.detection_rules = ["rule1"]
        mock_test_case.references = ["ref1"]

        self.mock_db.scalars.return_value.all.return_value = [mock_test_case]

        test_cases = self.service.get_mastg_test_cases()
        assert len(test_cases) == 1
        assert test_cases[0].identifier == "MASTG-STORAGE-001"

    def test_get_mastg_coverage(self):
        """Test MASTG coverage calculation."""
        mock_run1 = Mock()
        mock_run1.coverage_status = "tested"
        mock_run1.test_case_id = uuid4()

        mock_run2 = Mock()
        mock_run2.coverage_status = "not_tested"
        mock_run2.test_case_id = uuid4()

        mock_test_case1 = Mock()
        mock_test_case1.category = "MASVS-STORAGE"

        mock_test_case2 = Mock()
        mock_test_case2.category = "MASVS-CRYPTO"

        self.mock_db.scalars.return_value.all.side_effect = [
            [mock_run1, mock_run2],  # runs
            [mock_test_case1],  # test_case for run1
            [mock_test_case2],  # test_case for run2
        ]

        coverage = self.service.get_mastg_coverage(uuid4())
        assert coverage["total"] == 2
        assert coverage["tested"] == 1
        assert coverage["not_tested"] == 1
        assert coverage["coverage_percent"] == 50.0


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])