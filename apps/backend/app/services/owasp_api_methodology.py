"""OWASP API Security Top 10 2023 methodology and test cases.

This module defines the methodology version and test cases for the
OWASP API Security Top 10 2023 categories:
- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API6:2023 Unrestricted Access to Sensitive Business Flows
- API7:2023 Server Side Request Forgery
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs
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


# OWASP API Security Top 10 2023 Methodology
OWASP_API_SECURITY_2023: MethodologyData = {
    "name": "OWASP API Security Top 10",
    "description": "OWASP API Security Top 10 2023 methodology for API security assessment",
    "versions": [
        {
            "version": 2023,
            "name": "OWASP API Security Top 10 2023",
            "description": "The 2023 edition of the OWASP API Security Top 10",
            "is_active": True,
            "test_cases": [
                # API1:2023 - Broken Object Level Authorization
                {
                    "identifier": "API1-001",
                    "name": "BOLA - Object ID Manipulation in Path Parameters",
                    "description": "Test if object identifiers in path parameters can be manipulated to access unauthorized resources",
                    "category": "API1:2023 Broken Object Level Authorization",
                    "order": 1,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "HTTP request with manipulated object ID",
                        "HTTP response showing unauthorized data access",
                        "Comparison of accessible object IDs across users",
                    ],
                    "detection_rules": ["API1_BOLA_PATH_PARAM", "API1_OBJECT_ID_ENUMERATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API1-002",
                    "name": "BOLA - Object ID Manipulation in Query Parameters",
                    "description": "Test if object identifiers in query parameters can be manipulated",
                    "category": "API1:2023 Broken Object Level Authorization",
                    "order": 2,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "HTTP request with manipulated query parameter",
                        "HTTP response showing unauthorized data access",
                    ],
                    "detection_rules": ["API1_BOLA_QUERY_PARAM"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                },
                {
                    "identifier": "API1-003",
                    "name": "BOLA - Object ID Enumeration via IDOR",
                    "description": "Test for Insecure Direct Object Reference (IDOR) by enumerating object IDs",
                    "category": "API1:2023 Broken Object Level Authorization",
                    "order": 3,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Sequence of requests with incremented object IDs",
                        "Responses showing data from multiple users/objects",
                    ],
                    "detection_rules": ["API1_IDOR_ENUMERATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                },
                # API2:2023 - Broken Authentication
                {
                    "identifier": "API2-001",
                    "name": "Broken Authentication - Weak Password Policy",
                    "description": "Test for weak password policies and credential stuffing vulnerability",
                    "category": "API2:2023 Broken Authentication",
                    "order": 4,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Password policy documentation or response analysis",
                        "Successful login with weak password",
                    ],
                    "detection_rules": ["API2_WEAK_PASSWORD_POLICY", "API2_CREDENTIAL_STUFFING"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API2-002",
                    "name": "Broken Authentication - JWT Token Vulnerabilities",
                    "description": "Test for JWT algorithm confusion, none algorithm, weak secrets, missing validation",
                    "category": "API2:2023 Broken Authentication",
                    "order": 5,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "JWT token analysis",
                        "Modified token accepted by server",
                    ],
                    "detection_rules": ["API2_JWT_ALG_NONE", "API2_JWT_WEAK_SECRET", "API2_JWT_MISSING_VALIDATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API2-003",
                    "name": "Broken Authentication - Missing Rate Limiting on Auth Endpoints",
                    "description": "Test for missing rate limiting on login, registration, password reset endpoints",
                    "category": "API2:2023 Broken Authentication",
                    "order": 6,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Multiple rapid authentication attempts",
                        "No rate limit response (429)",
                    ],
                    "detection_rules": ["API2_AUTH_RATE_LIMIT_MISSING"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    ],
                },
                {
                    "identifier": "API2-004",
                    "name": "Broken Authentication - API Key in URL",
                    "description": "Test for API keys exposed in URLs (query parameters)",
                    "category": "API2:2023 Broken Authentication",
                    "order": 7,
                    "supported_target_types": ["api"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "API key found in URL query parameter",
                    ],
                    "detection_rules": ["API2_API_KEY_IN_URL"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    ],
                },
                # API3:2023 - Broken Object Property Level Authorization
                {
                    "identifier": "API3-001",
                    "name": "Mass Assignment - Write Access to Sensitive Properties",
                    "description": "Test if additional properties in request body can modify sensitive fields",
                    "category": "API3:2023 Broken Object Property Level Authorization",
                    "order": 8,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with additional properties",
                        "Response confirming property modification",
                        "Verification of changed sensitive field",
                    ],
                    "detection_rules": ["API3_MASS_ASSIGNMENT_WRITE"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API3-002",
                    "name": "Excessive Data Exposure - Read Access to Sensitive Properties",
                    "description": "Test if API responses expose sensitive properties that should be filtered",
                    "category": "API3:2023 Broken Object Property Level Authorization",
                    "order": 9,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "API response containing sensitive fields",
                        "Comparison with expected response schema",
                    ],
                    "detection_rules": ["API3_EXCESSIVE_DATA_EXPOSURE"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                },
                {
                    "identifier": "API3-003",
                    "name": "Property Injection - Hidden Field Manipulation",
                    "description": "Test if hidden/internal fields can be injected via request parameters",
                    "category": "API3:2023 Broken Object Property Level Authorization",
                    "order": 10,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with injected internal field",
                        "Response showing field was processed",
                    ],
                    "detection_rules": ["API3_PROPERTY_INJECTION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                },
                # API4:2023 - Unrestricted Resource Consumption
                {
                    "identifier": "API4-001",
                    "name": "Resource Exhaustion - No Rate Limiting",
                    "description": "Test for missing rate limiting on API endpoints",
                    "category": "API4:2023 Unrestricted Resource Consumption",
                    "order": 11,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "High volume of requests without 429 response",
                        "Resource usage metrics",
                    ],
                    "detection_rules": ["API4_NO_RATE_LIMIT", "API4_RATE_LIMIT_BYPASS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                },
                {
                    "identifier": "API4-002",
                    "name": "Resource Exhaustion - Unbounded Pagination",
                    "description": "Test for unbounded pagination allowing excessive data retrieval",
                    "category": "API4:2023 Unrestricted Resource Consumption",
                    "order": 12,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Request with very large page size/limit",
                        "Response with excessive data",
                    ],
                    "detection_rules": ["API4_UNBOUNDED_PAGINATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                },
                {
                    "identifier": "API4-003",
                    "name": "Resource Exhaustion - Large Payload DoS",
                    "description": "Test for DoS via large request payloads (JSON, file uploads)",
                    "category": "API4:2023 Unrestricted Resource Consumption",
                    "order": 13,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with oversized payload",
                        "Server degradation or error",
                    ],
                    "detection_rules": ["API4_LARGE_PAYLOAD_DOS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                },
                {
                    "identifier": "API4-004",
                    "name": "Resource Exhaustion - CPU/Resource Intensive Operations",
                    "description": "Test for endpoints that allow resource-intensive operations without limits",
                    "category": "API4:2023 Unrestricted Resource Consumption",
                    "order": 14,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request triggering intensive operation",
                        "Resource consumption metrics",
                    ],
                    "detection_rules": ["API4_INTENSIVE_OPERATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                },
                # API5:2023 - Broken Function Level Authorization
                {
                    "identifier": "API5-001",
                    "name": "BFLA - Unauthorized Access to Administrative Endpoints",
                    "description": "Test if non-admin users can access administrative functions",
                    "category": "API5:2023 Broken Function Level Authorization",
                    "order": 15,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Request to admin endpoint with non-admin credentials",
                        "Response showing successful access or sensitive data",
                    ],
                    "detection_rules": ["API5_BFLA_ADMIN_ENDPOINT"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                },
                {
                    "identifier": "API5-002",
                    "name": "BFLA - HTTP Method Override Bypass",
                    "description": "Test if HTTP method override (X-HTTP-Method-Override) bypasses authorization",
                    "category": "API5:2023 Broken Function Level Authorization",
                    "order": 16,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with X-HTTP-Method-Override header",
                        "Response showing unauthorized method execution",
                    ],
                    "detection_rules": ["API5_METHOD_OVERRIDE_BYPASS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                },
                {
                    "identifier": "API5-003",
                    "name": "BFLA - Missing Authorization Checks on Sensitive Functions",
                    "description": "Test if sensitive functions lack proper authorization checks",
                    "category": "API5:2023 Broken Function Level Authorization",
                    "order": 17,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Request to sensitive function without required role",
                        "Response showing function executed",
                    ],
                    "detection_rules": ["API5_MISSING_AUTHZ_CHECK"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                },
                # API6:2023 - Unrestricted Access to Sensitive Business Flows
                {
                    "identifier": "API6-001",
                    "name": "Business Flow - Unrestricted Purchase/Order Flow",
                    "description": "Test if purchase/order flows can be bypassed or manipulated",
                    "category": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                    "order": 18,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema", "web_application"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Manipulated purchase flow request",
                        "Response showing unauthorized order completion",
                    ],
                    "detection_rules": ["API6_BUSINESS_FLOW_BYPASS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                    ],
                },
                {
                    "identifier": "API6-002",
                    "name": "Business Flow - Missing Business Logic Validation",
                    "description": "Test for missing business logic validations (negative amounts, quantity manipulation)",
                    "category": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                    "order": 19,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with invalid business values",
                        "Response showing acceptance of invalid values",
                    ],
                    "detection_rules": ["API6_BUSINESS_LOGIC_BYPASS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                    ],
                },
                {
                    "identifier": "API6-003",
                    "name": "Business Flow - Race Condition in Critical Operations",
                    "description": "Test for race conditions in sensitive business operations",
                    "category": "API6:2023 Unrestricted Access to Sensitive Business Flows",
                    "order": 20,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["authenticated_user", "api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Concurrent requests to same operation",
                        "Inconsistent state or duplicate processing",
                    ],
                    "detection_rules": ["API6_RACE_CONDITION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                    ],
                },
                # API7:2023 - Server Side Request Forgery
                {
                    "identifier": "API7-001",
                    "name": "SSRF - URL Parameter Injection",
                    "description": "Test if user-supplied URLs are fetched by the server",
                    "category": "API7:2023 Server Side Request Forgery",
                    "order": 21,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with internal/localhost URL",
                        "Response showing server fetched the URL",
                        "DNS/HTTP callback confirmation",
                    ],
                    "detection_rules": ["API7_SSRF_URL_PARAMETER", "API7_SSRF_INTERNAL_ACCESS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API7-002",
                    "name": "SSRF - File Schema Injection",
                    "description": "Test for SSRF via file:// schema in URL parameters",
                    "category": "API7:2023 Server Side Request Forgery",
                    "order": 22,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request with file:// URL",
                        "Response showing local file content",
                    ],
                    "detection_rules": ["API7_SSRF_FILE_SCHEMA"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                    ],
                },
                {
                    "identifier": "API7-003",
                    "name": "SSRF - Cloud Metadata Service Access",
                    "description": "Test for SSRF targeting cloud metadata endpoints (169.254.169.254)",
                    "category": "API7:2023 Server Side Request Forgery",
                    "order": 23,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Request to cloud metadata IP",
                        "Response containing instance metadata",
                    ],
                    "detection_rules": ["API7_SSRF_CLOUD_METADATA"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                    ],
                },
                # API8:2023 - Security Misconfiguration
                {
                    "identifier": "API8-001",
                    "name": "Misconfiguration - Debug/Trace Endpoints Enabled",
                    "description": "Test for enabled debug endpoints, trace.axd, /actuator, /swagger in production",
                    "category": "API8:2023 Security Misconfiguration",
                    "order": 24,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Response from debug endpoint",
                        "Sensitive information in response",
                    ],
                    "detection_rules": ["API8_DEBUG_ENDPOINT", "API8_SWAGGER_EXPOSED"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                    ],
                },
                {
                    "identifier": "API8-002",
                    "name": "Misconfiguration - Missing Security Headers",
                    "description": "Test for missing security headers (CSP, HSTS, X-Frame-Options, etc.)",
                    "category": "API8:2023 Security Misconfiguration",
                    "order": 25,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "HTTP response headers analysis",
                        "Missing security headers list",
                    ],
                    "detection_rules": ["API8_MISSING_SECURITY_HEADERS"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                    ],
                },
                {
                    "identifier": "API8-003",
                    "name": "Misconfiguration - CORS Misconfiguration",
                    "description": "Test for overly permissive CORS (Access-Control-Allow-Origin: *)",
                    "category": "API8:2023 Security Misconfiguration",
                    "order": 26,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "CORS preflight response",
                        "Overly permissive origin/header settings",
                    ],
                    "detection_rules": ["API8_CORS_MISCONFIGURATION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                    ],
                },
                {
                    "identifier": "API8-004",
                    "name": "Misconfiguration - Default Credentials/Configurations",
                    "description": "Test for default credentials, default configurations, sample apps",
                    "category": "API8:2023 Security Misconfiguration",
                    "order": 27,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Successful login with default credentials",
                        "Access to default/sample endpoints",
                    ],
                    "detection_rules": ["API8_DEFAULT_CREDENTIALS", "API8_SAMPLE_APP_EXPOSED"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                    ],
                },
                # API9:2023 - Improper Inventory Management
                {
                    "identifier": "API9-001",
                    "name": "Inventory - Unknown/Undocumented API Endpoints",
                    "description": "Discover undocumented API endpoints not in OpenAPI spec",
                    "category": "API9:2023 Improper Inventory Management",
                    "order": 28,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Discovered endpoint not in spec",
                        "Response from undocumented endpoint",
                    ],
                    "detection_rules": ["API9_UNDOCUMENTED_ENDPOINT"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                },
                {
                    "identifier": "API9-002",
                    "name": "Inventory - Deprecated API Versions Exposed",
                    "description": "Test for exposed deprecated API versions",
                    "category": "API9:2023 Improper Inventory Management",
                    "order": 29,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Access to deprecated API version",
                        "Version in response headers or URL",
                    ],
                    "detection_rules": ["API9_DEPRECATED_VERSION_EXPOSED"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                },
                {
                    "identifier": "API9-003",
                    "name": "Inventory - Missing API Decommissioning",
                    "description": "Test for APIs that should be decommissioned but are still accessible",
                    "category": "API9:2023 Improper Inventory Management",
                    "order": 30,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": False,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Access to deprecated endpoint",
                        "No deprecation notice in response",
                    ],
                    "detection_rules": ["API9_MISSING_DECOMMISSION"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                },
                {
                    "identifier": "API9-004",
                    "name": "Inventory - Shadow/Zombie APIs",
                    "description": "Discover shadow APIs (unknown to security team) and zombie APIs (decommissioned but running)",
                    "category": "API9:2023 Improper Inventory Management",
                    "order": 31,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": [],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Discovered API not in inventory",
                        "Response confirming API functionality",
                    ],
                    "detection_rules": ["API9_SHADOW_API", "API9_ZOMBIE_API"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                },
                # API10:2023 - Unsafe Consumption of APIs
                {
                    "identifier": "API10-001",
                    "name": "Third-Party API - Unvalidated Response Consumption",
                    "description": "Test if application blindly trusts third-party API responses",
                    "category": "API10:2023 Unsafe Consumption of APIs",
                    "order": 32,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Third-party API response with malicious payload",
                        "Application processing malicious response",
                    ],
                    "detection_rules": ["API10_UNVALIDATED_THIRD_PARTY_RESPONSE"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/",
                    ],
                },
                {
                    "identifier": "API10-002",
                    "name": "Third-Party API - SSRF via Third-Party Service",
                    "description": "Test if third-party service integration can be used for SSRF",
                    "category": "API10:2023 Unsafe Consumption of APIs",
                    "order": 33,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": False,
                    "active_mode": True,
                    "safe_mode_compatible": False,
                    "evidence_requirements": [
                        "Third-party service call to internal resource",
                        "Internal resource response in application",
                    ],
                    "detection_rules": ["API10_SSRF_VIA_THIRD_PARTY"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/",
                    ],
                },
                {
                    "identifier": "API10-003",
                    "name": "Third-Party API - Data Injection via Compromised Provider",
                    "description": "Test if application handles malicious data from compromised third-party API",
                    "category": "API10:2023 Unsafe Consumption of APIs",
                    "order": 34,
                    "supported_target_types": ["api", "web_application"],
                    "prerequisites": ["api_schema"],
                    "passive_mode": True,
                    "active_mode": True,
                    "safe_mode_compatible": True,
                    "evidence_requirements": [
                        "Malicious data from third-party API",
                        "Application processing/storing malicious data",
                    ],
                    "detection_rules": ["API10_DATA_INJECTION_THIRD_PARTY"],
                    "references": [
                        "https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/",
                    ],
                },
            ],
        }
    ],
}


def seed_owasp_api_security_methodology(session: Session) -> Methodology:
    """Seed the OWASP API Security Top 10 2023 methodology into the database."""
    # Check if methodology already exists
    methodology = session.query(Methodology).filter(
        Methodology.name == OWASP_API_SECURITY_2023["name"]
    ).first()

    if not methodology:
        methodology = Methodology(
            name=OWASP_API_SECURITY_2023["name"],
            description=OWASP_API_SECURITY_2023["description"],
        )
        session.add(methodology)
        session.flush()

    # Check if version 2023 exists
    version = session.query(MethodologyVersion).filter(
        MethodologyVersion.methodology_id == methodology.id,
        MethodologyVersion.version == 2023,
    ).first()

    if not version:
        version = MethodologyVersion(
            methodology_id=methodology.id,
            version=2023,
            name=OWASP_API_SECURITY_2023["versions"][0]["name"],
            description=OWASP_API_SECURITY_2023["versions"][0]["description"],
            is_active=OWASP_API_SECURITY_2023["versions"][0]["is_active"],
        )
        session.add(version)
        session.flush()

        # Create test cases
        for tc_data in OWASP_API_SECURITY_2023["versions"][0]["test_cases"]:
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
            session.add(test_case)

    session.commit()
    return methodology
