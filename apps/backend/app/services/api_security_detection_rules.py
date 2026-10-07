"""Detection rules for OWASP API Security Top 10 2023 vulnerabilities.

These rules define patterns and logic to detect API security issues
from observations and test case executions.
"""


from sqlalchemy.orm import Session

from app.models.detection import DetectionRule
from app.models.enums import Confidence, Severity

# Detection rules for OWASP API Security Top 10 2023
API_SECURITY_DETECTION_RULES = [
    # API1:2023 - Broken Object Level Authorization
    {
        "name": "API1_BOLA_PATH_PARAM",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.path_params IS DEFINED AND
            observation.data.response.status_code == 200 AND
            observation.data.request.user_id != observation.data.response.object_owner_id
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects when a user accesses an object via path parameter that they don't own",
        "metadata": {"category": "API1:2023", "test_case": "API1-001"},
    },
    {
        "name": "API1_BOLA_QUERY_PARAM",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.query_params IS DEFINED AND
            observation.data.response.status_code == 200 AND
            observation.data.request.user_id != observation.data.response.object_owner_id
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects when a user accesses an object via query parameter that they don't own",
        "metadata": {"category": "API1:2023", "test_case": "API1-002"},
    },
    {
        "name": "API1_IDOR_ENUMERATION",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.sequential_requests > 10 AND
            observation.data.different_owners IN observation.data.responses AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "HIGH",
        "description": "Detects sequential object ID enumeration across different owners",
        "metadata": {"category": "API1:2023", "test_case": "API1-003"},
    },
    {
        "name": "API1_OBJECT_ID_ENUMERATION",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.enumeration_pattern == "sequential_numeric" AND
            observation.data.successful_responses > 5
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "MEDIUM",
        "description": "Detects predictable object ID enumeration patterns",
        "metadata": {"category": "API1:2023"},
    },

    # API2:2023 - Broken Authentication
    {
        "name": "API2_WEAK_PASSWORD_POLICY",
        "expression": """
            observation.type == "configuration" AND
            observation.data.password_min_length < 8 OR
            observation.data.password_requires_uppercase == false OR
            observation.data.password_requires_lowercase == false OR
            observation.data.password_requires_number == false OR
            observation.data.password_requires_special == false
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects weak password policy configuration",
        "metadata": {"category": "API2:2023", "test_case": "API2-001"},
    },
    {
        "name": "API2_CREDENTIAL_STUFFING",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.failed_login_attempts > 10 AND
            observation.data.time_window_seconds < 300 AND
            observation.data.rate_limited == false
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "HIGH",
        "description": "Detects credential stuffing attack patterns due to missing rate limiting",
        "metadata": {"category": "API2:2023", "test_case": "API2-003"},
    },
    {
        "name": "API2_JWT_ALG_NONE",
        "expression": """
            observation.type == "configuration" AND
            observation.data.jwt_algorithm == "none"
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "VERY_HIGH",
        "description": "Detects JWT tokens using 'none' algorithm",
        "metadata": {"category": "API2:2023", "test_case": "API2-002"},
    },
    {
        "name": "API2_JWT_WEAK_SECRET",
        "expression": """
            observation.type == "configuration" AND
            observation.data.jwt_secret_entropy < 128
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects JWT signed with weak secret",
        "metadata": {"category": "API2:2023", "test_case": "API2-002"},
    },
    {
        "name": "API2_JWT_MISSING_VALIDATION",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.jwt_modified == true AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "HIGH",
        "description": "Detects JWT accepted without proper signature validation",
        "metadata": {"category": "API2:2023", "test_case": "API2-002"},
    },
    {
        "name": "API2_AUTH_RATE_LIMIT_MISSING",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.endpoint IN ["/login", "/register", "/password/reset", "/auth/token"] AND
            observation.data.requests_per_minute > 30 AND
            observation.data.rate_limit_response == false
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "HIGH",
        "description": "Detects missing rate limiting on authentication endpoints",
        "metadata": {"category": "API2:2023", "test_case": "API2-003"},
    },
    {
        "name": "API2_API_KEY_IN_URL",
        "expression": """
            observation.type == "information_exposure" AND
            observation.data.api_key_in_query == true
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "VERY_HIGH",
        "description": "Detects API keys exposed in URL query parameters",
        "metadata": {"category": "API2:2023", "test_case": "API2-004"},
    },

    # API3:2023 - Broken Object Property Level Authorization
    {
        "name": "API3_MASS_ASSIGNMENT_WRITE",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.method IN ["PUT", "PATCH", "POST"] AND
            observation.data.request.extra_properties IS DEFINED AND
            observation.data.response.status_code == 200 AND
            observation.data.response.modified_sensitive_field == true
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "HIGH",
        "description": "Detects mass assignment vulnerability allowing write to sensitive properties",
        "metadata": {"category": "API3:2023", "test_case": "API3-001"},
    },
    {
        "name": "API3_EXCESSIVE_DATA_EXPOSURE",
        "expression": """
            observation.type == "information_exposure" AND
            observation.data.response.status_code == 200 AND
            observation.data.response.contains_sensitive_field == true AND
            observation.data.response.field_not_in_schema == true
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects excessive data exposure in API responses",
        "metadata": {"category": "API3:2023", "test_case": "API3-002"},
    },
    {
        "name": "API3_PROPERTY_INJECTION",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.method IN ["PUT", "PATCH", "POST"] AND
            observation.data.request.injected_internal_field == true AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects property injection via hidden/internal fields",
        "metadata": {"category": "API3:2023", "test_case": "API3-003"},
    },

    # API4:2023 - Unrestricted Resource Consumption
    {
        "name": "API4_NO_RATE_LIMIT",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.requests_per_minute > 100 AND
            observation.data.rate_limit_header_missing == true AND
            observation.data.response.status_code != 429
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects missing rate limiting on API endpoints",
        "metadata": {"category": "API4:2023", "test_case": "API4-001"},
    },
    {
        "name": "API4_RATE_LIMIT_BYPASS",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.rate_limit_bypass_detected == true
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects rate limit bypass techniques",
        "metadata": {"category": "API4:2023", "test_case": "API4-001"},
    },
    {
        "name": "API4_UNBOUNDED_PAGINATION",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.query_params.limit > 1000 AND
            observation.data.response.status_code == 200 AND
            observation.data.response.item_count > 1000
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects unbounded pagination allowing excessive data retrieval",
        "metadata": {"category": "API4:2023", "test_case": "API4-002"},
    },
    {
        "name": "API4_LARGE_PAYLOAD_DOS",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.request.payload_size_mb > 10 AND
            observation.data.response.time_ms > 5000
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "MEDIUM",
        "description": "Detects potential DoS via large request payloads",
        "metadata": {"category": "API4:2023", "test_case": "API4-003"},
    },
    {
        "name": "API4_INTENSIVE_OPERATION",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.response.time_ms > 30000 AND
            observation.data.endpoint_complexity == "high"
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "LOW",
        "description": "Detects endpoints allowing resource-intensive operations",
        "metadata": {"category": "API4:2023", "test_case": "API4-004"},
    },

    # API5:2023 - Broken Function Level Authorization
    {
        "name": "API5_BFLA_ADMIN_ENDPOINT",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.endpoint_path MATCHES "/admin|/management|/internal|/actuator" AND
            observation.data.request.user_role != "admin" AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "HIGH",
        "description": "Detects unauthorized access to administrative endpoints",
        "metadata": {"category": "API5:2023", "test_case": "API5-001"},
    },
    {
        "name": "API5_METHOD_OVERRIDE_BYPASS",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.headers["X-HTTP-Method-Override"] IS DEFINED AND
            observation.data.request.original_method != observation.data.request.overridden_method AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "HIGH",
        "description": "Detects HTTP method override bypassing authorization",
        "metadata": {"category": "API5:2023", "test_case": "API5-002"},
    },
    {
        "name": "API5_MISSING_AUTHZ_CHECK",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.endpoint.requires_privilege IS DEFINED AND
            observation.data.request.user_privileges DOES_NOT_CONTAIN observation.data.endpoint.required_privilege AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects missing authorization checks on sensitive functions",
        "metadata": {"category": "API5:2023", "test_case": "API5-003"},
    },

    # API6:2023 - Unrestricted Access to Sensitive Business Flows
    {
        "name": "API6_BUSINESS_FLOW_BYPASS",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.endpoint.is_sensitive_business_flow == true AND
            observation.data.request.bypassed_step IS DEFINED AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects bypass of sensitive business flow steps",
        "metadata": {"category": "API6:2023", "test_case": "API6-001"},
    },
    {
        "name": "API6_BUSINESS_LOGIC_BYPASS",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.invalid_business_value == true AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects missing business logic validation",
        "metadata": {"category": "API6:2023", "test_case": "API6-002"},
    },
    {
        "name": "API6_RACE_CONDITION",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.concurrent_requests > 1 AND
            observation.data.inconsistent_state == true
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "LOW",
        "description": "Detects race conditions in critical operations",
        "metadata": {"category": "API6:2023", "test_case": "API6-003"},
    },

    # API7:2023 - Server Side Request Forgery
    {
        "name": "API7_SSRF_URL_PARAMETER",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.url_parameter IS DEFINED AND
            observation.data.response.status_code == 200 AND
            observation.data.response.contains_internal_data == true
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "HIGH",
        "description": "Detects SSRF via user-supplied URL parameters",
                "metadata": {"category": "API7:2023", "test_case": "API7-001"},
            },
            {
                "name": "API7_SSRF_INTERNAL_ACCESS",
                "expression": r"""
                    observation.type == "response_behavior" AND
                    observation.data.request.target_url MATCHES "127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\." AND
                    observation.data.response.status_code == 200
                """,
                "severity_hint": "CRITICAL",
                "confidence_hint": "HIGH",
                "description": "Detects SSRF accessing internal/private IP ranges",
                "metadata": {"category": "API7:2023", "test_case": "API7-001"},
            },
            {
                "name": "API7_SSRF_FILE_SCHEMA",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.target_url STARTS_WITH "file://" AND
            observation.data.response.contains_file_content == true
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "HIGH",
        "description": "Detects SSRF via file:// schema",
        "metadata": {"category": "API7:2023", "test_case": "API7-002"},
    },
    {
        "name": "API7_SSRF_CLOUD_METADATA",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.request.target_url MATCHES "169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.azure\\.com|169\\.254\\.169\\.254" AND
            observation.data.response.contains_metadata == true
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "VERY_HIGH",
        "description": "Detects SSRF targeting cloud metadata services",
        "metadata": {"category": "API7:2023", "test_case": "API7-003"},
    },

    # API8:2023 - Security Misconfiguration
    {
        "name": "API8_DEBUG_ENDPOINT",
        "expression": """
            observation.type == "configuration" AND
            observation.data.endpoint_path MATCHES "/debug|/trace|/actuator|/health|/metrics" AND
            observation.data.response.status_code == 200 AND
            observation.data.response.exposes_sensitive_info == true
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects exposed debug/actuator endpoints",
        "metadata": {"category": "API8:2023", "test_case": "API8-001"},
    },
    {
        "name": "API8_SWAGGER_EXPOSED",
        "expression": """
            observation.type == "information_exposure" AND
            observation.data.endpoint_path MATCHES "/swagger|/openapi|/api-docs" AND
            observation.data.response.status_code == 200 AND
            observation.data.environment == "production"
        """,
        "severity_hint": "LOW",
        "confidence_hint": "HIGH",
        "description": "Detects exposed Swagger/OpenAPI documentation in production",
        "metadata": {"category": "API8:2023", "test_case": "API8-001"},
    },
    {
        "name": "API8_MISSING_SECURITY_HEADERS",
        "expression": """
            observation.type == "configuration" AND
            (
                observation.data.response.headers["Content-Security-Policy"] IS UNDEFINED OR
                observation.data.response.headers["Strict-Transport-Security"] IS UNDEFINED OR
                observation.data.response.headers["X-Frame-Options"] IS UNDEFINED OR
                observation.data.response.headers["X-Content-Type-Options"] IS UNDEFINED
            )
        """,
        "severity_hint": "LOW",
        "confidence_hint": "HIGH",
        "description": "Detects missing security headers",
        "metadata": {"category": "API8:2023", "test_case": "API8-002"},
    },
    {
        "name": "API8_CORS_MISCONFIGURATION",
        "expression": """
            observation.type == "configuration" AND
            observation.data.response.headers["Access-Control-Allow-Origin"] == "*" AND
            observation.data.response.headers["Access-Control-Allow-Credentials"] == "true"
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects overly permissive CORS with credentials",
        "metadata": {"category": "API8:2023", "test_case": "API8-003"},
    },
    {
        "name": "API8_DEFAULT_CREDENTIALS",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.endpoint_path MATCHES "/login|/auth" AND
            observation.data.request.credentials IN DEFAULT_CREDENTIALS_LIST AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "VERY_HIGH",
        "description": "Detects default credentials working",
        "metadata": {"category": "API8:2023", "test_case": "API8-004"},
    },
    {
        "name": "API8_SAMPLE_APP_EXPOSED",
        "expression": """
            observation.type == "configuration" AND
            observation.data.endpoint_path MATCHES "/sample|/demo|/test|/example" AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "LOW",
        "confidence_hint": "MEDIUM",
        "description": "Detects exposed sample/demo applications",
        "metadata": {"category": "API8:2023", "test_case": "API8-004"},
    },

    # API9:2023 - Improper Inventory Management
    {
        "name": "API9_UNDOCUMENTED_ENDPOINT",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.discovered_endpoint NOT_IN_API_SPEC AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects undocumented API endpoints",
        "metadata": {"category": "API9:2023", "test_case": "API9-001"},
    },
    {
        "name": "API9_DEPRECATED_VERSION_EXPOSED",
        "expression": """
            observation.type == "configuration" AND
            observation.data.api_version IS DEFINED AND
            observation.data.api_version.deprecated == true AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "LOW",
        "confidence_hint": "HIGH",
        "description": "Detects exposed deprecated API versions",
        "metadata": {"category": "API9:2023", "test_case": "API9-002"},
    },
    {
        "name": "API9_MISSING_DECOMMISSION",
        "expression": """
            observation.type == "configuration" AND
            observation.data.endpoint.deprecated == true AND
            observation.data.endpoint.sunset_date < NOW AND
            observation.data.response.status_code == 200 AND
            observation.data.response.deprecation_notice == false
        """,
        "severity_hint": "LOW",
        "confidence_hint": "MEDIUM",
        "description": "Detects missing API decommissioning",
        "metadata": {"category": "API9:2023", "test_case": "API9-003"},
    },
    {
        "name": "API9_SHADOW_API",
        "expression": """
            observation.type == "anomaly" AND
            observation.data.discovered_api NOT_IN_INVENTORY AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "MEDIUM",
        "description": "Detects shadow APIs unknown to inventory",
        "metadata": {"category": "API9:2023", "test_case": "API9-004"},
    },
    {
        "name": "API9_ZOMBIE_API",
        "expression": """
            observation.type == "configuration" AND
            observation.data.api.decommissioned == true AND
            observation.data.response.status_code == 200
        """,
        "severity_hint": "MEDIUM",
        "confidence_hint": "HIGH",
        "description": "Detects zombie APIs (decommissioned but still running)",
        "metadata": {"category": "API9:2023", "test_case": "API9-004"},
    },

    # API10:2023 - Unsafe Consumption of APIs
    {
        "name": "API10_UNVALIDATED_THIRD_PARTY_RESPONSE",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.third_party_response IS DEFINED AND
            observation.data.application_processes_without_validation == true
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects unvalidated consumption of third-party API responses",
        "metadata": {"category": "API10:2023", "test_case": "API10-001"},
    },
    {
        "name": "API10_SSRF_VIA_THIRD_PARTY",
        "expression": """
            observation.type == "response_behavior" AND
            observation.data.third_party_request.target INTERNAL_IP AND
            observation.data.application_processes_response == true
        """,
        "severity_hint": "CRITICAL",
        "confidence_hint": "HIGH",
        "description": "Detects SSRF via third-party service integration",
        "metadata": {"category": "API10:2023", "test_case": "API10-002"},
    },
    {
        "name": "API10_DATA_INJECTION_THIRD_PARTY",
        "expression": """
            observation.type == "information_exposure" AND
            observation.data.third_party_response.contains_malicious_payload == true AND
            observation.data.application_stores_or_processes == true
        """,
        "severity_hint": "HIGH",
        "confidence_hint": "MEDIUM",
        "description": "Detects data injection via compromised third-party API",
        "metadata": {"category": "API10:2023", "test_case": "API10-003"},
    },
]


def seed_api_security_detection_rules(session: Session) -> list[DetectionRule]:
    """Seed API security detection rules into the database."""
    created_rules = []

    for rule_data in API_SECURITY_DETECTION_RULES:
        # Check if rule already exists
        existing = session.query(DetectionRule).filter(
            DetectionRule.name == rule_data["name"]
        ).first()

        if not existing:
            rule = DetectionRule(
                name=str(rule_data["name"]),
                expression=str(rule_data["expression"]).strip(),
                severity_hint=Severity[str(rule_data["severity_hint"])],
                confidence_hint=Confidence[str(rule_data["confidence_hint"])],
                is_enabled=True,
                metadata_=rule_data.get("metadata", {}) if isinstance(rule_data.get("metadata"), dict) else {},
            )
            session.add(rule)
            created_rules.append(rule)
        else:
            created_rules.append(existing)

    session.commit()
    return created_rules
