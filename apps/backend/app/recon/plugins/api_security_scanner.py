"""API Security Scanner Plugin - Performs OWASP API Security Top 10 assessments.

This plugin integrates with the recon engine to perform API security testing
based on the OWASP API Security Top 10 2023 methodology.
"""

from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.models.api_assets import ApiDefinition, ApiEndpoint
from app.models.enums import ObservationType
from app.recon.base import ReconContext, ReconPlugin, ReconPluginConfig, ReconResult


class APISecurityScannerConfig(ReconPluginConfig):
    """Configuration for API Security Scanner plugin."""

    name: str = "api_security_scanner"
    version: str = "1.0.0"
    description: str = "OWASP API Security Top 10 2023 scanner for API definitions"
    target_types: list[str] = ["api_definition", "api", "web_application"]
    requires_network: bool = True
    timeout_seconds: int = 600
    rate_limit_per_minute: int = 30
    configuration_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "testing_profile": {
                "type": "string",
                "enum": ["passive", "safe", "active"],
                "default": "passive",
                "description": "Testing profile: passive (read-only), safe (non-destructive), active (full testing)",
            },
            "auth_contexts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string"},
                        "credentials": {"type": "object"},
                    },
                    "required": ["role"],
                },
                "default": [],
                "description": "Authentication contexts to test with (anonymous, user, admin, service_account)",
            },
            "target_categories": {
                "type": "array",
                "items": {"type": "string"},
                "default": [
                    "API1", "API2", "API3", "API4", "API5",
                    "API6", "API7", "API8", "API9", "API10"
                ],
                "description": "OWASP API Security categories to test",
            },
            "max_requests_per_endpoint": {
                "type": "integer",
                "default": 50,
                "description": "Maximum requests per endpoint",
            },
            "follow_redirects": {
                "type": "boolean",
                "default": False,
                "description": "Follow HTTP redirects",
            },
            "verify_ssl": {
                "type": "boolean",
                "default": True,
                "description": "Verify SSL certificates",
            },
        },
        "required": ["testing_profile"],
    }


class APISecurityScannerPlugin(ReconPlugin):
    """API Security Scanner - Tests APIs against OWASP API Security Top 10."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._http_client: httpx.AsyncClient | None = None
        self._api_definition: ApiDefinition | None = None
        self._auth_tokens: dict[str, str] = {}
        self._config: APISecurityScannerConfig | None = None

    @property
    def config(self) -> ReconPluginConfig:
        if self._config is None:
            self._config = APISecurityScannerConfig()
        return self._config

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that this plugin can run against the given target."""
        if context.target_type not in self.config.target_types:
            return False, f"Target type {context.target_type} not supported"

        # Check if we have an API definition for this target
        if not self._session_factory:
            return False, "No session factory configured"

        session = self._session_factory()
        try:
            api_def = session.query(ApiDefinition).filter(
                ApiDefinition.asset_id == context.target_id
            ).first()
            if not api_def:
                return False, "No API definition found for target"
            self._api_definition = api_def
            return True, None
        finally:
            session.close()

    async def _get_http_client(self, context: ReconContext) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=context.configuration.get("follow_redirects", False),
                verify=context.configuration.get("verify_ssl", True),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        return self._http_client

    async def _authenticate(self, context: ReconContext, role: str) -> str | None:
        """Authenticate and return token for a role."""
        # Check cache
        if role in self._auth_tokens:
            return self._auth_tokens[role]

        # Get auth context from configuration
        auth_contexts = context.configuration.get("auth_contexts", [])
        auth_config = next((a for a in auth_contexts if a.get("role") == role), None)

        if not auth_config:
            return None  # Anonymous

        credentials = auth_config.get("credentials", {})

        # Try to authenticate based on available auth schemes
        if not self._api_definition or not self._api_definition.spec:
            return None

        auth_schemes = self._api_definition.spec.get("components", {}).get("securitySchemes", {})

        client = await self._get_http_client(context)

        # Try each auth scheme
        for scheme_name, scheme in auth_schemes.items():
            if scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
                # OAuth2/JWT - try token endpoint
                token = await self._get_oauth_token(client, credentials, scheme)
                if token:
                    self._auth_tokens[role] = token
                    return token

            elif scheme.get("type") == "apiKey":
                # API Key - use provided key
                key = credentials.get("api_key") or credentials.get("apiKey")
                if key:
                    self._auth_tokens[role] = key
                    return key

            elif scheme.get("type") == "oauth2":
                token = await self._get_oauth_token(client, credentials, scheme)
                if token:
                    self._auth_tokens[role] = token
                    return token

        return None

    async def _get_oauth_token(
        self, client: httpx.AsyncClient, credentials: dict, scheme: dict
    ) -> str | None:
        """Get OAuth2 token."""
        flows = scheme.get("flows", {})

        # Try client credentials flow first
        if "clientCredentials" in flows:
            flow = flows["clientCredentials"]
            token_url = flow.get("tokenUrl")
            if token_url:
                client_id = credentials.get("client_id")
                client_secret = credentials.get("client_secret")
                if client_id and client_secret:
                    try:
                        resp = await client.post(
                            token_url,
                            data={
                                "grant_type": "client_credentials",
                                "client_id": client_id,
                                "client_secret": client_secret,
                            },
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            return data.get("access_token")
                    except Exception:
                        pass

        # Try password flow
        if "password" in flows:
            flow = flows["password"]
            token_url = flow.get("tokenUrl")
            if token_url:
                username = credentials.get("username")
                password = credentials.get("password")
                client_id = credentials.get("client_id")
                client_secret = credentials.get("client_secret")
                if username and password:
                    try:
                        data = {
                            "grant_type": "password",
                            "username": username,
                            "password": password,
                        }
                        if client_id:
                            data["client_id"] = client_id
                        if client_secret:
                            data["client_secret"] = client_secret

                        resp = await client.post(
                            token_url,
                            data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                        )
                        if resp.status_code == 200:
                            return resp.json().get("access_token")
                    except Exception:
                        pass

        return None

    def _build_headers(self, role: str, endpoint: ApiEndpoint) -> dict[str, str]:
        """Build request headers for a role."""
        headers = {
            "User-Agent": "APISecurityScanner/1.0",
            "Accept": "application/json",
        }

        token = self._auth_tokens.get(role)
        if token:
            # Check auth scheme type
            if self._api_definition and self._api_definition.security_schemes:
                for scheme in self._api_definition.security_schemes.values():
                    if scheme.get("type") == "apiKey":
                        # API Key in header
                        param_name = scheme.get("name", "X-API-Key")
                        headers[param_name] = token
                    elif scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
                        headers["Authorization"] = f"Bearer {token}"

        return headers

    def _get_base_url(self) -> str:
        """Get base URL for API requests."""
        if self._api_definition and self._api_definition.base_url:
            return self._api_definition.base_url.rstrip("/")
        if self._api_definition and self._api_definition.spec:
            servers = self._api_definition.spec.get("servers", [])
            if servers:
                return servers[0].get("url", "").rstrip("/")
        return ""

    async def _test_endpoint(
        self,
        client: httpx.AsyncClient,
        endpoint: ApiEndpoint,
        role: str,
        test_config: dict[str, Any],
    ) -> list[ReconResult]:
        """Test a single endpoint with various security checks."""
        results = []
        base_url = self._get_base_url()
        if not base_url:
            return results

        url = urljoin(base_url + "/", endpoint.path.lstrip("/"))
        headers = self._build_headers(role, endpoint)

        max_requests = test_config.get("max_requests_per_endpoint", 50)
        request_count = 0

        # Get parameters for this endpoint
        params_list = []
        for param in endpoint.parameters:
            if param.location.value == "query":
                params_list.append(param)
            elif param.location.value == "header":
                headers[param.name] = param.schema_.get("example", "test") if param.schema_ else "test"
            elif param.location.value == "path":
                # Path parameters need to be substituted in URL
                pass

        # Test 1: Basic request
        if request_count < max_requests:
            try:
                resp = await client.request(
                    method=endpoint.method.value.upper(),
                    url=url,
                    headers=headers,
                    params={p.name: p.schema_.get("example", "test") for p in params_list if p.location.value == "query"} if params_list else None,
                )
                request_count += 1

                # Create observation from response
                result = self._create_observation(
                    endpoint=endpoint,
                    role=role,
                    request_data={
                        "method": endpoint.method.value,
                        "url": url,
                        "headers": dict(headers),
                        "params": {p.name: "test" for p in params_list if p.location.value == "query"},
                    },
                    response_data={
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "body": resp.text[:5000] if resp.text else "",
                        "time_ms": resp.elapsed.total_seconds() * 1000,
                    },
                    test_type="basic_request",
                )
                if result:
                    results.append(result)

            except Exception as e:
                # Network error - create observation
                result = self._create_observation(
                    endpoint=endpoint,
                    role=role,
                    request_data={"method": endpoint.method.value, "url": url},
                    response_data={"error": str(e), "status_code": 0},
                    test_type="network_error",
                )
                if result:
                    results.append(result)

        # Test 2: Rate limiting (if active profile)
        if test_config.get("testing_profile") in ["safe", "active"] and request_count < max_requests:
            results.extend(await self._test_rate_limiting(client, url, headers, endpoint, role, max_requests - request_count))
            request_count = min(max_requests, request_count + 10)

        # Test 3: BOLA (if active profile and authenticated)
        if test_config.get("testing_profile") == "active" and role != "anonymous" and request_count < max_requests:
            results.extend(await self._test_bola(client, url, headers, endpoint, role, max_requests - request_count))

        # Test 4: Authentication issues
        results.extend(await self._test_authentication(client, url, headers, endpoint, role))

        # Test 5: SSRF (if active profile)
        if test_config.get("testing_profile") == "active" and request_count < max_requests:
            results.extend(await self._test_ssrf(client, url, headers, endpoint, role, max_requests - request_count))

        # Test 6: Mass Assignment / Excessive Data Exposure
        if role != "anonymous" and request_count < max_requests:
            results.extend(await self._test_property_authz(client, url, headers, endpoint, role, max_requests - request_count))

        return results

    async def _test_rate_limiting(
        self, client: httpx.AsyncClient, url: str, headers: dict,
        endpoint: ApiEndpoint, role: str, max_requests: int
    ) -> list[ReconResult]:
        """Test for rate limiting."""
        results = []
        rate_limited = False

        # Send rapid requests
        for i in range(min(20, max_requests)):
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    rate_limited = True
                    break
            except Exception:
                pass

        if not rate_limited:
            results.append(ReconResult(
                asset_kind="observation",
                value=f"no_rate_limit:{endpoint.method.value}:{endpoint.path}",
                source="api_security_scanner",
                attributes={
                    "type": "configuration",
                    "category": "API4:2023",
                    "title": "Missing Rate Limiting",
                    "description": f"No rate limiting detected on {endpoint.method.value} {endpoint.path}",
                    "severity": "medium",
                    "confidence": "high",
                    "endpoint": endpoint.path,
                    "method": endpoint.method.value,
                    "requests_sent": 20,
                    "rate_limit_detected": False,
                },
                confidence="high",
                scope_status="in_scope",
            ))

        return results

    async def _test_bola(
        self, client: httpx.AsyncClient, url: str, headers: dict,
        endpoint: ApiEndpoint, role: str, max_requests: int
    ) -> list[ReconResult]:
        """Test for Broken Object Level Authorization."""
        results = []

        # Look for path parameters that could be object IDs
        import re
        path_params = re.findall(r"\{([^}]+)\}", endpoint.path)
        object_id_params = [p for p in path_params if any(
            kw in p.lower() for kw in ["id", "uuid", "key", "pk"]
        )]

        if not object_id_params:
            return results

        # We'd need another user's object ID to test properly
        # For now, note the potential
        for param in object_id_params:
            results.append(ReconResult(
                asset_kind="observation",
                value=f"bola_potential:{endpoint.method.value}:{endpoint.path}:{param}",
                source="api_security_scanner",
                attributes={
                    "type": "response_behavior",
                    "category": "API1:2023",
                    "title": "Potential BOLA - Object ID in Path",
                    "description": f"Endpoint {endpoint.path} has object identifier '{param}' in path. Manual testing required for BOLA verification.",
                    "severity": "medium",
                    "confidence": "low",
                    "endpoint": endpoint.path,
                    "method": endpoint.method.value,
                    "object_id_param": param,
                    "requires_manual_verification": True,
                },
                confidence="low",
                scope_status="in_scope",
            ))

        return results

    async def _test_authentication(
        self, client: httpx.AsyncClient, url: str, headers: dict,
        endpoint: ApiEndpoint, role: str
    ) -> list[ReconResult]:
        """Test for authentication issues."""
        results = []

        # Check for API key in URL
        parsed = urlparse(url)
        query_params = parsed.query
        if query_params:
            for param in query_params.split("&"):
                if "key" in param.lower() or "token" in param.lower() or "api" in param.lower():
                    results.append(ReconResult(
                        asset_kind="observation",
                        value=f"api_key_in_url:{endpoint.path}",
                        source="api_security_scanner",
                        attributes={
                            "type": "information_exposure",
                            "category": "API2:2023",
                            "title": "API Key in URL",
                            "description": f"API key or token found in URL query parameters: {param}",
                            "severity": "medium",
                            "confidence": "very_high",
                            "endpoint": endpoint.path,
                            "parameter": param.split("=")[0] if "=" in param else param,
                        },
                        confidence="very_high",
                        scope_status="in_scope",
                    ))

        # Check for weak auth schemes in spec
        if self._api_definition and self._api_definition.security_schemes:
            for name, scheme in self._api_definition.security_schemes.items():
                if scheme.get("type") == "http" and scheme.get("scheme") == "basic":
                    results.append(ReconResult(
                        asset_kind="observation",
                        value=f"basic_auth:{name}",
                        source="api_security_scanner",
                        attributes={
                            "type": "configuration",
                            "category": "API2:2023",
                            "title": "Basic Authentication Scheme",
                            "description": f"API uses Basic authentication scheme '{name}' which is considered weak",
                            "severity": "medium",
                            "confidence": "high",
                            "auth_scheme": name,
                        },
                        confidence="high",
                        scope_status="in_scope",
                    ))

        return results

    async def _test_ssrf(
        self, client: httpx.AsyncClient, url: str, headers: dict,
        endpoint: ApiEndpoint, role: str, max_requests: int
    ) -> list[ReconResult]:
        """Test for SSRF vulnerabilities."""
        results = []

        # Find URL parameters
        url_params = [p for p in endpoint.parameters
                     if p.location.value == "query" and
                     p.schema_ and p.schema_.get("format") in ("uri", "url", "uri-reference")]

        if not url_params:
            return results

        # Test with internal URLs (safe mode - just check if parameter exists)
        for param in url_params:
            results.append(ReconResult(
                asset_kind="observation",
                value=f"ssrf_potential:{endpoint.path}:{param.name}",
                source="api_security_scanner",
                attributes={
                    "type": "configuration",
                    "category": "API7:2023",
                    "title": "Potential SSRF - URL Parameter",
                    "description": f"Endpoint {endpoint.path} accepts URL parameter '{param.name}' which could be used for SSRF",
                    "severity": "high",
                    "confidence": "medium",
                    "endpoint": endpoint.path,
                    "parameter": param.name,
                    "parameter_format": param.schema_.get("format"),
                    "requires_active_testing": True,
                },
                confidence="medium",
                scope_status="in_scope",
            ))

        return results

    async def _test_property_authz(
        self, client: httpx.AsyncClient, url: str, headers: dict,
        endpoint: ApiEndpoint, role: str, max_requests: int
    ) -> list[ReconResult]:
        """Test for property-level authorization issues."""
        results = []

        # Check for sensitive fields in responses (passive)
        if self._api_definition:
            for schema in self._api_definition.schemas:
                if schema.sensitive_fields:
                    results.append(ReconResult(
                        asset_kind="observation",
                        value=f"sensitive_fields_in_schema:{schema.name}",
                        source="api_security_scanner",
                        attributes={
                            "type": "information_exposure",
                            "category": "API3:2023",
                            "title": "Sensitive Fields in Schema Definition",
                            "description": f"Schema '{schema.name}' defines sensitive fields: {', '.join(schema.sensitive_fields)}",
                            "severity": "medium",
                            "confidence": "high",
                            "schema": schema.name,
                            "sensitive_fields": schema.sensitive_fields,
                        },
                        confidence="high",
                        scope_status="in_scope",
                    ))

        return results

    def _create_observation(
        self,
        endpoint: ApiEndpoint,
        role: str,
        request_data: dict,
        response_data: dict,
        test_type: str,
    ) -> ReconResult | None:
        """Create an observation from request/response."""
        status_code = response_data.get("status_code", 0)

        # Determine observation type and severity
        if status_code == 0:
            obs_type = ObservationType.ANOMALY
            severity = "low"
        elif status_code >= 500:
            obs_type = ObservationType.ANOMALY
            severity = "medium"
        elif status_code == 401 or status_code == 403:
            obs_type = ObservationType.RESPONSE_BEHAVIOR
            severity = "info"
        elif status_code == 429:
            obs_type = ObservationType.RESPONSE_BEHAVIOR
            severity = "info"
        elif status_code == 200:
            obs_type = ObservationType.RESPONSE_BEHAVIOR
            severity = "info"
        else:
            obs_type = ObservationType.RESPONSE_BEHAVIOR
            severity = "low"

        # Check for security-relevant findings
        findings = []

        # Check for information exposure
        body = response_data.get("body", "")
        sensitive_patterns = [
            (r"password", "password"),
            (r"secret", "secret"),
            (r"token", "token"),
            (r"api[_-]?key", "api_key"),
            (r"private[_-]?key", "private_key"),
            (r"access[_-]?token", "access_token"),
            (r"refresh[_-]?token", "refresh_token"),
            (r"authorization", "authorization_header"),
        ]

        for pattern, label in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(f"potential_{label}_exposure")

        # Check for debug info
        if "trace" in body.lower() or "stacktrace" in body.lower() or "exception" in body.lower():
            findings.append("debug_info_exposure")

        # Check security headers
        resp_headers = response_data.get("headers", {})
        missing_headers = []
        for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
            if header not in resp_headers:
                missing_headers.append(header)

        if missing_headers:
            findings.append(f"missing_security_headers: {', '.join(missing_headers)}")

        # CORS check
        cors_origin = resp_headers.get("Access-Control-Allow-Origin")
        cors_creds = resp_headers.get("Access-Control-Allow-Credentials")
        if cors_origin == "*" and cors_creds == "true":
            findings.append("cors_misconfiguration")

        if not findings and test_type == "basic_request":
            return None  # No significant findings from basic request

        return ReconResult(
            asset_kind="observation",
            value=f"{test_type}:{endpoint.method.value}:{endpoint.path}:{role}",
            source="api_security_scanner",
            attributes={
                "type": obs_type.value,
                "category": "General",
                "title": f"API Response Analysis - {endpoint.method.value} {endpoint.path}",
                "description": f"Response analysis for {endpoint.method.value} {endpoint.path} as {role}",
                "severity": severity,
                "confidence": "medium",
                "endpoint": endpoint.path,
                "method": endpoint.method.value,
                "role": role,
                "status_code": status_code,
                "response_time_ms": response_data.get("time_ms", 0),
                "findings": findings,
                "request": request_data,
                "response_headers": response_data.get("headers", {}),
            },
            confidence="medium",
            scope_status="in_scope",
        )

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Execute the API security scanner."""
        # This is a synchronous wrapper for the async implementation
        import asyncio

        # Configure from context
        self._config = APISecurityScannerConfig(
            **context.configuration
        ) if context.configuration else APISecurityScannerConfig()

        async def async_run() -> list[ReconResult]:
            return await self._async_run(context)

        return asyncio.run(async_run())

    async def _async_run(self, context: ReconContext) -> list[ReconResult]:
        """Async implementation of the scanner."""
        if not self._api_definition:
            return []

        all_results = []
        client = await self._get_http_client(context)

        # Get endpoints to test
        endpoints = self._api_definition.endpoints

        # Authenticate for each role
        auth_contexts = context.configuration.get("auth_contexts", [])
        roles = [a.get("role", "anonymous") for a in auth_contexts] if auth_contexts else ["anonymous"]

        for role in roles:
            await self._authenticate(context, role)

            for endpoint in endpoints:
                results = await self._test_endpoint(
                    client, endpoint, role,
                    context.configuration
                )
                all_results.extend(results)

        # Run methodology-based test cases
        methodology_results = await self._run_methodology_tests(context)
        all_results.extend(methodology_results)

        return all_results

    async def _run_methodology_tests(self, context: ReconContext) -> list[ReconResult]:
        """Run methodology-based test cases."""
        results = []

        # This would integrate with the TestPlanner and CoverageEngine
        # For now, return empty - the individual test methods above cover the main checks
        return results

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def __del__(self):
        if self._http_client:
            import asyncio
            try:
                asyncio.run(self.close())
            except Exception:
                pass


def create_api_security_scanner(session_factory) -> APISecurityScannerPlugin:
    """Factory function to create API security scanner plugin."""
    plugin = APISecurityScannerPlugin(session_factory)
    return plugin
