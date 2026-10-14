"""OpenAPI/Swagger importer service for API definitions.

Parses OpenAPI 3.x and Swagger 2.0 specifications and creates
ApiDefinition, ApiEndpoint, ApiParameter, ApiSchema, ApiResponse,
ApiAuthScheme, ApiAuthzContext, and ApiRateLimitProfile models.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.api_assets import (
    ApiAuthScheme,
    ApiAuthzContext,
    ApiDefinition,
    ApiEndpoint,
    ApiParameter,
    ApiRateLimitProfile,
    ApiResponse,
    ApiSchema,
)
from app.models.enums import HttpMethod, ParameterLocation


class OpenAPIImporter:
    """Import OpenAPI 3.x and Swagger 2.0 specifications."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.definition: ApiDefinition | None = None
        self.spec: dict[str, Any] = {}
        self.schema_cache: dict[str, uuid.UUID] = {}
        self.endpoint_cache: dict[str, ApiEndpoint] = {}

    def import_spec(
        self,
        spec: dict[str, Any],
        asset_id: uuid.UUID,
        name: str | None = None,
    ) -> ApiDefinition:
        """Import an OpenAPI/Swagger spec and create all related models."""
        self.spec = spec

        # Detect spec format and version
        spec_format, spec_version = self._detect_format(spec)

        # Extract base info
        info = spec.get("info", {})
        title = name or info.get("title", "Unnamed API")
        version = info.get("version", "1.0.0")

        # Create ApiDefinition
        self.definition = ApiDefinition(
            asset_id=asset_id,
            name=title,
            base_url=self._extract_base_url(spec),
            spec_format=spec_format,
            spec_version=spec_version,
            spec=spec,
            description=info.get("description"),
            version=version,
            terms_of_service=info.get("termsOfService"),
            contact=info.get("contact"),
            license=info.get("license"),
            servers=spec.get("servers", []),
        )

        # Extract security schemes
        security_schemes = self._extract_security_schemes(spec)
        self.definition.security_schemes = security_schemes

        # Create auth scheme models
        self._create_auth_schemes(security_schemes)

        # Create schemas first (referenced by endpoints)
        components = spec.get("components", {})
        self._create_schemas(components.get("schemas", {}))

        # Create endpoints
        paths = spec.get("paths", {})
        self._create_endpoints(paths)

        # Create authz contexts (inferred from security requirements)
        self._create_authz_contexts(paths, security_schemes)

        # Create rate limit profiles (from spec extensions or defaults)
        self._create_rate_limit_profiles(spec)

        self.session.add(self.definition)
        self.session.flush()

        return self.definition

    def _detect_format(self, spec: dict[str, Any]) -> tuple[str, str]:
        """Detect if spec is OpenAPI 3.x or Swagger 2.0."""
        if "openapi" in spec:
            version = spec["openapi"]
            return "openapi", version
        if "swagger" in spec:
            version = spec["swagger"]
            return "swagger", version
        return "unknown", "unknown"

    def _extract_base_url(self, spec: dict[str, Any]) -> str | None:
        """Extract base URL from servers (OpenAPI 3) or host/basePath (Swagger 2)."""
        servers = spec.get("servers", [])
        if servers:
            url = servers[0].get("url")
            return str(url) if url else None
        # Swagger 2.0
        host = spec.get("host")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        if host:
            return f"{schemes[0]}://{host}{base_path}"
        return None

    def _extract_security_schemes(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Extract security schemes from components/securitySchemes (OpenAPI) or securityDefinitions (Swagger)."""
        components = spec.get("components", {})
        schemes = components.get("securitySchemes", spec.get("securityDefinitions", {}))
        return dict(schemes) if schemes else {}

    def _create_auth_schemes(self, security_schemes: dict[str, Any]) -> None:
        """Create ApiAuthScheme models from security schemes."""
        if not self.definition:
            return

        for name, scheme in security_schemes.items():
            auth_scheme = ApiAuthScheme(
                api_definition_id=self.definition.id,
                name=name,
                type=scheme.get("type", "unknown"),
                scheme=scheme.get("scheme"),
                bearer_format=scheme.get("bearerFormat"),
                in_location=scheme.get("in"),
                param_name=scheme.get("name"),
                flows=scheme.get("flows"),
                openid_connect_url=scheme.get("openIdConnectUrl"),
                description=scheme.get("description"),
                is_weak=self._is_weak_auth_scheme(scheme),
                detected_issues=self._detect_auth_issues(scheme),
            )
            self.session.add(auth_scheme)

    def _is_weak_auth_scheme(self, scheme: dict[str, Any]) -> bool:
        """Check if auth scheme has known weaknesses."""
        scheme_type = scheme.get("type")
        if scheme_type == "http":
            http_scheme = scheme.get("scheme", "").lower()
            if http_scheme == "basic":
                return True
        if scheme_type == "apiKey":
            # API key in query is less secure
            if scheme.get("in") == "query":
                return True
        return False

    def _detect_auth_issues(self, scheme: dict[str, Any]) -> list[str]:
        """Detect potential issues with auth scheme."""
        issues = []
        if self._is_weak_auth_scheme(scheme):
            issues.append("weak_authentication_scheme")
        if scheme.get("type") == "oauth2":
            flows = scheme.get("flows", {})
            if "implicit" in flows:
                issues.append("oauth2_implicit_flow_deprecated")
            if "password" in flows:
                issues.append("oauth2_password_flow_not_recommended")
        return issues

    def _create_schemas(self, schemas: dict[str, Any]) -> None:
        """Create ApiSchema models from OpenAPI components/schemas."""
        if not self.definition:
            return

        for name, schema in schemas.items():
            api_schema = ApiSchema(
                api_definition_id=self.definition.id,
                name=name,
                title=schema.get("title"),
                description=schema.get("description"),
                type=schema.get("type"),
                schema_=schema,
                object_identifier_fields=self._extract_object_identifiers(schema),
                sensitive_fields=self._extract_sensitive_fields(schema),
                requires_privilege=self._extract_privileges(schema),
            )
            self.session.add(api_schema)
            self.session.flush()
            self.schema_cache[name] = api_schema.id

    def _extract_object_identifiers(self, schema: dict[str, Any]) -> list[str]:
        """Extract potential object identifier fields from schema."""
        identifiers = []
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if self._is_likely_object_id(prop_name, prop_schema):
                identifiers.append(prop_name)
        return identifiers

    def _is_likely_object_id(self, name: str, schema: dict[str, Any]) -> bool:
        """Heuristic to detect object identifier fields."""
        name_lower = name.lower()
        id_patterns = ["id", "uuid", "guid", "key", "pk", "identifier"]
        if any(pattern in name_lower for pattern in id_patterns):
            return True
        # Check format
        if schema.get("format") in ("uuid", "uuid4", "objectid"):
            return True
        return False

    def _extract_sensitive_fields(self, schema: dict[str, Any]) -> list[str]:
        """Extract potentially sensitive fields from schema."""
        sensitive = []
        properties = schema.get("properties", {})
        sensitive_keywords = [
            "password", "secret", "token", "key", "ssn", "credit", "card",
            "cvv", "cvc", "pin", "auth", "credential", "private", "ssn",
            "social", "tax", "bank", "account", "routing", "iban", "swift",
        ]
        for prop_name, prop_schema in properties.items():
            name_lower = prop_name.lower()
            if any(keyword in name_lower for keyword in sensitive_keywords):
                sensitive.append(prop_name)
        return sensitive

    def _extract_privileges(self, schema: dict[str, Any]) -> list[str]:
        """Extract required privileges from schema metadata."""
        privileges = []
        # Check x-privileges extension
        x_privileges = schema.get("x-privileges")
        if x_privileges and isinstance(x_privileges, list):
            privileges.extend(x_privileges)
        return privileges

    def _create_endpoints(self, paths: dict[str, Any]) -> None:
        """Create ApiEndpoint models from paths."""
        if not self.definition:
            return

        for path, path_item in paths.items():
            # HTTP methods
            for method_str in [
                "get", "post", "put", "patch", "delete", "head", "options", "trace"
            ]:
                if method_str not in path_item:
                    continue

                operation = path_item[method_str]
                method = HttpMethod(method_str.upper())

                endpoint = ApiEndpoint(
                    api_definition_id=self.definition.id,
                    method=method,
                    path=path,
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    operation_id=operation.get("operationId"),
                    deprecated=operation.get("deprecated", False),
                    security_requirements=operation.get("security", []),
                    is_sensitive_business_flow=self._is_sensitive_business_flow(operation),
                    ssrf_risk=self._has_ssrf_risk(operation),
                )
                self.session.add(endpoint)
                self.session.flush()

                # Cache endpoint for reference
                cache_key = f"{method.value}:{path}"
                self.endpoint_cache[cache_key] = endpoint

                # Create parameters
                self._create_parameters(endpoint, operation, path_item)

                # Create responses
                self._create_responses(endpoint, operation.get("responses", {}))

    def _create_parameters(
        self,
        endpoint: ApiEndpoint,
        operation: dict[str, Any],
        path_item: dict[str, Any],
    ) -> None:
        """Create ApiParameter models from operation parameters."""
        # Path-level parameters
        path_params = path_item.get("parameters", [])
        # Operation-level parameters (override path-level)
        op_params = operation.get("parameters", [])

        # Merge parameters (operation overrides path)
        param_map = {f"{p.get('in')}:{p.get('name')}": p for p in path_params}
        for p in op_params:
            param_map[f"{p.get('in')}:{p.get('name')}"] = p

        for param in param_map.values():
            location_str = param.get("in", "query")
            location = self._map_parameter_location(location_str)

            # Resolve schema reference
            schema = param.get("schema", {})
            schema_ref_id = None
            if "$ref" in schema:
                ref_name = schema["$ref"].split("/")[-1]
                schema_ref_id = self.schema_cache.get(ref_name)

            api_param = ApiParameter(
                api_endpoint_id=endpoint.id,
                name=param.get("name", ""),
                location=location,
                required=param.get("required", False),
                deprecated=param.get("deprecated", False),
                data_type=schema.get("type"),
                schema_=schema if "$ref" not in schema else None,
                schema_ref_id=schema_ref_id,
                is_object_identifier=self._is_likely_object_id(
                    param.get("name", ""), schema
                ),
                is_sensitive_property=self._is_sensitive_field(param.get("name", ""), schema),
                rate_limit_key=self._is_rate_limit_key(param.get("name", "")),
            )
            self.session.add(api_param)

        # Handle request body
        request_body = operation.get("requestBody")
        if request_body:
            content = request_body.get("content", {})
            for media_type, media_schema in content.items():
                schema = media_schema.get("schema", {})
                schema_ref_id = None
                if "$ref" in schema:
                    ref_name = schema["$ref"].split("/")[-1]
                    schema_ref_id = self.schema_cache.get(ref_name)

                # For body parameters, create a synthetic parameter
                api_param = ApiParameter(
                    api_endpoint_id=endpoint.id,
                    name=f"body:{media_type}",
                    location=ParameterLocation.BODY,
                    required=request_body.get("required", False),
                    schema_=schema if "$ref" not in schema else None,
                    schema_ref_id=schema_ref_id,
                )
                self.session.add(api_param)

    def _map_parameter_location(self, location_str: str) -> ParameterLocation:
        """Map OpenAPI parameter location to enum."""
        mapping = {
            "query": ParameterLocation.QUERY,
            "path": ParameterLocation.PATH,
            "header": ParameterLocation.HEADER,
            "cookie": ParameterLocation.COOKIE,
        }
        return mapping.get(location_str, ParameterLocation.QUERY)

    def _is_sensitive_field(self, name: str, schema: dict[str, Any]) -> bool:
        """Check if field is sensitive."""
        return len(self._extract_sensitive_fields({"properties": {name: schema}})) > 0

    def _is_rate_limit_key(self, name: str) -> bool:
        """Check if parameter is likely used for rate limiting."""
        rate_limit_keywords = ["page", "limit", "offset", "count", "size", "per_page"]
        return any(kw in name.lower() for kw in rate_limit_keywords)

    def _create_responses(
        self, endpoint: ApiEndpoint, responses: dict[str, Any]
    ) -> None:
        """Create ApiResponse models from operation responses."""
        for status_code, response in responses.items():
            content = response.get("content", {})
            headers = response.get("headers", {})

            # Check for sensitive data exposure
            exposes_sensitive = False
            sensitive_fields = []
            for media_type, media_schema in content.items():
                schema = media_schema.get("schema", {})
                sf = self._extract_sensitive_fields(schema)
                if sf:
                    exposes_sensitive = True
                    sensitive_fields.extend(sf)

            api_response = ApiResponse(
                api_endpoint_id=endpoint.id,
                status_code=status_code,
                description=response.get("description"),
                headers=headers,
                content=content,
                exposes_sensitive_data=exposes_sensitive,
                sensitive_fields=sensitive_fields,
                information_exposure_risk=exposes_sensitive,
            )
            self.session.add(api_response)

    def _is_sensitive_business_flow(self, operation: dict[str, Any]) -> bool:
        """Check if operation is a sensitive business flow (API6:2023)."""
        # Check x-sensitive-business-flow extension
        if operation.get("x-sensitive-business-flow"):
            return True
        # Heuristic: operations with financial, admin, user-management keywords
        summary = (operation.get("summary") or "").lower()
        description = (operation.get("description") or "").lower()
        sensitive_keywords = [
            "payment", "purchase", "billing", "subscription", "refund",
            "admin", "delete user", "reset password", "change email",
            "transfer", "withdraw", "deposit", "order", "checkout",
        ]
        text = f"{summary} {description}"
        return any(kw in text for kw in sensitive_keywords)

    def _has_ssrf_risk(self, operation: dict[str, Any]) -> bool:
        """Check if operation has SSRF risk (API7:2023)."""
        # Check parameters for URL-like inputs
        params = operation.get("parameters", [])
        for param in params:
            schema = param.get("schema", {})
            if schema.get("format") in ("uri", "url", "uri-reference"):
                return True
            if param.get("name", "").lower() in ("url", "uri", "callback", "redirect", "webhook", "target"):
                return True
        # Check request body
        request_body = operation.get("requestBody", {})
        content = request_body.get("content", {})
        for media_type, media_schema in content.items():
            schema = media_schema.get("schema", {})
            if self._schema_has_url_format(schema):
                return True
        return False

    def _schema_has_url_format(self, schema: dict[str, Any]) -> bool:
        """Recursively check if schema has URL format."""
        if schema.get("format") in ("uri", "url", "uri-reference"):
            return True
        # Check properties
        for prop_schema in schema.get("properties", {}).values():
            if self._schema_has_url_format(prop_schema):
                return True
        # Check items (for arrays)
        if "items" in schema and self._schema_has_url_format(schema["items"]):
            return True
        return False

    def _create_authz_contexts(
        self, paths: dict[str, Any], security_schemes: dict[str, Any]
    ) -> None:
        """Create inferred authorization contexts from security requirements."""
        if not self.definition:
            return

        # Define default roles for API security testing
        default_roles = [
            "anonymous",
            "user",
            "privileged_user",
            "administrator",
            "service_account",
        ]

        # For each role, create a basic authz context
        for role in default_roles:
            authz = ApiAuthzContext(
                api_definition_id=self.definition.id,
                role=role,
                privilege="read",
                source="inferred",
                confidence="low",
            )
            self.session.add(authz)

            # Add write privilege for non-anonymous roles
            if role != "anonymous":
                authz_write = ApiAuthzContext(
                    api_definition_id=self.definition.id,
                    role=role,
                    privilege="write",
                    source="inferred",
                    confidence="low",
                )
                self.session.add(authz_write)

    def _create_rate_limit_profiles(self, spec: dict[str, Any]) -> None:
        """Create rate limit profiles from spec extensions or defaults."""
        if not self.definition:
            return

        # Check for x-rate-limit extension
        x_rate_limit = spec.get("x-rate-limit")
        if x_rate_limit:
            profile = ApiRateLimitProfile(
                api_definition_id=self.definition.id,
                name="global",
                algorithm=x_rate_limit.get("algorithm", "token_bucket"),
                requests_per_window=x_rate_limit.get("requests", 100),
                window_seconds=x_rate_limit.get("window", 60),
                burst_allowance=x_rate_limit.get("burst"),
                key_strategy=x_rate_limit.get("key", "ip"),
                is_configured=True,
            )
            self.session.add(profile)
        else:
            # Create default profile (detected during testing)
            profile = ApiRateLimitProfile(
                api_definition_id=self.definition.id,
                name="default",
                is_configured=False,
                is_detected=False,
            )
            self.session.add(profile)


def import_openapi_spec(
    session: Session,
    spec: dict[str, Any],
    asset_id: uuid.UUID,
    name: str | None = None,
) -> ApiDefinition:
    """Convenience function to import an OpenAPI spec."""
    importer = OpenAPIImporter(session)
    return importer.import_spec(spec, asset_id, name)
