"""Pydantic schemas for Scope and ScopeRule API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ScopeRuleTargetType


def _validate_pattern_for_type(pattern: str, target_type: str) -> str:
    """Validate a pattern based on its target type."""
    pattern = pattern.strip()

    # Check for potential ReDoS patterns
    if _has_redos_risk(pattern):
        raise ValueError("Pattern contains potentially dangerous regex constructs")

    if target_type == ScopeRuleTargetType.DOMAIN.value:
        # Domain: alphanumeric, hyphens, dots; no leading/trailing dot
        # RFC 1035 compliant - labels max 63 chars, total max 253
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', pattern):
            raise ValueError("Invalid domain pattern")
        if pattern.startswith(".") or pattern.endswith(".") or ".." in pattern:
            raise ValueError("Invalid domain format")
        # Check label length
        labels = pattern.split(".")
        for label in labels:
            if len(label) > 63:
                raise ValueError("Domain label exceeds 63 characters")
        if len(pattern) > 253:
            raise ValueError("Domain exceeds 253 characters")

    elif target_type == ScopeRuleTargetType.SUBDOMAIN_PATTERN.value:
        # Subdomain pattern: *.example.com or example.com
        import re
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if not re.match(r'^\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', suffix):
                raise ValueError("Invalid subdomain pattern suffix")
            # Check suffix label length
            labels = suffix.lstrip(".").split(".")
            for label in labels:
                if len(label) > 63:
                    raise ValueError("Subdomain label exceeds 63 characters")
            if len(suffix) > 254:
                raise ValueError("Subdomain pattern too long")
        elif not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', pattern):
            raise ValueError("Invalid subdomain pattern")
        # Check label length for exact domain
        labels = pattern.split(".")
        for label in labels:
            if len(label) > 63:
                raise ValueError("Subdomain label exceeds 63 characters")
        if len(pattern) > 253:
            raise ValueError("Subdomain pattern too long")

    elif target_type == ScopeRuleTargetType.IP.value:
        # IP address
        import ipaddress
        try:
            ipaddress.ip_address(pattern)
        except ValueError as e:
            raise ValueError("Invalid IP address") from e

    elif target_type == ScopeRuleTargetType.CIDR.value:
        # CIDR notation - accept host IPs (strict=False)
        import ipaddress
        try:
            ipaddress.ip_network(pattern, strict=False)
        except ValueError as e:
            raise ValueError("Invalid CIDR notation") from e

    elif target_type in (ScopeRuleTargetType.URL.value, ScopeRuleTargetType.API.value):
        # URL pattern: must be valid URL with optional * at end of path
        from urllib.parse import urlparse
        try:
            parsed = urlparse(pattern)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL (requires scheme and host)")
            if parsed.scheme not in ("http", "https"):
                raise ValueError("URL scheme must be http or https")
            # Path can end with * for wildcard
            if parsed.path.endswith("*"):
                path_without_star = parsed.path[:-1]
                if not path_without_star.startswith("/"):
                    raise ValueError("URL path must start with /")
            # Validate host
            host = parsed.netloc.split(":")[0]  # Remove port if present
            if not host:
                raise ValueError("URL must have a host")
        except ValueError:
            raise
        except Exception as e:
            raise ValueError("Invalid URL pattern") from e

    elif target_type == ScopeRuleTargetType.APK.value:
        # APK package: com.example.app or com.example.*
        import re
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if not prefix.endswith("."):
                raise ValueError("APK wildcard pattern must end with '.*'")
            prefix = prefix[:-1]  # Remove trailing dot
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$', prefix):
                raise ValueError("Invalid APK package prefix")
        elif not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$', pattern):
            raise ValueError("Invalid APK package name")

    return pattern


def _has_redos_risk(pattern: str) -> bool:
    """Check for patterns that could cause ReDoS in regex evaluation."""
    # Check for nested quantifiers, excessive alternation, etc.
    dangerous_patterns = [
        r'\(\?.*\)[\*\+\?]',  # Nested quantifiers
        r'\{[0-9]+,[0-9]+\}[\*\+\?]',  # Bounded repeat followed by quantifier
        r'\|.*\|.*\|',  # Excessive alternation
    ]
    import re
    for dp in dangerous_patterns:
        if re.search(dp, pattern):
            return True
    return False


class ScopeCreate(BaseModel):
    """Create scope request."""

    name: Annotated[str, Field(min_length=1, max_length=255)]
    description: Annotated[str | None, Field(max_length=5000)] = None


class ScopeUpdate(BaseModel):
    """Update scope request."""

    name: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    description: Annotated[str | None, Field(max_length=5000)] = None
    is_active: bool | None = None


class ScopeResponse(BaseModel):
    """Scope response."""

    id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScopeDetailResponse(ScopeResponse):
    """Scope response with rules."""

    rules: list["ScopeRuleResponse"] = []


class ScopeListResponse(BaseModel):
    """Paginated scope list."""

    items: list[ScopeResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ScopeRuleCreate(BaseModel):
    """Create scope rule request."""

    effect: Annotated[str, Field(pattern="^(include|exclude)$")]
    target_type: Annotated[
        str,
        Field(pattern="^(domain|subdomain_pattern|ip|cidr|url|api|apk|other)$"),
    ]
    pattern: Annotated[str, Field(min_length=1, max_length=2048)]
    note: Annotated[str | None, Field(max_length=1000)] = None

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str, info) -> str:
        target_type = info.data.get("target_type")
        if target_type:
            return _validate_pattern_for_type(v, target_type)
        return v


class ScopeRuleUpdate(BaseModel):
    """Update scope rule request."""

    effect: Annotated[str | None, Field(pattern="^(include|exclude)$")] = None
    target_type: Annotated[
        str | None,
        Field(pattern="^(domain|subdomain_pattern|ip|cidr|url|api|apk|other)$"),
    ] = None
    pattern: Annotated[str | None, Field(min_length=1, max_length=2048)] = None
    note: Annotated[str | None, Field(max_length=1000)] = None
    order: int | None = None

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str | None, info) -> str | None:
        if v is not None:
            target_type = info.data.get("target_type")
            if target_type:
                return _validate_pattern_for_type(v, target_type)
        return v


class ScopeRuleResponse(BaseModel):
    """Scope rule response."""

    id: UUID
    scope_id: UUID
    order: int
    effect: str
    target_type: str
    pattern: str
    note: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScopeRuleListResponse(BaseModel):
    """Paginated scope rule list."""

    items: list[ScopeRuleResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ScopeSnapshotResponse(BaseModel):
    """Scope snapshot response."""

    id: UUID
    scope_id: UUID
    version: int
    payload: dict
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Update forward references
ScopeDetailResponse.model_rebuild()
