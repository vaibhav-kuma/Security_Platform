"""Audit logging utilities."""

import ipaddress
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.audit import AuditLog
from app.models.enums import SecurityEventType


def _get_trusted_source_ip(source_ip: str | None, request = None) -> str | None:
    """Validate source IP against trusted proxies.

    If request is provided and comes from a trusted proxy, extract
    the real client IP from X-Forwarded-For header.
    """
    if not source_ip:
        return None

    # If request object is provided, validate X-Forwarded-For against trusted proxies
    if request is not None:
        settings = get_settings()
        trusted_proxies = getattr(settings, "trusted_proxies", [])

        client_host = getattr(request, "client", None)
        if client_host and trusted_proxies and client_host.host in trusted_proxies:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                # Take the first IP in the chain (original client)
                source_ip = forwarded.split(",")[0].strip()

    # Validate IP format
    if source_ip:
        try:
            ipaddress.ip_address(source_ip)
            return source_ip
        except ValueError:
            return None
    return None


def write_audit_log(
    session: Session,
    event_type: SecurityEventType,
    user_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict[str, Any] | None = None,
    source_ip: str | None = None,
    project_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    request = None,
) -> AuditLog:
    """Write an audit log entry.

    Args:
        session: Database session
        event_type: Type of security event
        user_id: ID of the user who performed the action
        entity_type: Type of entity affected (e.g., "target", "scope", "project")
        entity_id: ID of the entity affected
        details: Additional details about the event
        source_ip: Source IP address of the request
        project_id: Optional project ID for context
        organization_id: Optional organization ID for context
        request: Optional FastAPI Request object for trusted proxy validation

    Returns:
        The created AuditLog entry
    """
    # Only include valid IP addresses, validate against trusted proxies
    valid_source_ip = _get_trusted_source_ip(source_ip, request)

    audit = AuditLog(
        actor_id=user_id,
        organization_id=organization_id,
        project_id=project_id,
        action=event_type.value,
        entity_type=entity_type,
        entity_id=uuid.UUID(entity_id) if entity_id else None,
        details=details or {},
        source_ip=valid_source_ip,
    )
    session.add(audit)
    session.flush()
    return audit
