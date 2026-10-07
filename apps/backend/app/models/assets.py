"""Asset graph: generic asset nodes, relationships, and per-kind detail tables.

Every discovered or declared thing (domain, subdomain, IP, port, URL,
endpoint, technology, certificate, ...) is an ``Asset`` row of a given
``kind``; kind-specific attributes live in the one-to-one detail tables.
Relationships between assets form the discovery graph. Discovery never
implies authorization — ``scope_status`` is decided by the ScopeEngine.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    AssetKind,
    AssetRelationshipType,
    HttpMethod,
    PortProtocol,
    PortState,
    ScopeStatus,
    native_enum,
)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Node in the asset graph. ``value`` is the canonical identifier
    (FQDN, IP, URL, ...) unique per project and kind."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "kind", "value", name="project_kind_value"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[AssetKind] = mapped_column(native_enum(AssetKind), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope_status: Mapped[ScopeStatus] = mapped_column(
        native_enum(ScopeStatus), nullable=False, default=ScopeStatus.UNKNOWN
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AssetRelationship(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Directed edge in the asset graph (e.g. subdomain RESOLVES_TO ip)."""

    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint("source_asset_id", "target_asset_id", "relationship_type", name="edge"),
        CheckConstraint("source_asset_id <> target_asset_id", name="no_self_relationship"),
    )

    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[AssetRelationshipType] = mapped_column(
        native_enum(AssetRelationshipType), nullable=False
    )
    note: Mapped[str | None] = mapped_column(Text)


class DomainDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "domain_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    fqdn: Mapped[str] = mapped_column(String(253), nullable=False)
    whois: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class SubdomainDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "subdomain_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    fqdn: Mapped[str] = mapped_column(String(253), nullable=False)
    is_wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class IpDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ip_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    address: Mapped[str] = mapped_column(String(45), nullable=False)
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PortDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "port_details"
    __table_args__ = (
        CheckConstraint("port_number >= 1 AND port_number <= 65535", name="port_range"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[PortProtocol] = mapped_column(native_enum(PortProtocol), nullable=False)
    state: Mapped[PortState] = mapped_column(
        native_enum(PortState), nullable=False, default=PortState.UNKNOWN
    )
    banner: Mapped[str | None] = mapped_column(Text)


class UrlDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "url_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    path: Mapped[str | None] = mapped_column(Text)
    query: Mapped[str | None] = mapped_column(Text)


class EndpointDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "endpoint_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[HttpMethod] = mapped_column(native_enum(HttpMethod), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class TechnologyDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "technology_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(128))
    category: Mapped[str | None] = mapped_column(String(128))


class CertificateDetail(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "certificate_details"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False)
    sha256_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    subject_alternative_names: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list
    )
