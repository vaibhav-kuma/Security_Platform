"""Android APK asset models: uploaded APK files and their manifest components.

APK contents are untrusted input; component metadata is stored for analysis
but never executed by the platform.
"""

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import ApkComponentType, native_enum


class ApkFile(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "apk_files"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version_name: Mapped[str | None] = mapped_column(String(128))
    version_code: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    object_key: Mapped[str | None] = mapped_column(String(1024))

    components: Mapped[list["ApkComponent"]] = relationship(back_populates="apk")


class ApkComponent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "apk_components"
    __table_args__ = (
        UniqueConstraint("apk_file_id", "component_type", "name", name="apk_type_name"),
    )

    apk_file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("apk_files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    component_type: Mapped[ApkComponentType] = mapped_column(
        native_enum(ApkComponentType), nullable=False
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    exported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    intent_filters: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)

    apk: Mapped[ApkFile] = relationship(back_populates="components")
