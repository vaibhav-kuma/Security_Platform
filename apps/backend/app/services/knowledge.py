"""Knowledge Base service for managing versioned security knowledge packs."""

import base64
import hashlib
import json
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.db.session import get_engine, make_session_factory
from app.models.knowledge import (
    KnowledgePack,
    KnowledgePackStatus,
    PackContent,
    PackVersion,
    PackDependency,
    PackInstallation,
    PackContentUsage,
    KnowledgePackType,
)
from app.models.enums import SecurityEventType
from app.core.audit import write_audit_log


def get_db_session() -> Session:
    """Get a new database session."""
    engine = get_engine()
    factory = make_session_factory(engine)
    return factory()


class KnowledgePackValidator:
    """Validates knowledge packs before installation."""

    SCHEMA_VERSION = "1.0"

    # Required fields for pack manifest
    REQUIRED_MANIFEST_FIELDS = [
        "name", "version", "pack_type", "description", "author",
        "license", "repository", "min_core_version", "schema_version", "checksum"
    ]

    # Allowed pack types
    ALLOWED_PACK_TYPES = [t.value for t in KnowledgePackType]

    # Content schema for validation
    CONTENT_REQUIRED_FIELDS = [
        "content_id", "content_version", "name", "description"
    ]

    def __init__(self):
        """Initialize validator."""
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def validate_manifest(self, manifest: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
        """Validate pack manifest."""
        self.errors = []
        self.warnings = []

        # Check required fields
        for field in self.REQUIRED_MANIFEST_FIELDS:
            if field not in manifest:
                self.errors.append(f"Missing required field: {field}")

        # Validate pack type
        if "pack_type" in manifest and manifest["pack_type"] not in self.ALLOWED_PACK_TYPES:
            self.errors.append(f"Invalid pack type: {manifest['pack_type']}")

        # Validate version format
        if "version" in manifest:
            if not self._is_valid_version(manifest["version"]):
                self.errors.append(f"Invalid version format: {manifest['version']}")

        # Validate schema version
        if "schema_version" in manifest and manifest["schema_version"] != self.SCHEMA_VERSION:
            self.warnings.append(f"Schema version mismatch: expected {self.SCHEMA_VERSION}, got {manifest['schema_version']}")

        return len(self.errors) == 0, self.errors, self.warnings

    def validate_content(self, content: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
        """Validate pack content item."""
        self.errors = []
        self.warnings = []

        for field in self.CONTENT_REQUIRED_FIELDS:
            if field not in content:
                self.errors.append(f"Content missing required field: {field}")

        # Validate target_types if present
        if "target_types" in content and not isinstance(content["target_types"], list):
            self.errors.append("target_types must be a list")

        # Validate severity_guidance
        if "severity_guidance" in content:
            sg = content["severity_guidance"]
            if not isinstance(sg, dict):
                self.errors.append("severity_guidance must be a dict")

        return len(self.errors) == 0, self.errors, self.warnings

    def validate_pack_structure(self, pack_dir: Path) -> tuple[bool, list[str], list[str]]:
        """Validate complete pack structure."""
        self.errors = []
        self.warnings = []

        # Check for manifest
        manifest_path = pack_dir / "manifest.json"
        if not manifest_path.exists():
            self.errors.append("manifest.json not found")
            return False, self.errors, self.warnings

        # Load and validate manifest
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid manifest JSON: {e}")
            return False, self.errors, self.warnings

        valid, errors, warnings = self.validate_manifest(manifest)
        self.errors.extend(errors)
        self.warnings.extend(warnings)

        if not valid:
            return False, self.errors, self.warnings

        # Validate content directory
        content_dir = pack_dir / "content"
        if not content_dir.exists():
            self.warnings.append("No content directory found")
        else:
            for content_file in content_dir.glob("*.json"):
                try:
                    with open(content_file) as f:
                        content = json.load(f)
                    if isinstance(content, list):
                        for item in content:
                            c_valid, c_errors, c_warnings = self.validate_content(item)
                            self.errors.extend(c_errors)
                            self.warnings.extend(c_warnings)
                    else:
                        c_valid, c_errors, c_warnings = self.validate_content(content)
                        self.errors.extend(c_errors)
                        self.warnings.extend(c_warnings)
                except json.JSONDecodeError as e:
                    self.errors.append(f"Invalid content JSON in {content_file.name}: {e}")

        return len(self.errors) == 0, self.errors, self.warnings

    def _is_valid_version(self, version: str) -> bool:
        """Validate semantic version format."""
        import re
        return bool(re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9\-\.]+)?$", version))


class KnowledgePackIntegrity:
    """Handles integrity verification for knowledge packs."""

    @staticmethod
    def compute_checksum(pack_dir: Path) -> str:
        """Compute SHA256 checksum of pack directory."""
        hasher = hashlib.sha256()
        for file_path in sorted(pack_dir.rglob("*")):
            if file_path.is_file():
                # Skip signature file
                if file_path.name == "signature.asc":
                    continue
                hasher.update(file_path.read_bytes())
        return hasher.hexdigest()

    @staticmethod
    def verify_checksum(pack_dir: Path, expected_checksum: str) -> bool:
        """Verify pack checksum."""
        actual = KnowledgePackIntegrity.compute_checksum(pack_dir)
        return actual == expected_checksum

    @staticmethod
    def verify_signature(pack_dir: Path, signature: str, public_key_path: Path | None = None) -> bool:
        """Verify GPG signature (placeholder for actual implementation)."""
        # In production, this would use python-gnupg or similar
        # For now, just check if signature exists
        return bool(signature)


class KnowledgePackService:
    """Service for managing knowledge packs."""

    def __init__(self):
        """Initialize service."""
        self.validator = KnowledgePackValidator()
        self.integrity = KnowledgePackIntegrity()

    def install_pack(
        self,
        pack_data: bytes,
        source: str = "upload",
        source_url: str | None = None,
        installed_by: UUID | None = None,
        force: bool = False,
    ) -> tuple[bool, list[str], list[str], KnowledgePack | None]:
        """
        Install a knowledge pack from ZIP data.

        Args:
            pack_data: ZIP file bytes
            source: upload, registry, auto
            source_url: Source URL if from registry
            installed_by: User who installed
            force: Force reinstall if exists

        Returns:
            Tuple of (success, errors, warnings, pack)
        """
        db = get_db_session()
        tmpdir = None
        try:
            # Create temp directory
            tmpdir = Path(tempfile.mkdtemp(prefix="kp_install_"))

            # Write ZIP data
            zip_path = tmpdir / "pack.zip"
            zip_path.write_bytes(pack_data)

            # Extract
            extract_dir = tmpdir / "pack"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            # Find pack directory
            pack_dirs = list(extract_dir.iterdir())
            if len(pack_dirs) == 1 and pack_dirs[0].is_dir():
                pack_dir = pack_dirs[0]
            else:
                pack_dir = extract_dir

            # Load manifest
            manifest_path = pack_dir / "manifest.json"
            if not manifest_path.exists():
                return False, ["manifest.json not found in pack"], [], None

            with open(manifest_path) as f:
                manifest = json.load(f)

            # Validate manifest
            valid, errors, warnings = self.validator.validate_manifest(manifest)
            if not valid:
                return False, errors, warnings, None

            # Check if pack already exists
            existing = db.scalar(
                select(KnowledgePack).where(
                    KnowledgePack.name == manifest["name"],
                    KnowledgePack.version == manifest["version"]
                )
            )

            if existing and not force:
                return False, [f"Pack {manifest['name']} v{manifest['version']} already installed"], warnings, None

            # Verify checksum
            if not self.integrity.verify_checksum(pack_dir, manifest["checksum"]):
                return False, ["Checksum verification failed"], warnings, None

            # Verify signature if present
            if manifest.get("signature"):
                if not self.integrity.verify_signature(pack_dir, manifest["signature"]):
                    self.warnings.append("Signature verification failed or not implemented")

            # Check core version compatibility
            from app.config import get_settings
            settings = get_settings()
            if not self._check_version_compatibility(manifest, settings.app_version):
                return False, [f"Pack requires core version {manifest['min_core_version']} - {manifest['max_core_version'] or 'any'}, current is {settings.app_version}"], warnings, None

            # Validate pack structure
            valid, struct_errors, struct_warnings = self.validator.validate_pack_structure(pack_dir)
            if not valid:
                return False, struct_errors, warnings + struct_warnings, None

            # Determine target directory
            packs_root = Path("./knowledge_packs")
            packs_root.mkdir(exist_ok=True)
            target_dir = packs_root / f"{manifest['name']}-{manifest['version']}"

            # Remove existing if force
            if target_dir.exists():
                import shutil
                shutil.rmtree(target_dir)

            # Copy pack to installation directory
            import shutil
            shutil.copytree(pack_dir, target_dir)

            # Create or update pack record
            if existing:
                pack = existing
                pack.status = KnowledgePackStatus.INSTALLED
                pack.checksum = manifest["checksum"]
                pack.signature = manifest.get("signature")
                pack.installed_at = datetime.now(UTC)
                pack.installed_by = installed_by
            else:
                pack = KnowledgePack(
                    name=manifest["name"],
                    version=manifest["version"],
                    pack_type=manifest["pack_type"],
                    description=manifest["description"],
                    author=manifest["author"],
                    license=manifest.get("license", "MIT"),
                    homepage=manifest.get("homepage"),
                    repository=manifest["repository"],
                    min_core_version=manifest["min_core_version"],
                    max_core_version=manifest.get("max_core_version"),
                    schema_version=manifest["schema_version"],
                    checksum=manifest["checksum"],
                    signature=manifest.get("signature"),
                    status=KnowledgePackStatus.INSTALLED,
                    is_official=manifest.get("is_official", False),
                    installed_by=installed_by,
                    installed_at=datetime.now(UTC),
                    tags=manifest.get("tags", []),
                    metadata=manifest.get("metadata", {}),
                )
                db.add(pack)
                db.flush()

            # Process content files
            content_dir = pack_dir / "content"
            if content_dir.exists():
                self._process_content_files(db, pack, content_dir)

            # Process version history
            versions_file = pack_dir / "versions.json"
            if versions_file.exists():
                with open(versions_file) as f:
                    versions = json.load(f)
                for v in versions:
                    self._create_version_record(db, pack, v)

            # Process dependencies
            deps_file = pack_dir / "dependencies.json"
            if deps_file.exists():
                with open(deps_file) as f:
                    deps = json.load(f)
                for dep in deps:
                    self._create_dependency_record(db, pack, dep)

            # Create installation record
            installation = PackInstallation(
                pack_id=pack.id,
                installed_by=installed_by,
                installed_at=datetime.now(UTC),
                source=source,
                source_url=source_url,
                status="success",
            )
            db.add(installation)

            db.commit()
            db.refresh(pack)

            # Log audit event
            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_INSTALL,
                user_id=installed_by,
                entity_type="knowledge_pack",
                entity_id=str(pack.id),
                details={"name": pack.name, "version": pack.version, "pack_type": pack.pack_type}
            )

            return True, [], warnings, pack

        except Exception as e:
            db.rollback()
            return False, [str(e)], [], None
        finally:
            db.close()
            if tmpdir:
                import shutil
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _process_content_files(self, db: Session, pack: KnowledgePack, content_dir: Path) -> None:
        """Process content JSON files."""
        for content_file in content_dir.glob("*.json"):
            with open(content_file) as f:
                contents = json.load(f)

            if not isinstance(contents, list):
                contents = [contents]

            for content in contents:
                # Check if content already exists
                existing = db.scalar(
                    select(PackContent).where(
                        PackContent.pack_id == pack.id,
                        PackContent.content_id == content["content_id"]
                    )
                )

                if existing:
                    # Update existing
                    for key, value in content.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                    existing.updated_at = datetime.now(UTC)
                else:
                    # Create new
                    new_content = PackContent(
                        pack_id=pack.id,
                        **content
                    )
                    db.add(new_content)

    def _create_version_record(self, db: Session, pack: KnowledgePack, version_data: dict[str, Any]) -> None:
        """Create pack version record."""
        existing = db.scalar(
            select(PackVersion).where(
                PackVersion.pack_id == pack.id,
                PackVersion.version == version_data["version"]
            )
        )

        if not existing:
            version = PackVersion(
                pack_id=pack.id,
                version=version_data["version"],
                changelog=version_data.get("changelog", ""),
                compatibility_notes=version_data.get("compatibility_notes"),
                breaking_changes=version_data.get("breaking_changes", []),
                deprecated_content=version_data.get("deprecated_content", []),
                new_content=version_data.get("new_content", []),
                updated_content=version_data.get("updated_content", []),
                released_at=datetime.fromisoformat(version_data["released_at"]) if "released_at" in version_data else datetime.now(UTC),
                released_by=version_data.get("released_by"),
            )
            db.add(version)

    def _create_dependency_record(self, db: Session, pack: KnowledgePack, dep_data: dict[str, Any]) -> None:
        """Create pack dependency record."""
        # Find the dependency pack
        dep_pack = db.scalar(
            select(KnowledgePack).where(
                KnowledgePack.name == dep_data["depends_on"]
            )
        )

        if not dep_pack:
            # Dependency not installed yet, record anyway
            pass

        existing = db.scalar(
            select(PackDependency).where(
                PackDependency.pack_id == pack.id,
                PackDependency.depends_on_id == (dep_pack.id if dep_pack else None)
            )
        )

        if not existing:
            dependency = PackDependency(
                pack_id=pack.id,
                depends_on_id=dep_pack.id if dep_pack else None,
                dependency_type=dep_data.get("dependency_type", "required"),
                min_version=dep_data.get("min_version"),
                max_version=dep_data.get("max_version"),
                reason=dep_data.get("reason"),
            )
            db.add(dependency)

    def _check_version_compatibility(self, manifest: dict[str, Any], core_version: str) -> bool:
        """Check if pack is compatible with core version."""
        from packaging import version

        core_ver = version.parse(core_version)
        min_ver = version.parse(manifest["min_core_version"])

        if core_ver < min_ver:
            return False

        if manifest.get("max_core_version"):
            max_ver = version.parse(manifest["max_core_version"])
            if core_ver > max_ver:
                return False

        return True

    def activate_pack(self, pack_id: UUID, activated_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Activate a knowledge pack."""
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return False, ["Pack not found"]

            if pack.status not in (KnowledgePackStatus.INSTALLED, KnowledgePackStatus.DEPRECATED):
                return False, [f"Cannot activate pack in status: {pack.status}"]

            # Deactivate other packs of same type/name
            db.execute(
                select(KnowledgePack).where(
                    KnowledgePack.name == pack.name,
                    KnowledgePack.id != pack.id,
                    KnowledgePack.status == KnowledgePackStatus.ACTIVE
                )
            ).scalars().all()
            for other in _:
                other.status = KnowledgePackStatus.INSTALLED
                other.activated_at = None

            pack.status = KnowledgePackStatus.ACTIVE
            pack.activated_at = datetime.now(UTC)

            db.commit()

            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_ACTIVATE,
                user_id=activated_by,
                entity_type="knowledge_pack",
                entity_id=str(pack_id),
                details={"name": pack.name, "version": pack.version}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def deactivate_pack(self, pack_id: UUID, deactivated_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Deactivate a knowledge pack."""
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return False, ["Pack not found"]

            if pack.status != KnowledgePackStatus.ACTIVE:
                return False, [f"Pack is not active: {pack.status}"]

            pack.status = KnowledgePackStatus.INSTALLED
            pack.activated_at = None

            db.commit()

            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_DEACTIVATE,
                user_id=deactivated_by,
                entity_type="knowledge_pack",
                entity_id=str(pack_id),
                details={"name": pack.name, "version": pack.version}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def deprecate_pack(self, pack_id: UUID, deprecated_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Deprecate a knowledge pack."""
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return False, ["Pack not found"]

            if pack.status == KnowledgePackStatus.ACTIVE:
                # Deactivate first
                pack.status = KnowledgePackStatus.DEPRECATED
                pack.activated_at = None
                pack.deprecated_at = datetime.now(UTC)
            else:
                pack.status = KnowledgePackStatus.DEPRECATED
                pack.deprecated_at = datetime.now(UTC)

            db.commit()

            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_DEPRECATE,
                user_id=deprecated_by,
                entity_type="knowledge_pack",
                entity_id=str(pack_id),
                details={"name": pack.name, "version": pack.version}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def rollback_pack(self, pack_id: UUID, target_version: str | None = None, rolled_back_by: UUID | None = None, reason: str | None = None) -> tuple[bool, list[str], KnowledgePack | None]:
        """Rollback a knowledge pack to previous version."""
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return False, ["Pack not found"], None

            # Find target version
            if target_version:
                target_pack = db.scalar(
                    select(KnowledgePack).where(
                        KnowledgePack.name == pack.name,
                        KnowledgePack.version == target_version
                    )
                )
            else:
                # Get previous installation
                prev_install = db.scalar(
                    select(PackInstallation).where(
                        PackInstallation.pack_id == pack_id,
                        PackInstallation.status == "success"
                    ).order_by(PackInstallation.installed_at.desc()).limit(2)
                ).all()
                if len(prev_install) >= 2:
                    prev_version = prev_install[1].source_url  # This would need proper version tracking
                    target_pack = db.scalar(
                        select(KnowledgePack).where(
                            KnowledgePack.name == pack.name,
                            KnowledgePack.version == prev_version
                        )
                    )
                else:
                    return False, ["No previous version to rollback to"], None

            if not target_pack:
                return False, [f"Target version {target_version or 'previous'} not found"], None

            # Deactivate current if active
            if pack.status == KnowledgePackStatus.ACTIVE:
                pack.status = KnowledgePackStatus.INSTALLED
                pack.activated_at = None

            # Activate target
            target_pack.status = KnowledgePackStatus.ACTIVE
            target_pack.activated_at = datetime.now(UTC)

            # Record rollback
            rollback_install = PackInstallation(
                pack_id=target_pack.id,
                installed_by=rolled_back_by,
                installed_at=datetime.now(UTC),
                source="rollback",
                source_url=pack.version,
                previous_version=pack.version,
                status="success",
                rollback_at=datetime.now(UTC),
                rolled_back_by=rolled_back_by,
            )
            db.add(rollback_install)

            db.commit()
            db.refresh(target_pack)

            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_ROLLBACK,
                user_id=rolled_back_by,
                entity_type="knowledge_pack",
                entity_id=str(pack_id),
                details={
                    "from_version": pack.version,
                    "to_version": target_pack.version,
                    "reason": reason
                }
            )

            return True, [], target_pack

        except Exception as e:
            db.rollback()
            return False, [str(e)], None
        finally:
            db.close()

    def uninstall_pack(self, pack_id: UUID, uninstalled_by: UUID | None = None) -> tuple[bool, list[str]]:
        """Uninstall a knowledge pack."""
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return False, ["Pack not found"]

            if pack.status == KnowledgePackStatus.ACTIVE:
                return False, ["Cannot uninstall active pack; deactivate first"]

            # Soft delete
            pack.deleted_at = datetime.now(UTC)
            pack.status = KnowledgePackStatus.DEPRECATED

            db.commit()

            write_audit_log(
                session=db,
                event_type=SecurityEventType.KNOWLEDGE_PACK_UNINSTALL,
                user_id=uninstalled_by,
                entity_type="knowledge_pack",
                entity_id=str(pack_id),
                details={"name": pack.name, "version": pack.version}
            )

            return True, []

        except Exception as e:
            db.rollback()
            return False, [str(e)]
        finally:
            db.close()

    def list_packs(
        self,
        pack_type: str | None = None,
        status: str | None = None,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[KnowledgePack], int]:
        """List knowledge packs."""
        db = get_db_session()
        try:
            query = select(KnowledgePack)

            if pack_type:
                query = query.where(KnowledgePack.pack_type == pack_type)
            if status:
                query = query.where(KnowledgePack.status == status)
            if active_only:
                query = query.where(KnowledgePack.status == KnowledgePackStatus.ACTIVE)

            total = db.scalar(select(KnowledgePack.id).select_from(query.subquery()).count())

            query = query.order_by(KnowledgePack.name, KnowledgePack.version.desc()).limit(limit).offset(offset)
            packs = db.scalars(query).all()

            return list(packs), total

        finally:
            db.close()

    def get_pack(self, pack_id: UUID) -> KnowledgePack | None:
        """Get pack by ID."""
        db = get_db_session()
        try:
            return db.get(KnowledgePack, pack_id)
        finally:
            db.close()

    def get_pack_content(
        self,
        pack_id: UUID,
        content_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[PackContent], int]:
        """Get pack content."""
        db = get_db_session()
        try:
            query = select(PackContent).where(PackContent.pack_id == pack_id)

            if content_id:
                query = query.where(PackContent.content_id == content_id)

            total = db.scalar(select(PackContent.id).select_from(query.subquery()).count())
            query = query.order_by(PackContent.content_id).limit(limit).offset(offset)
            contents = db.scalars(query).all()

            return list(contents), total

        finally:
            db.close()

    def get_pack_versions(self, pack_id: UUID) -> list[PackVersion]:
        """Get pack version history."""
        db = get_db_session()
        try:
            return list(db.scalars(
                select(PackVersion).where(PackVersion.pack_id == pack_id).order_by(PackVersion.released_at.desc())
            ).all())
        finally:
            db.close()

    def get_pack_dependencies(self, pack_id: UUID) -> list[PackDependency]:
        """Get pack dependencies."""
        db = get_db_session()
        try:
            return list(db.scalars(
                select(PackDependency).where(PackDependency.pack_id == pack_id)
            ).all())
        finally:
            db.close()

    def get_pack_installations(self, pack_id: UUID) -> list[PackInstallation]:
        """Get pack installation history."""
        db = get_db_session()
        try:
            return list(db.scalars(
                select(PackInstallation).where(PackInstallation.pack_id == pack_id).order_by(PackInstallation.installed_at.desc())
            ).all())
        finally:
            db.close()

    def check_updates(self, pack_id: UUID) -> dict[str, Any]:
        """Check for pack updates from registry."""
        # This would connect to a remote registry
        # Placeholder implementation
        db = get_db_session()
        try:
            pack = db.get(KnowledgePack, pack_id)
            if not pack:
                return {"error": "Pack not found"}

            # In production, this would query a registry API
            return {
                "pack_id": str(pack_id),
                "current_version": pack.version,
                "latest_version": pack.version,  # Would come from registry
                "update_available": False,
                "changelog": None,
                "breaking_changes": [],
            }
        finally:
            db.close()

    def record_content_usage(
        self,
        pack_content_id: UUID,
        scan_id: UUID,
        finding_id: UUID | None = None,
        matched: bool = False,
        match_details: dict[str, Any] | None = None,
    ) -> PackContentUsage:
        """Record that pack content was used in a scan."""
        db = get_db_session()
        try:
            usage = PackContentUsage(
                pack_content_id=pack_content_id,
                scan_id=scan_id,
                finding_id=finding_id,
                used_at=datetime.now(UTC),
                matched=matched,
                match_details=match_details,
            )
            db.add(usage)
            db.commit()
            db.refresh(usage)
            return usage
        finally:
            db.close()

    def get_pack_audit_log(self, pack_id: UUID, limit: int = 100) -> list[dict[str, Any]]:
        """Get audit log for a pack."""
        from app.models.audit import AuditLog
        db = get_db_session()
        try:
            events = db.scalars(
                select(AuditLog).where(
                    AuditLog.entity_type == "knowledge_pack",
                    AuditLog.entity_id == str(pack_id)
                ).order_by(AuditLog.created_at.desc()).limit(limit)
            ).all()

            return [
                {
                    "id": e.id,
                    "pack_id": pack_id,
                    "action": e.action,
                    "performed_by": e.actor_id,
                    "performed_at": e.created_at,
                    "details": e.details,
                    "previous_state": e.previous_state,
                    "new_state": e.new_state,
                }
                for e in events
            ]
        finally:
            db.close()


# Celery tasks for async operations
@celery_app.task(bind=True, name="app.knowledge.tasks.install_pack_async")
def install_pack_async(
    self,
    pack_data_b64: str,
    source: str = "registry",
    source_url: str | None = None,
    installed_by: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Async pack installation task."""
    import base64
    pack_data = base64.b64decode(pack_data_b64)
    installed_by_uuid = UUID(installed_by) if installed_by else None

    service = KnowledgePackService()
    success, errors, warnings, pack = service.install_pack(
        pack_data=pack_data,
        source=source,
        source_url=source_url,
        installed_by=installed_by_uuid,
        force=force,
    )

    return {
        "success": success,
        "errors": errors,
        "warnings": warnings,
        "pack_id": str(pack.id) if pack else None,
    }


@celery_app.task(bind=True, name="app.knowledge.tasks.check_all_updates")
def check_all_updates(self) -> dict[str, Any]:
    """Check all installed packs for updates."""
    service = KnowledgePackService()
    packs, _ = service.list_packs(active_only=False)

    results = []
    for pack in packs:
        update_info = service.check_updates(pack.id)
        results.append(update_info)

    return {
        "checked": len(packs),
        "updates_available": sum(1 for r in results if r.get("update_available")),
        "results": results,
    }