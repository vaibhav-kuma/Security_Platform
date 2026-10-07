"""Idempotent seed data for the system RBAC catalog (Phase 2).

Only the minimal system roles and permissions land here, per
``docs/architecture/PHASE_DEPENDENCIES.md`` ("Keep seed data minimal").
Permission codes are derived from the capability areas documented in
``docs/architecture/COMPONENTS.md`` (projects, scopes, scans, findings,
reports, org admin); enforcement mechanics arrive in Phase 3.

The seed is safe to re-run: permissions are looked up by ``code``, roles by
the ``name_scope`` unique constraint, and role grants are reconciled rather
than duplicated.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import RoleScope
from app.models.identity import Permission, Role

# Canonical permission codes. Keys are the unique ``permissions.code``
# values; values are human-readable descriptions.
PERMISSIONS: dict[str, str] = {
    "org:manage": "Administer the organization, its members, and its roles",
    "project:create": "Create projects in the organization",
    "project:read": "View projects and their details",
    "project:update": "Update project settings",
    "project:delete": "Delete or archive projects",
    "member:manage": "Manage organization and project membership",
    "scope:read": "View scope versions and scope rules",
    "scope:manage": "Create and modify scope versions and rules",
    "scan:create": "Launch scans within approved scope",
    "scan:read": "View scans, scan jobs, and scan events",
    "scan:cancel": "Cancel running scans and jobs",
    "finding:read": "View observations, findings, and evidence",
    "finding:triage": "Comment on findings and change their status",
    "finding:manage": "Manage finding relationships and evidence",
    "report:create": "Request report generation",
    "report:read": "View and download reports",
}

_VIEWER_CODES = (
    "project:read",
    "scope:read",
    "scan:read",
    "finding:read",
    "report:read",
)

# System roles and their grants, most privileged last. ``owner`` receives
# every permission defined above.
ROLE_GRANTS: dict[str, tuple[str, ...]] = {
    "viewer": _VIEWER_CODES,
    "researcher": (
        *_VIEWER_CODES,
        "scan:create",
        "scan:cancel",
        "finding:triage",
        "report:create",
    ),
    "admin": (
        *_VIEWER_CODES,
        "scan:create",
        "scan:cancel",
        "finding:triage",
        "report:create",
        "project:create",
        "project:update",
        "member:manage",
        "scope:manage",
        "finding:manage",
    ),
    "owner": tuple(PERMISSIONS),
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    "viewer": "Read-only access to projects, scopes, scans, findings, and reports",
    "researcher": "Viewer access plus running scans and triaging findings",
    "admin": "Researcher access plus project, scope, and membership management",
    "owner": "Full control of the organization and all of its projects",
}


def seed_system_rbac(session: Session) -> None:
    """Upsert canonical permissions and system roles.

    Idempotent: existing rows are looked up by their unique keys and role
    permission grants are reconciled in place. The caller owns the
    transaction; this function never commits or rolls it back.
    """
    permissions: dict[str, Permission] = {}
    for code, description in PERMISSIONS.items():
        permission = session.scalar(select(Permission).where(Permission.code == code))
        if permission is None:
            permission = Permission(code=code, description=description)
            session.add(permission)
            session.flush()
        permissions[code] = permission

    for role_name, codes in ROLE_GRANTS.items():
        role = session.scalar(
            select(Role).where(Role.name == role_name, Role.scope == RoleScope.SYSTEM)
        )
        if role is None:
            role = Role(
                name=role_name,
                scope=RoleScope.SYSTEM,
                is_system=True,
                description=ROLE_DESCRIPTIONS[role_name],
            )
            session.add(role)
            session.flush()

        desired = {permissions[code] for code in codes}
        current = set(role.permissions)
        for missing in desired - current:
            role.permissions.append(missing)
        for stale in current - desired:
            role.permissions.remove(stale)
