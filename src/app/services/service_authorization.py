"""FeedNow-owned membership-role to registered-service permission policy."""

from __future__ import annotations

from datetime import datetime

from app.models.enums import MembershipRole
from app.models.timestamps import to_utc_rfc3339

ROLE_SERVICE_PERMISSIONS: dict[MembershipRole, frozenset[str]] = {
    MembershipRole.OWNER: frozenset({"projects:read", "projects:write", "inspect"}),
    MembershipRole.ORG_ADMIN: frozenset({"projects:read", "projects:write", "inspect"}),
    MembershipRole.MEMBER: frozenset({"projects:read", "inspect"}),
    MembershipRole.VIEWER: frozenset({"projects:read"}),
}


def service_permissions_for_role(
    role: MembershipRole, allowed_permissions: tuple[str, ...]
) -> tuple[str, ...]:
    """Return the stable permission intersection for a role and service."""
    return tuple(sorted(ROLE_SERVICE_PERMISSIONS[role].intersection(allowed_permissions)))


def membership_permission_version(role: MembershipRole, created_at: datetime) -> str:
    """Build a deterministic snapshot version that changes with role or membership."""
    return f"{role.value}:{to_utc_rfc3339(created_at)}"


__all__ = [
    "ROLE_SERVICE_PERMISSIONS",
    "membership_permission_version",
    "service_permissions_for_role",
]
