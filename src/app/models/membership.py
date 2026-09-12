"""``Membership`` domain entity (spec §4).

Grants one :class:`~app.models.user.User` a :class:`~app.models.enums.MembershipRole`
inside one :class:`~app.models.organization.Organization`.

Phase 01 semantics (pinned in the breakdown):

- Member removal is a **physical delete** (the storage contract already has
  ``delete_membership``); ``status=disabled`` is a temporary suspension.
- Uniqueness of ``(organization_id, user_id)`` is Phase 02 storage work, not
  a model constraint.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from app.models.enums import MembershipRole, MembershipStatus
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.timestamps import UtcDatetime


class Membership(BaseModel):
    """A user's role-bearing membership in an organization."""

    model_config = ConfigDict(extra="forbid")

    id: MembershipId
    organization_id: OrganizationId
    user_id: UserId
    role: MembershipRole
    status: MembershipStatus
    created_at: UtcDatetime


__all__ = ["Membership"]
