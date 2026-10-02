"""``Membership`` domain entity (domain model contract).

Grants one :class:`~app.models.user.User` a :class:`~app.models.enums.MembershipRole`
inside one :class:`~app.models.organization.Organization`.

initial semantics (pinned in the design notes):

- Member removal is a **physical delete** (the storage contract already has
  ``delete_membership``); ``status=disabled`` is a temporary suspension.
- Uniqueness of ``(organization_id, user_id)`` is storage storage work, not
  a model constraint.

Current behavior and invariants: ``docs/authorization.md``."""

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
