"""Membership endpoint schemas (spec §14: members list / create / remove).

§15 defines no membership bodies, so these are Phase 01 **derived
payloads** — every field is listed in the manifest docstring and flagged as
a spec-revision proposal:

- :class:`MemberResponse` shows a membership as the organization sees it:
  ``user_id`` (``usr_`` application identity), ``role``, ``status``, and
  ``created_at`` (join time). The membership **record ID** (``mem_``) is
  internal by Phase 01 convention and is deliberately not exposed; member
  removal targets ``user_id`` (the §14 path parameter), never the record ID.
- :class:`MemberCreateRequest` accepts ``user_id`` and ``role`` only.
  ``status`` is server-assigned (``active`` on add) — and removal is a
  physical delete (pinned enum decision), so there is no client-side
  status/disabled input.
- ``DELETE /v1/organizations/{organization_id}/members/{user_id}`` has no
  request or response body (204, declared in the manifest).

List usage: ``GET .../members`` returns ``Page[MemberResponse]``.
"""

from __future__ import annotations

from app.api.schemas.common import ApiSchema
from app.models.enums import MembershipRole, MembershipStatus
from app.models.ids import UserId
from app.models.timestamps import UtcDatetime


class MemberCreateRequest(ApiSchema):
    """Body for ``POST /v1/organizations/{organization_id}/members`` (derived)."""

    user_id: UserId
    role: MembershipRole


class MemberResponse(ApiSchema):
    """A member row in list items and the add-member response (derived)."""

    user_id: UserId
    role: MembershipRole
    status: MembershipStatus
    created_at: UtcDatetime


__all__ = ["MemberCreateRequest", "MemberResponse"]
