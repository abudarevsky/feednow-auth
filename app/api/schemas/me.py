"""``GET /v1/me`` response schema (spec §14 "Current User").

The spec defines the endpoint but no body, so :class:`MeResponse` is a
Phase 01 **derived payload** (listed in the manifest docstring and flagged
as a spec-revision proposal): the caller's own user record, mirroring the
§4 ``User`` field list exactly. External identities, memberships, and
credentials are deliberately absent — each has its own endpoint or owner
phase, and ``/me`` must not become a catch-all that later phases cannot
close without breaking consumers.
"""

from __future__ import annotations

from app.api.schemas.common import ApiSchema
from app.models.enums import UserStatus
from app.models.ids import UserId
from app.models.timestamps import UtcDatetime
from app.models.user import DisplayText, Email


class MeResponse(ApiSchema):
    """The authenticated user's own profile (derived from spec §4 ``User``)."""

    id: UserId
    display_name: DisplayText
    email: Email
    status: UserStatus
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["MeResponse"]
