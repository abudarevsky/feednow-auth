"""``GET /v1/me`` response schema (API contract "Current User").

The contract defines the endpoint but no body, so :class:`MeResponse` is a
**derived payload** (listed in the manifest docstring and flagged
as a contract-revision proposal): the caller's own user record, mirroring the
domain model contract ``User`` field list exactly (plus application-role implementation ``application_role``, which
is the only API response change in this projection). External identities,
memberships, and credentials are deliberately absent — each has its own
surface, and ``/me`` must not become a catch-all that later changes without
breaking consumers.

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, field_validator

from app.api.schemas.common import ApiSchema
from app.models.enums import ApplicationRole, UserStatus
from app.models.ids import UserId
from app.models.timestamps import UtcDatetime
from app.models.user import DisplayText, Email


class MeResponse(ApiSchema):
    """The authenticated user's own profile (derived from domain model contract ``User``)."""

    id: UserId
    display_name: DisplayText
    email: Email
    status: UserStatus
    application_role: ApplicationRole
    created_at: UtcDatetime
    updated_at: UtcDatetime


class ProfileUpdateRequest(ApiSchema):
    display_name: Annotated[str, StringConstraints(min_length=2, max_length=255)]

    @field_validator("display_name", mode="before")
    @classmethod
    def trim_display_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


__all__ = ["MeResponse", "ProfileUpdateRequest"]
