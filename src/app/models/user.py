"""``User`` domain entity (spec §4).

Fields are the §4 list plus the Phase 12 ``application_role`` (spec 12
invariant 1) — nothing else. ``id`` is the internal
FeedNow application identity (``usr_``); email, Cognito username/``sub``, and
Shopify IDs are **never** user identifiers (AGENTS.md). From Phase 12 on,
email is **not unique** — distinct verified Cognito subjects may share an
address and stay separate users — so email is an exact-lookup field only,
and ``sub``/email never become identifiers through any side door.

Deliberate Phase 01 boundaries:

- ``email`` is a constrained string, not a format-validated address type:
  format rules are owner-phase work (provisioning in Phase 03) and must not
  be pinned here; the uniqueness assumption was retired in Phase 12.
- Status transitions and ``updated_at`` maintenance are service rules; the
  model is a mutable container so Phase 03+ can update it.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import ApplicationRole, UserStatus
from app.models.ids import UserId
from app.models.timestamps import UtcDatetime

#: Bounded non-empty display text for ``User.display_name``.
DisplayText = Annotated[str, StringConstraints(min_length=1, max_length=255)]

#: Upper bound is the RFC 5321 path limit (254 chars) plus margin for
#: quoted local-parts; the format pattern is intentionally absent — see
#: module docstring.
Email = Annotated[str, StringConstraints(min_length=1, max_length=320)]


class User(BaseModel):
    """A FeedNow application user."""

    model_config = ConfigDict(extra="forbid")

    id: UserId
    display_name: DisplayText
    email: Email
    status: UserStatus
    #: Global application role (Phase 12). The explicit default makes ``USER``
    #: the only value any writer obtains without naming it; provisioning sets
    #: it explicitly and administration is out-of-band (Phase 13). Separate
    #: from the organization-local ``MembershipRole`` by contract.
    application_role: ApplicationRole = ApplicationRole.USER
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["Email", "User"]
