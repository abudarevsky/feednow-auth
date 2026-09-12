"""``User`` domain entity (spec §4).

Fields are exactly the §4 list — no more, no fewer. ``id`` is the internal
FeedNow application identity (``usr_``); email, Cognito username/``sub``, and
Shopify IDs are **never** user identifiers (AGENTS.md).

Deliberate Phase 01 boundaries:

- ``email`` is a constrained string, not a format-validated address type:
  format rules and email uniqueness are owner-phase work (provisioning in
  Phase 03, storage constraints in Phase 02) and must not be pinned here.
- Status transitions and ``updated_at`` maintenance are service rules; the
  model is a mutable container so Phase 03+ can update it.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import UserStatus
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
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["Email", "User"]
