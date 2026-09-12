"""``Organization`` domain entity (spec §4).

Every business resource in FeedNow applications belongs to an organization;
``id`` (``org_``) is the internal tenancy identity used across the API
(spec §10, §14).

Deliberate Phase 01 boundaries (same policy as ``User.email``):

- ``slug`` is a bounded non-empty string only. Format rules (e.g. lowercase
  hyphen-separated normalization) and slug uniqueness are owner-phase work —
  provisioning in Phase 03 and storage constraints in Phase 02 — and are
  deliberately not pinned here.
- ``name`` is bounded display text; no format rule beyond non-empty.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import OrganizationStatus, OrganizationType
from app.models.ids import OrganizationId
from app.models.timestamps import UtcDatetime

#: Bounded human-readable organization name.
OrganizationName = Annotated[str, StringConstraints(min_length=1, max_length=255)]

#: Bounded URL identifier segment; format intentionally unconstrained in
#: Phase 01 — see module docstring.
OrganizationSlug = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class Organization(BaseModel):
    """A FeedNow tenant: personal, customer, or internal."""

    model_config = ConfigDict(extra="forbid")

    id: OrganizationId
    name: OrganizationName
    slug: OrganizationSlug
    type: OrganizationType
    status: OrganizationStatus
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["Organization", "OrganizationName", "OrganizationSlug"]
