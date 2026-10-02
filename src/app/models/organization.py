"""``Organization`` domain entity (domain model contract).

Every business resource in FeedNow applications belongs to an organization;
``id`` (``org_``) is the internal tenancy identity used across the API
(authorization-context contract, API contract).

Deliberate initial boundaries (same policy as ``User.email``):

- ``slug`` is a bounded non-empty string only. Format rules (e.g. lowercase
  hyphen-separated normalization) and slug uniqueness are owner-capability work —
  provisioning in identity and storage constraints in storage — and are
  deliberately not pinned here.
- ``name`` is bounded display text; no format rule beyond non-empty.

Current behavior and invariants: ``docs/authorization.md``."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import OrganizationNameStatus, OrganizationStatus, OrganizationType
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
    name_status: OrganizationNameStatus = OrganizationNameStatus.CONFIRMED
    suspended_at: UtcDatetime | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["Organization", "OrganizationName", "OrganizationSlug"]
