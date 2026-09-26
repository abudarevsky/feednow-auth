"""Organization endpoint schemas (spec §14 plus the local rename contract).

§15 defines bodies only for key creation, so these are Phase 01 **derived
payloads** — minimal shapes from endpoint semantics, every field listed in
the manifest docstring and flagged as a spec-revision proposal:

- :class:`OrganizationResponse` mirrors the ``Organization`` entity and
  includes the nullable ``suspended_at`` lifecycle timestamp.
- :class:`OrganizationCreateRequest` accepts ``name`` and ``slug`` as
  required caller-supplied data and ``type`` as an optional choice that
  defaults to ``customer``: ``personal`` organizations are auto-created by
  provisioning (spec §7) and ``internal`` organizations are operator-
  managed, so neither is selectable through this endpoint. ``status`` is
  server-assigned (new organizations start ``active``) and ``id``/
  timestamps are server-generated — none of them are client input.

List usage: ``GET /v1/organizations`` returns ``Page[OrganizationResponse]``
(see :mod:`app.api.schemas.manifest`).
"""

from __future__ import annotations

from app.api.schemas.common import ApiSchema
from app.models.enums import OrganizationNameStatus, OrganizationStatus, OrganizationType
from app.models.ids import OrganizationId
from app.models.organization import OrganizationName, OrganizationSlug
from app.models.timestamps import UtcDatetime


class OrganizationCreateRequest(ApiSchema):
    """Body for ``POST /v1/organizations`` (derived)."""

    name: OrganizationName
    slug: OrganizationSlug
    type: OrganizationType = OrganizationType.CUSTOMER


class OrganizationRenameRequest(ApiSchema):
    name: OrganizationName


class OrganizationResponse(ApiSchema):
    """An organization as returned by get/create/list item payloads (mirrors §4)."""

    id: OrganizationId
    name: OrganizationName
    slug: OrganizationSlug
    type: OrganizationType
    status: OrganizationStatus
    name_status: OrganizationNameStatus
    suspended_at: UtcDatetime | None = None
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["OrganizationCreateRequest", "OrganizationRenameRequest", "OrganizationResponse"]
