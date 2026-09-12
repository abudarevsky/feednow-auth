"""Organization endpoint schemas (spec §14: get / list / create).

§15 defines bodies only for key creation, so these are Phase 01 **derived
payloads** — minimal shapes from endpoint semantics, every field listed in
the manifest docstring and flagged as a spec-revision proposal:

- :class:`OrganizationResponse` mirrors the §4 ``Organization`` field list
  exactly (id, name, slug, type, status, created_at, updated_at).
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
from app.models.enums import OrganizationStatus, OrganizationType
from app.models.ids import OrganizationId
from app.models.organization import OrganizationName, OrganizationSlug
from app.models.timestamps import UtcDatetime


class OrganizationCreateRequest(ApiSchema):
    """Body for ``POST /v1/organizations`` (derived)."""

    name: OrganizationName
    slug: OrganizationSlug
    type: OrganizationType = OrganizationType.CUSTOMER


class OrganizationResponse(ApiSchema):
    """An organization as returned by get/create/list item payloads (mirrors §4)."""

    id: OrganizationId
    name: OrganizationName
    slug: OrganizationSlug
    type: OrganizationType
    status: OrganizationStatus
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = ["OrganizationCreateRequest", "OrganizationResponse"]
