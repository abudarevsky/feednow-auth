"""Versioned request/response schemas for the §14 API surface.

Phase 01 contract surface (frozen for Phase 04/05 mounting):

- :mod:`app.api.schemas.common` — :class:`ApiSchema` base (``extra="forbid"``
  everywhere) and the pagination re-exports (``Page``, ``PageParams``).
- Resource modules :mod:`me`, :mod:`organizations`, :mod:`members`,
  :mod:`api_keys` — request/response models per §14 endpoint group.
- :mod:`app.api.schemas.manifest` — the frozen endpoint manifest
  (``API_V1_PREFIX``, ``EndpointSpec``, ``ENDPOINTS``, ``endpoint_for``)
  declaring method, path, models, success status, pagination usage, and
  path-parameter identity types for every §14 route.

No routers or handlers live here; endpoint behavior is owner-phase work
(Phase 01 non-goal).
"""

from app.api.schemas.api_keys import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeySummary,
    FullApiKey,
)
from app.api.schemas.common import ApiSchema, Page, PageParams
from app.api.schemas.manifest import (
    API_V1_PREFIX,
    ENDPOINTS,
    EndpointSpec,
    endpoint_for,
)
from app.api.schemas.me import MeResponse
from app.api.schemas.members import MemberCreateRequest, MemberResponse
from app.api.schemas.organizations import OrganizationCreateRequest, OrganizationResponse

__all__ = [
    "API_V1_PREFIX",
    "ENDPOINTS",
    "ApiKeyCreateRequest",
    "ApiKeyCreatedResponse",
    "ApiKeySummary",
    "ApiSchema",
    "EndpointSpec",
    "FullApiKey",
    "MeResponse",
    "MemberCreateRequest",
    "MemberResponse",
    "OrganizationCreateRequest",
    "OrganizationResponse",
    "Page",
    "PageParams",
    "endpoint_for",
]
