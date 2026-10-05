"""Versioned request/response schemas for the API contract API surface.

initial contract surface (frozen for organization and API-keymounting):

- :mod:`app.api.schemas.common` — :class:`ApiSchema` base (``extra="forbid"``
  everywhere) and the pagination re-exports (``Page``, ``PageParams``).
- Resource modules :mod:`me`, :mod:`organizations`, :mod:`members`,
  :mod:`api_keys` — request/response models per API contract endpoint group.
- :mod:`app.api.schemas.manifest` — the frozen endpoint manifest
  (``API_V1_PREFIX``, ``EndpointSpec``, ``ENDPOINTS``, ``endpoint_for``)
  declaring method, path, models, success status, pagination usage, and
  path-parameter identity types for every API contract route.

No routers or handlers live here; endpoint behavior is owner-capability work
(initial non-goal).

Current behavior and invariants: ``docs/architecture.md``."""

from app.api.schemas.admin import (
    AdminMember,
    AdminOrganization,
    AdminOrganizationDetail,
    AdminOrganizationQuery,
    AdminSummary,
)
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
from app.api.schemas.members import MemberCreateRequest, MemberResponse, OwnerTransferRequest
from app.api.schemas.organizations import (
    OrganizationCreateRequest,
    OrganizationRenameRequest,
    OrganizationResponse,
    OrganizationSlugAvailabilityQuery,
    OrganizationSlugAvailabilityResponse,
)
from app.api.schemas.service_auth import (
    ApiKeyValidationRequest,
    ApiKeyValidationResponse,
    ServiceAuthorizationContextResponse,
    ServiceCodeExchangeRequest,
    ServiceHandoffRequest,
)

__all__ = [
    "API_V1_PREFIX",
    "ENDPOINTS",
    "AdminMember",
    "AdminOrganization",
    "AdminOrganizationDetail",
    "AdminOrganizationQuery",
    "AdminSummary",
    "ApiKeyCreateRequest",
    "ApiKeyCreatedResponse",
    "ApiKeySummary",
    "ApiKeyValidationRequest",
    "ApiKeyValidationResponse",
    "ApiSchema",
    "EndpointSpec",
    "FullApiKey",
    "MeResponse",
    "MemberCreateRequest",
    "MemberResponse",
    "OwnerTransferRequest",
    "OrganizationCreateRequest",
    "OrganizationRenameRequest",
    "OrganizationResponse",
    "OrganizationSlugAvailabilityQuery",
    "OrganizationSlugAvailabilityResponse",
    "Page",
    "PageParams",
    "ServiceAuthorizationContextResponse",
    "ServiceCodeExchangeRequest",
    "ServiceHandoffRequest",
    "endpoint_for",
]
