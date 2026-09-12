"""Frozen endpoint manifest for every spec §14 route (Phase 01 mount contract).

Phase 01 ships **no routers** (endpoint behavior is a non-goal). Instead,
Phase 04/05 mount against this manifest: each entry pins the HTTP method,
full versioned path, request/response models, success status, pagination
usage, and path-parameter identity types for one §14 endpoint. Routers land
in ``app/api/<resource>.py`` and register through ``create_app``'s documented
extension point (task 6); a route may only be added when it appears here.

Naming collision to keep straight (see :mod:`app.models.ids` and
:mod:`app.models.api_key`): the ``{key_id}`` **path parameter** carries the
``key_`` application identity (:class:`~app.models.ids.ApiKeyId`, i.e.
``ApiKeySummary.id``). It is *not* the §8 non-secret ``key_id`` credential
segment inside ``fn_live_<key-id>_<secret>`` (``app.models.api_key.KeyId``),
which never appears in any path or response.

Derived-payload register (Phase 01 contract additions, flagged for spec
revision — §14/§15 define no body for these; §15's key-creation request and
response below are copied verbatim and are NOT derived):

- ``GET /v1/me`` → ``MeResponse``: ``id``, ``display_name``, ``email``,
  ``status``, ``created_at``, ``updated_at`` (mirrors the §4 ``User``).
- ``POST /v1/organizations`` → ``OrganizationCreateRequest``: ``name``,
  ``slug``, ``type`` (default ``customer``); → ``OrganizationResponse``:
  ``id``, ``name``, ``slug``, ``type``, ``status``, ``created_at``,
  ``updated_at`` (mirrors §4 ``Organization``; reused by organization GETs
  and as the create response).
- ``GET .../members`` → ``Page[MemberResponse]``; ``POST .../members`` →
  ``MemberCreateRequest``: ``user_id``, ``role``; → ``MemberResponse``:
  ``user_id``, ``role``, ``status``, ``created_at``. The ``mem_`` record ID
  is internal and deliberately absent.
- ``GET .../api-keys`` → ``Page[ApiKeySummary]`` with ``ApiKeySummary``:
  ``id``, ``name``, ``environment``, ``key_prefix``, ``status``, ``scopes``,
  ``created_at``, ``last_used_at``, ``expires_at``, ``revoked_at`` — masked
  only; no ``secret_hash``, no plaintext, no §8 ``key_id`` segment.
- Success statuses: GETs are 200; creates (POST) are 201 (derived REST
  convention — the spec pins only "deletes = 204"); both DELETEs are 204
  with no request or response body.

Secret rule (AGENTS.md; acceptance criterion): across every model reachable
from this manifest, the only field that may carry credential material is
``ApiKeyCreatedResponse.key``, returned exactly once at creation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from pydantic import BaseModel

from app.api.schemas.api_keys import ApiKeyCreatedResponse, ApiKeyCreateRequest, ApiKeySummary
from app.api.schemas.me import MeResponse
from app.api.schemas.members import MemberCreateRequest, MemberResponse
from app.api.schemas.organizations import OrganizationCreateRequest, OrganizationResponse
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.pagination import Page, PageParams

#: Versioned prefix for every §14 route. Routers mount under this constant;
#: changing it is a new API version, not an edit.
API_V1_PREFIX = "/v1"

_MODEL = type[BaseModel] | None


def _no_params() -> Mapping[str, type]:
    """Default factory: an empty, immutable path-parameter mapping."""
    return MappingProxyType({})


@dataclass(frozen=True)
class EndpointSpec:
    """One frozen §14 endpoint: mount contract, not implementation."""

    operation_id: str
    method: str
    path: str
    success_status: int
    request_model: _MODEL = None
    response_model: _MODEL = None
    query_model: _MODEL = None
    paginated: bool = False
    path_params: Mapping[str, type] = field(default_factory=_no_params)

    def __post_init__(self) -> None:
        if not self.path.startswith(f"{API_V1_PREFIX}/"):
            raise ValueError(
                f"{self.operation_id}: path must start with the versioned prefix '{API_V1_PREFIX}/'"
            )
        if self.success_status == 204 and self.response_model is not None:
            raise ValueError(f"{self.operation_id}: 204 responses must have no response model")
        if self.paginated and not self.is_list:
            raise ValueError(f"{self.operation_id}: paginated endpoints must return Page[...]")
        if self.is_list and not self.paginated:
            raise ValueError(f"{self.operation_id}: Page[...] responses must be paginated")
        if self.paginated and self.query_model is not PageParams:
            raise ValueError(
                f"{self.operation_id}: paginated endpoints must declare PageParams "
                "as their query_model"
            )
        if not self.paginated and self.query_model is not None:
            raise ValueError(f"{self.operation_id}: only paginated endpoints may declare a query")
        if self.method in ("GET", "DELETE") and self.request_model is not None:
            raise ValueError(f"{self.operation_id}: {self.method} must not declare a request model")
        if self.method == "POST" and self.request_model is None:
            raise ValueError(f"{self.operation_id}: POST must declare a request model")
        placeholders = {part[1:-1] for part in self.path.split("/") if part.startswith("{")}
        if placeholders != set(self.path_params):
            raise ValueError(
                f"{self.operation_id}: path placeholders {sorted(placeholders)} "
                f"do not match path_params {sorted(self.path_params)}"
            )

    @property
    def is_list(self) -> bool:
        """True when the response is a (parameterized) pagination ``Page``."""
        return self.response_model is not None and issubclass(self.response_model, Page)

    @property
    def item_model(self) -> type[BaseModel] | None:
        """The item type of a ``Page[...]`` response; None for non-list endpoints."""
        if not self.is_list:
            return None
        args = self.response_model.__pydantic_generic_metadata__["args"]
        assert len(args) == 1 and isinstance(args[0], type), self.operation_id
        return args[0]


_ORG_PATH_PARAMS = MappingProxyType({"organization_id": OrganizationId})
_MEMBER_PATH_PARAMS = MappingProxyType({"organization_id": OrganizationId, "user_id": UserId})
_KEY_PATH_PARAMS = MappingProxyType({"organization_id": OrganizationId, "key_id": ApiKeyId})

#: Every §14 endpoint, in spec order. Tuple so downstream code cannot mutate
#: the frozen contract.
ENDPOINTS: tuple[EndpointSpec, ...] = (
    EndpointSpec(
        operation_id="get_current_user",
        method="GET",
        path=f"{API_V1_PREFIX}/me",
        success_status=200,
        response_model=MeResponse,
    ),
    EndpointSpec(
        operation_id="list_organizations",
        method="GET",
        path=f"{API_V1_PREFIX}/organizations",
        success_status=200,
        response_model=Page[OrganizationResponse],
        query_model=PageParams,
        paginated=True,
    ),
    EndpointSpec(
        operation_id="create_organization",
        method="POST",
        path=f"{API_V1_PREFIX}/organizations",
        success_status=201,
        request_model=OrganizationCreateRequest,
        response_model=OrganizationResponse,
    ),
    EndpointSpec(
        operation_id="get_organization",
        method="GET",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}",
        success_status=200,
        response_model=OrganizationResponse,
        path_params=_ORG_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="list_members",
        method="GET",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/members",
        success_status=200,
        response_model=Page[MemberResponse],
        query_model=PageParams,
        paginated=True,
        path_params=_ORG_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="create_member",
        method="POST",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/members",
        success_status=201,
        request_model=MemberCreateRequest,
        response_model=MemberResponse,
        path_params=_ORG_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="remove_member",
        method="DELETE",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/members/{{user_id}}",
        success_status=204,
        path_params=_MEMBER_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="list_api_keys",
        method="GET",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/api-keys",
        success_status=200,
        response_model=Page[ApiKeySummary],
        query_model=PageParams,
        paginated=True,
        path_params=_ORG_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="create_api_key",
        method="POST",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/api-keys",
        success_status=201,
        request_model=ApiKeyCreateRequest,
        response_model=ApiKeyCreatedResponse,
        path_params=_ORG_PATH_PARAMS,
    ),
    EndpointSpec(
        operation_id="revoke_api_key",
        method="DELETE",
        path=f"{API_V1_PREFIX}/organizations/{{organization_id}}/api-keys/{{key_id}}",
        success_status=204,
        path_params=_KEY_PATH_PARAMS,
    ),
)


def endpoint_for(operation_id: str) -> EndpointSpec:
    """Look up one frozen entry by ``operation_id`` (KeyError if unknown)."""
    for spec in ENDPOINTS:
        if spec.operation_id == operation_id:
            return spec
    raise KeyError(f"unknown operation_id: {operation_id!r}")


__all__ = ["API_V1_PREFIX", "ENDPOINTS", "EndpointSpec", "endpoint_for"]
