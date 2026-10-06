"""API-key endpoint schemas (API contract keys endpoints, key-creation contract creation payloads).

Secret policy (AGENTS.md; initial acceptance criterion):

- :class:`ApiKeyCreateRequest` and :class:`ApiKeyCreatedResponse` are copied
  **verbatim** from key-creation contract — not derived. ``ApiKeyCreatedResponse.key`` is
  the only field anywhere in the API surface that carries a full credential
  literal: it is returned once at creation and is never stored, logged,
  audited, or re-served by any other endpoint.
- :class:`ApiKeySummary` is the list representation: identification and
  lifecycle data only (``key_prefix``, status, scopes, environment,
  timestamps). It has no ``secret_hash`` field, no plaintext field, and does
  not expose the credential contract non-secret ``key_id`` credential segment — that is a
  verification-lookup detail owned by API-key. Clients target revocation
  with the ``key_`` application identity (``ApiKeySummary.id``), which is
  what the API contract ``{key_id}`` path parameter carries.
- ``scopes`` reuses the single-source :data:`~app.models.api_key.Scope`
  value type; the shape pattern is never re-declared here. A creation
  request must include the ``scopes`` field, but an empty list is valid
  (a zero-scope key simply authorizes nothing) — plan/rate-limit policy
  must never be encoded in scopes (design rule, not a runtime denylist).

Current behavior and invariants: ``docs/credentials.md``."""

from __future__ import annotations

from typing import Annotated

from pydantic import ConfigDict, StringConstraints

from app.api.schemas.common import ApiSchema
from app.models.api_key import ApiKeyName, KeyPrefix, Scope
from app.models.enums import ApiKeyEnvironment, ApiKeyStatus
from app.models.ids import ApiKeyId
from app.models.timestamps import UtcDatetime

#: Upper bound fits the §8 literal (``fn_<env>_<key-id>_<secret>``) with a
#: 256+-bit secret generously encoded. Format/entropy are owned by Phase 05;
#: this type only bounds the one-time transport.
FullApiKey = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class ApiKeyCreateRequest(ApiSchema):
    """Body for ``POST /v1/organizations/{organization_id}/api-keys``.

    The request shape follows the key-creation contract verbatim.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "Vispector inspection key",
                    "environment": "test",
                    "scopes": ["vispector:inspection:run"],
                }
            ]
        }
    )

    name: ApiKeyName
    environment: ApiKeyEnvironment
    scopes: list[Scope]


class VispectorApiKeyCreateRequest(ApiSchema):
    """Restricted account request; service and scope are assigned by FeedNow."""

    name: ApiKeyName
    environment: ApiKeyEnvironment


class ApiKeyCreatedResponse(ApiSchema):
    """Response of key creation (key-creation contract, verbatim).

    The **only** response type that exposes the full key. Returned once;
    every later read serves :class:`ApiKeySummary` (masked) instead.
    """

    id: ApiKeyId
    name: ApiKeyName
    key: FullApiKey
    created_at: UtcDatetime


class ApiKeySummary(ApiSchema):
    """Masked key representation for list items (derived).

    Never contains ``secret_hash``, the plaintext secret, or the raw credential contract
    ``key_id`` segment — only the display prefix, lifecycle status, scopes,
    and timestamps (plus non-secret identification: id/name/environment).
    """

    id: ApiKeyId
    name: ApiKeyName
    service_id: str
    environment: ApiKeyEnvironment
    key_prefix: KeyPrefix
    status: ApiKeyStatus
    scopes: list[Scope]
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None = None
    expires_at: UtcDatetime | None = None
    revoked_at: UtcDatetime | None = None


__all__ = [
    "ApiKeyCreateRequest",
    "ApiKeyCreatedResponse",
    "ApiKeySummary",
    "FullApiKey",
    "VispectorApiKeyCreateRequest",
]
