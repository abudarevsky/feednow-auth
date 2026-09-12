"""API-key endpoint schemas (spec §14 keys endpoints, §15 creation payloads).

Secret policy (AGENTS.md; Phase 01 acceptance criterion):

- :class:`ApiKeyCreateRequest` and :class:`ApiKeyCreatedResponse` are copied
  **verbatim** from spec §15 — not derived. ``ApiKeyCreatedResponse.key`` is
  the only field anywhere in the API surface that carries a full credential
  literal: it is returned once at creation and is never stored, logged,
  audited, or re-served by any other endpoint.
- :class:`ApiKeySummary` is the list representation: identification and
  lifecycle data only (``key_prefix``, status, scopes, environment,
  timestamps). It has no ``secret_hash`` field, no plaintext field, and does
  not expose the §8 non-secret ``key_id`` credential segment — that is a
  verification-lookup detail owned by Phase 05. Clients target revocation
  with the ``key_`` application identity (``ApiKeySummary.id``), which is
  what the §14 ``{key_id}`` path parameter carries.
- ``scopes`` reuses the single-source :data:`~app.models.api_key.Scope`
  value type; the shape pattern is never re-declared here. A creation
  request must include the ``scopes`` field, but an empty list is valid
  (a zero-scope key simply authorizes nothing) — plan/rate-limit policy
  must never be encoded in scopes (design rule, not a runtime denylist).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints

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
    """Body for ``POST /v1/organizations/{organization_id}/api-keys`` (spec §15, verbatim)."""

    name: ApiKeyName
    environment: ApiKeyEnvironment
    scopes: list[Scope]


class ApiKeyCreatedResponse(ApiSchema):
    """Response of key creation (spec §15, verbatim).

    The **only** response type that exposes the full key. Returned once;
    every later read serves :class:`ApiKeySummary` (masked) instead.
    """

    id: ApiKeyId
    name: ApiKeyName
    key: FullApiKey
    created_at: UtcDatetime


class ApiKeySummary(ApiSchema):
    """Masked key representation for list items (derived).

    Never contains ``secret_hash``, the plaintext secret, or the raw §8
    ``key_id`` segment — only the display prefix, lifecycle status, scopes,
    and timestamps (plus non-secret identification: id/name/environment).
    """

    id: ApiKeyId
    name: ApiKeyName
    environment: ApiKeyEnvironment
    key_prefix: KeyPrefix
    status: ApiKeyStatus
    scopes: list[Scope]
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None = None
    expires_at: UtcDatetime | None = None
    revoked_at: UtcDatetime | None = None


__all__ = ["ApiKeyCreateRequest", "ApiKeyCreatedResponse", "ApiKeySummary", "FullApiKey"]
