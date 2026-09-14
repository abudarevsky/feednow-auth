"""``/v1/organizations/{organization_id}/api-keys`` routers (Phase 05 task 6; spec §14/§15).

:func:`build_api_keys_router` mirrors the published ``organizations.py`` /
``members.py`` shape: a factory closing over the injected
:class:`~app.storage.contract.Storage`, :class:`~app.auth.cognito.
AccessTokenVerifier`, and :class:`~app.auth.pepper.PepperSource`, registering
**from the frozen manifest entries themselves** (:func:`~app.api.schemas.
manifest.endpoint_for`) so method, path, success status, and response model
cannot drift from the §14 contract.

Authorization wiring (decisions 6/8):

- ``GET .../api-keys`` registers the shared **member** access dependency and
  ``POST .../api-keys`` / ``DELETE .../api-keys/{key_id}`` the **admin** one —
  both with ``pepper_source`` wired, so the key-rejection branch is live: an
  API-key bearer on any management route gets the uniform 403 with the
  audited ``human_only`` denial (AC 4's no-escalation proof). All tenancy,
  rank, and denial-audit logic lives in the task-5 dependency — this module
  carries none of it.
- The path ``{key_id}`` carries the **``key_`` application identity**
  (:class:`~app.models.ids.ApiKeyId`, per the frozen manifest and
  ``ApiKeySummary.id``) — never the §8 non-secret credential segment, which
  appears in no path and no response.

HTTP translation is the decision-11 table only (shape validation stays with
the frozen schemas/422 handler; anything unmapped stays untranslated and
lands on the frozen 500 handler, adapter text never echoed):

- ``InvalidCursorError`` → 400 ``validation_error`` (Phase 04 precedent);
- :class:`~app.services.api_key_service.ApiKeyConflictError` (ULID/record-id
  collision) → 409 ``conflict`` with the fixed retry message;
- :class:`~app.services.api_key_service.ApiKeyNotFoundError` (unknown **or**
  foreign-org key — one indistinguishable 404, the no-oracle isolation
  proof) → 404 ``not_found``;
- ``ReferenceNotFoundError`` from create is structurally unreachable (the
  dependency just read the active org row; the human actor exists by
  construction) and deliberately **not** mapped — if it ever fires it is a
  bug and surfaces as the frozen 500, never a misleading 4xx.

The literal crosses into an HTTP response at exactly **one** point: the
201 :class:`~app.api.schemas.api_keys.ApiKeyCreatedResponse.key` below
(spec §15; AGENTS.md). List responses are field-by-field
:class:`~app.api.schemas.api_keys.ApiKeySummary` projections — masked
``key_prefix`` only, no ``secret_hash``, no plaintext, no §8 segment — with
``limit``/``next_cursor`` passed through verbatim (Phase 04 decision-8
pattern). The pepper is resolved from the injected source once per creation
(``current()`` is the Phase 07 rotation seam); nothing here persists or logs
it.
"""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the handler signatures reference closure locals in
# ``Annotated[..., Depends(...)]`` position, which PEP 563 stringified
# annotations could not resolve at import time.
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.schemas.api_keys import ApiKeyCreatedResponse, ApiKeyCreateRequest, ApiKeySummary
from app.api.schemas.manifest import endpoint_for
from app.auth.cognito import AccessTokenVerifier
from app.auth.organization_access import (
    OrganizationAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
)
from app.auth.pepper import PepperSource
from app.models.api_key import ApiKey
from app.models.ids import ApiKeyId, OrganizationId
from app.models.pagination import Page, PageParams
from app.services import api_key_service
from app.services.api_key_service import ApiKeyConflictError, ApiKeyNotFoundError
from app.storage.contract import InvalidCursorError, Storage

#: The frozen §14 entries this router must register exactly.
_LIST_SPEC = endpoint_for("list_api_keys")
_CREATE_SPEC = endpoint_for("create_api_key")
_REVOKE_SPEC = endpoint_for("revoke_api_key")

#: Fixed safe message for a rejected client cursor (decision 11; the
#: Phase 04 precedent — the adapter's cursor text never echoes upward).
INVALID_CURSOR_MESSAGE = "pagination cursor is invalid"


def _to_summary(api_key: ApiKey) -> ApiKeySummary:
    """Project a stored key onto the masked list schema field-by-field.

    Carries identification and lifecycle data only; ``secret_hash``, the
    plaintext secret, and the §8 ``key_id`` segment are structurally absent
    from the target schema (frozen Phase 01 contract).
    """
    return ApiKeySummary(
        id=api_key.id,
        name=api_key.name,
        environment=api_key.environment,
        key_prefix=api_key.key_prefix,
        status=api_key.status,
        scopes=list(api_key.scopes),
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
    )


def build_api_keys_router(
    storage: Storage,
    verifier: AccessTokenVerifier,
    pepper_source: PepperSource,
) -> APIRouter:
    """Build the API-key routers bound to ``storage``, ``verifier``, and ``pepper_source``."""
    router = APIRouter(tags=["api-keys"])
    # Decision 8: list is member-rank, create/revoke are admin-rank; the
    # pepper wiring makes the ``human_only`` key-refusal branch live.
    list_access = build_organization_member_dependency(
        storage, verifier, "list_api_keys", pepper_source=pepper_source
    )
    create_access = build_organization_admin_dependency(
        storage, verifier, "create_api_key", pepper_source=pepper_source
    )
    revoke_access = build_organization_admin_dependency(
        storage, verifier, "revoke_api_key", pepper_source=pepper_source
    )

    def list_api_keys(
        access: Annotated[OrganizationAccess, Depends(list_access)],
        page: Annotated[PageParams, Query()],
    ) -> Page[ApiKeySummary]:
        """Caller-authorized page of the organization's keys (all statuses)."""
        try:
            domain_page = api_key_service.list_api_keys(storage, access.organization.id, page)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail=INVALID_CURSOR_MESSAGE) from exc
        return Page[ApiKeySummary](
            items=[_to_summary(api_key) for api_key in domain_page.items],
            limit=domain_page.limit,
            next_cursor=domain_page.next_cursor,
        )

    def create_api_key(
        body: ApiKeyCreateRequest,
        access: Annotated[OrganizationAccess, Depends(create_access)],
    ) -> ApiKeyCreatedResponse:
        """Mint one key; 201 with the **only** full-literal response of the API."""
        try:
            api_key, literal = api_key_service.create_api_key(
                storage,
                access.identity.user.id,
                access.organization.id,
                body.name,
                body.environment,
                body.scopes,
                pepper=pepper_source.current(),
            )
        except ApiKeyConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        # The single crossing point: ``literal`` enters no other response,
        # row, log, or audit (decision 9; swept by the task-7 proofs).
        return ApiKeyCreatedResponse(
            id=api_key.id,
            name=api_key.name,
            key=literal,
            created_at=api_key.created_at,
        )

    def revoke_api_key(
        organization_id: OrganizationId,
        key_id: ApiKeyId,
        access: Annotated[OrganizationAccess, Depends(revoke_access)],
    ) -> None:
        """CAS-revoke one key; 204 empty body (manifest-pinned), idempotent."""
        try:
            api_key_service.revoke_api_key(
                storage,
                access.identity.user.id,
                organization_id,
                key_id,
            )
        except ApiKeyNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    router.add_api_route(
        _LIST_SPEC.path,
        list_api_keys,
        methods=[_LIST_SPEC.method],
        status_code=_LIST_SPEC.success_status,
        response_model=_LIST_SPEC.response_model,
    )
    router.add_api_route(
        _CREATE_SPEC.path,
        create_api_key,
        methods=[_CREATE_SPEC.method],
        status_code=_CREATE_SPEC.success_status,
        response_model=_CREATE_SPEC.response_model,
    )
    router.add_api_route(
        _REVOKE_SPEC.path,
        revoke_api_key,
        methods=[_REVOKE_SPEC.method],
        status_code=_REVOKE_SPEC.success_status,
        response_model=_REVOKE_SPEC.response_model,
    )
    return router


__all__ = ["build_api_keys_router"]
