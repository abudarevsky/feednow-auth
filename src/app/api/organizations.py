"""``/v1/organizations`` routers (Phase 04 task 4; spec §14).

:func:`build_organizations_router` mirrors the published ``me.py`` shape: a
factory closing over the injected :class:`~app.storage.contract.Storage` and
:class:`~app.auth.cognito.AccessTokenVerifier`, registering **from the frozen
manifest entries themselves** (:func:`~app.api.schemas.manifest.
endpoint_for`) so method, path, success status, and response model cannot
drift from the §14 contract.

Authorization wiring (decisions 3/5/6):

- ``GET /v1/organizations`` and ``POST /v1/organizations`` consume the
  Phase 03 authentication chain only — the list is inherently caller-scoped
  (the contract returns only active-membership organizations) and creation
  requires authentication with the creator becoming ``owner`` via the
  atomic batch. (A caller with **no** active organization is already a
  uniform 403 from the auth chain itself.)
- ``GET /v1/organizations/{organization_id}`` registers the shared
  member-access dependency: the five decision-4 denial outcomes are one
  byte-identical 403 raised inside the dependency, so this module carries
  **no** authz logic — only the decision-6 translation table for service
  and storage errors (type guard → 400, slug conflict → 409, foreign/
  malformed cursor → 400; anything else stays untranslated and lands on the
  frozen 500 handler, adapter text never echoed).

Responses are field-by-field projections of the domain models (decision 8);
``limit`` and the opaque ``next_cursor`` pass through verbatim.
"""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the handler signatures reference closure locals in
# ``Annotated[..., Depends(...)]`` position, which PEP 563 stringified
# annotations could not resolve at import time.
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.schemas.manifest import endpoint_for
from app.api.schemas.organizations import OrganizationCreateRequest, OrganizationResponse
from app.auth.cognito import AccessTokenVerifier
from app.auth.dependencies import build_current_user
from app.auth.organization_access import OrganizationAccess, build_organization_member_dependency
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
from app.services import organization as organization_service
from app.services.authorization import (
    OrganizationSlugConflictError,
    OrganizationTypeNotSelectableError,
)
from app.services.identity import ResolvedIdentity
from app.storage.contract import InvalidCursorError, Storage

#: The frozen §14 entries this router must register exactly.
_LIST_SPEC = endpoint_for("list_organizations")
_CREATE_SPEC = endpoint_for("create_organization")
_GET_SPEC = endpoint_for("get_organization")

#: Fixed safe message for a rejected client cursor (decision 6; the adapter's
#: cursor text never echoes upward).
INVALID_CURSOR_MESSAGE = "pagination cursor is invalid"


def _to_response(organization: Organization) -> OrganizationResponse:
    """Project a domain organization onto the frozen response schema."""
    return OrganizationResponse(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        type=organization.type,
        status=organization.status,
        created_at=organization.created_at,
        updated_at=organization.updated_at,
    )


def build_organizations_router(storage: Storage, verifier: AccessTokenVerifier) -> APIRouter:
    """Build the organization routers bound to ``storage`` and ``verifier``."""
    router = APIRouter(tags=["organizations"])
    current_user = build_current_user(storage, verifier)
    get_access = build_organization_member_dependency(storage, verifier, "get_organization")

    def list_organizations(
        identity: Annotated[ResolvedIdentity, Depends(current_user)],
        page: Annotated[PageParams, Query()],
    ) -> Page[OrganizationResponse]:
        """Caller-scoped page of the user's active-membership organizations."""
        try:
            domain_page = organization_service.list_organizations(storage, identity.user.id, page)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail=INVALID_CURSOR_MESSAGE) from exc
        return Page[OrganizationResponse](
            items=[_to_response(organization) for organization in domain_page.items],
            limit=domain_page.limit,
            next_cursor=domain_page.next_cursor,
        )

    def create_organization(
        body: OrganizationCreateRequest,
        identity: Annotated[ResolvedIdentity, Depends(current_user)],
    ) -> OrganizationResponse:
        """Atomically create the customer organization with the caller as owner."""
        try:
            created = organization_service.create_organization(
                storage,
                identity.user.id,
                body.name,
                body.slug,
                body.type,
            )
        except OrganizationTypeNotSelectableError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except OrganizationSlugConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _to_response(created)

    def get_organization(
        access: Annotated[OrganizationAccess, Depends(get_access)],
    ) -> OrganizationResponse:
        """One organization, already authorized by the member dependency."""
        return _to_response(access.organization)

    router.add_api_route(
        _LIST_SPEC.path,
        list_organizations,
        methods=[_LIST_SPEC.method],
        status_code=_LIST_SPEC.success_status,
        response_model=_LIST_SPEC.response_model,
    )
    router.add_api_route(
        _CREATE_SPEC.path,
        create_organization,
        methods=[_CREATE_SPEC.method],
        status_code=_CREATE_SPEC.success_status,
        response_model=_CREATE_SPEC.response_model,
    )
    router.add_api_route(
        _GET_SPEC.path,
        get_organization,
        methods=[_GET_SPEC.method],
        status_code=_GET_SPEC.success_status,
        response_model=_GET_SPEC.response_model,
    )
    return router


__all__ = ["build_organizations_router"]
