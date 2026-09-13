"""``/v1/organizations/{organization_id}/members`` routers (Phase 04 task 5).

:func:`build_members_router` registers the three frozen §14 member entries
from the manifest specs themselves (the ``me.py`` pattern): list through the
shared **member** access dependency, add/remove through the **admin** one
(decision 3: mutations require rank >= admin). All tenancy/role checks and
their uniform 403 + denial audit happen inside the dependency — this module
carries only the decision-6 translation table for service/storage errors:

- ``OwnerRoleNotAssignableError`` → 400 ``validation_error``;
- ``MemberNotFoundError`` / ``TargetUserNotFoundError`` → 404 ``not_found``;
- ``MembershipConflictError`` / ``OwnerMembershipImmutableError`` → 409
  ``conflict``;
- ``InvalidCursorError`` → 400 ``validation_error``;
- anything else stays untranslated (frozen 500 handler; adapter text is
  never echoed).

``DELETE`` answers 204 with an empty body (manifest-pinned). Response
projections carry no ``mem_`` record id and no email (frozen
``MemberResponse``); the record id appears only inside audit targets.
"""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the handler signatures reference closure locals in
# ``Annotated[..., Depends(...)]`` position, which PEP 563 stringified
# annotations could not resolve at import time.
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.schemas.manifest import endpoint_for
from app.api.schemas.members import MemberCreateRequest, MemberResponse
from app.auth.cognito import AccessTokenVerifier
from app.auth.organization_access import (
    OrganizationAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
)
from app.models.ids import OrganizationId, UserId
from app.models.membership import Membership
from app.models.pagination import Page, PageParams
from app.services import member as member_service
from app.services.authorization import (
    MemberNotFoundError,
    MembershipConflictError,
    OwnerMembershipImmutableError,
    OwnerRoleNotAssignableError,
    TargetUserNotFoundError,
)
from app.storage.contract import InvalidCursorError, Storage

#: The frozen §14 entries this router must register exactly.
_LIST_SPEC = endpoint_for("list_members")
_CREATE_SPEC = endpoint_for("create_member")
_REMOVE_SPEC = endpoint_for("remove_member")

#: Fixed safe message for a rejected client cursor (decision 6).
INVALID_CURSOR_MESSAGE = "pagination cursor is invalid"


def _to_response(membership: Membership) -> MemberResponse:
    """Project a domain membership onto the frozen response (no ``mem_`` id)."""
    return MemberResponse(
        user_id=membership.user_id,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
    )


def build_members_router(storage: Storage, verifier: AccessTokenVerifier) -> APIRouter:
    """Build the member routers bound to ``storage`` and ``verifier``."""
    router = APIRouter(tags=["members"])
    list_access = build_organization_member_dependency(storage, verifier, "list_members")
    create_access = build_organization_admin_dependency(storage, verifier, "create_member")
    remove_access = build_organization_admin_dependency(storage, verifier, "remove_member")

    def list_members(
        access: Annotated[OrganizationAccess, Depends(list_access)],
        page: Annotated[PageParams, Query()],
    ) -> Page[MemberResponse]:
        """Caller-authorized page of the organization's memberships."""
        try:
            domain_page = member_service.list_members(storage, access.organization.id, page)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail=INVALID_CURSOR_MESSAGE) from exc
        return Page[MemberResponse](
            items=[_to_response(membership) for membership in domain_page.items],
            limit=domain_page.limit,
            next_cursor=domain_page.next_cursor,
        )

    def create_member(
        body: MemberCreateRequest,
        access: Annotated[OrganizationAccess, Depends(create_access)],
    ) -> MemberResponse:
        """Grant a user a role; 201 with the derived member projection."""
        try:
            membership = member_service.add_member(
                storage,
                access.identity.user.id,
                access.organization.id,
                body.user_id,
                body.role,
            )
        except OwnerRoleNotAssignableError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (MemberNotFoundError, TargetUserNotFoundError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (MembershipConflictError, OwnerMembershipImmutableError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _to_response(membership)

    def remove_member(
        organization_id: OrganizationId,
        user_id: UserId,
        access: Annotated[OrganizationAccess, Depends(remove_access)],
    ) -> None:
        """Physically remove a membership; 204 with an empty body."""
        try:
            member_service.remove_member(
                storage,
                access.identity.user.id,
                organization_id,
                user_id,
            )
        except (MemberNotFoundError, TargetUserNotFoundError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (MembershipConflictError, OwnerMembershipImmutableError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    router.add_api_route(
        _LIST_SPEC.path,
        list_members,
        methods=[_LIST_SPEC.method],
        status_code=_LIST_SPEC.success_status,
        response_model=_LIST_SPEC.response_model,
    )
    router.add_api_route(
        _CREATE_SPEC.path,
        create_member,
        methods=[_CREATE_SPEC.method],
        status_code=_CREATE_SPEC.success_status,
        response_model=_CREATE_SPEC.response_model,
    )
    router.add_api_route(
        _REMOVE_SPEC.path,
        remove_member,
        methods=[_REMOVE_SPEC.method],
        status_code=_REMOVE_SPEC.success_status,
        response_model=_REMOVE_SPEC.response_model,
    )
    return router


__all__ = ["build_members_router"]
