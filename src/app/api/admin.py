"""Read-only local platform administration API for the account milestone."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.api.schemas.admin import (
    AdminDeleteRequest,
    AdminMember,
    AdminOrganization,
    AdminOrganizationDetail,
    AdminReactivateRequest,
    AdminSummary,
    AdminSuspendRequest,
)
from app.api.schemas.manifest import endpoint_for
from app.auth.application_access import build_application_admin_user_dependency
from app.auth.cognito import AccessTokenVerifier, ProfileSource
from app.auth.pepper import PepperSource
from app.auth.session import SessionManager
from app.models.ids import OrganizationId
from app.models.pagination import PageParams
from app.models.timestamps import utc_now
from app.models.user import User
from app.storage.contract import EntityNotFoundError
from app.storage.local_admin import LocalAdminStorage

ADMIN_FORBIDDEN = "you do not have permission to administer the application"
_SUMMARY_SPEC = endpoint_for("get_admin_summary")
_SEARCH_SPEC = endpoint_for("search_admin_organizations")
_DETAIL_SPEC = endpoint_for("get_admin_organization")
_MEMBERS_SPEC = endpoint_for("list_admin_organization_members")
_SUSPEND_SPEC = endpoint_for("suspend_admin_organization")
_REACTIVATE_SPEC = endpoint_for("reactivate_admin_organization")
_DELETE_SPEC = endpoint_for("delete_admin_organization")


def build_admin_router(
    storage: LocalAdminStorage,
    verifier: AccessTokenVerifier,
    *,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
    pepper_source: PepperSource | None = None,
) -> APIRouter:
    """Build local admin reads; authorization is evaluated from current backend identity."""
    router = APIRouter(prefix="/v1/admin", tags=["administration"])
    if pepper_source is None:
        raise ValueError("admin router requires the configured API-key pepper")
    current_admin = build_application_admin_user_dependency(
        storage, verifier, pepper_source, profile_source, session_manager
    )

    def members_for(organization_id: OrganizationId) -> list[AdminMember]:
        page = storage.list_memberships(organization_id, PageParams(limit=100))
        result: list[AdminMember] = []
        for membership in page.items:
            user = storage.get_user(membership.user_id)
            result.append(
                AdminMember(
                    user_id=str(user.id),
                    display_name=user.display_name,
                    email=user.email,
                    account_status=str(user.status),
                    membership_status=membership.status,
                    role=str(membership.role),
                    registered_at=user.created_at,
                    joined_at=membership.created_at,
                )
            )
        return result

    @router.get(
        _SUMMARY_SPEC.path.removeprefix("/v1/admin"), response_model=_SUMMARY_SPEC.response_model
    )
    def summary(_principal: Annotated[User, Depends(current_admin)]) -> AdminSummary:
        counts = storage.admin_summary()  # SQLite local adapter query, never browser-side.
        return AdminSummary(**counts)

    @router.get(
        _SEARCH_SPEC.path.removeprefix("/v1/admin"), response_model=_SEARCH_SPEC.response_model
    )
    def search_organizations(
        _principal: Annotated[User, Depends(current_admin)],
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
        q: Annotated[str, Query(max_length=120)] = "",
    ) -> dict[str, Any]:
        result = storage.admin_search_organizations(
            q.strip(), PageParams(limit=limit, cursor=cursor)
        )
        items: list[AdminOrganization] = []
        for org in result.items:
            members = members_for(org.id)
            items.append(
                AdminOrganization(
                    id=str(org.id),
                    name=org.name,
                    name_status=str(org.name_status),
                    status=str(org.status),
                    suspended_at=org.suspended_at,
                    created_at=org.created_at,
                    member_count=len(members),
                    members=members,
                )
            )
        return {"items": items, "limit": result.limit, "next_cursor": result.next_cursor}

    @router.get(
        _DETAIL_SPEC.path.removeprefix("/v1/admin"), response_model=_DETAIL_SPEC.response_model
    )
    def organization_detail(
        organization_id: OrganizationId,
        _principal: Annotated[User, Depends(current_admin)],
    ) -> AdminOrganizationDetail:
        try:
            org = storage.get_organization(organization_id)
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail="organization not found") from exc
        members = members_for(organization_id)
        keys = storage.list_api_keys(organization_id, PageParams(limit=100)).items
        return AdminOrganizationDetail(
            id=str(org.id),
            name=org.name,
            name_status=str(org.name_status),
            status=str(org.status),
            suspended_at=org.suspended_at,
            created_at=org.created_at,
            member_count=len(members),
            members=members,
            type=str(org.type),
            updated_at=org.updated_at,
            services=[{"id": "vispector", "name": "Vispector"}],
            api_keys=[
                {
                    "id": str(key.id),
                    "name": key.name,
                    "service_id": key.service_id,
                    "status": str(key.status),
                    "created_at": key.created_at,
                }
                for key in keys
            ],
        )

    @router.get(
        _MEMBERS_SPEC.path.removeprefix("/v1/admin"), response_model=_MEMBERS_SPEC.response_model
    )
    def organization_members(
        organization_id: OrganizationId,
        _principal: Annotated[User, Depends(current_admin)],
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
    ) -> dict[str, Any]:
        memberships = storage.list_memberships(
            organization_id, PageParams(limit=limit, cursor=cursor)
        )
        items = []
        for membership in memberships.items:
            user = storage.get_user(membership.user_id)
            items.append(
                AdminMember(
                    user_id=str(user.id),
                    display_name=user.display_name,
                    email=user.email,
                    account_status=str(user.status),
                    membership_status=membership.status,
                    role=str(membership.role),
                    registered_at=user.created_at,
                    joined_at=membership.created_at,
                )
            )
        return {"items": items, "limit": memberships.limit, "next_cursor": memberships.next_cursor}

    @router.post(_SUSPEND_SPEC.path.removeprefix("/v1/admin"), status_code=204)
    def suspend_organization(
        organization_id: OrganizationId,
        request: AdminSuspendRequest,
        _principal: Annotated[User, Depends(current_admin)],
    ) -> Response:
        try:
            storage.admin_suspend_organization(organization_id, utc_now())
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail="organization not found") from exc
        return Response(status_code=204)

    @router.post(_REACTIVATE_SPEC.path.removeprefix("/v1/admin"), status_code=204)
    def reactivate_organization(
        organization_id: OrganizationId,
        request: AdminReactivateRequest,
        _principal: Annotated[User, Depends(current_admin)],
    ) -> Response:
        try:
            storage.admin_reactivate_organization(organization_id, utc_now())
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail="organization not found") from exc
        return Response(status_code=204)

    @router.post(_DELETE_SPEC.path.removeprefix("/v1/admin"), status_code=204)
    def delete_organization(
        organization_id: OrganizationId,
        request: AdminDeleteRequest,
        _principal: Annotated[User, Depends(current_admin)],
    ) -> Response:
        try:
            organization = storage.get_organization(organization_id)
            if request.organization_name != organization.name:
                raise HTTPException(
                    status_code=409, detail="organization confirmation does not match"
                )
            storage.admin_delete_organization(organization_id)
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=404, detail="organization not found") from exc
        return Response(status_code=204)

    return router


__all__ = ["ADMIN_FORBIDDEN", "build_admin_router"]
