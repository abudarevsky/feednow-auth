"""Server-to-server endpoints used by registered product services."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Security
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from app.api.schemas.manifest import endpoint_for
from app.api.schemas.service_auth import (
    ApiKeyValidationRequest,
    ApiKeyValidationResponse,
    ServiceAuthorizationContextResponse,
    ServiceCodeExchangeRequest,
    ServiceContextValidationRequest,
    ServiceContextValidationResponse,
    ServiceHandoffRequest,
)
from app.auth.api_key_auth import ApiKeyAuthenticationError, verify_api_key
from app.auth.pepper import PepperSource
from app.auth.session import SessionManager, read_session_cookie
from app.models.enums import MembershipStatus, OrganizationStatus, UserStatus
from app.models.ids import OrganizationId
from app.models.pagination import PageParams
from app.models.service_authorization import ServiceAuthorizationCode, ServiceRegistration
from app.models.timestamps import utc_now
from app.services.service_authorization import (
    membership_permission_version,
    service_permissions_for_role,
)
from app.storage.contract import EntityNotFoundError, Storage

_VISPECTOR_INSPECTION_SCOPE = "vispector:inspection:run"
_VALIDATE_SPEC = endpoint_for("validate_service_api_key")
_SERVICE_BEARER = HTTPBearer(
    auto_error=False,
    scheme_name="ServiceBearerAuth",
    description="Server-only service credential configured by the FeedNow operator.",
)
_AUTHORIZATION_CODE_TTL = timedelta(minutes=2)


def build_service_auth_router(
    storage: Storage,
    pepper_source: PepperSource,
    *,
    service_credential: str,
    service_registration: ServiceRegistration | None = None,
    session_manager: SessionManager | None = None,
) -> APIRouter:
    """Build API-key validation routes protected by a server-only service secret."""
    router = APIRouter(tags=["service-auth"])

    @router.post(
        _VALIDATE_SPEC.path,
        status_code=_VALIDATE_SPEC.success_status,
        response_model=ApiKeyValidationResponse,
    )
    def validate_api_key(
        body: ApiKeyValidationRequest,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_SERVICE_BEARER)],
    ) -> ApiKeyValidationResponse:
        """Validate a Vispector key and return only its safe authorization context."""
        if (
            not service_credential
            or credentials is None
            or not hmac.compare_digest(
                credentials.credentials.encode(), service_credential.encode()
            )
        ):
            raise HTTPException(status_code=401, detail="invalid service credentials")

        try:
            verified = verify_api_key(storage, pepper_source, body.key)
        except ApiKeyAuthenticationError as exc:
            raise HTTPException(status_code=401, detail="invalid API key credentials") from exc

        api_key = verified.api_key
        if api_key.service_id != "vispector" or api_key.scopes != [_VISPECTOR_INSPECTION_SCOPE]:
            raise HTTPException(status_code=403, detail="service access denied")
        try:
            organization = storage.get_organization(OrganizationId(api_key.organization_id))
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=403, detail="service access denied") from exc
        if organization.status is not OrganizationStatus.ACTIVE:
            raise HTTPException(status_code=403, detail="service access denied")

        return ApiKeyValidationResponse(
            actor_type="api_key",
            actor_id=api_key.id,
            user_id=api_key.created_by_user_id,
            organization_id=api_key.organization_id,
            service="vispector",
            permissions=["inspect"],
            expires_at=api_key.expires_at,
        )

    handoff_spec = endpoint_for("handoff_to_registered_service")
    exchange_spec = endpoint_for("exchange_service_authorization_code")
    context_spec = endpoint_for("validate_service_context")

    def resolve_active_context(user_id: str, organization_id: OrganizationId | None):
        try:
            user = storage.get_user(user_id)
            if organization_id is None:
                organizations = storage.list_user_organizations(user_id, PageParams(limit=2)).items
                if len(organizations) != 1:
                    raise HTTPException(status_code=403, detail="service access denied")
                organization = organizations[0]
                organization_id = OrganizationId(organization.id)
            else:
                organization = storage.get_organization(organization_id)
            membership = storage.get_membership(organization_id=organization_id, user_id=user_id)
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=403, detail="service access denied") from exc
        if (
            user.status is not UserStatus.ACTIVE
            or organization.status is not OrganizationStatus.ACTIVE
            or membership.status is not MembershipStatus.ACTIVE
        ):
            raise HTTPException(status_code=403, detail="service access denied")
        return user, organization, membership

    def issue_handoff(user_id: str, body: ServiceHandoffRequest) -> RedirectResponse:
        if (
            service_registration is None
            or body.service_id != service_registration.service_id
            or not service_registration.enabled
        ):
            raise HTTPException(status_code=403, detail="service access denied")
        user, organization, membership = resolve_active_context(user_id, body.organization_id)
        permissions = service_permissions_for_role(
            membership.role, service_registration.allowed_permissions
        )
        if not permissions:
            raise HTTPException(status_code=403, detail="service access denied")
        now = utc_now()
        raw_code = secrets.token_urlsafe(32)
        code_digest = hashlib.sha256(raw_code.encode("ascii")).hexdigest()
        storage.save_service_authorization_code(
            ServiceAuthorizationCode(
                code_digest=code_digest,
                service_id=service_registration.service_id,
                user_id=user.id,
                organization_id=organization.id,
                permissions=permissions,
                permission_version=membership_permission_version(
                    membership.role, membership.created_at
                ),
                expires_at=now + _AUTHORIZATION_CODE_TTL,
            )
        )
        destination = (
            service_registration.allowed_origins[0].rstrip("/")
            + service_registration.callback_path
        )
        return RedirectResponse(
            f"{destination}?{urlencode({'code': raw_code, 'state': body.state})}",
            status_code=handoff_spec.success_status,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
            },
        )

    @router.post(context_spec.path, response_model=ServiceContextValidationResponse)
    def validate_service_context(
        body: ServiceContextValidationRequest,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_SERVICE_BEARER)],
    ) -> ServiceContextValidationResponse:
        """Revalidate a Vispector local session against FeedNow's current grant."""
        if (
            not service_credential
            or credentials is None
            or not hmac.compare_digest(
                credentials.credentials.encode(), service_credential.encode()
            )
        ):
            raise HTTPException(status_code=401, detail="invalid service credentials")
        if (
            body.service_id != "vispector"
            or service_registration is None
            or not service_registration.enabled
            or service_registration.service_id != body.service_id
        ):
            raise HTTPException(status_code=403, detail="service access denied")
        user, organization, membership = resolve_active_context(body.user_id, body.organization_id)
        permissions = service_permissions_for_role(
            membership.role, service_registration.allowed_permissions
        )
        if not permissions:
            raise HTTPException(status_code=403, detail="service access denied")
        return ServiceContextValidationResponse(
            user_id=user.id,
            organization_id=organization.id,
            display_name=user.display_name,
            organization_name=organization.name,
            service=body.service_id,
            permissions=list(permissions),
            permission_version=membership_permission_version(
                membership.role, membership.created_at
            ),
        )

    @router.post(handoff_spec.path, status_code=handoff_spec.success_status)
    async def handoff_to_service(request: Request) -> RedirectResponse:
        """Issue a short-lived code and redirect only to configured service origin."""
        if service_registration is None or session_manager is None:
            raise HTTPException(status_code=503, detail="service authorization is not configured")
        try:
            if request.headers.get("content-type", "").startswith(
                "application/x-www-form-urlencoded"
            ):
                body = ServiceHandoffRequest.model_validate(dict(await request.form()))
            else:
                body = ServiceHandoffRequest.model_validate(await request.json())
        except (ValidationError, ValueError):
            raise HTTPException(status_code=422, detail="invalid service handoff request") from None
        origin = request.headers.get("origin")
        if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            if origin is None or origin.rstrip("/") not in service_registration.allowed_origins:
                raise HTTPException(status_code=403, detail="service access denied")
        elif origin and origin.rstrip("/") not in service_registration.allowed_origins:
            raise HTTPException(status_code=403, detail="service access denied")
        session_id = read_session_cookie(request)
        user_id = session_manager.verify(session_id) if session_id is not None else None
        if user_id is None:
            raise HTTPException(status_code=401, detail="authenticated session required")
        return issue_handoff(user_id, body)

    @router.get("/v1/oauth/service-handoff/continue", include_in_schema=False)
    async def continue_service_handoff(state: str, request: Request) -> RedirectResponse:
        """Resume a browser handoff using the authenticated top-level GET."""
        if service_registration is None or session_manager is None:
            raise HTTPException(status_code=503, detail="service authorization is not configured")
        try:
            ServiceHandoffRequest.model_validate(
                {"service_id": service_registration.service_id, "state": state}
            )
        except ValidationError:
            raise HTTPException(status_code=400, detail="invalid service handoff state") from None
        if not service_registration.enabled:
            raise HTTPException(status_code=403, detail="service access denied")
        session_id = read_session_cookie(request)
        user_id = session_manager.verify(session_id) if session_id is not None else None
        headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
        if user_id is None:
            callback = (
                service_registration.allowed_origins[0]
                + service_registration.callback_path
                + "?"
                + urlencode({"resume": state})
            )
            return RedirectResponse(
                "/api/oauth/login?" + urlencode({"next": callback}),
                status_code=303,
                headers=headers,
            )
        return issue_handoff(
            user_id,
            ServiceHandoffRequest(service_id=service_registration.service_id, state=state),
        )

    @router.post(
        exchange_spec.path,
        status_code=exchange_spec.success_status,
        response_model=ServiceAuthorizationContextResponse,
    )
    def exchange_code(
        body: ServiceCodeExchangeRequest,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_SERVICE_BEARER)],
    ) -> ServiceAuthorizationContextResponse:
        """Authenticate the registered service, consume, then recheck the grant."""
        if service_registration is None:
            raise HTTPException(status_code=503, detail="service authorization is not configured")
        if (
            body.service_id != service_registration.service_id
            or not service_registration.enabled
            or not service_credential
            or credentials is None
            or not hmac.compare_digest(
                credentials.credentials.encode(), service_credential.encode()
            )
        ):
            raise HTTPException(status_code=401, detail="invalid service credentials")
        digest = hashlib.sha256(body.code.encode("utf-8")).hexdigest()
        code = storage.consume_service_authorization_code(digest)
        if code is None or code.service_id != service_registration.service_id:
            raise HTTPException(status_code=401, detail="invalid authorization code")
        try:
            user = storage.get_user(code.user_id)
            organization = storage.get_organization(code.organization_id)
            membership = storage.get_membership(
                organization_id=code.organization_id, user_id=code.user_id
            )
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=403, detail="service access denied") from exc
        permissions = service_permissions_for_role(
            membership.role, service_registration.allowed_permissions
        )
        current_version = membership_permission_version(membership.role, membership.created_at)
        if (
            user.status is not UserStatus.ACTIVE
            or organization.status is not OrganizationStatus.ACTIVE
            or membership.status is not MembershipStatus.ACTIVE
            or current_version != code.permission_version
            or permissions != code.permissions
        ):
            raise HTTPException(status_code=403, detail="service access denied")
        return ServiceAuthorizationContextResponse(
            user_id=user.id,
            organization_id=organization.id,
            service=service_registration.service_id,
            permissions=list(permissions),
            permission_version=current_version,
        )

    return router


__all__ = ["build_service_auth_router"]
