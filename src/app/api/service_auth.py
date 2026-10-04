"""Server-to-server endpoints used by registered product services."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.schemas.manifest import endpoint_for
from app.api.schemas.service_auth import ApiKeyValidationRequest, ApiKeyValidationResponse
from app.auth.api_key_auth import ApiKeyAuthenticationError, verify_api_key
from app.auth.pepper import PepperSource
from app.models.enums import OrganizationStatus
from app.models.ids import OrganizationId
from app.storage.contract import EntityNotFoundError, Storage

_VISPECTOR_INSPECTION_SCOPE = "vispector:inspection:run"
_VALIDATE_SPEC = endpoint_for("validate_service_api_key")
_SERVICE_BEARER = HTTPBearer(
    auto_error=False,
    scheme_name="ServiceBearerAuth",
    description="Server-only service credential configured by the FeedNow operator.",
)


def build_service_auth_router(
    storage: Storage,
    pepper_source: PepperSource,
    *,
    service_credential: str,
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

    return router


__all__ = ["build_service_auth_router"]
