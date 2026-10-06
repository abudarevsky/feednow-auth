"""Schemas for authenticated service-to-service authorization."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.api.schemas.common import ApiSchema
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.service_authorization import ServiceId


class ApiKeyValidationRequest(ApiSchema):
    """An existing API-key literal submitted by an authenticated service."""

    key: str = Field(min_length=1, max_length=512)


class ApiKeyValidationResponse(ApiSchema):
    """Safe authorization context; never includes key or credential material."""

    actor_type: Literal["api_key"]
    actor_id: ApiKeyId
    user_id: UserId
    organization_id: OrganizationId
    service: Literal["vispector"]
    permissions: list[str]
    expires_at: datetime | None


class ServiceHandoffRequest(ApiSchema):
    """Authenticated user selection for a registered service handoff."""

    service_id: ServiceId
    organization_id: OrganizationId | None = None
    state: str = Field(min_length=16, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")


class ServiceCodeExchangeRequest(ApiSchema):
    """One-time opaque code supplied by the registered service callback."""

    service_id: ServiceId
    code: str = Field(min_length=1, max_length=512)


class ServiceAuthorizationContextResponse(ApiSchema):
    """Strict user authorization context returned to an authenticated service."""

    user_id: UserId
    organization_id: OrganizationId
    service: ServiceId
    permissions: list[str]
    permission_version: str


class ServiceContextValidationRequest(ApiSchema):
    """Current FeedNow identity and organization context held by a service session."""

    service_id: ServiceId
    user_id: UserId
    organization_id: OrganizationId | None = None


class ServiceContextValidationResponse(ApiSchema):
    """Fresh, safe authorization context for a registered service."""

    user_id: UserId
    organization_id: OrganizationId
    display_name: str
    organization_name: str
    service: ServiceId
    permissions: list[str]
    permission_version: str
