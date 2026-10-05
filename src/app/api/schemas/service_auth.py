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
    organization_id: OrganizationId
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
